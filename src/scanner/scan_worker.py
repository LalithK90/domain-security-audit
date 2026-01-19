"""Scanner worker pool (consumer).

WHY THIS EXISTS:
- Claims eligible targets from SQLite queue atomically
- Respects rescan policy (don't rescan until RESCAN_HOURS elapsed)
- Bounded concurrency (won't overload system)
- Crash-safe (lease timeouts recover stuck jobs)
- Runs in parallel with enumerator (processes discoveries as they arrive)

SCANNING FLOW:
1. Claim batch of eligible targets (atomic SQL query)
2. Run probing + checks for each target
3. Mark complete with next_scan_time
4. Repeat until no more eligible targets
"""

import logging
import asyncio
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime

from state.state_manager import StateManager
from scanner.probes.dns_probe import DNSProbe
from scanner.probes.http_probe import HTTPProbe
from scanner.probes.tls_probe import TLSProbe
from scanner.probes.email_probe import EmailProbe
from scanner.checks.evaluator import CheckEvaluator
from scanner.scoring.model import ScoringModel
from util.config import Config
from util.cache import Cache
from util.types import ProbeResult, CheckResult

logger = logging.getLogger(__name__)


class ScanWorker:
    """Scanner worker that processes scan queue.
    
    Claims jobs atomically, scans them, marks complete.
    Respects rescan policy and crash recovery.
    """
    
    def __init__(self, domain: str, state_mgr: StateManager, config: Config, run_id: str):
        """Initialize scanner worker.
        
        Args:
            domain: Base domain
            state_mgr: State manager for queue operations
            config: Configuration
            run_id: Current scan run ID
        """
        self.domain = domain
        self.state_mgr = state_mgr
        self.config = config
        self.run_id = run_id
        
        # Create cache
        cache_dir = config.out_dir / domain / "cache"
        self.cache = Cache(cache_dir)
        
        # Create probe instances
        self.dns_probe = DNSProbe(self.cache, timeout=config.dns_timeout)
        self.tls_probe = TLSProbe(self.cache, timeout=config.tls_timeout)
        self.email_probe = EmailProbe(self.cache, timeout=config.dns_timeout)
        # Note: HTTP probe needs to be created in async context (has session)
        
        self.evaluator = CheckEvaluator()
        self.scoring_model = ScoringModel()
        
        self.scanned_count = 0
        self.error_count = 0
        self._running = False
        
        # Results accumulator (for export)
        self.all_results = []
    
    async def run(self, continuous: bool = False, stop_when_empty_count: int = 3):
        """Run scanner worker.
        
        Args:
            continuous: If True, keep polling for new jobs until stopped.
                       If False, process all eligible jobs once and exit.
            stop_when_empty_count: In continuous mode, stop after this many consecutive
                                  empty polls (prevents infinite waiting)
        
        WHY continuous mode: Allows scanner to process discoveries as enumerator finds them.
        WHY batch mode: For one-shot scans when enumeration is complete.
        WHY stop_when_empty_count: Allows scanner to exit gracefully after enumeration completes.
        """
        self._running = True
        logger.info(f"🔬 Scanner worker starting (continuous={continuous})")
        
        consecutive_empty = 0  # Track consecutive empty polls
        
        try:
            while self._running:
                # Claim batch of eligible jobs
                batch = self.state_mgr.claim_scan_jobs(batch_size=self.config.max_scan_batch)
                
                if not batch:
                    consecutive_empty += 1
                    
                    if continuous:
                        # Check if enumeration is complete
                        enumeration_done = self.state_mgr.get_meta(
                            'enumeration_done', 'false') == 'true'

                        # No jobs available, wait and retry
                        if consecutive_empty >= stop_when_empty_count and enumeration_done:
                            logger.info(
                                f"No new jobs after {consecutive_empty} polls and enumeration complete, scanner worker exiting")
                            break
                        elif consecutive_empty >= stop_when_empty_count and not enumeration_done:
                            logger.info(
                                f"No jobs available but enumeration still running, continuing to poll...")
                            consecutive_empty = 0  # Reset counter to keep waiting

                        logger.debug(f"No eligible jobs, waiting {self.config.scan_poll_seconds}s... ({consecutive_empty}/{stop_when_empty_count})")
                        await asyncio.sleep(self.config.scan_poll_seconds)
                        continue
                    else:
                        # Batch mode: exit when no more jobs
                        logger.info("No more eligible jobs, scanner worker exiting")
                        break
                
                # Reset consecutive empty counter when we get jobs
                consecutive_empty = 0
                
                logger.info(f"Claimed {len(batch)} targets for scanning")
                
                # Scan batch
                await self._scan_batch(batch)
                
                # Update run statistics
                self.state_mgr.update_run(
                    self.run_id,
                    scanned=self.scanned_count,
                    errors=self.error_count
                )
        
        except Exception as e:
            logger.error(f"Scanner worker error: {e}", exc_info=True)
        finally:
            self._running = False
    
    async def _scan_batch(self, fqdns: List[str]):
        """Scan a batch of targets.
        
        WHY batch processing: Efficient use of async I/O and connection pooling.
        """
        for fqdn in fqdns:
            try:
                await self._scan_single(fqdn)
                self.scanned_count += 1
            except Exception as e:
                logger.error(f"Failed to scan {fqdn}: {e}")
                self.error_count += 1
                
                # Mark as error
                self.state_mgr.mark_scan_complete(
                    fqdn,
                    success=False,
                    error_msg=str(e)
                )
    
    async def _scan_single(self, fqdn: str):
        """Scan a single target.
        
        WHY: Execute full scan pipeline: probe → evaluate → score → persist.
        """
        logger.debug(f"Scanning {fqdn}...")
        
        # Phase 1: Probing
        # Create HTTP probe (needs async context)
        async with HTTPProbe(self.cache, timeout=self.config.http_timeout) as http_probe:
            # Run DNS probe first
            dns_result = await self.dns_probe.resolve(fqdn)
            
            if not dns_result.success:
                # DNS failed - target doesn't exist
                logger.warning(f"DNS failed for {fqdn}: {dns_result.error}")
                self.state_mgr.mark_scan_complete(
                    fqdn,
                    success=False,
                    error_msg=f"DNS resolution failed: {dns_result.error}"
                )
                return
            
            # Run HTTP, TLS, Email probes in parallel
            http_results = await http_probe.probe_both(fqdn)
            tls_result = await self.tls_probe.probe(fqdn)
            
            # Email probes only for apex domain (not subdomains)
            if fqdn == self.domain or fqdn.count('.') <= 1:
                email_result = await self.email_probe.probe_all(fqdn)
            else:
                email_result = None
            
            # Build probe_data structure expected by evaluator
            # WHY: Evaluator expects ProbeResult objects with .success, .data, .error attributes
            #      NOT just data dicts - it needs to check .success before accessing .data
            probe_data = {
                'dns': dns_result if dns_result else None,
                'http': http_results.get('http') if http_results.get('http') else None,
                'https': http_results.get('https') if http_results.get('https') else None,
                'tls': tls_result if tls_result else None,
                'email': email_result if email_result else {}
            }
        
        # Phase 2: Evaluate security checks
        try:
            check_results = await self.evaluator.evaluate_all_async(fqdn, probe_data)
        except Exception as e:
            logger.error(f"Check evaluation failed for {fqdn}: {e}", exc_info=True)
            self.state_mgr.mark_scan_complete(
                fqdn,
                success=False,
                error_msg=f"Check evaluation failed: {e}"
            )
            return
        
        # Convert to dicts for storage
        check_dicts = [result.to_dict() for result in check_results]
        
        # Phase 3: Compute score
        score = self.scoring_model.score_subdomain(fqdn, check_results)
        overall_score = score.pass_rate if score else 0.0
        
        # Phase 4: Persist results
        self.state_mgr.save_scan_result(
            fqdn=fqdn,
            run_id=self.run_id,
            check_results=check_dicts,
            overall_score=overall_score
        )
        
        # Mark scan complete (schedules next scan based on policy)
        self.state_mgr.mark_scan_complete(fqdn, success=True)
        
        # Accumulate results for export
        for result in check_results:
            result_dict = result.to_dict()
            result_dict['run_id'] = self.run_id
            self.all_results.append(result_dict)
        
        logger.debug(f"✓ Scanned {fqdn}: {len(check_results)} checks, score={overall_score:.1f}")
    
    def stop(self):
        """Stop scanner worker gracefully."""
        logger.info("Stopping scanner worker...")
        self._running = False
    
    def is_running(self) -> bool:
        """Check if scanner is running."""
        return self._running
    
    def get_stats(self) -> Dict[str, int]:
        """Get scanner statistics."""
        return {
            'scanned': self.scanned_count,
            'errors': self.error_count
        }
    
    def get_all_results(self) -> List[Dict[str, Any]]:
        """Get all accumulated results for export."""
        return self.all_results


async def run_scanner_worker(domain: str, state_mgr: StateManager, config: Config, 
                             run_id: str, continuous: bool = False):
    """Run scanner worker.
    
    WHY standalone function: Can be run as separate task/process.
    
    Args:
        domain: Base domain
        state_mgr: Shared state manager
        config: Configuration
        run_id: Current scan run ID
        continuous: Whether to keep polling for new jobs
    
    Returns:
        ScanWorker instance (for results export)
    """
    worker = ScanWorker(domain, state_mgr, config, run_id)
    await worker.run(continuous=continuous)
    return worker
