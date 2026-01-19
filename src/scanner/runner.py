"""Scanner pipeline runner - orchestrates the entire scan workflow.

This is where all the pieces come together:
1. Enumerate targets
2. Run probes (DNS, HTTP, TLS, Email)
3. Evaluate checks
4. Score results
5. Write output
"""

import asyncio
import logging
from typing import List, Dict, Any
from pathlib import Path
from collections import defaultdict

from util.types import ScanConfig, ScanTarget, CheckResult, ProbeResult
from util.time import now_utc, duration_ms
from util.cache import Cache
from util.concurrency import ConcurrencyController
from util.log import get_logger

from scanner.profiles import DomainProfile
from scanner.enumeration import TargetEnumerator
from scanner.probes.dns_probe import DNSProbe
from scanner.probes.http_probe import HTTPProbe
from scanner.probes.tls_probe import TLSProbe
from scanner.probes.email_probe import EmailProbe
from scanner.checks.evaluator import CheckEvaluator
from scanner.scoring.model import ScoringModel, SubdomainScore
from scanner.output.writer import OutputWriter

logger = get_logger(__name__)


class ScanRunner:
    """Orchestrates the complete security scan pipeline.
    
    This is the main engine - coordinates all the moving parts.
    """
    
    def __init__(self, config: ScanConfig):
        """Initialize scanner with configuration."""
        self.config = config
        self.profile = DomainProfile(config.domain)
        
        # Set up cache
        cache_dir = Path(config.out_dir) / config.domain / "cache"
        self.cache = Cache(cache_dir, ttl_hours=config.cache_ttl_hours)
        
        # Clear cache if force rescan
        if config.force_rescan:
            cleared = self.cache.clear()
            logger.info(f"Force rescan: cleared {cleared} cache files")
        
        # Concurrency controller
        self.concurrency = ConcurrencyController(
            max_workers=config.max_workers,
            rate_limit_delay=config.rate_limit_delay
        )
        
        logger.info(f"Scanner initialized for {config.domain}")
        logger.info(f"Max workers: {config.max_workers}, Rate limit: {config.rate_limit_delay}s")
    
    async def run(self) -> Dict[str, Any]:
        """Run the complete scan pipeline.
        
        Returns summary dict with results and metadata.
        """
        start_time = now_utc()
        logger.info("=" * 60)
        logger.info(f"Starting security scan for {self.config.domain}")
        logger.info("=" * 60)
        
        # Phase 1: Enumerate targets
        logger.info("Phase 1: Target Enumeration")
        enumerator = TargetEnumerator(self.config.domain, self.cache, self.config)
        targets = await enumerator.enumerate_async()
        logger.info(f"Enumerated {len(targets)} targets")
        
        if not targets:
            logger.error("No targets found - aborting scan")
            return {'error': 'No targets enumerated'}
        
        # Phase 2: Run probes on all targets
        logger.info("Phase 2: Probing Targets")
        probe_results = await self._probe_all_targets(targets)
        logger.info(f"Completed probing {len(probe_results)} targets")
        
        # Phase 3: Evaluate security checks
        logger.info("Phase 3: Evaluating Security Checks")
        check_results = self._evaluate_all_checks(probe_results)
        logger.info(f"Evaluated {len(check_results)} checks")
        
        # Phase 4: Compute scores
        logger.info("Phase 4: Computing Scores")
        scoring_model = ScoringModel()
        subdomain_scores = self._compute_scores(check_results, scoring_model)
        domain_summary = scoring_model.aggregate_domain_score(subdomain_scores)
        logger.info(f"Computed scores for {len(subdomain_scores)} subdomains")
        
        # Phase 5: Write output
        logger.info("Phase 5: Writing Output")
        writer = OutputWriter(
            domain=self.config.domain,
            out_dir=self.config.out_dir,
            enable_excel=self.config.enable_excel
        )
        
        run_metadata = {
            'domain': self.config.domain,
            'start_time': start_time.isoformat(),
            'end_time': now_utc().isoformat(),
            'duration_seconds': duration_ms(start_time) / 1000,
            'target_count': len(targets),
            'check_count': len(check_results),
            'config': {
                'max_workers': self.config.max_workers,
                'cache_ttl_hours': self.config.cache_ttl_hours,
                'force_rescan': self.config.force_rescan,
            }
        }
        
        writer.write_all(
            check_results=check_results,
            subdomain_scores=subdomain_scores,
            domain_summary=domain_summary,
            run_metadata=run_metadata
        )
        
        # Summary
        elapsed = duration_ms(start_time) / 1000
        logger.info("=" * 60)
        logger.info("Scan Complete!")
        logger.info(f"Duration: {elapsed:.1f}s")
        logger.info(f"Targets scanned: {len(targets)}")
        logger.info(f"Checks evaluated: {len(check_results)}")
        logger.info(f"Average pass rate: {domain_summary['avg_pass_rate']:.1f}%")
        logger.info(f"Output: {writer.get_output_dir()}")
        logger.info("=" * 60)
        
        return {
            'success': True,
            'domain': self.config.domain,
            'targets_scanned': len(targets),
            'checks_evaluated': len(check_results),
            'domain_summary': domain_summary,
            'output_dir': str(writer.get_output_dir()),
            'duration_seconds': elapsed
        }
    
    async def _probe_all_targets(self, targets: List[ScanTarget]) -> Dict[str, Dict[str, ProbeResult]]:
        """Run all probes on all targets.
        
        Returns dict mapping fqdn -> probe results
        """
        # Initialize probes
        dns_probe = DNSProbe(self.cache, timeout=self.config.dns_timeout)
        tls_probe = TLSProbe(self.cache, timeout=self.config.tls_timeout)
        email_probe = EmailProbe(self.cache, timeout=self.config.dns_timeout)
        
        # Use context manager for HTTP probe (needs session)
        async with HTTPProbe(self.cache, timeout=self.config.http_timeout) as http_probe:
            # Probe all targets concurrently
            tasks = [
                self._probe_single_target(target, dns_probe, http_probe, tls_probe, email_probe)
                for target in targets
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Build result dict
            probe_results = {}
            for target, result in zip(targets, results):
                if isinstance(result, Exception):
                    logger.error(f"Error probing {target.fqdn}: {result}")
                    # Create empty probe results
                    probe_results[target.fqdn] = {
                        'target': target.fqdn,
                        'dns': None,
                        'http': None,
                        'https': None,
                        'tls': None,
                        'email': None
                    }
                else:
                    probe_results[target.fqdn] = result
            
            return probe_results
    
    async def _probe_single_target(self,
                                   target: ScanTarget,
                                   dns_probe: DNSProbe,
                                   http_probe: HTTPProbe,
                                   tls_probe: TLSProbe,
                                   email_probe: EmailProbe) -> Dict[str, Any]:
        """Run all probes for a single target with concurrency control."""
        async with self.concurrency.acquire():
            fqdn = target.fqdn
            
            # Start with DNS (needed to know if target exists)
            dns_result = await dns_probe.resolve(fqdn)
            
            # If DNS fails, skip other probes (target doesn't exist)
            if not dns_result.success:
                logger.debug(f"DNS failed for {fqdn} - skipping other probes")
                return {
                    'target': fqdn,
                    'dns': dns_result,
                    'http': None,
                    'https': None,
                    'tls': None,
                    'email': None
                }
            
            # Run HTTP, TLS, and Email probes in parallel (DNS succeeded)
            http_results = await http_probe.probe_both(fqdn)
            tls_result = await tls_probe.probe(fqdn)
            
            # Email probes only for apex domain
            email_results = {}
            if self.profile.is_apex_domain() or target.fqdn == self.profile.base_domain:
                email_results = await email_probe.probe_all(target.fqdn)
            
            return {
                'target': fqdn,
                'dns': dns_result,
                'http': http_results.get('http'),
                'https': http_results.get('https'),
                'tls': tls_result,
                'email': email_results
            }
    
    def _evaluate_all_checks(self, probe_results: Dict[str, Dict[str, Any]]) -> List[CheckResult]:
        """Evaluate security checks for all targets.
        
        Args:
            probe_results: Dict mapping fqdn -> probe results
        
        Returns:
            List of all CheckResults across all targets
        """
        evaluator = CheckEvaluator()
        all_results = []
        
        for fqdn, probe_data in probe_results.items():
            # Evaluate checks for this target
            results = evaluator.evaluate_all(fqdn, probe_data)
            all_results.extend(results)
        
        return all_results
    
    def _compute_scores(self, check_results: List[CheckResult], scoring_model: ScoringModel) -> List[SubdomainScore]:
        """Compute scores for each subdomain from check results.
        
        Groups results by target and scores each.
        """
        # Group results by target
        by_target = defaultdict(list)
        for result in check_results:
            by_target[result.target].append(result)
        
        # Score each target
        scores = []
        for target, results in by_target.items():
            score = scoring_model.score_subdomain(target, results)
            scores.append(score)
        
        return scores
