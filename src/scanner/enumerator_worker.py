"""Continuous subdomain enumerator (producer).

WHY THIS EXISTS:
- Discovers subdomains ONCE and persists them (no rediscovery every run)
- Runs in parallel with scanner (producer/consumer model)
- Uses existing enumeration logic but writes to SQLite instead of returning list
- Supports incremental discovery (add new subdomains as found)

DISCOVERY FLOW:
1. Check if enumeration ran recently (last 24h) => use cache
2. If stale, run full enumeration:
   - CT logs (crt.sh)
   - Public databases (HackerTarget, ThreatCrowd)
   - DNS brute-force (18,991 patterns)
   - Wildcard detection
3. Write each discovered subdomain to SQLite immediately
4. Scanner can consume discoveries in real-time (no waiting for completion)
"""

import logging
import asyncio
from pathlib import Path
from typing import Set
from datetime import datetime, timedelta

from state.state_manager import StateManager
from scanner.enumeration import TargetEnumerator
from util.cache import Cache
from util.config import Config

logger = logging.getLogger(__name__)


class EnumeratorWorker:
    """Continuous subdomain discovery worker.
    
    Discovers new subdomains and writes them to persistent state.
    Can run in parallel with scanner (scanner consumes as we discover).
    """
    
    def __init__(self, domain: str, state_mgr: StateManager, config: Config):
        """Initialize enumerator worker.
        
        Args:
            domain: Base domain to enumerate (e.g., 'ac.lk')
            state_mgr: State manager for persistence
            config: Configuration object
        """
        self.domain = domain
        self.state_mgr = state_mgr
        self.config = config
        
        # Create cache for enumeration
        cache_dir = config.out_dir / domain / "cache"
        self.cache = Cache(cache_dir)
        
        # Create actual enumerator (reuses existing logic)
        self.enumerator = TargetEnumerator(
            domain=domain,
            cache=self.cache,
            config=config
        )
        
        self.discovered_count = 0
        self.method_counts = {}
        self._running = False
    
    async def run(self):
        """Run continuous enumeration.
        
        WHY: Discovers subdomains and persists immediately to SQLite.
        Scanner can start consuming while we're still discovering.
        """
        self._running = True
        logger.info(f"🔍 Enumerator worker starting for {self.domain}")
        
        try:
            # Check if enumeration is fresh (< 24h old)
            stats = self.state_mgr.get_stats()
            
            if stats['total_candidates'] > 0:
                # Have existing candidates - check if enumeration is recent
                # For now, always run enumeration (can add cache logic later)
                logger.info(f"Found {stats['total_candidates']} existing candidates")
                logger.info("Running fresh enumeration to discover new subdomains...")
            
            # Run comprehensive enumeration
            logger.info("Starting comprehensive subdomain enumeration...")
            logger.info(f"  Methods: CT logs, Public DBs, DNS brute-force (18,991 patterns)")
            
            # Enumerate (this returns a list of ScanTarget objects)
            discovered_targets = await self.enumerator.enumerate_async()
            
            # Extract method counts from cache
            cache_key = f"enumeration:{self.domain}"
            cached_data = self.cache.get(cache_key)
            if cached_data and 'method_counts' in cached_data:
                self.method_counts = cached_data['method_counts']
            
            # Write all discovered subdomains to state
            logger.info(f"Writing {len(discovered_targets)} discovered subdomains to state...")
            
            for target in discovered_targets:
                # Determine source based on discovery method
                fqdn = target.fqdn if hasattr(target, 'fqdn') else str(target)
                sources = self._infer_sources(fqdn, target)
                confidence = self._infer_confidence(sources)
                
                # Upsert to state (idempotent)
                self.state_mgr.upsert_candidate(
                    fqdn=fqdn,
                    sources=sources,
                    confidence=confidence
                )
                
                self.discovered_count += 1
            
            logger.info(f"✓ Enumeration complete: {self.discovered_count} subdomains discovered")
            logger.info(f"  All candidates persisted to SQLite")
            logger.info(f"  Scanner can now process eligible targets")
            
            # Signal enumeration completion for scanner coordination
            self.state_mgr.set_meta('enumeration_done', 'true')
            logger.info("  Set enumeration_done=true for scanner coordination")

        except Exception as e:
            logger.error(f"Enumerator worker error: {e}", exc_info=True)
        finally:
            self._running = False
    
    def _infer_sources(self, fqdn: str, target) -> list:
        """Get actual discovery sources for a subdomain.
        
        WHY: Track provenance of each subdomain for research transparency.
        Uses the discovered_from attribute set during enumeration.
        
        Args:
            fqdn: The fully qualified domain name
            target: ScanTarget object with discovered_from attribute
        
        Returns:
            List of discovery source tags (e.g., ['ct_logs'], ['dns_brute'])
        """
        sources = []
        
        # Get actual source from target (set during enumeration)
        if hasattr(target, 'discovered_from') and target.discovered_from != "unknown":
            sources.append(target.discovered_from)
        
        # Fallback only if no source was tracked
        if not sources:
            # This shouldn't happen with proper enumeration tracking
            # but provide reasonable fallback
            if fqdn == self.domain:
                sources.append("apex_domain")
            else:
                sources.append("unknown")
        
        return sources
    
    def _infer_confidence(self, sources: list) -> str:
        """Infer confidence level based on sources.
        
        WHY: Prioritize high-confidence discoveries.
        """
        if "ct_logs" in sources:
            return "High"  # CT logs are authoritative
        elif "dns_brute_force" in sources:
            return "Medium"  # DNS resolution confirms existence
        else:
            return "Low"
    
    def is_running(self) -> bool:
        """Check if enumerator is running."""
        return self._running
    
    def get_discovered_count(self) -> int:
        """Get number of discovered subdomains."""
        return self.discovered_count
    
    def get_method_counts(self) -> dict:
        """Get discovery method counts."""
        return self.method_counts


async def run_enumerator(domain: str, state_dir: Path, config: Config, state_mgr: StateManager):
    """Run enumerator worker.
    
    WHY standalone function: Can be run as separate task/process.
    
    Args:
        domain: Base domain
        state_dir: State directory
        config: Configuration
        state_mgr: Shared state manager
    
    Returns:
        Tuple of (discovered_count, method_counts)
    """
    worker = EnumeratorWorker(domain, state_mgr, config)
    await worker.run()
    return worker.get_discovered_count(), worker.get_method_counts()
