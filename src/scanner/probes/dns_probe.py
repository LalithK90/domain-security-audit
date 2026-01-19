"""DNS probe - resolve names and cache results.

This is our first step for any target: can we even resolve it?
Results get cached so we don't hammer DNS servers.
"""

import asyncio
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime

from util.types import ProbeResult
from util.time import now_utc, duration_ms
from util.cache import Cache

logger = logging.getLogger(__name__)


class DNSProbe:
    """Async DNS resolver with caching.
    
    Uses system DNS resolver (via asyncio) which is plenty fast.
    No need for custom DNS libraries unless we need DNSSEC validation later.
    """
    
    def __init__(self, cache: Cache, timeout: float = 4.0):
        """Initialize DNS probe with cache and timeout."""
        self.cache = cache
        self.timeout = timeout
    
    async def resolve(self, fqdn: str) -> ProbeResult:
        """Resolve a domain name to IP addresses.
        
        Returns ProbeResult with:
          - success=True if at least one record found
          - data={'a_records': [...], 'aaaa_records': [...]}
          - error if resolution failed
        """
        start = now_utc()
        
        # Check cache first
        cache_key = f"dns:{fqdn}"
        cached = self.cache.get(cache_key)
        if cached:
            logger.debug(f"DNS cache hit for {fqdn}")
            return ProbeResult(
                target=fqdn,
                probe_type='dns',
                success=cached['success'],
                data=cached['data'],
                error=cached.get('error'),
                duration_ms=0,  # Cached, no actual lookup
                timestamp=now_utc()
            )
        
        # Resolve A and AAAA records in parallel
        try:
            loop = asyncio.get_event_loop()
            
            # Fire both lookups at once
            a_task = loop.getaddrinfo(fqdn, None, family=2)  # AF_INET (IPv4)
            aaaa_task = loop.getaddrinfo(fqdn, None, family=10)  # AF_INET6 (IPv6)
            
            a_results, aaaa_results = await asyncio.gather(
                asyncio.wait_for(a_task, timeout=self.timeout),
                asyncio.wait_for(aaaa_task, timeout=self.timeout),
                return_exceptions=True
            )
            
            # Extract IPs
            a_records = []
            if not isinstance(a_results, Exception):
                a_records = list(set([r[4][0] for r in a_results]))
            
            aaaa_records = []
            if not isinstance(aaaa_results, Exception):
                aaaa_records = list(set([r[4][0] for r in aaaa_results]))
            
            # Success if we got at least one record
            success = bool(a_records or aaaa_records)
            
            data = {
                'a_records': a_records,
                'aaaa_records': aaaa_records
            }
            
            result = ProbeResult(
                target=fqdn,
                probe_type='dns',
                success=success,
                data=data,
                error=None if success else "No DNS records found",
                duration_ms=duration_ms(start),
                timestamp=now_utc()
            )
            
            # Cache the result
            self.cache.set(cache_key, {
                'success': result.success,
                'data': result.data,
                'error': result.error
            })
            
            return result
        
        except asyncio.TimeoutError:
            logger.warning(f"DNS timeout for {fqdn}")
            result = ProbeResult(
                target=fqdn,
                probe_type='dns',
                success=False,
                data={},
                error="DNS timeout",
                duration_ms=duration_ms(start),
                timestamp=now_utc()
            )
            # Cache failures too (avoid retry storm)
            self.cache.set(cache_key, {
                'success': False,
                'data': {},
                'error': result.error
            })
            return result
        
        except Exception as e:
            logger.warning(f"DNS error for {fqdn}: {e}")
            result = ProbeResult(
                target=fqdn,
                probe_type='dns',
                success=False,
                data={},
                error=f"DNS error: {str(e)}",
                duration_ms=duration_ms(start),
                timestamp=now_utc()
            )
            self.cache.set(cache_key, {
                'success': False,
                'data': {},
                'error': result.error
            })
            return result
    
    async def resolve_batch(self, fqdns: List[str]) -> Dict[str, ProbeResult]:
        """Resolve multiple domains in parallel.
        
        Returns dict mapping fqdn -> ProbeResult
        """
        tasks = [self.resolve(fqdn) for fqdn in fqdns]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Map results back to FQDNs
        result_map = {}
        for fqdn, result in zip(fqdns, results):
            if isinstance(result, Exception):
                logger.error(f"Unexpected error resolving {fqdn}: {result}")
                result_map[fqdn] = ProbeResult(
                    target=fqdn,
                    probe_type='dns',
                    success=False,
                    data={},
                    error=str(result),
                    duration_ms=0,
                    timestamp=now_utc()
                )
            else:
                result_map[fqdn] = result
        
        return result_map
