"""HTTP probe - check reachability and grab headers.

Measures if we can reach the service over HTTP/HTTPS and collects
security-relevant headers for later evaluation.
"""

import asyncio
import logging
from typing import Dict, Any, Optional
from datetime import datetime
import aiohttp
from urllib.parse import urlparse

from util.types import ProbeResult
from util.time import now_utc, duration_ms
from util.cache import Cache

logger = logging.getLogger(__name__)


class HTTPProbe:
    """Async HTTP client for reachability and header collection.
    
    Uses aiohttp for async performance and connection pooling.
    Collects just enough data for security checks - not full responses.
    """
    
    def __init__(self, cache: Cache, timeout: float = 8.0):
        """Initialize HTTP probe with cache and timeout."""
        self.cache = cache
        self.timeout = timeout
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self):
        """Set up aiohttp session with connection pooling."""
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        connector = aiohttp.TCPConnector(limit=100, limit_per_host=10)
        self.session = aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers={
                'User-Agent': 'LK-Domain-Security-Research/1.0 (Academic Study; Non-intrusive security posture measurement; +https://github.com/research-project)'
            }
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Clean up session."""
        if self.session:
            await self.session.close()
    
    async def probe(self, fqdn: str, scheme: str = 'https') -> ProbeResult:
        """Probe HTTP(S) endpoint and collect headers.
        
        Args:
            fqdn: Domain to probe
            scheme: 'http' or 'https'
        
        Returns ProbeResult with:
          - success=True if we got a response
          - data={'status': 200, 'headers': {...}, 'redirect_to': '...'}
          - error if connection failed
        """
        start = now_utc()
        url = f"{scheme}://{fqdn}/"
        
        # Check cache
        cache_key = f"http:{scheme}:{fqdn}"
        cached = self.cache.get(cache_key)
        if cached:
            logger.debug(f"HTTP cache hit for {url}")
            return ProbeResult(
                target=fqdn,
                probe_type=f'http_{scheme}',
                success=cached['success'],
                data=cached['data'],
                error=cached.get('error'),
                duration_ms=0,
                timestamp=now_utc()
            )
        
        try:
            # Make request with redirects disabled (we want to check redirects ourselves)
            async with self.session.get(url, allow_redirects=False, ssl=False) as resp:
                # Collect relevant data
                data = {
                    'status': resp.status,
                    'headers': dict(resp.headers),
                    'url': str(resp.url)
                }
                
                # Check for redirects
                if resp.status in (301, 302, 303, 307, 308):
                    data['redirect_to'] = resp.headers.get('Location', '')
                
                success = True
                error = None
                
                result = ProbeResult(
                    target=fqdn,
                    probe_type=f'http_{scheme}',
                    success=success,
                    data=data,
                    error=error,
                    duration_ms=duration_ms(start),
                    timestamp=now_utc()
                )
                
                # Cache result
                self.cache.set(cache_key, {
                    'success': success,
                    'data': data,
                    'error': error
                })
                
                return result
        
        except asyncio.TimeoutError:
            logger.debug(f"HTTP timeout for {url}")
            result = ProbeResult(
                target=fqdn,
                probe_type=f'http_{scheme}',
                success=False,
                data={},
                error="HTTP timeout",
                duration_ms=duration_ms(start),
                timestamp=now_utc()
            )
            self.cache.set(cache_key, {
                'success': False,
                'data': {},
                'error': result.error
            })
            return result
        
        except aiohttp.ClientError as e:
            logger.debug(f"HTTP error for {url}: {e}")
            result = ProbeResult(
                target=fqdn,
                probe_type=f'http_{scheme}',
                success=False,
                data={},
                error=f"HTTP error: {type(e).__name__}",
                duration_ms=duration_ms(start),
                timestamp=now_utc()
            )
            self.cache.set(cache_key, {
                'success': False,
                'data': {},
                'error': result.error
            })
            return result
        
        except Exception as e:
            logger.warning(f"Unexpected error probing {url}: {e}")
            result = ProbeResult(
                target=fqdn,
                probe_type=f'http_{scheme}',
                success=False,
                data={},
                error=f"Unexpected error: {str(e)}",
                duration_ms=duration_ms(start),
                timestamp=now_utc()
            )
            self.cache.set(cache_key, {
                'success': False,
                'data': {},
                'error': result.error
            })
            return result
    
    async def probe_both(self, fqdn: str) -> Dict[str, ProbeResult]:
        """Probe both HTTP and HTTPS for a domain.
        
        Returns dict with keys 'http' and 'https'
        """
        http_result, https_result = await asyncio.gather(
            self.probe(fqdn, 'http'),
            self.probe(fqdn, 'https'),
            return_exceptions=True
        )
        
        # Handle any exceptions
        if isinstance(http_result, Exception):
            logger.error(f"Error in HTTP probe: {http_result}")
            http_result = ProbeResult(
                target=fqdn,
                probe_type='http_http',
                success=False,
                data={},
                error=str(http_result),
                duration_ms=0,
                timestamp=now_utc()
            )
        
        if isinstance(https_result, Exception):
            logger.error(f"Error in HTTPS probe: {https_result}")
            https_result = ProbeResult(
                target=fqdn,
                probe_type='http_https',
                success=False,
                data={},
                error=str(https_result),
                duration_ms=0,
                timestamp=now_utc()
            )
        
        return {
            'http': http_result,
            'https': https_result
        }
