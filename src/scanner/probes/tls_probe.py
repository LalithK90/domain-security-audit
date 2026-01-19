"""TLS probe - fast handshake to check certificate and protocol version.

We only do basic TLS checks by default - no deep cryptanalysis.
Goal is to verify cert validity, hostname match, and TLS version.
"""

import asyncio
import logging
import ssl
from typing import Dict, Any, Optional
from datetime import datetime

from util.types import ProbeResult
from util.time import now_utc, duration_ms
from util.cache import Cache

logger = logging.getLogger(__name__)


class TLSProbe:
    """Async TLS handshake for certificate and protocol checks.
    
    Does a quick handshake to grab cert details without full HTTP exchange.
    Much faster than using requests/aiohttp when we only need TLS info.
    """
    
    def __init__(self, cache: Cache, timeout: float = 8.0):
        """Initialize TLS probe with cache and timeout."""
        self.cache = cache
        self.timeout = timeout
    
    async def probe(self, fqdn: str, port: int = 443) -> ProbeResult:
        """Perform TLS handshake and extract certificate details.
        
        Returns ProbeResult with:
          - success=True if handshake succeeded
          - data={'cert': {...}, 'tls_version': '...', 'cipher': '...'}
          - error if handshake failed
        """
        start = now_utc()
        
        # Check cache
        cache_key = f"tls:{fqdn}:{port}"
        cached = self.cache.get(cache_key)
        if cached:
            logger.debug(f"TLS cache hit for {fqdn}:{port}")
            return ProbeResult(
                target=fqdn,
                probe_type='tls',
                success=cached['success'],
                data=cached['data'],
                error=cached.get('error'),
                duration_ms=0,
                timestamp=now_utc()
            )
        
        try:
            # Create SSL context that accepts all certs (we want to inspect them, not validate here)
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Open connection and do handshake
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(fqdn, port, ssl=context, server_hostname=fqdn),
                timeout=self.timeout
            )
            
            # Get TLS info from the socket
            sock = writer.get_extra_info('socket')
            ssl_obj = writer.get_extra_info('ssl_object')
            
            if ssl_obj:
                # Extract cert as DER, then parse
                cert_der = ssl_obj.getpeercert(binary_form=True)
                cert_dict = ssl_obj.getpeercert()
                
                # Get TLS version and cipher
                tls_version = ssl_obj.version()
                cipher = ssl_obj.cipher()
                
                # Parse cert details we care about
                cert_data = {}
                if cert_dict:
                    cert_data = {
                        'subject': dict(x[0] for x in cert_dict.get('subject', [])),
                        'issuer': dict(x[0] for x in cert_dict.get('issuer', [])),
                        'version': cert_dict.get('version'),
                        'serialNumber': cert_dict.get('serialNumber'),
                        'notBefore': cert_dict.get('notBefore'),
                        'notAfter': cert_dict.get('notAfter'),
                        'subjectAltName': [x[1] for x in cert_dict.get('subjectAltName', [])],
                    }
                
                data = {
                    'cert': cert_data,
                    'tls_version': tls_version,
                    'cipher': cipher[0] if cipher else None,
                    'cipher_bits': cipher[2] if cipher and len(cipher) > 2 else None
                }
                
                success = True
                error = None
            else:
                data = {}
                success = False
                error = "No SSL object in connection"
            
            # Close connection
            writer.close()
            await writer.wait_closed()
            
            result = ProbeResult(
                target=fqdn,
                probe_type='tls',
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
            logger.debug(f"TLS timeout for {fqdn}:{port}")
            result = ProbeResult(
                target=fqdn,
                probe_type='tls',
                success=False,
                data={},
                error="TLS timeout",
                duration_ms=duration_ms(start),
                timestamp=now_utc()
            )
            self.cache.set(cache_key, {
                'success': False,
                'data': {},
                'error': result.error
            })
            return result
        
        except ssl.SSLError as e:
            # SSL errors are expected for bad configs - that's what we're measuring
            logger.debug(f"TLS SSL error for {fqdn}:{port}: {e}")
            result = ProbeResult(
                target=fqdn,
                probe_type='tls',
                success=False,
                data={},
                error=f"SSL error: {str(e)}",
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
            logger.warning(f"TLS error for {fqdn}:{port}: {e}")
            result = ProbeResult(
                target=fqdn,
                probe_type='tls',
                success=False,
                data={},
                error=f"TLS error: {str(e)}",
                duration_ms=duration_ms(start),
                timestamp=now_utc()
            )
            self.cache.set(cache_key, {
                'success': False,
                'data': {},
                'error': result.error
            })
            return result
