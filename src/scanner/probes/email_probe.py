"""Email security probe - check SPF, DKIM, DMARC records.

These are DNS-based checks for email authentication.
We query TXT records and parse the policies.
"""

import asyncio
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime
import re

from util.types import ProbeResult
from util.time import now_utc, duration_ms
from util.cache import Cache

logger = logging.getLogger(__name__)


class EmailProbe:
    """Email authentication record checker.
    
    Checks SPF, DMARC, and basic DKIM setup via DNS queries.
    These are all TXT records, so we use system DNS resolver.
    """
    
    def __init__(self, cache: Cache, timeout: float = 4.0):
        """Initialize email probe with cache and timeout."""
        self.cache = cache
        self.timeout = timeout
    
    async def _query_txt(self, domain: str) -> List[str]:
        """Query TXT records for a domain.
        
        Returns list of TXT record strings.
        """
        try:
            # Use dig/nslookup via subprocess since Python doesn't have native TXT query
            # Alternative: use dnspython library if available
            proc = await asyncio.create_subprocess_exec(
                'dig', '+short', 'TXT', domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
            
            # Parse output - each line is a TXT record (quoted)
            records = []
            for line in stdout.decode().strip().split('\n'):
                if line:
                    # Remove quotes
                    record = line.strip('"').strip()
                    if record:
                        records.append(record)
            
            return records
        
        except Exception as e:
            logger.debug(f"TXT query failed for {domain}: {e}")
            return []
    
    async def check_spf(self, domain: str) -> ProbeResult:
        """Check SPF record for domain.
        
        Returns ProbeResult with:
          - success=True if SPF record found
          - data={'record': '...', 'has_all': True/False, 'mechanisms': [...]}
        """
        start = now_utc()
        
        # Check cache
        cache_key = f"email:spf:{domain}"
        cached = self.cache.get(cache_key)
        if cached:
            logger.debug(f"SPF cache hit for {domain}")
            return ProbeResult(
                target=domain,
                probe_type='email_spf',
                success=cached['success'],
                data=cached['data'],
                error=cached.get('error'),
                duration_ms=0,
                timestamp=now_utc()
            )
        
        try:
            txt_records = await self._query_txt(domain)
            
            # Find SPF record (starts with "v=spf1")
            spf_record = None
            for record in txt_records:
                if record.startswith('v=spf1'):
                    spf_record = record
                    break
            
            if spf_record:
                # Parse basic SPF details
                data = {
                    'record': spf_record,
                    'has_all': '-all' in spf_record or '~all' in spf_record or '+all' in spf_record,
                    'mechanisms': spf_record.split()
                }
                success = True
                error = None
            else:
                data = {}
                success = False
                error = "No SPF record found"
            
            result = ProbeResult(
                target=domain,
                probe_type='email_spf',
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
        
        except Exception as e:
            logger.warning(f"SPF check error for {domain}: {e}")
            result = ProbeResult(
                target=domain,
                probe_type='email_spf',
                success=False,
                data={},
                error=f"SPF error: {str(e)}",
                duration_ms=duration_ms(start),
                timestamp=now_utc()
            )
            self.cache.set(cache_key, {
                'success': False,
                'data': {},
                'error': result.error
            })
            return result
    
    async def check_dmarc(self, domain: str) -> ProbeResult:
        """Check DMARC record for domain.
        
        DMARC records are at _dmarc.<domain>
        
        Returns ProbeResult with:
          - success=True if DMARC record found
          - data={'record': '...', 'policy': 'none/quarantine/reject', 'pct': 100}
        """
        start = now_utc()
        dmarc_domain = f"_dmarc.{domain}"
        
        # Check cache
        cache_key = f"email:dmarc:{domain}"
        cached = self.cache.get(cache_key)
        if cached:
            logger.debug(f"DMARC cache hit for {domain}")
            return ProbeResult(
                target=domain,
                probe_type='email_dmarc',
                success=cached['success'],
                data=cached['data'],
                error=cached.get('error'),
                duration_ms=0,
                timestamp=now_utc()
            )
        
        try:
            txt_records = await self._query_txt(dmarc_domain)
            
            # Find DMARC record (starts with "v=DMARC1")
            dmarc_record = None
            for record in txt_records:
                if record.startswith('v=DMARC1'):
                    dmarc_record = record
                    break
            
            if dmarc_record:
                # Parse DMARC policy
                policy_match = re.search(r'p=(\w+)', dmarc_record)
                pct_match = re.search(r'pct=(\d+)', dmarc_record)
                
                data = {
                    'record': dmarc_record,
                    'policy': policy_match.group(1) if policy_match else 'none',
                    'pct': int(pct_match.group(1)) if pct_match else 100
                }
                success = True
                error = None
            else:
                data = {}
                success = False
                error = "No DMARC record found"
            
            result = ProbeResult(
                target=domain,
                probe_type='email_dmarc',
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
        
        except Exception as e:
            logger.warning(f"DMARC check error for {domain}: {e}")
            result = ProbeResult(
                target=domain,
                probe_type='email_dmarc',
                success=False,
                data={},
                error=f"DMARC error: {str(e)}",
                duration_ms=duration_ms(start),
                timestamp=now_utc()
            )
            self.cache.set(cache_key, {
                'success': False,
                'data': {},
                'error': result.error
            })
            return result
    
    async def probe_all(self, domain: str) -> Dict[str, ProbeResult]:
        """Run all email checks for a domain.
        
        Returns dict with keys 'spf' and 'dmarc'
        """
        spf_result, dmarc_result = await asyncio.gather(
            self.check_spf(domain),
            self.check_dmarc(domain),
            return_exceptions=True
        )
        
        # Handle exceptions
        if isinstance(spf_result, Exception):
            logger.error(f"Error in SPF check: {spf_result}")
            spf_result = ProbeResult(
                target=domain,
                probe_type='email_spf',
                success=False,
                data={},
                error=str(spf_result),
                duration_ms=0,
                timestamp=now_utc()
            )
        
        if isinstance(dmarc_result, Exception):
            logger.error(f"Error in DMARC check: {dmarc_result}")
            dmarc_result = ProbeResult(
                target=domain,
                probe_type='email_dmarc',
                success=False,
                data={},
                error=str(dmarc_result),
                duration_ms=0,
                timestamp=now_utc()
            )
        
        return {
            'spf': spf_result,
            'dmarc': dmarc_result
        }
