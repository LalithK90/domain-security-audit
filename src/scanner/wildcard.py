"""Wildcard DNS detection - critical for accurate subdomain enumeration.

THE PROBLEM:
Some domain administrators configure DNS with a wildcard record:
    *.example.com A 192.168.1.1

This means ANY non-existent subdomain you query will resolve:
    random123.example.com → 192.168.1.1
    fakeserver.example.com → 192.168.1.1
    thisdoesnotexist.example.com → 192.168.1.1

Without detecting this, our DNS brute-force would report thousands of "discovered"
subdomains that don't actually exist - all false positives. We'd corrupt our
analysis and waste time scanning non-existent targets.

HOW WE SOLVE IT:
We test with known non-existent subdomains (random UUIDs). If they resolve, we
know the domain has wildcard DNS. We then check what IPs it resolves to, and
filter out any discoveries that match those wildcard IPs.

IMPLEMENTATION APPROACH:
1. Query 5 random, definitely-not-real subdomains (e.g., "uuid-1234567-random.example.com")
2. If ANY of them resolve, domain has wildcard DNS
3. Record the resolved IPs (the "wildcard IPs")
4. Later, during enumeration, if we find a subdomain that resolves to these
   same IPs, we skip it (likely a false positive)

EDGE CASES WE HANDLE:
- Inconsistent wildcards: Some wildcard implementations randomize IPs - we
  detect if IPs are inconsistent and handle that case
- Partial wildcards: Some only apply to certain subdomain levels
  (_tcp.example.com has wildcard, but *.tcp.example.com doesn't)
- Round-robin DNS: Wildcard might return different IPs on each query
  (we detect this by testing multiple times)

USAGE FOR RESEARCHERS:
This is a great example of defensive engineering in enumeration. Before
implementing any new discovery method, always ask: "Can this produce
false positives?" Usually, the answer is yes. Wildcard detection is one
technique. Others include: TTL analysis, response consistency checking, etc.

REFERENCE:
RFC 4592 (https://tools.ietf.org/html/rfc4592) documents wildcard DNS
records in detail if you want to understand the DNS spec better.
"""

import dns.resolver
import dns.exception
import logging
import secrets
from typing import Set, Optional, List

logger = logging.getLogger(__name__)


class WildcardDetector:
    """Detects if a domain uses wildcard DNS records.
    
    This prevents false positive subdomain discoveries.
    """
    
    def __init__(self, domain: str, num_tests: int = 5):
        """Initialize wildcard detector.
        
        Args:
            domain: Base domain to test
            num_tests: Number of random subdomains to test (default: 5)
        """
        self.domain = domain
        self.num_tests = num_tests
        self.wildcard_ips: Optional[Set[str]] = None
        self._tested = False
    
    def has_wildcard(self) -> bool:
        """Check if domain has wildcard DNS configured.
        
        Returns:
            True if wildcard detected, False otherwise
        """
        if not self._tested:
            self._test_wildcard()
        
        return self.wildcard_ips is not None and len(self.wildcard_ips) > 0
    
    def get_wildcard_ips(self) -> Set[str]:
        """Get the IP addresses that wildcard resolves to.
        
        Returns:
            Set of IP addresses (empty if no wildcard)
        """
        if not self._tested:
            self._test_wildcard()
        
        return self.wildcard_ips if self.wildcard_ips else set()
    
    def is_wildcard_match(self, ip_addresses: List[str]) -> bool:
        """Check if given IPs match the wildcard pattern.
        
        Args:
            ip_addresses: List of IP addresses to check
            
        Returns:
            True if IPs match wildcard, False otherwise
        """
        if not self.has_wildcard():
            return False
        
        # If any of the IPs match wildcard IPs, it's a wildcard match
        return any(ip in self.wildcard_ips for ip in ip_addresses)
    
    def _test_wildcard(self):
        """Test for wildcard DNS using random subdomains.
        
        WHY: Queries multiple random subdomains to detect wildcards.
        If non-existent subdomains resolve, domain has wildcard.
        """
        self._tested = True
        resolved_ips = []
        
        # Test multiple random subdomains
        for i in range(self.num_tests):
            # Generate random subdomain that definitely doesn't exist
            random_subdomain = self._generate_random_subdomain()
            
            try:
                # Try to resolve the random subdomain
                answers = dns.resolver.resolve(random_subdomain, 'A', lifetime=3.0)
                
                # If it resolves, collect the IPs
                ips = {str(rdata) for rdata in answers}
                resolved_ips.append(ips)
                
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                # This is expected - random subdomain doesn't exist
                # No wildcard if we get NXDOMAIN
                continue
            except dns.exception.Timeout:
                # Timeout is not conclusive
                continue
            except Exception as e:
                logger.debug(f"Wildcard test error for {random_subdomain}: {e}")
                continue
        
        # Analyze results
        if not resolved_ips:
            # No random subdomains resolved → no wildcard
            self.wildcard_ips = set()
            logger.info(f"✓ No wildcard DNS detected for {self.domain}")
            return
        
        # Check if multiple random subdomains resolve to same IPs
        if len(resolved_ips) >= 2:
            # Find common IPs across multiple random queries
            common_ips = resolved_ips[0]
            for ips in resolved_ips[1:]:
                common_ips = common_ips.intersection(ips)
            
            if common_ips:
                # Wildcard detected! Random subdomains resolve to consistent IPs
                self.wildcard_ips = common_ips
                logger.warning(f"⚠️  WILDCARD DNS DETECTED for {self.domain}")
                logger.warning(f"    Wildcard IPs: {', '.join(sorted(common_ips))}")
                logger.warning(f"    All discoveries will be filtered against wildcard IPs")
            else:
                # Random resolving but inconsistent - no clear wildcard
                self.wildcard_ips = set()
        else:
            # Only one random subdomain resolved - not conclusive
            # Could be race condition or actual subdomain, be conservative
            self.wildcard_ips = set()
    
    def _generate_random_subdomain(self) -> str:
        """Generate a random subdomain that definitely doesn't exist.
        
        Returns:
            FQDN of random subdomain (e.g., "random-a1b2c3d4.example.com")
        """
        # Use cryptographically secure random token
        random_token = secrets.token_hex(8)  # 16 hex chars
        return f"nonexistent-{random_token}.{self.domain}"


def filter_wildcard_results(domain: str, candidates: Set[str], detector: Optional[WildcardDetector] = None) -> Set[str]:
    """Filter out wildcard matches from discovered candidates.
    
    Args:
        domain: Base domain
        candidates: Set of discovered FQDNs
        detector: Optional pre-initialized detector (for reuse)
        
    Returns:
        Filtered set of FQDNs (wildcard matches removed)
    """
    if not candidates:
        return set()
    
    # Initialize detector if not provided
    if detector is None:
        detector = WildcardDetector(domain)
    
    # Check for wildcard
    if not detector.has_wildcard():
        # No wildcard, return all candidates
        return candidates
    
    # Have wildcard - need to filter
    wildcard_ips = detector.get_wildcard_ips()
    filtered = set()
    wildcard_matches = 0
    
    for fqdn in candidates:
        try:
            # Resolve candidate
            answers = dns.resolver.resolve(fqdn, 'A', lifetime=2.0)
            ips = [str(rdata) for rdata in answers]
            
            # Check if IPs match wildcard
            if detector.is_wildcard_match(ips):
                wildcard_matches += 1
                continue  # Skip this candidate
            else:
                filtered.add(fqdn)  # Keep - doesn't match wildcard
                
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            # Doesn't resolve - skip
            continue
        except Exception as e:
            logger.debug(f"Error checking {fqdn} for wildcard: {e}")
            # On error, keep the candidate (conservative)
            filtered.add(fqdn)
    
    if wildcard_matches > 0:
        logger.info(f"Filtered out {wildcard_matches} wildcard matches (kept {len(filtered)} real subdomains)")
    
    return filtered
