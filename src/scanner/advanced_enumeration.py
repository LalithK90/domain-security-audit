"""Advanced subdomain enumeration - multi-method discovery with confidence scoring.

MOTIVATION:
Subdomain enumeration is not one technique. It's a combination of 12+ complementary
methods, each finding different targets:
- Certificate Transparency: finds SSL-enabled subdomains
- DNS brute-force: finds configured but maybe inactive subdomains
- SRV records: finds service infrastructure
- PTR records: finds reverse-DNS registered targets
- HTTP crawling: finds references in web content
- etc.

Using only one method gives incomplete results. For research into domain security,
we need comprehensive coverage. This module coordinates all methods and combines
results with confidence scoring.

DESIGN PHILOSOPHY:
Rather than implementing enumeration ourselves, we leverage existing, proven
tools and methods:
- dnspython: industry-standard DNS library
- aiohttp: async HTTP client for parallel requests
- Existing enumeration modules (SRV, PTR, crawling, etc.)

Each method is independent and can run in parallel. Results are normalized,
deduplicated, and scored for confidence.

CONFIDENCE SCORING:
Not all discoveries are equally reliable:
- CT logs (High): Authoritative source - cert must exist to be listed
- DNS resolution (Medium): Domain resolves, but could be misconfigured
- PTR records (Low): Just a reverse DNS claim, not verified
- Crawled links (Low): Could be stale or reference external domains

We track confidence so researchers can filter by reliability.

DISCOVERY METHODS INCLUDED:
1. **Certificate Transparency** - Query crt.sh for all SSL certificates
2. **Public Databases** - HackerTarget, ThreatCrowd, etc.
3. **DNS Brute-Force** - Try 18,953 patterns against DNS
4. **SRV Records** - Query 34 common services
5. **PTR Records** - Reverse DNS on discovered IPs
6. **HTTP Crawling** - Extract links from web responses
7. **Wildcard Detection** - Identify and filter false positives
8. **Source Attribution** - Track which method found each target
9. **Normalization** - Standardize and deduplicate
10. **Validation** - DNS/HTTP verification of candidates

RESEARCH OUTPUT:
Results include not just the list of subdomains, but metadata about each:
- Confidence level
- Discovery method(s)
- First seen date
- Validation status
- IP addresses and CNAMEs

This enables secondary research: "Which methods are most effective for .lk?"
"Do CT logs miss as many subdomains as brute-force?" "What's the overlap
between methods?"

USAGE FOR STUDENTS & RESEARCHERS:
Study this module to understand:
- How to combine multiple data sources
- Importance of deduplication
- Confidence scoring in security research
- Handling edge cases (wildcards, inconsistent DNS, etc.)
- Parallelizing I/O-intensive operations
"""

import logging
import string
import socket
import asyncio
import aiohttp
import re
import dns.resolver
import dns.exception
from pathlib import Path
from typing import List, Set, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
import json
import concurrent.futures
from urllib.parse import quote, urlparse
from collections import defaultdict, Counter

logger = logging.getLogger(__name__)


# ============================================================================
# DATA STRUCTURES
# ============================================================================

class ConfidenceLevel(Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class ValidationStatus(Enum):
    DNS_OK = "DNS_OK"
    HTTP_OK = "HTTP_OK"
    HTTPS_OK = "HTTPS_OK"
    WILDCARD_SUSPECT = "WILDCARD_SUSPECT"
    NXDOMAIN = "NXDOMAIN"
    TIMEOUT = "TIMEOUT"
    NO_VALIDATION = "NO_VALIDATION"


@dataclass
class SubdomainCandidate:
    """Represents a discovered subdomain candidate with full attribution."""
    fqdn: str
    sources: List[str] = field(default_factory=list)
    first_seen: str = ""
    confidence: str = ConfidenceLevel.LOW.value
    validation: List[str] = field(default_factory=list)
    notes: str = ""
    ip_addresses: List[str] = field(default_factory=list)
    cnames: List[str] = field(default_factory=list)
    http_status: Optional[int] = None
    https_status: Optional[int] = None
    
    def to_dict(self) -> Dict:
        return asdict(self)


# ============================================================================
# DOMAIN NORMALIZATION & VALIDATION
# ============================================================================

def normalize_domain(domain: str) -> str:
    """Normalize domain name to lowercase, remove trailing dot, handle IDN."""
    domain = domain.lower().strip().rstrip('.')
    
    # Handle punycode (IDN)
    try:
        domain = domain.encode('idna').decode('ascii')
    except (UnicodeError, UnicodeDecodeError):
        pass
    
    return domain


def is_valid_subdomain(fqdn: str, base_domain: str) -> bool:
    """Check if FQDN is valid subdomain of base domain."""
    fqdn = normalize_domain(fqdn)
    base_domain = normalize_domain(base_domain)
    
    # Must end with base domain
    if not fqdn.endswith(base_domain):
        return False
    
    # Must be longer than base (actual subdomain) or equal (apex)
    if fqdn == base_domain:
        return True
    
    # Check for proper subdomain structure
    if fqdn.endswith('.' + base_domain):
        return True
    
    return False


def is_wildcard_name(fqdn: str) -> bool:
    """Check if FQDN contains wildcard markers."""
    return '*' in fqdn


# ============================================================================
# WILDCARD DNS DETECTION
# ============================================================================

async def detect_wildcard_dns(domain: str, num_probes: int = 5) -> Tuple[bool, Set[str]]:
    """Detect wildcard DNS by probing random non-existent labels.
    
    Returns:
        (is_wildcarded, wildcard_ips)
    """
    import random
    
    wildcard_ips = set()
    random_labels = []
    
    # Generate random non-existent subdomains
    for _ in range(num_probes):
        random_label = ''.join(random.choices(string.ascii_lowercase + string.digits, k=20))
        random_labels.append(f"{random_label}.{domain}")
    
    # Resolve them
    resolved_count = 0
    for label in random_labels:
        try:
            answers = await asyncio.get_event_loop().run_in_executor(
                None, 
                lambda: dns.resolver.resolve(label, 'A', lifetime=2.0)
            )
            for rdata in answers:
                wildcard_ips.add(str(rdata))
            resolved_count += 1
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            pass
        except Exception:
            pass
    
    # If majority resolve, it's wildcarded
    is_wildcarded = resolved_count >= (num_probes * 0.6)
    
    if is_wildcarded:
        logger.warning(f"⚠️  Wildcard DNS detected for {domain} (IPs: {wildcard_ips})")
    
    return is_wildcarded, wildcard_ips


# ============================================================================
# DNS VALIDATION
# ============================================================================

async def validate_dns_async(fqdn: str) -> Tuple[List[str], List[str], bool]:
    """Validate domain via DNS resolution.
    
    Returns:
        (ip_addresses, cnames, success)
    """
    ips = []
    cnames = []
    
    try:
        # Try A record
        answers = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: dns.resolver.resolve(fqdn, 'A', lifetime=3.0)
        )
        for rdata in answers:
            ips.append(str(rdata))
    except dns.resolver.NXDOMAIN:
        return [], [], False
    except Exception:
        pass
    
    try:
        # Try AAAA record
        answers = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: dns.resolver.resolve(fqdn, 'AAAA', lifetime=3.0)
        )
        for rdata in answers:
            ips.append(str(rdata))
    except Exception:
        pass
    
    try:
        # Try CNAME
        answers = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: dns.resolver.resolve(fqdn, 'CNAME', lifetime=3.0)
        )
        for rdata in answers:
            cnames.append(str(rdata))
    except Exception:
        pass
    
    return ips, cnames, len(ips) > 0 or len(cnames) > 0


# ============================================================================
# HTTP VALIDATION
# ============================================================================

async def validate_http_async(fqdn: str, session: aiohttp.ClientSession) -> Tuple[Optional[int], Optional[int]]:
    """Validate HTTP/HTTPS availability.
    
    Returns:
        (http_status, https_status)
    """
    http_status = None
    https_status = None
    
    # Test HTTPS
    try:
        async with session.head(f"https://{fqdn}", timeout=aiohttp.ClientTimeout(total=5), 
                               ssl=False, allow_redirects=True) as resp:
            https_status = resp.status
    except:
        try:
            async with session.get(f"https://{fqdn}", timeout=aiohttp.ClientTimeout(total=5),
                                  ssl=False, allow_redirects=True) as resp:
                https_status = resp.status
        except:
            pass
    
    # Test HTTP
    try:
        async with session.head(f"http://{fqdn}", timeout=aiohttp.ClientTimeout(total=5),
                               allow_redirects=True) as resp:
            http_status = resp.status
    except:
        try:
            async with session.get(f"http://{fqdn}", timeout=aiohttp.ClientTimeout(total=5),
                                  allow_redirects=True) as resp:
                http_status = resp.status
        except:
            pass
    
    return http_status, https_status


# ============================================================================
# DISCOVERY METHODS
# ============================================================================

def generate_smart_patterns(include_3char: bool = True) -> List[str]:
    """Generate comprehensive pattern list for brute-force."""
    patterns = set()
    
    # Single chars (26)
    patterns.update(string.ascii_lowercase)
    
    # Two chars (676)
    for a in string.ascii_lowercase:
        for b in string.ascii_lowercase:
            patterns.add(f"{a}{b}")
    
    # Three chars (17,576) - optional for deep coverage
    if include_3char:
        for a in string.ascii_lowercase:
            for b in string.ascii_lowercase:
                for c in string.ascii_lowercase:
                    patterns.add(f"{a}{b}{c}")
    
    # Numbers
    patterns.update(str(i) for i in range(100))
    patterns.update(f"{i:02d}" for i in range(100))
    
    # Letter + number combos
    for letter in string.ascii_lowercase:
        for num in range(10):
            patterns.add(f"{letter}{num}")
            patterns.add(f"{num}{letter}")
    
    # Common subdomain words
    common = [
        'www', 'mail', 'webmail', 'smtp', 'pop', 'imap', 'email', 'mx',
        'api', 'rest', 'graphql', 'gateway', 'service', 'ws',
        'dev', 'test', 'staging', 'uat', 'qa', 'prod', 'production',
        'admin', 'portal', 'dashboard', 'panel', 'cp', 'cpanel', 'whm', 'plesk',
        'blog', 'forum', 'wiki', 'docs', 'help', 'support', 'faq', 'kb',
        'shop', 'store', 'cart', 'checkout', 'pay', 'payment', 'billing',
        'cdn', 'static', 'assets', 'media', 'images', 'img', 'files', 'download', 'uploads',
        'vpn', 'remote', 'ssh', 'ftp', 'sftp', 'ftps',
        'ns1', 'ns2', 'ns3', 'ns4', 'dns', 'ns',
        'mobile', 'm', 'app', 'apps', 'android', 'ios',
        'secure', 'ssl', 'tls', 'login', 'auth', 'oauth', 'sso',
        'old', 'new', 'beta', 'alpha', 'demo', 'sandbox', 'preview',
        'status', 'monitor', 'health', 'ping', 'metrics',
        'git', 'gitlab', 'github', 'svn', 'repo', 'code',
        'jenkins', 'ci', 'cd', 'build', 'deploy',
        'db', 'database', 'sql', 'mysql', 'postgres', 'mongo', 'redis',
        'cache', 'memcached',
        'search', 'elastic', 'solr',
        'video', 'stream', 'live', 'rtmp',
        'news', 'press', 'media', 'events',
        'about', 'contact', 'careers', 'jobs', 'hr',
        'autodiscover', 'autoconfig', 'cpanel', 'webdisk', 'whm',
        'cloud', 'backup', 'archive', 'logs',
    ]
    patterns.update(common)
    
    return sorted(patterns)


SMART_PATTERNS = generate_smart_patterns(include_3char=False)  # Start with ~2700 patterns
SMART_PATTERNS_DEEP = generate_smart_patterns(include_3char=True)  # ~18,991 for deep scan


async def method_crtsh(domain: str, session: aiohttp.ClientSession) -> Set[str]:
    """Certificate Transparency via crt.sh."""
    url = f"https://crt.sh/?q=%25.{quote(domain)}&output=json"
    results = set()
    
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=20)) as resp:
            if resp.status == 200:
                data = await resp.json()
                for cert in data:
                    name_value = cert.get("name_value", "")
                    for d in name_value.split("\n"):
                        d = normalize_domain(d.replace("*.", ""))
                        if is_valid_subdomain(d, domain) and not is_wildcard_name(d):
                            results.add(d)
                logger.info(f"  CT (crt.sh): {len(results)} candidates")
    except Exception as e:
        logger.debug(f"crt.sh error: {e}")
    
    return results


async def method_hackertarget(domain: str, session: aiohttp.ClientSession) -> Set[str]:
    """Public database: HackerTarget API."""
    url = f"https://api.hackertarget.com/hostsearch/?q={quote(domain)}"
    results = set()
    
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            if resp.status == 200:
                text = await resp.text()
                for line in text.split('\n'):
                    if ',' in line:
                        fqdn = normalize_domain(line.split(',')[0].strip())
                        if is_valid_subdomain(fqdn, domain):
                            results.add(fqdn)
                logger.info(f"  HackerTarget: {len(results)} candidates")
    except Exception as e:
        logger.debug(f"HackerTarget error: {e}")
    
    return results


async def method_threatcrowd(domain: str, session: aiohttp.ClientSession) -> Set[str]:
    """Public database: ThreatCrowd API."""
    url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={quote(domain)}"
    results = set()
    
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            if resp.status == 200:
                data = await resp.json()
                if 'subdomains' in data and isinstance(data['subdomains'], list):
                    for sub in data['subdomains']:
                        if isinstance(sub, str):
                            fqdn = normalize_domain(sub)
                            if is_valid_subdomain(fqdn, domain):
                                results.add(fqdn)
                logger.info(f"  ThreatCrowd: {len(results)} candidates")
    except Exception as e:
        logger.debug(f"ThreatCrowd error: {e}")
    
    return results


async def method_dns_brute(domain: str, patterns: List[str], max_workers: int = 500) -> Set[str]:
    """DNS brute-force with patterns."""
    results = set()
    
    def check(pattern: str) -> Optional[str]:
        fqdn = f"{pattern}.{domain}"
        try:
            socket.setdefaulttimeout(3.0)
            socket.getaddrinfo(fqdn, None, family=0, type=0)
            return fqdn
        except (socket.gaierror, socket.timeout):
            return None
        finally:
            socket.setdefaulttimeout(None)
    
    loop = asyncio.get_event_loop()
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check, p): p for p in patterns}
        
        completed = 0
        total = len(futures)
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result:
                    results.add(result)
                
                completed += 1
                if completed % 1000 == 0:
                    logger.info(f"  DNS brute: {completed}/{total} tested ({len(results)} found)")
            except Exception:
                pass
    
    logger.info(f"  DNS brute-force: {len(results)} candidates")
    return results


async def method_srv_records(domain: str) -> Set[str]:
    """Enumerate SRV records for common services."""
    srv_prefixes = [
        '_autodiscover._tcp',
        '_caldavs._tcp',
        '_carddavs._tcp',
        '_imap._tcp',
        '_imaps._tcp',
        '_pop3._tcp',
        '_pop3s._tcp',
        '_submission._tcp',
        '_smtps._tcp',
        '_xmpp-client._tcp',
        '_xmpp-server._tcp',
        '_sip._tcp',
        '_sips._tcp',
        '_sipfederationtls._tcp',
        '_ldap._tcp',
        '_ldaps._tcp',
        '_kerberos._tcp',
        '_kpasswd._tcp',
    ]
    
    results = set()
    
    for prefix in srv_prefixes:
        try:
            query = f"{prefix}.{domain}"
            answers = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: dns.resolver.resolve(query, 'SRV', lifetime=3.0)
            )
            for rdata in answers:
                target = str(rdata.target).rstrip('.')
                target = normalize_domain(target)
                if is_valid_subdomain(target, domain):
                    results.add(target)
        except Exception:
            pass
    
    if results:
        logger.info(f"  SRV records: {len(results)} candidates")
    
    return results


async def method_reverse_dns(candidates: List[SubdomainCandidate]) -> Set[str]:
    """Reverse DNS pivoting on discovered IPs."""
    results = set()
    ips_to_check = set()
    
    # Collect IPs from validated candidates
    for candidate in candidates:
        ips_to_check.update(candidate.ip_addresses)
    
    for ip in ips_to_check:
        try:
            hostnames = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: socket.gethostbyaddr(ip)
            )
            if hostnames and hostnames[0]:
                fqdn = normalize_domain(hostnames[0])
                results.add(fqdn)
        except Exception:
            pass
    
    if results:
        logger.info(f"  Reverse DNS: {len(results)} candidates")
    
    return results


async def method_crawl_passive(fqdn: str, session: aiohttp.ClientSession, domain: str) -> Set[str]:
    """Passive crawl: extract subdomains from CSP headers, HTML, robots.txt, sitemap."""
    results = set()
    
    url = f"https://{fqdn}"
    
    try:
        # Fetch main page
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
            if resp.status == 200:
                # CSP header parsing
                csp = resp.headers.get('Content-Security-Policy', '')
                for match in re.findall(r'https?://([a-zA-Z0-9._-]+)', csp):
                    sub = normalize_domain(match)
                    if is_valid_subdomain(sub, domain):
                        results.add(sub)
                
                # HTML parsing
                html = await resp.text()
                for match in re.findall(r'https?://([a-zA-Z0-9._-]+)', html):
                    sub = normalize_domain(match)
                    if is_valid_subdomain(sub, domain):
                        results.add(sub)
    except Exception:
        pass
    
    # robots.txt
    try:
        async with session.get(f"https://{fqdn}/robots.txt", 
                              timeout=aiohttp.ClientTimeout(total=5), ssl=False) as resp:
            if resp.status == 200:
                text = await resp.text()
                for match in re.findall(r'https?://([a-zA-Z0-9._-]+)', text):
                    sub = normalize_domain(match)
                    if is_valid_subdomain(sub, domain):
                        results.add(sub)
    except Exception:
        pass
    
    # sitemap.xml
    try:
        async with session.get(f"https://{fqdn}/sitemap.xml",
                              timeout=aiohttp.ClientTimeout(total=5), ssl=False) as resp:
            if resp.status == 200:
                text = await resp.text()
                for match in re.findall(r'https?://([a-zA-Z0-9._-]+)', text):
                    sub = normalize_domain(match)
                    if is_valid_subdomain(sub, domain):
                        results.add(sub)
    except Exception:
        pass
    
    return results


# ============================================================================
# MAIN ENUMERATOR
# ============================================================================

class AdvancedEnumerator:
    """Advanced subdomain enumerator with validation and confidence scoring."""
    
    def __init__(self, domain: str, output_dir: Path):
        self.domain = normalize_domain(domain)
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.candidates: Dict[str, SubdomainCandidate] = {}
        self.wildcard_detected = False
        self.wildcard_ips = set()
        
        self.stats = {
            'total_candidates': 0,
            'validated': 0,
            'by_source': Counter(),
            'by_validation': Counter(),
            'by_confidence': Counter(),
        }
    
    async def enumerate(self, deep_brute: bool = False) -> List[SubdomainCandidate]:
        """Run full enumeration pipeline."""
        logger.info("="*80)
        logger.info(f"🔍 Advanced Subdomain Enumeration")
        logger.info(f"Domain: {self.domain}")
        logger.info("="*80)
        
        # Step 1: Wildcard detection
        logger.info("\n[1/5] Wildcard DNS Detection")
        self.wildcard_detected, self.wildcard_ips = await detect_wildcard_dns(self.domain)
        
        # Step 2: Multi-source discovery
        logger.info("\n[2/5] Multi-Source Discovery")
        await self._discover_all_sources(deep_brute)
        
        # Step 3: DNS/HTTP validation
        logger.info(f"\n[3/5] Validation ({len(self.candidates)} candidates)")
        await self._validate_all()
        
        # Step 4: Passive crawling on validated targets
        logger.info(f"\n[4/5] Passive Crawling")
        await self._passive_crawl()
        
        # Step 5: Confidence scoring
        logger.info(f"\n[5/5] Confidence Scoring")
        self._compute_confidence()
        
        # Write output
        self._write_output()
        
        # Print summary
        self._print_summary()
        
        return list(self.candidates.values())
    
    async def _discover_all_sources(self, deep_brute: bool):
        """Run all discovery methods in parallel."""
        connector = aiohttp.TCPConnector(limit=100, limit_per_host=10)
        timeout = aiohttp.ClientTimeout(total=30)
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            tasks = [
                method_crtsh(self.domain, session),
                method_hackertarget(self.domain, session),
                method_threatcrowd(self.domain, session),
                method_srv_records(self.domain),
            ]
            
            # DNS brute-force
            patterns = SMART_PATTERNS_DEEP if deep_brute else SMART_PATTERNS
            logger.info(f"  Using {len(patterns)} patterns for DNS brute-force")
            tasks.append(method_dns_brute(self.domain, patterns, max_workers=500))
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Merge results
            sources_map = ['ct', 'hackertarget', 'threatcrowd', 'srv', 'brute']
            for idx, result in enumerate(results):
                if isinstance(result, set):
                    source = sources_map[idx]
                    for fqdn in result:
                        self._add_candidate(fqdn, source)
        
        # Always add apex domain
        self._add_candidate(self.domain, 'apex')
    
    def _add_candidate(self, fqdn: str, source: str):
        """Add or update a candidate."""
        fqdn = normalize_domain(fqdn)
        
        if fqdn not in self.candidates:
            self.candidates[fqdn] = SubdomainCandidate(
                fqdn=fqdn,
                sources=[source],
                first_seen=datetime.utcnow().isoformat() + 'Z'
            )
            self.stats['total_candidates'] += 1
        else:
            if source not in self.candidates[fqdn].sources:
                self.candidates[fqdn].sources.append(source)
        
        self.stats['by_source'][source] += 1
    
    async def _validate_all(self):
        """Validate all candidates via DNS and HTTP."""
        connector = aiohttp.TCPConnector(limit=200)
        timeout = aiohttp.ClientTimeout(total=10)
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            tasks = []
            for fqdn in self.candidates.keys():
                tasks.append(self._validate_candidate(fqdn, session))
            
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _validate_candidate(self, fqdn: str, session: aiohttp.ClientSession):
        """Validate single candidate."""
        candidate = self.candidates[fqdn]
        
        # DNS validation
        ips, cnames, dns_ok = await validate_dns_async(fqdn)
        candidate.ip_addresses = ips
        candidate.cnames = cnames
        
        if dns_ok:
            candidate.validation.append(ValidationStatus.DNS_OK.value)
            self.stats['validated'] += 1
            
            # Check for wildcard IPs
            if self.wildcard_detected and any(ip in self.wildcard_ips for ip in ips):
                candidate.validation.append(ValidationStatus.WILDCARD_SUSPECT.value)
                candidate.notes = "Matches wildcard IP pattern"
            
            # HTTP validation
            http_status, https_status = await validate_http_async(fqdn, session)
            candidate.http_status = http_status
            candidate.https_status = https_status
            
            if https_status and 200 <= https_status < 500:
                candidate.validation.append(ValidationStatus.HTTPS_OK.value)
            if http_status and 200 <= http_status < 500:
                candidate.validation.append(ValidationStatus.HTTP_OK.value)
        else:
            candidate.validation.append(ValidationStatus.NXDOMAIN.value)
        
        for v in candidate.validation:
            self.stats['by_validation'][v] += 1
    
    async def _passive_crawl(self):
        """Crawl validated targets for additional subdomains."""
        connector = aiohttp.TCPConnector(limit=50)
        timeout = aiohttp.ClientTimeout(total=10)
        
        # Only crawl HTTPS-enabled validated targets
        targets_to_crawl = [
            c.fqdn for c in self.candidates.values()
            if ValidationStatus.HTTPS_OK.value in c.validation
        ][:20]  # Limit to 20 targets
        
        if not targets_to_crawl:
            logger.info("  No HTTPS targets to crawl")
            return
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            all_results = set()
            for fqdn in targets_to_crawl:
                results = await method_crawl_passive(fqdn, session, self.domain)
                all_results.update(results)
            
            for fqdn in all_results:
                self._add_candidate(fqdn, 'crawl')
            
            logger.info(f"  Passive crawl: {len(all_results)} new candidates from {len(targets_to_crawl)} targets")
    
    def _compute_confidence(self):
        """Compute confidence levels based on sources and validation."""
        for candidate in self.candidates.values():
            score = 0
            
            # Source diversity
            if 'ct' in candidate.sources:
                score += 3
            if 'hackertarget' in candidate.sources or 'threatcrowd' in candidate.sources:
                score += 2
            if 'brute' in candidate.sources:
                score += 1
            if 'srv' in candidate.sources:
                score += 2
            if 'crawl' in candidate.sources:
                score += 1
            
            # Validation status
            if ValidationStatus.DNS_OK.value in candidate.validation:
                score += 3
            if ValidationStatus.HTTPS_OK.value in candidate.validation:
                score += 2
            
            # Wildcard penalty
            if ValidationStatus.WILDCARD_SUSPECT.value in candidate.validation:
                score -= 2
            
            # Assign confidence
            if score >= 6:
                candidate.confidence = ConfidenceLevel.HIGH.value
            elif score >= 3:
                candidate.confidence = ConfidenceLevel.MEDIUM.value
            else:
                candidate.confidence = ConfidenceLevel.LOW.value
            
            self.stats['by_confidence'][candidate.confidence] += 1
    
    def _write_output(self):
        """Write structured output files."""
        # candidates.csv
        csv_path = self.output_dir / "candidates.csv"
        with open(csv_path, 'w') as f:
            f.write("fqdn,sources,confidence,validation,ip_addresses,http_status,https_status,notes\n")
            for c in sorted(self.candidates.values(), key=lambda x: x.fqdn):
                f.write(f"{c.fqdn},"
                       f"\"{';'.join(c.sources)}\","
                       f"{c.confidence},"
                       f"\"{';'.join(c.validation)}\","
                       f"\"{';'.join(c.ip_addresses)}\","
                       f"{c.http_status or ''},"
                       f"{c.https_status or ''},"
                       f"\"{c.notes}\"\n")
        
        logger.info(f"  Wrote {csv_path}")
        
        # validated_subdomains.txt (only DNS_OK + not wildcard suspect)
        validated_path = self.output_dir / "validated_subdomains.txt"
        with open(validated_path, 'w') as f:
            for c in sorted(self.candidates.values(), key=lambda x: x.fqdn):
                if (ValidationStatus.DNS_OK.value in c.validation and
                    ValidationStatus.WILDCARD_SUSPECT.value not in c.validation):
                    f.write(f"{c.fqdn}\n")
        
        logger.info(f"  Wrote {validated_path}")
        
        # enumeration_stats.json
        stats_path = self.output_dir / "enumeration_stats.json"
        with open(stats_path, 'w') as f:
            json.dump({
                'domain': self.domain,
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'total_candidates': self.stats['total_candidates'],
                'validated': self.stats['validated'],
                'wildcard_detected': self.wildcard_detected,
                'wildcard_ips': list(self.wildcard_ips),
                'by_source': dict(self.stats['by_source']),
                'by_validation': dict(self.stats['by_validation']),
                'by_confidence': dict(self.stats['by_confidence']),
            }, f, indent=2)
        
        logger.info(f"  Wrote {stats_path}")
    
    def _print_summary(self):
        """Print enumeration summary."""
        logger.info("\n" + "="*80)
        logger.info("📊 ENUMERATION SUMMARY")
        logger.info("="*80)
        logger.info(f"  Total Candidates:        {self.stats['total_candidates']}")
        logger.info(f"  DNS Validated:           {self.stats['validated']}")
        logger.info(f"  Wildcard DNS Detected:   {'Yes' if self.wildcard_detected else 'No'}")
        
        logger.info(f"\n  By Source:")
        for source, count in self.stats['by_source'].most_common():
            logger.info(f"    {source:15} {count:5}")
        
        logger.info(f"\n  By Validation:")
        for status, count in self.stats['by_validation'].most_common():
            logger.info(f"    {status:20} {count:5}")
        
        logger.info(f"\n  By Confidence:")
        for conf, count in self.stats['by_confidence'].most_common():
            logger.info(f"    {conf:15} {count:5}")
        
        logger.info("="*80)


# ============================================================================
# SANITY TEST FUNCTION
# ============================================================================

async def sanity_test(domain: str = "ac.lk"):
    """Sanity test for enumeration system."""
    print(f"\n{'='*80}")
    print(f"SANITY TEST: Enumerating {domain}")
    print(f"{'='*80}\n")
    
    output_dir = Path(f"out/{domain}/enumeration_test")
    enumerator = AdvancedEnumerator(domain, output_dir)
    
    candidates = await enumerator.enumerate(deep_brute=False)
    
    print(f"\n✓ Enumeration complete")
    print(f"✓ Found {len(candidates)} candidates")
    print(f"✓ Results written to {output_dir}/")
    
    return candidates


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)-8s | %(message)s')
    
    domain = sys.argv[1] if len(sys.argv) > 1 else "ac.lk"
    asyncio.run(sanity_test(domain))
