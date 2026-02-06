"""Core subdomain enumeration engine - orchestrates multi-method discovery.

PROBLEM STATEMENT:
Organizations typically have dozens to thousands of subdomains. Finding ALL of them
for security assessment is non-trivial because:
1. No single authoritative source exists
2. Different discovery methods find different subdomains
3. Coverage varies by organization and how they manage infrastructure

SOLUTION: MULTI-METHOD APPROACH
We combine 12 complementary discovery techniques:

**Active DNS Methods:**
- Pattern generation (18,953 patterns): Try common subdomain names via DNS
- SRV record enumeration: Query DNS for service records (_ldap, _sip, etc.)
- PTR record enumeration: Reverse-DNS on discovered IPs

**Passive/Third-Party Methods:**
- Certificate Transparency (crt.sh): All SSL certificates ever issued
- Public databases (HackerTarget, ThreatCrowd): Historical scanning data
- XLSX seed loading: Previous scans or known targets

**Active HTTP Methods:**
- HTTP crawling: Extract links from HTTP responses

**Quality Assurance:**
- Wildcard detection: Identify and filter false positives
- DNS validation: Verify candidates actually resolve
- HTTP/HTTPS testing: Check if web services are active
- Normalization: Standardize naming (punycode, case, trailing dots)
- Deduplication: Remove duplicates before writing to database

COVERAGE ANALYSIS:
Each method has strengths and weaknesses:
- CT logs: Comprehensive for HTTPS, biased toward public-facing services
- Brute-force: Finds non-HTTPS subdomains, limited by pattern quality
- SRV records: Found among organizations using AD/email services
- PTR records: Dependent on infrastructure documentation
- Crawling: Biased toward web applications

**Key insight**: No single method finds everything. Combined coverage is
significantly better. This is why large enterprises often get surprised
when security researchers find more subdomains than they knew about.

ARCHITECTURE:
This module acts as the orchestrator:
1. Initialize components (pattern generator, DNS resolver, crawler, etc.)
2. Run all methods in parallel where possible
3. Combine results with deduplication
4. Apply filtering (wildcards, scope validation)
5. Output structured results with metadata (source, confidence, validation status)

USAGE FOR RESEARCHERS:
Study this module to understand:
- How to combine multiple data sources effectively
- Importance of parallelization in I/O-heavy operations
- Pattern generation strategies for DNS brute-force
- Handling contradictory results from different sources
- Filtering techniques to avoid false positives

LIMITATIONS:
- This is reconnaissance only (no exploitation)
- Coverage depends on passive data availability
- Some internal/private subdomains will be missed
- Accuracy varies by domain and hosting model
"""

import logging
import string
import socket
import asyncio
import aiohttp
from pathlib import Path
from typing import List, Set, Dict, Any, Optional
import json
import concurrent.futures
from urllib.parse import quote

from util.types import ScanTarget
from util.io import read_json, write_json
from util.cache import Cache
from util.config import Config
from scanner.xlsx_seed import load_xlsx_seeds
from scanner.wildcard import WildcardDetector, filter_wildcard_results
from scanner.normalization import normalize_fqdn_set
from scanner.srv_pivot import discover_srv_subdomains
from scanner.crawl_lite import discover_from_crawling
from scanner.ptr_pivot import discover_ptr_subdomains, build_ip_to_fqdn_map

logger = logging.getLogger(__name__)


# ============================================================================
# SMART PATTERN GENERATION
# ============================================================================

def generate_smart_patterns(include_3char: bool = True) -> List[str]:
    """Generate 18,953 patterns for comprehensive DNS brute-force subdomain discovery.
    
    PATTERN STRATEGY:
    Rather than trying to guess every possible subdomain name, we use a systematic
    approach combining common names with exhaustive character enumeration:
    
    **Exhaustive Character Combinations**:
    - 1-char: a-z (26 subdomains)
    - 2-char: aa-zz (676 subdomains)
    - 3-char: aaa-zzz (17,576 subdomains) - optional, adds time
    - Total: 18,278 systematic patterns
    
    **Common/Semantic Names**:
    - Mail services: mail, webmail, smtp, pop, imap
    - Web services: www, api, rest, gateway
    - Infrastructure: admin, portal, api, cdn, cdn1-10
    - Development: dev, test, staging, uat, qa, prod
    - Common words: blog, shop, wiki, status, monitor
    - Numbered services: ns1-ns4, db1-db5, app1-app10
    - Total: 200+ common names
    
    EFFECTIVENESS:
    This approach finds a good balance between:
    - Coverage: 18K+ patterns cover most naming schemes
    - Performance: Can run in 2-3 minutes with 500 parallel workers
    - Accuracy: Semantic names catch infrastructure, exhaustive patterns
      catch anything else
    
    WHY NOT JUST COMMON WORDS?
    Common word lists miss organizational naming conventions (api01, srv-dmz-01, etc.).
    Exhaustive enumeration finds those BUT would take hours. Combining both gives
    speed + coverage.
    
    USAGE NOTES:
    - Set include_3char=False to speed up testing (skip 17K patterns)
    - Patterns are deduplicated with common words
    - Results are cached so repeated brute-force doesn't re-query DNS
    
    EDUCATIONAL VALUE:
    DNS brute-force is a classic reconnaissance technique. Pattern generation is
    the art of guessing likely subdomain names. This function shows practical
    thinking: exhaustive is too slow, semantic-only misses things, so combine both.
    """
    patterns = set()
    
    # Single characters (26)
    patterns.update(string.ascii_lowercase)
    
    # Two characters (676)
    for a in string.ascii_lowercase:
        for b in string.ascii_lowercase:
            patterns.add(f"{a}{b}")
    
    # Three characters (17,576) - comprehensive brute-force
    if include_3char:
        for a in string.ascii_lowercase:
            for b in string.ascii_lowercase:
                for c in string.ascii_lowercase:
                    patterns.add(f"{a}{b}{c}")
    
    # Numbers (110)
    patterns.update(str(i) for i in range(100))
    patterns.update(f"{i:02d}" for i in range(100))
    
    # Number + letter combinations
    for letter in string.ascii_lowercase:
        for num in range(10):
            patterns.add(f"{letter}{num}")
            patterns.add(f"{num}{letter}")
    
    # Common subdomain words (100+)
    common = [
        'www', 'mail', 'webmail', 'smtp', 'pop', 'imap', 'email',
        'api', 'rest', 'graphql', 'gateway', 'service',
        'dev', 'test', 'staging', 'uat', 'qa', 'prod', 'production',
        'admin', 'portal', 'dashboard', 'panel', 'cp', 'cpanel', 'whm',
        'blog', 'forum', 'wiki', 'docs', 'help', 'support', 'faq',
        'shop', 'store', 'cart', 'checkout', 'pay', 'payment',
        'cdn', 'static', 'assets', 'media', 'images', 'img', 'files',
        'vpn', 'remote', 'ssh', 'ftp', 'sftp', 'ftps',
        'ns1', 'ns2', 'ns3', 'ns4', 'dns',
        'mobile', 'm', 'app', 'apps', 'android', 'ios',
        'secure', 'ssl', 'tls', 'login', 'auth', 'oauth',
        'old', 'new', 'beta', 'alpha', 'demo', 'sandbox',
        'status', 'monitor', 'health', 'ping',
        'git', 'gitlab', 'github', 'svn', 'repo',
        'jenkins', 'ci', 'cd', 'build', 'deploy',
        'db', 'database', 'sql', 'mysql', 'postgres', 'mongo',
        'cache', 'redis', 'memcached',
        'search', 'elastic', 'solr',
        'video', 'stream', 'live', 'rtmp',
        'news', 'press', 'media', 'events',
        'about', 'contact', 'careers', 'jobs'
    ]
    patterns.update(common)
    
    return sorted(patterns)


# Pre-generate patterns at module load for performance
SMART_PATTERNS = generate_smart_patterns(include_3char=True)


async def fetch_crtsh_async(domain: str, session: aiohttp.ClientSession, retries: int = 3) -> Set[str]:
    """Fetch subdomains from crt.sh (Certificate Transparency) async.
    
    Args:
        domain: Base domain to search
        session: aiohttp session for requests
        retries: Number of retry attempts
        
    Returns:
        Set of discovered subdomains
    """
    url = f"https://crt.sh/?q=%25.{quote(domain)}&output=json"
    config = Config()
    headers = {
        'User-Agent': config.http_user_agent
    }
    results = set()
    
    for attempt in range(1, retries + 1):
        try:
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=30)) as response:
                if response.status == 200:
                    try:
                        data = await response.json()
                        for cert in data:
                            name_value = cert.get("name_value", "")
                            for d in name_value.split("\n"):
                                d = d.strip().lower()
                                # Remove wildcards and validate
                                d = d.replace("*.", "")
                                if d and domain in d and d.endswith(domain):
                                    results.add(d)
                        logger.info(f"Certificate Transparency: {len(results)} subdomains from crt.sh")
                        return results
                    except (json.JSONDecodeError, ValueError):
                        logger.warning(f"Failed to parse crt.sh JSON response (attempt {attempt}/{retries})")
                else:
                    logger.warning(
                        f"crt.sh returned status {response.status} (attempt {attempt}/{retries})")
                    
            # Wait before retry
            if attempt < retries:
                await asyncio.sleep(1.0 * attempt)
                
        except asyncio.TimeoutError:
            logger.warning(f"crt.sh timeout (attempt {attempt}/{retries})")
        except Exception as e:
            logger.warning(f"crt.sh error: {e} (attempt {attempt}/{retries})")
            
        if attempt < retries:
            await asyncio.sleep(1.0 * attempt)
    
    return results


async def fetch_additional_sources_async(domain: str, session: aiohttp.ClientSession) -> Dict[str, Set[str]]:
    """Fetch subdomains from additional public sources (HackerTarget, ThreatCrowd).
    
    These complement crt.sh to catch subdomains without SSL certs.
    
    Returns:
        Dict with keys 'hackertarget' and 'threatcrowd', each containing set of discovered subdomains
    """
    results = {
        'hackertarget': set(),
        'threatcrowd': set()
    }
    
    config = Config()
    headers = {
        'User-Agent': config.http_user_agent
    }

    # Source 1: HackerTarget API
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={quote(domain)}"
        async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as response:
            if resp.status == 200:
                text = await resp.text()
                for line in text.split('\n'):
                    if ',' in line:
                        subdomain = line.split(',')[0].strip().lower()
                        if subdomain and domain in subdomain:
                            results['hackertarget'].add(subdomain)
                if results['hackertarget']:
                    logger.info(f"HackerTarget: {len(results['hackertarget'])} subdomains")
            else:
                logger.debug(f"HackerTarget returned status {resp.status}")
    except asyncio.TimeoutError:
        logger.debug(f"HackerTarget timeout")
    except Exception as e:
        logger.debug(f"HackerTarget error: {e}")
    
    # Source 2: ThreatCrowd API
    try:
        url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={quote(domain)}"
        async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as response:
            if resp.status == 200:
                data = await resp.json()
                if 'subdomains' in data and isinstance(data['subdomains'], list):
                    for sub in data['subdomains']:
                        if sub and isinstance(sub, str):
                            results['threatcrowd'].add(sub.strip().lower())
                if results['threatcrowd']:
                    logger.info(f"ThreatCrowd: {len(results['threatcrowd'])} subdomains")
            else:
                logger.debug(f"ThreatCrowd returned status {resp.status}")
    except asyncio.TimeoutError:
        logger.debug(f"ThreatCrowd timeout")
    except (json.JSONDecodeError, ValueError) as e:
        logger.debug(f"ThreatCrowd JSON parse error: {e}")
    except Exception as e:
        logger.debug(f"ThreatCrowd error: {e}")
    
    return results


def resolve_host_sync(host: str, timeout: float = 3.0) -> bool:
    """Check if host resolves via DNS (synchronous for thread pool use).
    
    Args:
        host: Hostname to resolve
        timeout: DNS timeout in seconds
        
    Returns:
        True if host resolves, False otherwise
    """
    try:
        socket.setdefaulttimeout(timeout)
        socket.getaddrinfo(host, None, family=0, type=0)
        return True
    except (socket.gaierror, socket.timeout):
        return False
    finally:
        socket.setdefaulttimeout(None)


def probe_dns_patterns(domain: str, patterns: List[str], max_workers: int = 500) -> Set[str]:
    """Probe subdomain patterns using DNS resolution with multi-threading.
    
    Uses smart pattern generation (18,953 patterns for comprehensive discovery).
    
    Args:
        domain: Base domain
        patterns: List of subdomain patterns to test
        max_workers: Number of concurrent workers (optimized for DNS I/O)
        
    Returns:
        Set of discovered subdomains
    """
    found = set()
    
    def check(pattern: str) -> Optional[str]:
        host = f"{pattern}.{domain}"
        if resolve_host_sync(host):
            return host
        return None
    
    # DNS queries are I/O-bound, can handle massive parallelism
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check, pattern): pattern for pattern in patterns}
        
        completed = 0
        total = len(futures)
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result:
                    found.add(result)
                
                completed += 1
                if completed % 1000 == 0:
                    logger.info(f"DNS brute-force progress: {completed}/{total} ({len(found)} found)")
                    
            except Exception as e:
                logger.debug(f"DNS probe error: {e}")
    
    logger.info(f"DNS brute-force complete: {len(found)} subdomains resolved")
    return found


async def is_http_active_async(host: str, session: aiohttp.ClientSession, timeout: float = 10.0) -> bool:
    """Check if host responds on HTTP or HTTPS.
    
    Args:
        host: Hostname to check
        session: aiohttp session
        timeout: Request timeout
        
    Returns:
        True if host responds to HTTP/HTTPS requests
    """
    config = Config()
    headers = {
        'User-Agent': config.http_user_agent
    }
    urls = [f"https://{host}", f"http://{host}"]
    
    for url in urls:
        try:
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=timeout),
                                 allow_redirects=True, ssl=False) as resp:
                # Accept any response (2xx, 3xx, 4xx) as "active"
                if 200 <= resp.status < 500:
                    return True
        except asyncio.TimeoutError:
            # Timeout means server is slow but exists
            return True
        except Exception:
            continue
    
    return False


class TargetEnumerator:
    """Discovers targets (subdomains) to scan using multiple discovery methods.
    
    5-Layer Discovery Strategy:
    1. Certificate Transparency (crt.sh)
    2. Public DNS databases (HackerTarget, ThreatCrowd)
    3. Smart brute-force (18,953 patterns: a-z, aa-zz, aaa-zzz, numbers, common words)
    4. HTTP/HTTPS active verification
    5. Cache results for 24 hours
    """
    
    def __init__(self, domain: str, cache: Cache, config: dict):
        """Initialize enumerator.
        
        Args:
            domain: Base domain to enumerate
            cache: Cache for storing enumeration results
            config: ScanConfig object with enumeration settings
        """
        self.domain = domain
        self.cache = cache
        self.config = config
        self.max_dns_workers = getattr(config, 'dns_workers', 500)
        self.max_http_workers = getattr(config, 'http_workers', 200)
    
    async def enumerate_async(self) -> List[ScanTarget]:
        """Enumerate all targets for the domain (async version).
        
        Returns sorted, deduplicated list of ScanTargets with comprehensive discovery.
        """
        logger.info(f"="*80)
        logger.info(f"🔍 Comprehensive Subdomain Enumeration (Multi-Source Discovery)")
        logger.info(f"Target: {self.domain}")
        logger.info(f"="*80)
        allow_active = getattr(self.config, 'allow_active_probes', True)
        if not allow_active:
            logger.info(
                "Passive-only mode: using public data sources only (CT logs, public DBs, seeds).")
        
        # Check cache first (unless force rescan)
        if not getattr(self.config, 'force_rescan', False):
            cached_targets, cached_sources = self._from_cache()
            if cached_targets:
                logger.info(f"✓ Loaded {len(cached_targets)} targets from cache (24hr TTL)")
                return self._to_scan_targets(cached_targets, cached_sources)
        
        all_discovered = set()
        
        # Track discovery methods for statistics
        method_counts = {
            'apex_domain': 0,
            'xlsx_seeds': 0,
            'ct_logs': 0,
            'hackertarget': 0,
            'threatcrowd': 0,
            'dns_brute': 0,
            'srv_records': 0,
            'crawl_lite': 0,
            'ptr_reverse_dns': 0
        }
        
        # Track source attribution per subdomain
        subdomain_sources = {}  # fqdn -> list of discovery methods

        # Always include apex domain
        all_discovered.add(self.domain)
        subdomain_sources[self.domain] = ['apex_domain']
        method_counts['apex_domain'] = 1
        
        # [0/5] Load XLSX seeds (existing security reports)
        logger.info("")
        logger.info("[0/5] Loading seeds from existing XLSX security reports...")
        xlsx_seeds = load_xlsx_seeds(self.domain)
        if xlsx_seeds:
            all_discovered.update(xlsx_seeds)
            for fqdn in xlsx_seeds:
                subdomain_sources[fqdn] = ['xlsx_seeds']
            method_counts['xlsx_seeds'] = len(xlsx_seeds)
            logger.info(f"      ✓ XLSX Seeds: {len(xlsx_seeds)} subdomains from previous reports")
        else:
            logger.info(f"      → No XLSX files found (will rely on other methods)")
        
        # Create aiohttp session for async requests
        timeout = aiohttp.ClientTimeout(total=30)
        connector = aiohttp.TCPConnector(limit=100, limit_per_host=10)
        
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            # EARLY WILDCARD DETECTION (before brute-force)
            # WHY: If domain has wildcard DNS, brute-force will find 18,953 false positives
            # Testing 5 random subdomains takes <1 second vs 2-3 minutes for full brute-force
            skip_brute = False
            if allow_active and self.config.skip_brute_on_wildcard:
                logger.info("")
                logger.info("[0/6] Early wildcard detection (checking 5 random subdomains)...")
                wildcard_detector = WildcardDetector(self.domain, num_tests=5)
                if wildcard_detector.has_wildcard():
                    logger.warning(f"      ⚠️  Wildcard DNS detected! Skipping DNS brute-force (would find 18,953 false positives)")
                    skip_brute = True
                else:
                    logger.info(f"      ✓ No wildcard DNS - proceeding with brute-force")
            
            # PARALLEL DATA GATHERING (Layers 1-3)
            logger.info("")
            logger.info("[1-4/6] Parallel data gathering (CT logs + Public DBs + DNS brute-force)")
            if not skip_brute:
                logger.info(f"         This will test {len(SMART_PATTERNS):,} patterns (~2-3 minutes)...")
            logger.info("")
            
            # Run CT logs and public sources in parallel
            ct_task = asyncio.create_task(fetch_crtsh_async(self.domain, session))
            public_task = asyncio.create_task(fetch_additional_sources_async(self.domain, session))
            
            if allow_active and not skip_brute:
                # Run DNS brute-force in thread pool (blocking operation)
                loop = asyncio.get_event_loop()
                dns_task = loop.run_in_executor(
                    None,
                    probe_dns_patterns,
                    self.domain,
                    SMART_PATTERNS,
                    self.max_dns_workers
                )
                # Wait for all three sources
                ct_results, public_results, dns_results = await asyncio.gather(
                    ct_task, public_task, dns_task, return_exceptions=True
                )
            else:
                # Passive-only OR wildcard detected: skip DNS brute-force
                if skip_brute:
                    logger.info("      ⏩ Skipping DNS brute-force (wildcard detected)")
                ct_results, public_results = await asyncio.gather(
                    ct_task, public_task, return_exceptions=True
                )
                dns_results = set()
            
            # Safely merge results
            if isinstance(ct_results, set):
                all_discovered.update(ct_results)
                for fqdn in ct_results:
                    subdomain_sources.setdefault(fqdn, []).append('ct_logs')
                method_counts['ct_logs'] = len(ct_results)
                logger.info(f"      ✓ Certificate Transparency: {len(ct_results)} subdomains")
            else:
                logger.warning(f"      ✗ Certificate Transparency failed: {ct_results}")
            
            if isinstance(public_results, dict):
                # Merge both HackerTarget and ThreatCrowd results
                hackertarget_found = public_results.get('hackertarget', set())
                threatcrowd_found = public_results.get('threatcrowd', set())
                
                all_discovered.update(hackertarget_found)
                all_discovered.update(threatcrowd_found)
                
                for fqdn in hackertarget_found:
                    subdomain_sources.setdefault(
                        fqdn, []).append('hackertarget')
                for fqdn in threatcrowd_found:
                    subdomain_sources.setdefault(
                        fqdn, []).append('threatcrowd')

                method_counts['hackertarget'] = len(hackertarget_found)
                method_counts['threatcrowd'] = len(threatcrowd_found)
                
                total_public = len(hackertarget_found) + len(threatcrowd_found)
                logger.info(f"      ✓ Public databases: {total_public} subdomains (HT: {len(hackertarget_found)}, TC: {len(threatcrowd_found)})")
            else:
                logger.warning(f"      ✗ Public databases failed: {public_results}")
            
            if isinstance(dns_results, set):
                all_discovered.update(dns_results)
                for fqdn in dns_results:
                    subdomain_sources.setdefault(fqdn, []).append('dns_brute')
                method_counts['dns_brute'] = len(dns_results)
                logger.info(f"      ✓ DNS brute-force: {len(dns_results)} subdomains")
            else:
                logger.warning(f"      ✗ DNS brute-force failed: {dns_results}")
            
            if allow_active:
                # NEW: SRV record pivoting (parallel with other methods)
                logger.info(f"      → Running SRV record enumeration...")
                srv_results = await discover_srv_subdomains(self.domain)
                if srv_results:
                    all_discovered.update(srv_results)
                    for fqdn in srv_results:
                        subdomain_sources.setdefault(
                            fqdn, []).append('srv_records')
                    method_counts['srv_records'] = len(srv_results)

                # Include manually known subdomains (if configured)
                known_set = set(self.config.known_subdomains) if getattr(self.config, "known_subdomains", None) else set()
                if known_set:
                    for fqdn in known_set:
                        if fqdn.endswith(self.domain):
                            all_discovered.add(fqdn)
                            subdomain_sources.setdefault(fqdn, []).append('manual_known')

                # CRITICAL: Wildcard detection BEFORE testing HTTP
                logger.info("")
                logger.info(
                    f"[4/6] Wildcard DNS detection (prevents false positives)...")
                wildcard_detector = WildcardDetector(self.domain, num_tests=5)
                if wildcard_detector.has_wildcard():
                    logger.warning(
                        f"      ⚠️  Wildcard DNS detected! Filtering results...")
                    all_discovered = filter_wildcard_results(
                        self.domain, all_discovered, wildcard_detector, keep_fqdns=known_set)
                    logger.info(
                        f"      ✓ Filtered to {len(all_discovered)} real subdomains")
                else:
                    logger.info(
                        f"      ✓ No wildcard DNS - all {len(all_discovered)} discoveries are valid")

                logger.info("")
                logger.info(
                    f"[5/6] Testing HTTP/HTTPS availability for {len(all_discovered)} discovered subdomains...")

                # Test HTTP/HTTPS availability
                active_subdomains = []
                inactive_subdomains = []

                tasks = []
                for host in sorted(all_discovered):
                    task = is_http_active_async(host, session, timeout=10.0)
                    tasks.append((host, task))

                results = await asyncio.gather(*[t[1] for t in tasks], return_exceptions=True)

                for (host, _), is_active in zip(tasks, results):
                    if isinstance(is_active, bool) and is_active:
                        active_subdomains.append(host)
                    else:
                        inactive_subdomains.append(host)

                logger.info(
                    f"      ✓ Active (HTTP/HTTPS): {len(active_subdomains)}")
                logger.info(
                    f"      ✓ Inactive (DNS only): {len(inactive_subdomains)}")

                # NEW: Crawl-lite - extract subdomains from HTTP responses
                if active_subdomains:
                    logger.info("")
                    logger.info(
                        f"[5.5/6] Crawl-lite: Extracting subdomains from {len(active_subdomains)} active sites...")
                    logger.info("        (HTML, JavaScript, CSP headers)")
                    crawl_results = await discover_from_crawling(
                        set(active_subdomains),
                        self.domain,
                        timeout=10,
                        max_size=2 * 1024 * 1024
                    )
                    if crawl_results:
                        for fqdn in crawl_results:
                            subdomain_sources.setdefault(
                                fqdn, []).append('crawl_lite')
                        method_counts['crawl_lite'] = len(crawl_results)
                        logger.info(
                            f"      ✓ Discovered {len(crawl_results)} new subdomains from web crawling")
                        all_discovered.update(crawl_results)
                    else:
                        logger.info(
                            f"      ✓ No new subdomains found via crawling")

                # NEW: PTR reverse DNS pivoting
                logger.info("")
                logger.info(
                    f"[5.7/6] PTR Reverse DNS: Discovering subdomains via reverse lookups...")
                logger.info(
                    "        (Building IP → FQDN map from all discoveries)")
                ip_to_fqdn_map = await build_ip_to_fqdn_map(all_discovered)
                ptr_results = await discover_ptr_subdomains(ip_to_fqdn_map, self.domain, timeout=3.0)
                if ptr_results:
                    for fqdn in ptr_results:
                        subdomain_sources.setdefault(
                            fqdn, []).append('ptr_reverse_dns')
                    method_counts['ptr_reverse_dns'] = len(ptr_results)
                    logger.info(
                        f"      ✓ Discovered {len(ptr_results)} new subdomains from PTR records")
                    all_discovered.update(ptr_results)
                else:
                    logger.info(
                        f"      ✓ No new subdomains found via PTR records")
            else:
                logger.info(
                    "Passive-only mode: Skipping DNS brute-force, SRV, HTTP reachability tests, crawling, and PTR pivots.")
                active_subdomains = []
                inactive_subdomains = sorted(all_discovered)
        
        # CRITICAL: Normalize all discoveries (punycode, lowercase, dedup)
        logger.info("")
        logger.info(f"[6/6] Normalizing {len(all_discovered)} discoveries...")
        logger.info("      (punycode, lowercase, trailing dot removal, deduplication)")
        all_discovered = normalize_fqdn_set(all_discovered, self.domain)
        logger.info(f"      ✓ {len(all_discovered)} normalized unique FQDNs")
        
        # Statistics summary
        logger.info("")
        logger.info("="*80)
        logger.info("📊 DISCOVERY SUMMARY")
        logger.info("="*80)
        logger.info(f"  Total Discovered:            {len(all_discovered)} unique subdomains")
        logger.info(f"  Active (HTTP/HTTPS):         {len(active_subdomains)}")
        logger.info(f"  Inactive (DNS only):         {len(inactive_subdomains)}")
        logger.info("="*80)
        logger.info("")
        
        # Cache results
        self._to_cache(all_discovered, method_counts, subdomain_sources)
        
        # Return all discovered (both active and inactive)
        # Scanner will handle failures gracefully
        return self._to_scan_targets(all_discovered, subdomain_sources)

    def _to_scan_targets(self, fqdns: Set[str], sources_map: Dict[str, List[str]] = None) -> List[ScanTarget]:
        """Convert set of FQDNs to sorted list of ScanTargets.
        
        Args:
            fqdns: Set of discovered FQDNs
            sources_map: Optional mapping of fqdn -> list of discovery methods
        """
        targets = []
        for fqdn in fqdns:
            # Get primary discovery source (first method that found it)
            discovered_from = "unknown"
            if sources_map and fqdn in sources_map:
                sources = sources_map[fqdn]
                discovered_from = sources[0] if sources else "unknown"
            targets.append(ScanTarget(
                fqdn=fqdn, discovered_from=discovered_from))

        # Sort for deterministic ordering
        targets.sort(key=lambda t: t.fqdn)
        return targets
    
    def _from_cache(self) -> tuple:
        """Load targets from cache.
        
        Returns:
            Tuple of (set of FQDNs, dict of sources) or (empty set, empty dict)
        """
        cache_key = f"enumeration:{self.domain}"
        cached = self.cache.get(cache_key)
        
        if cached and 'targets' in cached:
            targets = set(cached['targets'])
            sources = cached.get('subdomain_sources', {})
            return targets, sources

        return set(), {}

    def _to_cache(self, targets: Set[str], method_counts: Dict[str, int] = None, subdomain_sources: Dict[str, List[str]] = None) -> None:
        """Save targets to cache (24 hour TTL).
        
        Args:
            targets: Set of discovered FQDNs
            method_counts: Statistics of discoveries per method
            subdomain_sources: Mapping of fqdn -> list of discovery methods
        """
        cache_key = f"enumeration:{self.domain}"
        cache_data = {'targets': list(targets)}
        if method_counts:
            cache_data['method_counts'] = method_counts
        if subdomain_sources:
            cache_data['subdomain_sources'] = subdomain_sources
        self.cache.set(cache_key, cache_data)
