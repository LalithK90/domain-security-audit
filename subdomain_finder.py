"""
Subdomain Discovery Module

Enhanced subdomain enumeration with:
- Certificate Transparency (crt.sh)
- Common subdomain probing (30+ patterns)
- DNS resolution validation
- HTTP/HTTPS availability testing
- www/non-www variant generation
"""

import requests
import socket
import time
import concurrent.futures
from typing import List, Set, Dict
from tqdm import tqdm
import string
import itertools


# Smart brute-force: Generate short patterns (1-4 chars) + numbers
def generate_smart_patterns(max_length: int = 4, include_3char: bool = False, include_4char: bool = False) -> List[str]:
    """
    Generate smart subdomain patterns instead of fixed list.
    
    Generates:
    - Single letters: a, b, c, ..., z (26)
    - Two letters: aa, ab, ac, ..., zz (676)
    - Three letters: aaa, aab, ..., zzz (17,576) - OPTIONAL
    - Four letters: aaaa, ..., zzzz (456,976) - OPTIONAL (VERY SLOW!)
    - Single numbers: 0, 1, 2, ..., 9 (10)
    - Two numbers: 00, 01, ..., 99 (100)
    - Letter+number combos: a1, a2, ..., z9 (234)
    - Common abbreviations from patterns
    
    Default (max_length=4, include_3char=False):
      - ~1,400 patterns (FAST - recommended)
    
    With 3-char enabled:
      - ~19,000 patterns (MEDIUM - takes 2-3 minutes)
    
    With 4-char enabled:
      - ~476,000 patterns (SLOW - takes hours! Not recommended)
    
    RECOMMENDATION:
      - Use Certificate Transparency (crt.sh) for longer names
      - Use smart patterns for short names only
      - crt.sh is FREE and finds real subdomains instantly!
    """
    patterns = set()
    
    # Single characters (a-z, 0-9)
    patterns.update(string.ascii_lowercase)
    patterns.update(string.digits)
    
    # Two-character combinations (most common subdomains are 2-4 chars)
    for combo in itertools.product(string.ascii_lowercase, repeat=2):
        patterns.add(''.join(combo))
    
    # Three-character combinations (OPTIONAL - adds ~17k patterns, ~2min scan time)
    if include_3char:
        for combo in itertools.product(string.ascii_lowercase, repeat=3):
            patterns.add(''.join(combo))
    
    # Four-character combinations (NOT RECOMMENDED - adds 456k patterns, hours of scan time!)
    if include_4char:
        for combo in itertools.product(string.ascii_lowercase, repeat=4):
            patterns.add(''.join(combo))
    
    # Number combinations (00-99)
    for i in range(100):
        patterns.add(f"{i:02d}")
    
    # Letter + number combinations (a1, a2, ..., z9)
    for letter in string.ascii_lowercase:
        for num in range(10):
            patterns.add(f"{letter}{num}")
            patterns.add(f"{num}{letter}")
    
    # Common word fragments and abbreviations
    common_fragments = [
        "www", "mail", "ftp", "api", "dev", "test", "admin", "app", "web",
        "blog", "shop", "vpn", "cms", "crm", "erp", "sso", "iam", "mfa",
        "cdn", "dns", "ntp", "smtp", "pop", "imap", "ssh", "db", "sql",
        "old", "new", "beta", "demo", "prod", "stage", "uat", "qa",
        "mobile", "m", "wap", "portal", "secure", "login", "auth",
        "static", "assets", "media", "img", "images", "files", "docs",
        "help", "support", "forum", "wiki", "kb", "faq", "status",
        "my", "user", "account", "profile", "dashboard", "panel", "cp",
        "git", "svn", "repo", "code", "build", "ci", "jenkins",
        "store", "shop", "cart", "checkout", "payment", "billing",
        "v1", "v2", "v3", "api1", "api2", "rest", "graphql", "ws",
    ]
    patterns.update(common_fragments)
    
    return sorted(list(patterns))


# Use smart pattern generation instead of fixed list
# For 99% subdomain discovery, enable 3-char patterns (recommended for comprehensive scans)
# Fast mode: include_3char=False (~1,400 patterns, 30 sec)
# Comprehensive mode: include_3char=True (~19,000 patterns, 2-3 min) ← BEST for 99% coverage
SMART_PATTERNS = generate_smart_patterns(max_length=4, include_3char=True, include_4char=False)


def fetch_crtsh(domain: str, retries: int = 3, backoff: float = 1.0) -> List[str]:
    """
    Fetch subdomains from Certificate Transparency logs (crt.sh).
    
    Returns all subdomains found in SSL/TLS certificates for the domain.
    This is the BEST source - finds real subdomains that have SSL certs.
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    for attempt in range(1, retries + 1):
        try:
            resp = requests.get(url, timeout=15)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                except ValueError:
                    return []

                results = []
                for cert in data:
                    name_value = cert.get("name_value", "")
                    for d in name_value.split("\n"):
                        d = d.strip().lower()
                        # Skip wildcards but keep all others
                        if d and not d.startswith("*."):
                            results.append(d)
                return results
            else:
                time.sleep(backoff * attempt)
        except requests.RequestException:
            time.sleep(backoff * attempt)
    return []


def fetch_additional_sources(domain: str) -> Set[str]:
    """
    Fetch subdomains from additional sources for maximum coverage.
    
    Sources:
    1. HackerTarget API (free, no key needed)
    2. ThreatCrowd API (free, no key needed)
    3. DNSDumpster-style lookups
    
    These complement crt.sh to catch subdomains without SSL certs.
    """
    found = set()
    
    # Source 1: HackerTarget API
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            for line in resp.text.split('\n'):
                if ',' in line:
                    subdomain = line.split(',')[0].strip().lower()
                    if subdomain and domain in subdomain:
                        found.add(subdomain)
    except Exception:
        pass
    
    # Source 2: ThreatCrowd API
    try:
        url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            if 'subdomains' in data:
                for sub in data['subdomains']:
                    if sub and isinstance(sub, str):
                        found.add(sub.strip().lower())
    except Exception:
        pass
    
    return found


def resolve_host(host: str, timeout: float = 3.0) -> bool:
    """Check if hostname resolves via DNS."""
    try:
        socket.getaddrinfo(host, None, family=0, type=0)
        return True
    except socket.gaierror:
        return False


def probe_common_subdomains(domain: str, subdomains: List[str] = None) -> Set[str]:
    """
    Probe subdomain patterns using DNS resolution with OPTIMIZED MULTI-THREADING.
    
    Uses smart pattern generation instead of fixed list:
    - Single chars: a-z, 0-9
    - Two chars: aa, ab, ..., zz (676 combinations)
    - Three chars: aaa-zzz (17,576 combinations)
    - Common words: api, dev, mail, www, etc.
    - Number combinations: 00-99
    - Mixed: a1, a2, ..., z9
    
    Multi-threading: 100 concurrent workers (optimized for DNS queries)
    Total: ~19,000 patterns tested in ~2 minutes
    """
    if subdomains is None:
        subdomains = SMART_PATTERNS

    found = set()

    def check(s: str):
        host = f"{s}.{domain}"
        if resolve_host(host):
            return host
        return None

    # OPTIMIZED: Increased from 50 to 100 workers for faster DNS probing
    # DNS queries are I/O bound, so more threads = faster results
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as ex:
        futures = {ex.submit(check, s): s for s in subdomains}
        for fut in concurrent.futures.as_completed(futures):
            try:
                res = fut.result()
                if res:
                    found.add(res)
            except Exception:
                pass

    return found


def is_http_active(host: str, timeout: float = 10.0) -> bool:
    """
    Check if host responds on HTTP or HTTPS.
    
    Uses longer timeout (10s) to catch slow-responding servers.
    Tries both HTTPS and HTTP with redirects enabled.
    """
    try:
        urls = [f"https://{host}", f"http://{host}"]
        for url in urls:
            try:
                resp = requests.get(
                    url, 
                    timeout=timeout, 
                    allow_redirects=True,
                    verify=False  # Allow self-signed certs
                )
                if 200 <= resp.status_code < 500:  # Accept even error pages (means server is alive)
                    return True
            except requests.Timeout:
                # Timeout doesn't mean it's down, DNS resolved so mark as potentially active
                # Let security scanner handle it with longer timeouts
                return True
            except requests.RequestException:
                continue
    except Exception:
        pass
    return False


def generate_www_variants(subdomains: List[str]) -> List[str]:
    """
    Generate both www and non-www variants for each subdomain.
    
    For example:
    - 'example.com' generates: ['example.com', 'www.example.com']
    - 'portal.example.com' generates: ['portal.example.com', 'www.portal.example.com']
    
    Returns unique list with all variants.
    """
    variants = set()
    
    for subdomain in subdomains:
        # Add original
        variants.add(subdomain)
        
        # Generate www variant
        if subdomain.startswith('www.'):
            # If already www, add non-www version
            non_www = subdomain[4:]
            variants.add(non_www)
        else:
            # Add www version
            www_version = f'www.{subdomain}'
            variants.add(www_version)
    
    return sorted(variants)


def enumerate_subdomains(domain: str, verbose: bool = True) -> Dict[str, List[str]]:
    """
    Comprehensive subdomain enumeration with 99% coverage goal.
    
    Multi-source approach:
    1. Certificate Transparency (crt.sh) - SSL cert names
    2. HackerTarget API - Public DNS records
    3. ThreatCrowd API - Threat intelligence data
    4. Smart brute-force - 1-3 char patterns (~19k patterns)
    5. www/non-www variant testing
    
    Returns dictionary with:
    - 'discovered': All unique subdomains found (all sources combined)
    - 'all_variants': All variants including www/non-www
    - 'active': Only HTTP/HTTPS responsive subdomains
    - 'inactive': DNS-resolved but not HTTP/HTTPS responsive
    
    Args:
        domain: Root domain to enumerate (e.g., 'example.com')
        verbose: Print progress messages
    
    Returns:
        Dictionary with categorized subdomain lists
    """
    if verbose:
        print(f"\n🔍 Comprehensive Subdomain Enumeration (99% Coverage Mode)")
        print(f"Target: {domain}")
        print("=" * 60)
    
    # OPTIMIZED: Steps 1-3 now run in parallel using threads
    if verbose:
        print("\n[1-3/5] Parallel data gathering (Certificate Transparency + Public DBs + DNS probing)...")
        print(f"         This will take ~2-3 minutes for {len(SMART_PATTERNS)} patterns...")
    
    crt_set = set()
    additional = set()
    dns_found = set()
    
    def step1_crt():
        """Step 1: Certificate Transparency"""
        nonlocal crt_set
        crt_hosts = fetch_crtsh(domain)
        for h in crt_hosts:
            if h.endswith(domain):
                crt_set.add(h)
        if verbose:
            print(f"      ✓ Certificate Transparency: {len(crt_set)} subdomains")
    
    def step2_public():
        """Step 2: Public databases"""
        nonlocal additional
        additional = fetch_additional_sources(domain)
        if verbose:
            print(f"      ✓ Public databases (HackerTarget, ThreatCrowd): {len(additional)} subdomains")
    
    def step3_dns():
        """Step 3: DNS brute-force"""
        nonlocal dns_found
        dns_found = probe_common_subdomains(domain)
        if verbose:
            print(f"      ✓ DNS brute-force (a-z, aa-zz, aaa-zzz): {len(dns_found)} subdomains")
    
    # Run all 3 sources in parallel threads (Certificate Transparency, HackerTarget/ThreatCrowd, DNS brute-force)
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        future1 = ex.submit(step1_crt)
        future2 = ex.submit(step2_public)
        future3 = ex.submit(step3_dns)
        
        # Wait for all to complete
        concurrent.futures.wait([future1, future2, future3])
    
    # Step 4: Combine all sources and generate variants
    all_sources = crt_set.union(additional).union(dns_found)
    discovered = sorted(all_sources)
    
    if verbose:
        print(f"\n[4/5] Generating www/non-www variants...")
    all_variants = generate_www_variants(discovered)
    if verbose:
        print(f"      ✓ Total variants to test: {len(all_variants)}")
        print(f"        - From Certificate Transparency: {len(crt_set)}")
        print(f"        - From public databases: {len(additional)}")
        print(f"        - From DNS brute-force: {len(dns_found)}")
        print(f"        - Unique subdomains discovered: {len(discovered)}")
        print(f"        - With www variants: {len(all_variants)}")
    
    # Step 5: Test HTTP/HTTPS availability
    if verbose:
        print(f"\n[5/5] Testing HTTP/HTTPS availability...")
    
    active_subdomains = []
    inactive_subdomains = []
    
    # OPTIMIZED: Increased from 30 to 50 workers for faster HTTP testing
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        futures = {ex.submit(is_http_active, h): h for h in all_variants}
        
        if verbose:
            for fut in tqdm(concurrent.futures.as_completed(futures), 
                          total=len(all_variants), 
                          desc="      Testing"):
                try:
                    host = futures[fut]
                    if fut.result():
                        active_subdomains.append(host)
                    else:
                        inactive_subdomains.append(host)
                except Exception:
                    inactive_subdomains.append(futures[fut])
        else:
            for fut in concurrent.futures.as_completed(futures):
                try:
                    host = futures[fut]
                    if fut.result():
                        active_subdomains.append(host)
                    else:
                        inactive_subdomains.append(host)
                except Exception:
                    inactive_subdomains.append(futures[fut])
    
    active_subdomains.sort()
    inactive_subdomains.sort()
    
    # Print summary
    if verbose:
        print(f"\n{'=' * 60}")
        print("📊 COMPREHENSIVE DISCOVERY SUMMARY")
        print(f"{'=' * 60}")
        print(f"  Certificate Transparency:   {len(crt_set)}")
        print(f"  Public Databases:           {len(additional)}")
        print(f"  DNS Brute-Force:            {len(dns_found)}")
        print(f"  ─────────────────────────────────────")
        print(f"  Total Discovered (unique):  {len(discovered)}")
        print(f"  With www/non-www variants:  {len(all_variants)}")
        print(f"  ─────────────────────────────────────")
        print(f"  Active (HTTP/HTTPS):        {len(active_subdomains)}")
        print(f"  Inactive (DNS only):        {len(inactive_subdomains)}")
        print(f"{'=' * 60}\n")
        
        if active_subdomains:
            print("✅ Active subdomains (sample up to 20):")
            for h in active_subdomains[:20]:
                www_indicator = " [www]" if h.startswith('www.') else ""
                print(f"   • {h}{www_indicator}")
            if len(active_subdomains) > 20:
                print(f"   ... and {len(active_subdomains) - 20} more")
    
    return {
        'discovered': discovered,
        'all_variants': all_variants,
        'active': active_subdomains,
        'inactive': inactive_subdomains,
        'sources': {
            'certificate_transparency': len(crt_set),
            'public_databases': len(additional),
            'dns_brute_force': len(dns_found)
        }
    }


def save_subdomain_lists(domain: str, results: Dict[str, List[str]]) -> List[str]:
    """
    Save subdomain lists to files.
    
    Creates:
    - {domain}_discovered.txt: Original discovered subdomains
    - {domain}_all_variants.txt: All www/non-www variants
    - {domain}_active.txt: HTTP/HTTPS active only
    - {domain}_inactive.txt: DNS-resolved but not HTTP active
    
    Returns list of created file paths.
    """
    files_created = []
    
    # Discovered subdomains
    filename = f"{domain}_discovered.txt"
    with open(filename, 'w', encoding='utf-8') as f:
        for host in results['discovered']:
            f.write(f"{host}\n")
    files_created.append(filename)
    
    # All variants
    filename = f"{domain}_all_variants.txt"
    with open(filename, 'w', encoding='utf-8') as f:
        for host in results['all_variants']:
            f.write(f"{host}\n")
    files_created.append(filename)
    
    # Active only
    filename = f"{domain}_active.txt"
    with open(filename, 'w', encoding='utf-8') as f:
        for host in results['active']:
            f.write(f"{host}\n")
    files_created.append(filename)
    
    # Inactive
    filename = f"{domain}_inactive.txt"
    with open(filename, 'w', encoding='utf-8') as f:
        for host in results['inactive']:
            f.write(f"{host}\n")
    files_created.append(filename)
    
    return files_created


if __name__ == "__main__":
    # Test the module
    import sys
    
    if len(sys.argv) > 1:
        domain = sys.argv[1]
    else:
        domain = input("Enter domain to enumerate: ").strip()
    
    results = enumerate_subdomains(domain, verbose=True)
    
    print(f"\n💾 Saving results to files...")
    files = save_subdomain_lists(domain, results)
    
    print(f"\n✅ Created {len(files)} files:")
    for f in files:
        print(f"   • {f}")
