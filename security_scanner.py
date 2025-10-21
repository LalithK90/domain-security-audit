"""
Comprehensive Subdomain Security Scanner

Universal 106-parameter security assessment with dynamic, context-aware scanning.
See README.md for complete documentation.

Usage:
    python security_scanner.py --domain example.com         # Auto-enumerate subdomains
    python security_scanner.py --file subdomains.txt        # Use existing file
    python security_scanner.py --file domain_list.xlsx      # Use Excel file
    python security_scanner.py                              # Interactive mode

Output: website_ranking.xlsx with security scores and detailed results
"""

import pandas as pd
import requests
from bs4 import BeautifulSoup
from datetime import datetime
from pathlib import Path
from tqdm import tqdm
import time
import re
import sys
import argparse
import socket
import json
import concurrent.futures
from typing import List, Set
from sslyze import (
    Scanner,
    ServerScanRequest,
    ServerNetworkLocation,
    ScanCommand,
    ServerConnectivityTester,
    ServerConnectivityStatusEnum
)
from sslyze.errors import ConnectionToServerFailed
import dns.resolver
from dns.exception import DNSException
import warnings
warnings.filterwarnings('ignore')


COMMON_SUBDOMAINS = [
    "www", "mail", "webmail", "admin", "m", "api", "dev", "staging",
    "test", "portal", "vpn", "crm", "shop", "beta", "smtp", "pop",
    "imap", "ns1", "ns2", "git", "gitlab", "support", "cdn", "static",
    "images", "docs", "status"
]


def fetch_crtsh(domain: str, retries: int = 3, backoff: float = 1.0) -> List[str]:
    """Fetch subdomains from crt.sh with retry logic."""
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
                        if d and not d.startswith("*."):
                            results.append(d)
                return results
            else:
                time.sleep(backoff * attempt)
        except requests.RequestException:
            time.sleep(backoff * attempt)
    return []


def resolve_host(host: str, timeout: float = 3.0) -> bool:
    """Check if host resolves via DNS."""
    try:
        socket.getaddrinfo(host, None, family=0, type=0)
        return True
    except socket.gaierror:
        return False


def probe_common_subdomains(domain: str, subdomains: List[str] = None) -> Set[str]:
    """Probe common subdomains for a domain."""
    if subdomains is None:
        subdomains = COMMON_SUBDOMAINS

    found = set()

    def check(s: str):
        host = f"{s}.{domain}"
        if resolve_host(host):
            return host
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(check, s): s for s in subdomains}
        for fut in concurrent.futures.as_completed(futures):
            try:
                res = fut.result()
                if res:
                    found.add(res)
            except Exception:
                pass

    return found


def is_http_active(host: str, timeout: float = 5.0) -> bool:
    """Check if host responds on HTTP or HTTPS."""
    try:
        urls = [f"https://{host}", f"http://{host}"]
        for url in urls:
            try:
                resp = requests.get(url, timeout=timeout, allow_redirects=True)
                if 200 <= resp.status_code < 400:
                    return True
            except requests.RequestException:
                continue
    except Exception:
        pass
    return False


def enumerate_subdomains(domain: str) -> List[str]:
    """Enumerate subdomains for a domain and return active ones."""
    print(f"\n🔍 Enumerating subdomains for: {domain}")
    print("  ├─ Querying crt.sh (Certificate Transparency)...")

    crt_hosts = fetch_crtsh(domain)
    crt_set = set()
    for h in crt_hosts:
        if h.endswith(domain):
            crt_set.add(h)
    print(f"  │  Found {len(crt_set)} subdomains from certificates")

    print("  ├─ Probing common subdomains...")
    active = probe_common_subdomains(domain)
    print(f"  │  Found {len(active)} from common subdomain probing")

    combined = sorted(crt_set.union(active))
    print(f"  └─ Total unique subdomains: {len(combined)}")

    print("\n🌐 Testing HTTP/HTTPS availability...")
    active_subdomains = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
        futures = {ex.submit(is_http_active, h): h for h in combined}
        for fut in tqdm(concurrent.futures.as_completed(futures), total=len(combined), desc="  Testing"):
            try:
                if fut.result():
                    active_subdomains.append(futures[fut])
            except Exception:
                pass

    active_subdomains.sort()
    print(f"\n✅ Found {len(active_subdomains)} active subdomains")

    if active_subdomains:
        print("\nActive subdomains (sample up to 10):")
        for h in active_subdomains[:10]:
            print(f"  • {h}")
        if len(active_subdomains) > 10:
            print(f"  ... and {len(active_subdomains) - 10} more")

    return active_subdomains


def classify_subdomain(subdomain):
    """Classify subdomain as webapp, api, static, or other."""
    try:
        resp = requests.get(
            f'https://{subdomain}', timeout=8, verify=False, allow_redirects=True)
        ct = resp.headers.get('Content-Type', '').lower()
        if 'json' in ct or '/api/' in resp.url or 'swagger' in resp.text.lower() or 'openapi' in resp.text.lower():
            return 'api'
        if '<form' in resp.text.lower() or 'login' in resp.text.lower() or 'password' in resp.text.lower():
            return 'webapp'
        if '<html' in resp.text.lower() and not ('<form' in resp.text.lower() or 'login' in resp.text.lower()):
            return 'static'
        return 'other'
    except Exception:
        return 'other'


TYPE_CHECKS = {
    'webapp': [
        # TLS & Certificate Security
        'TLS-1', 'CERT-1', 'FS-1', 'WC-1', 'TLS-2', 'CERT-2', 'HSTS-2',
        # HTTP Headers & Protocols
        'HTTPS-1', 'HSTS-1', 'CSP-1', 'XFO-1', 'XCTO-1', 'XXP-1', 'RP-1', 'PP-1', 'HEADER-1', 'HEADER-2', 'HEADER-3', 'CORS-1', 'WAF-1', 'REPORT-1', 'HEADER-5', 'HEADER-6',
        # Authentication & Session Management
        'COO-1', 'AUTH-1', 'AUTH-2', 'AUTH-3', 'SESSION-1', 'SAMESITE-1', 'AUTH-4', 'AUTH-5', 'AUTH-6', 'AUTH-7',
        # Input Validation & Sanitization
        'INPUT-1', 'INPUT-2', 'INPUT-3', 'INPUT-4', 'INPUT-5', 'INPUT-6', 'INPUT-7', 'INPUT-8', 'INPUT-9',
        # Access Control & Authorization
        'AUTHZ-1', 'AUTHZ-2', 'AUTHZ-3', 'AUTHZ-4', 'AUTHZ-5', 'AUTHZ-6',
        # Security Headers & Browser Policies
        'HEADER-7',
        # Encryption & Data Protection
        'ENCRYPT-1', 'ENCRYPT-2',
        # Logging, Monitoring & Incident Response
        'LOG-1', 'LOG-2', 'LOG-3', 'LOG-4',
        # Cloud & Infrastructure Security
        'CLOUD-1', 'CLOUD-2', 'CLOUD-3',
        # Email & DNS Security
        'DNS-1', 'SPF-1', 'DMARC-1', 'DNS-2', 'MX-1', 'DNS-3', 'DNS-4',
        # File & Directory Security
        'DIR-1', 'ADMIN-1', 'ROBOTS-1', 'SEC-1', 'BACKUP-1', 'GIT-1', 'CONFIG-1',
        # Information Disclosure
        'SI-1', 'TITLE-1', 'ETag-1', 'ERROR-1', 'HEADER-4', 'ERROR-2',
        # Performance & Cache Security
        'Cache-1', 'CACHE-2',
        # Redirect & Navigation Security
        'REDIR-1', 'REDIR-2',
        # Content & Resource Security
        'SR-1', 'SRI-2', 'MIME-1', 'MIXED-1', 'THIRD-1',
        # API & Modern Web Features
        'API-1', 'API-2', 'HTTP2-1',
        # Advanced Security Controls
        'AUTHZ-1', 'AUTHZ-2', 'LOG-1',
        # Compliance & Standards
        'COMP-1', 'COMP-2', 'COMP-3',
        # Subdomain Security
        'SUB-1', 'SUB-2',
        # WAF & DDoS Protection
        'WAF-2', 'DDoS-1',
        # Server & Infrastructure Security
        'SERVER-1',
        # Third-Party & Supply Chain Security
        'THIRD-2', 'THIRD-3',
        # Compliance & Documentation
        'COMP-4', 'COMP-5', 'COMP-6'
    ],
    'api': [
        'TLS-1', 'CERT-1', 'FS-1', 'WC-1', 'TLS-2', 'CERT-2', 'HSTS-2',
        'HTTPS-1', 'HSTS-1', 'CORS-1', 'WAF-1', 'HEADER-2', 'HEADER-3', 'HEADER-5', 'HEADER-6', 'COO-1', 'AUTH-2', 'AUTH-4', 'AUTH-5', 'AUTH-6', 'AUTH-7',
        'INPUT-1', 'INPUT-2', 'INPUT-4', 'INPUT-5', 'INPUT-6', 'INPUT-7', 'INPUT-9',
        'AUTHZ-1', 'AUTHZ-2', 'AUTHZ-3', 'AUTHZ-4', 'AUTHZ-5', 'AUTHZ-6', 'ENCRYPT-1', 'ENCRYPT-2', 'LOG-1', 'LOG-2', 'LOG-3', 'LOG-4', 'CLOUD-1', 'CLOUD-2', 'CLOUD-3',
        'DNS-1', 'SPF-1', 'DMARC-1', 'DNS-2', 'MX-1', 'DNS-3', 'DNS-4', 'DIR-1', 'ADMIN-1', 'SEC-1', 'BACKUP-1', 'GIT-1', 'CONFIG-1', 'SI-1', 'ETag-1', 'ERROR-1', 'HEADER-4', 'ERROR-2', 'Cache-1', 'CACHE-2', 'REDIR-1', 'API-1', 'API-2', 'HTTP2-1', 'COMP-1', 'COMP-2', 'COMP-3', 'SUB-1', 'SUB-2', 'WAF-2', 'DDoS-1', 'SERVER-1', 'THIRD-2', 'THIRD-3', 'COMP-4', 'COMP-5', 'COMP-6'
    ],
    'static': [
        'TLS-1', 'CERT-1', 'FS-1', 'WC-1', 'TLS-2', 'CERT-2', 'HSTS-2', 'HTTPS-1', 'HSTS-1', 'CSP-1', 'XFO-1', 'XCTO-1', 'XXP-1', 'RP-1', 'PP-1', 'HEADER-1', 'HEADER-2', 'HEADER-3', 'WAF-1', 'HEADER-5', 'HEADER-6', 'COO-1', 'SAMESITE-1', 'HEADER-7', 'ENCRYPT-1', 'ENCRYPT-2', 'LOG-1', 'LOG-2', 'LOG-3', 'LOG-4', 'CLOUD-1', 'CLOUD-2', 'CLOUD-3', 'DNS-1', 'SPF-1', 'DMARC-1', 'DNS-2', 'MX-1', 'DNS-3', 'DNS-4', 'DIR-1', 'ADMIN-1', 'ROBOTS-1', 'SEC-1', 'BACKUP-1', 'GIT-1', 'CONFIG-1', 'SI-1', 'TITLE-1', 'ETag-1', 'ERROR-1', 'HEADER-4', 'ERROR-2', 'Cache-1', 'CACHE-2', 'SR-1', 'SRI-2', 'MIME-1', 'MIXED-1', 'THIRD-1', 'COMP-1', 'COMP-2', 'COMP-3', 'SUB-1', 'SUB-2', 'WAF-2', 'DDoS-1', 'SERVER-1', 'THIRD-2', 'THIRD-3', 'COMP-4', 'COMP-5', 'COMP-6'
    ],
    'other': [
        'DNS-1', 'SPF-1', 'DMARC-1', 'DNS-2', 'MX-1', 'DNS-3', 'DNS-4', 'SUB-1', 'SUB-2'
    ]
}


CHECKS = {
    # TLS & Certificate Security
    'TLS-1': {'priority': 'High', 'desc': 'TLS 1.2+ enforced'},
    'CERT-1': {'priority': 'High', 'desc': 'Valid cert chain'},
    'FS-1': {'priority': 'Medium', 'desc': 'Forward secrecy (ECDHE ciphers)'},
    'WC-1': {'priority': 'Medium', 'desc': 'No weak ciphers (RC4/3DES)'},
    'TLS-2': {'priority': 'Medium', 'desc': 'OCSP stapling enabled'},
    'CERT-2': {'priority': 'Medium', 'desc': 'Certificate transparency compliance'},
    'HSTS-2': {'priority': 'High', 'desc': 'HSTS preload directive enabled'},
    # HTTP Headers & Protocols
    'HTTPS-1': {'priority': 'High', 'desc': 'HTTPS enforced (HTTP → HTTPS redirect)'},
    'HSTS-1': {'priority': 'High', 'desc': 'HSTS max-age ≥31536000 + includeSubDomains'},
    'CSP-1': {'priority': 'Medium', 'desc': 'CSP present (non-empty)'},
    'XFO-1': {'priority': 'Medium', 'desc': 'X-Frame-Options: DENY/SAMEORIGIN'},
    'XCTO-1': {'priority': 'Medium', 'desc': 'X-Content-Type-Options: nosniff'},
    'XXP-1': {'priority': 'Medium', 'desc': 'X-XSS-Protection: 1; mode=block'},
    'RP-1': {'priority': 'Medium', 'desc': 'Referrer-Policy: strict-origin-when-cross-origin or stricter'},
    'PP-1': {'priority': 'Medium', 'desc': 'Permissions-Policy present (non-empty)'},
    'HEADER-1': {'priority': 'Low', 'desc': 'Clear-Site-Data header present'},
    'HEADER-2': {'priority': 'Medium', 'desc': 'Cross-Origin-Opener-Policy: same-origin'},
    'HEADER-3': {'priority': 'Medium', 'desc': 'Cross-Origin-Embedder-Policy: require-corp'},
    'CORS-1': {'priority': 'Medium', 'desc': 'Restrictive CORS (Access-Control-Allow-Origin ≠ "*")'},
    'WAF-1': {'priority': 'Medium', 'desc': 'WAF presence (e.g., X-WAF/Cloudflare headers)'},
    'REPORT-1': {'priority': 'Low', 'desc': 'Report-To header for security reports'},
    'HEADER-5': {'priority': 'Medium', 'desc': 'Cross-Origin-Resource-Policy: same-site'},
    'HEADER-6': {'priority': 'Low', 'desc': 'Remove Server/X-Powered-By headers'},
    # Authentication & Session Management
    'COO-1': {'priority': 'Low', 'desc': 'Cookies Secure/HttpOnly'},
    'AUTH-1': {'priority': 'High', 'desc': 'Session timeout ≤30 minutes'},
    'AUTH-2': {'priority': 'High', 'desc': 'CSRF tokens on state-changing operations'},
    'AUTH-3': {'priority': 'Medium', 'desc': 'No autocomplete on password fields'},
    'SESSION-1': {'priority': 'Medium', 'desc': 'Session cookie regenerated on login'},
    'SAMESITE-1': {'priority': 'Medium', 'desc': 'Cookies with SameSite=Lax/Strict'},
    'AUTH-4': {'priority': 'High', 'desc': 'Multi-Factor Authentication (MFA) for privileged accounts'},
    'AUTH-5': {'priority': 'High', 'desc': 'Account lockout/exponential backoff on failed logins'},
    'AUTH-6': {'priority': 'Medium', 'desc': 'No username enumeration in login errors'},
    'AUTH-7': {'priority': 'Medium', 'desc': 'Password policy: complexity, rotation, or passkey support'},
    # Input Validation & Sanitization
    'INPUT-1': {'priority': 'High', 'desc': 'SQL injection protection'},
    'INPUT-2': {'priority': 'High', 'desc': 'XSS protection (reflects user input safely)'},
    'INPUT-3': {'priority': 'Medium', 'desc': 'File upload restrictions'},
    'INPUT-4': {'priority': 'Medium', 'desc': 'Path traversal prevention'},
    'INPUT-5': {'priority': 'High', 'desc': 'OS/Command injection protection'},
    'INPUT-6': {'priority': 'High', 'desc': 'LDAP/NoSQL/Template injection protection'},
    'INPUT-7': {'priority': 'High', 'desc': 'SSRF protection'},
    'INPUT-8': {'priority': 'Medium', 'desc': 'File upload malware scanning and execution prevention'},
    'INPUT-9': {'priority': 'Medium', 'desc': 'Deserialization security'},
    # Access Control & Authorization
    'AUTHZ-1': {'priority': 'High', 'desc': 'Access control (vertical privilege escalation)'},
    'AUTHZ-2': {'priority': 'High', 'desc': 'IDOR protection'},
    'AUTHZ-3': {'priority': 'High', 'desc': 'Least privilege and RBAC enforcement'},
    'AUTHZ-4': {'priority': 'High', 'desc': 'Authorization checks on every request'},
    'AUTHZ-5': {'priority': 'High', 'desc': 'IDOR and privilege escalation testing'},
    'AUTHZ-6': {'priority': 'Medium', 'desc': 'Business logic flaw testing'},
    # Security Headers & Browser Policies
    'HEADER-7': {'priority': 'Medium', 'desc': 'Strict CSP (no unsafe-inline/unsafe-eval, all resource types)'},
    # Encryption & Data Protection
    'ENCRYPT-1': {'priority': 'High', 'desc': 'Encryption at rest for sensitive data'},
    'ENCRYPT-2': {'priority': 'Medium', 'desc': 'Secure key management (no hard-coded keys)'},
    # Logging, Monitoring & Incident Response
    'LOG-1': {'priority': 'Low', 'desc': 'Security logging presence'},
    'LOG-2': {'priority': 'High', 'desc': 'Comprehensive logging (auth, data access, admin actions)'},
    'LOG-3': {'priority': 'Medium', 'desc': 'Intrusion detection and anomaly monitoring'},
    'LOG-4': {'priority': 'Medium', 'desc': 'Error handling (no stack traces exposed, logs sanitized)'},
    # Cloud & Infrastructure Security
    'CLOUD-1': {'priority': 'High', 'desc': 'Secure IAM roles and least privilege'},
    'CLOUD-2': {'priority': 'Medium', 'desc': 'Private subnets for databases, encrypted storage'},
    'CLOUD-3': {'priority': 'Medium', 'desc': 'Container/VM security (non-root, patched, scanned)'},
    # Email & DNS Security
    'DNS-1': {'priority': 'Low', 'desc': 'DNSSEC (DS records)'},
    'SPF-1': {'priority': 'Low', 'desc': 'SPF TXT record'},
    'DMARC-1': {'priority': 'Low', 'desc': 'DMARC TXT record exists'},
    'DNS-2': {'priority': 'Low', 'desc': 'CAA record present'},
    'MX-1': {'priority': 'Low', 'desc': 'MX record configuration'},
    'DNS-3': {'priority': 'Medium', 'desc': 'DKIM signing enabled'},
    'DNS-4': {'priority': 'Medium', 'desc': 'DMARC policy set to p=quarantine/reject'},
    # File & Directory Security
    'DIR-1': {'priority': 'Medium', 'desc': 'No directory listing'},
    'ADMIN-1': {'priority': 'Medium', 'desc': 'No exposed common admin paths'},
    'ROBOTS-1': {'priority': 'Low', 'desc': '/robots.txt does not expose sensitive paths'},
    'SEC-1': {'priority': 'Low', 'desc': '/.well-known/security.txt exists'},
    'BACKUP-1': {'priority': 'Medium', 'desc': 'No backup files exposed (.bak, .old, .tmp)'},
    'GIT-1': {'priority': 'High', 'desc': 'No .git directory exposed'},
    'CONFIG-1': {'priority': 'High', 'desc': 'No config files exposed (.env, config.json)'},
    # Information Disclosure
    'SI-1': {'priority': 'Low', 'desc': 'No server info leakage'},
    'TITLE-1': {'priority': 'Low', 'desc': 'Page title not default'},
    'ETag-1': {'priority': 'Low', 'desc': 'ETag not timestamp-based'},
    'ERROR-1': {'priority': 'Medium', 'desc': 'No stack traces in error pages'},
    'HEADER-4': {'priority': 'Low', 'desc': 'No version disclosure in headers'},
    'ERROR-2': {'priority': 'Medium', 'desc': 'Custom error pages (no verbose details)'},
    # Performance & Cache Security
    'Cache-1': {'priority': 'Low', 'desc': 'Cache-Control: no-store on root'},
    'CACHE-2': {'priority': 'Low', 'desc': 'No cache on sensitive pages'},
    # Redirect & Navigation Security
    'REDIR-1': {'priority': 'Medium', 'desc': 'No open redirect vulnerabilities'},
    'REDIR-2': {'priority': 'Medium', 'desc': 'Relative URLs used (not absolute)'},
    # Content & Resource Security
    'SR-1': {'priority': 'Low', 'desc': 'SRI on external scripts'},
    'SRI-2': {'priority': 'Low', 'desc': 'External resources from trusted CDNs'},
    'MIME-1': {'priority': 'Low', 'desc': 'Correct Content-Type headers'},
    'MIXED-1': {'priority': 'Medium', 'desc': 'No mixed active content on HTTPS'},
    'THIRD-1': {'priority': 'Low', 'desc': 'Limited risky third-party scripts'},
    # API & Modern Web Features
    'API-1': {'priority': 'Medium', 'desc': 'Rate limiting on endpoints'},
    'API-2': {'priority': 'Medium', 'desc': 'JSON encoding safe (no XSS)'},
    'HTTP2-1': {'priority': 'Low', 'desc': 'HTTP/2 or HTTP/3 support'},
    # Advanced Security Controls
    # (AUTHZ-1, AUTHZ-2, LOG-1 already above)
    # Compliance & Standards
    'COMP-1': {'priority': 'Low', 'desc': 'Privacy policy accessible'},
    'COMP-2': {'priority': 'Low', 'desc': 'GDPR compliance indicators'},
    'COMP-3': {'priority': 'Low', 'desc': 'Accessibility security (WCAG)'},
    # Subdomain Security
    'SUB-1': {'priority': 'High', 'desc': 'No unmanaged or forgotten subdomains'},
    'SUB-2': {'priority': 'High', 'desc': 'No subdomain takeover risks'},
    # WAF & DDoS Protection
    'WAF-2': {'priority': 'Medium', 'desc': 'WAF actively blocks malicious requests'},
    'DDoS-1': {'priority': 'Medium', 'desc': 'DDoS protection (e.g., Cloudflare, AWS Shield)'},
    # Server & Infrastructure Security
    'SERVER-1': {'priority': 'Medium', 'desc': 'Server software is up-to-date'},
    # Third-Party & Supply Chain Security
    'THIRD-2': {'priority': 'Medium', 'desc': 'Regularly audit third-party libraries for vulnerabilities'},
    'THIRD-3': {'priority': 'Medium', 'desc': 'Subresource Integrity (SRI) for all third-party scripts/styles'},
    # Compliance & Documentation
    'COMP-4': {'priority': 'Medium', 'desc': 'Incident response plan documented and tested'},
    'COMP-5': {'priority': 'Medium', 'desc': 'Software Bill of Materials (SBOM) maintained'},
    'COMP-6': {'priority': 'Low', 'desc': 'Cookie consent banner is present and functional'},
}

CATEGORIES = {
    'Encryption/TLS': {'weight': 25, 'checks': ['TLS-1', 'CERT-1', 'HTTPS-1', 'HSTS-1', 'FS-1', 'WC-1']},
    'Secure Headers': {'weight': 30, 'checks': ['CSP-1', 'XFO-1', 'XCTO-1', 'XXP-1', 'RP-1', 'PP-1']},
    'Configuration Protections': {'weight': 20, 'checks': ['SR-1', 'COO-1', 'HPKP-1', 'ETag-1', 'Cache-1']},
    'Information Disclosure': {'weight': 10, 'checks': ['SI-1']},
    'DNS/Email': {'weight': 15, 'checks': ['DNS-1', 'SPF-1']},
}


def normalize_subdomain(subdomain):
    """Normalize subdomain by stripping whitespace and removing trailing dots."""
    if not subdomain:
        return None
    subdomain = str(subdomain).strip().lower()
    if subdomain.endswith('.'):
        subdomain = subdomain[:-1]
    return subdomain if subdomain else None


def get_www_variants(subdomain):
    """Generate both www and non-www variants of a subdomain.
    
    Returns a list of subdomains to check:
    - If subdomain starts with 'www.', returns [subdomain, subdomain_without_www]
    - If subdomain doesn't start with 'www.', returns [subdomain, www.subdomain]
    """
    if subdomain.startswith('www.'):
        non_www = subdomain[4:]  # Remove 'www.'
        return [subdomain, non_www]
    else:
        www_version = f'www.{subdomain}'
        return [subdomain, www_version]


def load_subdomains_from_file(file_path):
    """Load subdomains from TXT or Excel file."""
    file_path = Path(file_path)
    
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    
    subdomains = []
    
    if file_path.suffix.lower() == '.txt':
        print(f"Reading from TXT file: {file_path}")
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                subdomain = normalize_subdomain(line)
                if subdomain:
                    subdomains.append(subdomain)
    
    elif file_path.suffix.lower() in ['.xlsx', '.xls']:
        print(f"Reading from Excel file: {file_path}")
        df = pd.read_excel(file_path)
        
        if 'Subdomain' not in df.columns:
            raise ValueError(f"Excel file must have a 'Subdomain' column. Found: {list(df.columns)}")
        
        for subdomain in df['Subdomain']:
            normalized = normalize_subdomain(subdomain)
            if normalized:
                subdomains.append(normalized)
    
    else:
        raise ValueError(f"Unsupported file type: {file_path.suffix}. Use .txt or .xlsx")

    unique_subdomains = []
    seen = set()
    for subdomain in subdomains:
        if subdomain not in seen:
            unique_subdomains.append(subdomain)
            seen.add(subdomain)
    
    print(f"Loaded {len(unique_subdomains)} unique subdomains")
    if len(subdomains) > len(unique_subdomains):
        print(f"  (removed {len(subdomains) - len(unique_subdomains)} duplicates)")
    
    return unique_subdomains


def check_https_redirect(subdomain):
    """Check if HTTP redirects to HTTPS (301/302)."""
    try:
        resp_http = requests.get(f'http://{subdomain}', timeout=10, allow_redirects=False, verify=False)
        location = resp_http.headers.get('location', '').lower()
        if resp_http.status_code in [301, 302, 307, 308] and location.startswith('https://'):
            return True
        return False
    except Exception:
        return False


def check_hsts(hsts_header):
    """Check HSTS for max-age >=31536000 and includeSubDomains."""
    if not hsts_header:
        return False
    max_age_match = re.search(r'max-age=(\d+)', str(hsts_header), re.I)
    include_match = 'includesubdomains' in str(hsts_header).lower()
    if max_age_match and int(max_age_match.group(1)) >= 31536000 and include_match:
        return True
    return False


def check_csp(csp_header):
    """Check if CSP is present and non-empty."""
    if not csp_header or not str(csp_header).strip():
        return False
    return True


def check_xfo(xfo_header):
    """X-Frame-Options: DENY or SAMEORIGIN."""
    if not xfo_header:
        return False
    return str(xfo_header).upper() in ['DENY', 'SAMEORIGIN']


def check_xcto(xcto_header):
    """X-Content-Type-Options: nosniff."""
    if not xcto_header:
        return False
    return str(xcto_header).lower() == 'nosniff'


def check_xxp(xxp_header):
    """X-XSS-Protection: 1; mode=block."""
    if not xxp_header:
        return False
    xxp_str = str(xxp_header)
    return '1' in xxp_str and 'mode=block' in xxp_str.lower()


def check_rp(rp_header):
    """Check Referrer-Policy for strict policies."""
    if not rp_header:
        return False
    strict_policies = ['strict-origin-when-cross-origin', 'strict-origin', 'no-referrer', 'same-origin']
    return any(policy in str(rp_header).lower() for policy in strict_policies)


def check_pp(pp_header):
    """Check if Permissions-Policy is present and non-empty."""
    return bool(pp_header and str(pp_header).strip())


def check_cookies_secure_httponly(response):
    """Check if all cookies have Secure and HttpOnly flags."""
    cookies = response.cookies
    if not cookies:
        return True
    
    set_cookie_headers = response.headers.get('Set-Cookie', '')
    if not set_cookie_headers:
        return True
    
    cookie_list = [set_cookie_headers] if isinstance(set_cookie_headers, str) else set_cookie_headers
    
    for cookie_header in cookie_list:
        cookie_lower = cookie_header.lower()
        if 'secure' not in cookie_lower or 'httponly' not in cookie_lower:
            return False
    return True


def check_si(server_header):
    """Check if Server header leaks version information."""
    if not server_header:
        return True
    return '/' not in str(server_header)


def check_spf(subdomain):
    """SPF TXT record present."""
    try:
        parts = subdomain.split('.')
        domain = '.'.join(parts[-2:]) if len(parts) >= 2 else subdomain
        
        txt_records = dns.resolver.resolve(domain, 'TXT')
        for txt in txt_records:
            txt_string = str(txt).strip('"')
            if txt_string.startswith('v=spf1'):
                return True
        return False
    except DNSException:
        return False


def check_dnssec(subdomain):
    """Check if DNSSEC is enabled (DS records present)."""
    try:
        parts = subdomain.split('.')
        domain = '.'.join(parts[-2:]) if len(parts) >= 2 else subdomain
        
        ds_records = dns.resolver.resolve(domain, 'DS')
        return bool(ds_records)
    except DNSException:
        return False


def check_hpkp(hpkp_header):
    """Check HPKP is absent (deprecated, should not be present)."""
    return not hpkp_header


def check_etag(etag_header):
    """Check if ETag is not weak or timestamp-based."""
    if not etag_header:
        return True
    etag_str = str(etag_header)
    if etag_str.startswith('W/'):
        return False
    return not re.search(r'\d{10,}', etag_str)


def check_cache(cache_header):
    """Cache-Control: no-store present."""
    if not cache_header:
        return False
    return 'no-store' in str(cache_header).lower()


def check_sri(resp_text):
    """Check if external scripts have integrity attribute."""
    try:
        soup = BeautifulSoup(resp_text, 'html.parser')
        scripts = soup.find_all('script', src=True)
        
        for script in scripts:
            src = script.get('src', '')
            if (src.startswith('http') or src.startswith('//')) and script.get('integrity'):
                return True
        return False
    except Exception:
        return False


def scan_headers_and_config(subdomain):
    """Manual header and config checks."""
    all_results = {}
    success = False
    
    try:
        resp = requests.get(f'https://{subdomain}', timeout=10, verify=False, allow_redirects=True)
        headers = resp.headers
        html = resp.text
        success = (resp.status_code == 200)
        
        all_results['HTTPS-1'] = check_https_redirect(subdomain)
        all_results['CSP-1'] = check_csp(headers.get('Content-Security-Policy'))
        all_results['XFO-1'] = check_xfo(headers.get('X-Frame-Options'))
        all_results['XCTO-1'] = check_xcto(headers.get('X-Content-Type-Options'))
        all_results['XXP-1'] = check_xxp(headers.get('X-XSS-Protection'))
        all_results['RP-1'] = check_rp(headers.get('Referrer-Policy'))
        all_results['PP-1'] = check_pp(headers.get('Permissions-Policy'))
        all_results['COO-1'] = check_cookies_secure_httponly(resp)
        all_results['SI-1'] = check_si(headers.get('Server'))
        all_results['HPKP-1'] = check_hpkp(headers.get('Public-Key-Pins'))
        all_results['ETag-1'] = check_etag(headers.get('ETag'))
        all_results['Cache-1'] = check_cache(headers.get('Cache-Control'))
        all_results['SR-1'] = check_sri(html)
        
        return all_results, success
        
    except Exception:
        return {
            'HTTPS-1': False, 'CSP-1': False, 'XFO-1': False, 'XCTO-1': False,
            'XXP-1': False, 'RP-1': False, 'PP-1': False, 'COO-1': False,
            'SI-1': False, 'HPKP-1': True, 'ETag-1': True, 'Cache-1': False,
            'SR-1': False
        }, False


def scan_tls_and_dns(subdomain):
    """TLS via sslyze, DNS via dnspython."""
    tls_results = {}
    dns_results = {}
    
    # DNS checks
    dns_results['DNS-1'] = check_dnssec(subdomain)
    dns_results['SPF-1'] = check_spf(subdomain)
    
    # TLS checks with sslyze
    try:
        server_location = ServerNetworkLocation(hostname=subdomain, port=443)
        
        try:
            server_info = ServerConnectivityTester().perform(server_location)
        except ConnectionToServerFailed:
            tls_results['TLS-1'] = False
            tls_results['CERT-1'] = False
            tls_results['HSTS-1'] = False
            tls_results['FS-1'] = False
            tls_results['WC-1'] = False
            return tls_results, dns_results
        
        scan_request = ServerScanRequest(
            server_info=server_info,
            scan_commands={
                ScanCommand.CERTIFICATE_INFO,
                ScanCommand.TLS_1_2_CIPHER_SUITES,
                ScanCommand.TLS_1_3_CIPHER_SUITES,
                ScanCommand.HTTP_HEADERS,
            }
        )
        
        scanner = Scanner()
        scanner.queue_scans([scan_request])
        
        for server_scan_result in scanner.get_results():
            scan_result = server_scan_result.scan_result
            
            # CERT-1: Valid certificate chain
            if scan_result.certificate_info.status.name == 'COMPLETED':
                cert_result = scan_result.certificate_info.result
                if cert_result.certificate_deployments:
                    cert_deployment = cert_result.certificate_deployments[0]
                    received_chain = cert_deployment.received_certificate_chain
                    
                    if received_chain:
                        leaf_cert = received_chain[0]
                        now = datetime.utcnow()
                        
                        valid_dates = (leaf_cert.not_valid_before_utc <= now <= leaf_cert.not_valid_after_utc)
                        path_validation_results = cert_deployment.path_validation_results
                        is_trusted = any(result.was_validation_successful for result in path_validation_results)
                        
                        tls_results['CERT-1'] = valid_dates and is_trusted
                    else:
                        tls_results['CERT-1'] = False
                else:
                    tls_results['CERT-1'] = False
            else:
                tls_results['CERT-1'] = False
            
            # TLS-1: TLS 1.2+ enforced
            tls12_result = scan_result.tls_1_2_cipher_suites
            tls13_result = scan_result.tls_1_3_cipher_suites
            
            has_tls12 = (tls12_result.status.name == 'COMPLETED' and 
                        len(tls12_result.result.accepted_cipher_suites) > 0)
            has_tls13 = (tls13_result.status.name == 'COMPLETED' and 
                        len(tls13_result.result.accepted_cipher_suites) > 0)
            
            tls_results['TLS-1'] = has_tls12 or has_tls13
            
            # FS-1: Forward secrecy
            tls_results['FS-1'] = False
            for suite_result in [tls12_result, tls13_result]:
                if suite_result.status.name == 'COMPLETED':
                    for accepted_suite in suite_result.result.accepted_cipher_suites:
                        if 'ECDHE' in accepted_suite.cipher_suite.name or 'DHE' in accepted_suite.cipher_suite.name:
                            tls_results['FS-1'] = True
                            break
                if tls_results['FS-1']:
                    break
            
            # WC-1: No weak ciphers
            weak_patterns = ['RC4', '3DES', 'NULL', 'EXPORT', 'DES', 'MD5']
            tls_results['WC-1'] = True
            for suite_result in [tls12_result, tls13_result]:
                if suite_result.status.name == 'COMPLETED':
                    for accepted_suite in suite_result.result.accepted_cipher_suites:
                        if any(weak in accepted_suite.cipher_suite.name.upper() for weak in weak_patterns):
                            tls_results['WC-1'] = False
                            break
                if not tls_results['WC-1']:
                    break
            
            # HSTS-1: From HTTP headers
            if scan_result.http_headers.status.name == 'COMPLETED':
                hsts_header = scan_result.http_headers.result.strict_transport_security_header
                if hsts_header:
                    tls_results['HSTS-1'] = check_hsts(hsts_header.max_age)
                else:
                    tls_results['HSTS-1'] = False
            else:
                tls_results['HSTS-1'] = False
                
    except Exception:
        if 'TLS-1' not in tls_results:
            tls_results['TLS-1'] = False
        if 'CERT-1' not in tls_results:
            tls_results['CERT-1'] = False
        if 'HSTS-1' not in tls_results:
            tls_results['HSTS-1'] = False
        if 'FS-1' not in tls_results:
            tls_results['FS-1'] = False
        if 'WC-1' not in tls_results:
            tls_results['WC-1'] = False
    
    return tls_results, dns_results


def compute_scores(all_checks):
    """Compute category and total scores."""
    scores = {}
    total_score = 0
    
    for cat, info in CATEGORIES.items():
        cat_checks = [all_checks.get(check, False) for check in info['checks']]
        if len(cat_checks) > 0:
            cat_score = (sum(cat_checks) / len(cat_checks)) * info['weight']
        else:
            cat_score = 0
        scores[cat] = round(cat_score, 2)
        total_score += cat_score
    
    return scores, round(total_score, 2)


def main():
    parser = argparse.ArgumentParser(
        description='Comprehensive Subdomain Security Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Auto-enumerate subdomains and scan (NEW!)
  python security_scanner.py --domain example.com
  
  # Use existing subdomain file
  python security_scanner.py --file oeducat.org_active.txt
  python security_scanner.py --file domain_list.xlsx
  
  # Interactive mode
  python security_scanner.py

Output:
  website_ranking.xlsx - Comprehensive security assessment with scores
        """
    )
    parser.add_argument(
        '--domain', '-d', help='Domain to enumerate and scan (e.g., example.com)')
    parser.add_argument(
        '--file', '-f', help='Input file with subdomains (TXT or XLSX)')
    parser.add_argument('--output', '-o', default='website_ranking.xlsx', help='Output Excel file')
    
    args = parser.parse_args()
    
    print("=" * 80)
    print("Comprehensive Subdomain Security Scanner")
    print("=" * 80)
    print()

    # Determine input method: --domain, --file, or interactive
    subdomains = None

    if args.domain and args.file:
        print("❌ Error: Please specify either --domain OR --file, not both")
        return

    if args.domain:
        # AUTO-ENUMERATE MODE
        print(f"Mode: Auto-enumeration for domain '{args.domain}'")
        subdomains = enumerate_subdomains(args.domain)

        if not subdomains:
            print("\n❌ No active subdomains found!")
            return

    elif args.file:
        # FILE MODE
        input_file = args.file
        print(f"Mode: Loading from file '{input_file}'")
        try:
            subdomains = load_subdomains_from_file(input_file)
        except Exception as e:
            print(f"\n❌ Error loading file: {e}")
            return
    else:
        # INTERACTIVE MODE
        print("Mode: Interactive")
        print("\nNo input specified. Available files:")
        txt_files = list(Path('.').glob('*_active.txt'))
        xlsx_files = list(Path('.').glob('*.xlsx'))
        
        all_files = txt_files + xlsx_files
        if all_files:
            for i, f in enumerate(all_files, 1):
                print(f"  {i}. {f.name}")
            print()
            choice = input("Enter file number, path, or domain name: ").strip()
            
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(all_files):
                    input_file = str(all_files[idx])
                    try:
                        subdomains = load_subdomains_from_file(input_file)
                    except Exception as e:
                        print(f"\n❌ Error loading file: {e}")
                        return
                else:
                    print("Invalid choice!")
                    return
            except ValueError:
                # Check if it looks like a domain name (no path separators, no extension)
                if '/' not in choice and '.' in choice and not choice.endswith(('.txt', '.xlsx', '.xls')):
                    print(f"\nTreating '{choice}' as domain name...")
                    subdomains = enumerate_subdomains(choice)
                    if not subdomains:
                        print("\n❌ No active subdomains found!")
                        return
                else:
                    # Treat as file path
                    try:
                        subdomains = load_subdomains_from_file(choice)
                    except Exception as e:
                        print(f"\n❌ Error loading file: {e}")
                        return
        else:
            user_input = input("Enter file path or domain name: ").strip()

            # Check if it looks like a domain name
            if '/' not in user_input and '.' in user_input and not user_input.endswith(('.txt', '.xlsx', '.xls')):
                print(f"\nTreating '{user_input}' as domain name...")
                subdomains = enumerate_subdomains(user_input)
                if not subdomains:
                    print("\n❌ No active subdomains found!")
                    return
            else:
                try:
                    subdomains = load_subdomains_from_file(user_input)
                except Exception as e:
                    print(f"\n❌ Error loading file: {e}")
                    return
    
    if not subdomains:
        print("\n❌ No subdomains found!")
        return
    
    print(f"\nStarting security scan of {len(subdomains)} subdomains...")
    print(f"Note: Both www and non-www variants will be checked for each subdomain")
    print(
        f"Estimated time: ~{len(subdomains) * 2 * 3 / 60:.1f} minutes (with 3s rate limit)")
    print()
    
    results_list = []
    scanned_count = 0
    total_to_scan = len(subdomains) * 2  # Each subdomain has 2 variants
    
    for subdomain in tqdm(subdomains, desc="Scanning"):
        variants = get_www_variants(subdomain)

        for variant in variants:
            scanned_count += 1
            print(f"\n[{scanned_count}/{total_to_scan}] {variant}")
            sub_type = classify_subdomain(variant)
            print(f"  Detected type: {sub_type}")
            relevant_checks = TYPE_CHECKS.get(sub_type, TYPE_CHECKS['other'])
            all_checks = {}
            success = False

            # Run only relevant checks
            if 'HTTPS-1' in relevant_checks or 'CSP-1' in relevant_checks:
                try:
                    header_results, success = scan_headers_and_config(variant)
                    for k in header_results:
                        if k in relevant_checks:
                            all_checks[k] = header_results[k]
                except Exception:
                    pass
            if any(x in relevant_checks for x in ['TLS-1', 'CERT-1', 'FS-1', 'WC-1', 'HSTS-1']):
                try:
                    tls_results, dns_results = scan_tls_and_dns(variant)
                    for k in tls_results:
                        if k in relevant_checks:
                            all_checks[k] = tls_results[k]
                except Exception:
                    pass
            if any(x in relevant_checks for x in ['DNS-1', 'SPF-1']):
                try:
                    _, dns_results = scan_tls_and_dns(variant)
                    for k in dns_results:
                        if k in relevant_checks:
                            all_checks[k] = dns_results[k]
                except Exception:
                    pass
            # Mark missing relevant checks as False
            for check in relevant_checks:
                if check not in all_checks:
                    all_checks[check] = False

            # Compute context-aware score
            score = 0
            total_weight = 0
            for check in relevant_checks:
                weight = CHECKS[check]['weight'] if 'weight' in CHECKS[check] else 1
                total_weight += weight if weight else 1
                if all_checks[check]:
                    score += weight if weight else 1
            final_score = round((score / total_weight) * 100,
                                2) if total_weight else 0

            print(f"  Score: {final_score}/100 | Type: {sub_type}")

            # Build result row
            result_row = {
                'Subdomain': variant,
                'Type': sub_type,
                'Scan_Success': success,
                'Total_Score': final_score,
            }
            for check_id in relevant_checks:
                result_row[f"{check_id}_Pass"] = 'Yes' if all_checks[check_id] else 'No'
            results_list.append(result_row)
            time.sleep(3)
    
    print("\n" + "=" * 80)
    print("Processing results...")
    print("=" * 80)

    df_results = pd.DataFrame(results_list)

    summary_rows = []
    for sub_type in df_results['Type'].unique():
        group = df_results[df_results['Type'] == sub_type]
        summary_rows.append({
            'Type': sub_type,
            'Count': len(group),
            'Avg_Score': round(group['Total_Score'].mean(), 2),
            'Median_Score': round(group['Total_Score'].median(), 2),
            'Max_Score': round(group['Total_Score'].max(), 2),
            'Min_Score': round(group['Total_Score'].min(), 2)
        })
    df_summary = pd.DataFrame(summary_rows)

    all_cols = ['Subdomain', 'Type', 'Scan_Success', 'Total_Score']
    check_cols = sorted(
        {col for row in results_list for col in row if col.endswith('_Pass')})
    all_cols += check_cols
    df_results = df_results[all_cols]

    output_path = Path(args.output)
    try:
        with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
            df_results.to_excel(
                writer, sheet_name='Security Results', index=False)
            df_summary.to_excel(
                writer, sheet_name='Summary By Type', index=False)

            checklist_data = []
            for check_id, info in sorted(CHECKS.items()):
                checklist_data.append({
                    'Control_ID': check_id,
                    'Priority': info['priority'],
                    'Description': info['desc']
                })
            checklist_df = pd.DataFrame(checklist_data)
            checklist_df.to_excel(writer, sheet_name='Checklist', index=False)
        print(f"\n✅ Results saved to: {output_path}")
        print()
        print("Summary By Type:")
        print(df_summary.to_string(index=False))
        print()
    except Exception as e:
        print(f"❌ Error writing Excel: {e}")
        csv_output = output_path.with_suffix('.csv')
        df_results.to_csv(csv_output, index=False)
        print(f"Results saved to CSV instead: {csv_output}")


if __name__ == "__main__":
    main()
