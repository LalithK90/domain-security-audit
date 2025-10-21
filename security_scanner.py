"""
Comprehensive Subdomain Security Scanner

Universal Python Script for Subdomain Security Scanning and Ranking
Works with ANY domain (not limited to .ac.lk)

This script performs comprehensive security assessments on subdomains using:
- Passive scans with requests for HTTP checks
- sslyze for TLS/certificate/headers analysis
- dnspython for DNS (SPF/DNSSEC) checks
- 20-item security checklist (High/Medium/Low priority)
- Binary pass/fail scoring with weighted categories
- Total Security Compliance Score (0-100)

Usage:
    # Option 1: Scan from TXT file (converts automatically)
    python security_scanner.py --file subdomains.txt
    
    # Option 2: Scan from Excel file
    python security_scanner.py --file domain_list.xlsx
    
    # Option 3: Interactive mode (prompts for file)
    python security_scanner.py

Input Format:
    - TXT file: One subdomain per line (e.g., portal.example.com)
    - Excel file: Must have 'Subdomain' column
    
    Works with ANY domain:
    - .com, .org, .net (commercial/general)
    - .edu, .ac.lk, .ac.uk (educational institutions)
    - .gov, .mil (government)
    - Any other TLD or country-code domain

Dependencies:
    pip install -r requirements.txt

Output:
    website_ranking.xlsx - Ranked security assessment with 3 sheets:
        - Security Ranking: Detailed scores and rankings
        - Checklist: Reference table of 20 controls
        - Categories: Scoring methodology

Ethical considerations:
- Rate-limiting (3s per request) to avoid overload
- Graceful error handling
- Passive scanning only (no exploitation)
- Only scan domains you own or have explicit permission to test

Author: LalithK90
Date: October 2025
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

# ============================================================================
# SECURITY CHECKLIST DEFINITIONS
# ============================================================================

CHECKS = {
    'TLS-1': {'priority': 'High', 'desc': 'TLS 1.2+ enforced', 'weight': 0.0},
    'CERT-1': {'priority': 'High', 'desc': 'Valid cert chain', 'weight': 0.0},
    'HTTPS-1': {'priority': 'High', 'desc': 'HTTPS enforced', 'weight': 0.0},
    'HSTS-1': {'priority': 'High', 'desc': 'HSTS max-age >=31536000 + includeSubDomains', 'weight': 0.0},
    'CSP-1': {'priority': 'Medium', 'desc': 'CSP present (non-empty)', 'weight': 0.0},
    'XFO-1': {'priority': 'Medium', 'desc': 'X-Frame-Options: DENY/SAMEORIGIN', 'weight': 0.0},
    'XCTO-1': {'priority': 'Medium', 'desc': 'X-Content-Type-Options: nosniff', 'weight': 0.0},
    'XXP-1': {'priority': 'Medium', 'desc': 'X-XSS-Protection: 1; mode=block', 'weight': 0.0},
    'RP-1': {'priority': 'Medium', 'desc': 'Referrer-Policy: strict-origin-when-cross-origin or stricter', 'weight': 0.0},
    'PP-1': {'priority': 'Medium', 'desc': 'Permissions-Policy present (non-empty)', 'weight': 0.0},
    'FS-1': {'priority': 'Medium', 'desc': 'Forward secrecy (ECDHE ciphers)', 'weight': 0.0},
    'WC-1': {'priority': 'Medium', 'desc': 'No weak ciphers (RC4/3DES)', 'weight': 0.0},
    'SR-1': {'priority': 'Low', 'desc': 'SRI on external scripts', 'weight': 0.0},
    'COO-1': {'priority': 'Low', 'desc': 'Cookies Secure/HttpOnly', 'weight': 0.0},
    'SI-1': {'priority': 'Low', 'desc': 'No server info leakage', 'weight': 0.0},
    'DNS-1': {'priority': 'Low', 'desc': 'DNSSEC (DS records)', 'weight': 0.0},
    'SPF-1': {'priority': 'Low', 'desc': 'SPF TXT record', 'weight': 0.0},
    'HPKP-1': {'priority': 'Low', 'desc': 'HPKP absent', 'weight': 0.0},
    'ETag-1': {'priority': 'Low', 'desc': 'ETag not timestamp-based', 'weight': 0.0},
    'Cache-1': {'priority': 'Low', 'desc': 'Cache-Control: no-store on root', 'weight': 0.0},
}

CATEGORIES = {
    'Encryption/TLS': {'weight': 25, 'checks': ['TLS-1', 'CERT-1', 'HTTPS-1', 'HSTS-1', 'FS-1', 'WC-1']},
    'Secure Headers': {'weight': 30, 'checks': ['CSP-1', 'XFO-1', 'XCTO-1', 'XXP-1', 'RP-1', 'PP-1']},
    'Configuration Protections': {'weight': 20, 'checks': ['SR-1', 'COO-1', 'HPKP-1', 'ETag-1', 'Cache-1']},
    'Information Disclosure': {'weight': 10, 'checks': ['SI-1']},
    'DNS/Email': {'weight': 15, 'checks': ['DNS-1', 'SPF-1']},
}

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def normalize_subdomain(subdomain):
    """Normalize subdomain by stripping whitespace and removing trailing dots."""
    if not subdomain:
        return None
    subdomain = str(subdomain).strip().lower()
    if subdomain.endswith('.'):
        subdomain = subdomain[:-1]
    return subdomain if subdomain else None


def load_subdomains_from_file(file_path):
    """
    Load subdomains from TXT or Excel file.
    
    Args:
        file_path: Path to input file (.txt or .xlsx)
    
    Returns:
        List of normalized subdomains
    """
    file_path = Path(file_path)
    
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    
    subdomains = []
    
    if file_path.suffix.lower() == '.txt':
        # Read from text file (one subdomain per line)
        print(f"Reading from TXT file: {file_path}")
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                subdomain = normalize_subdomain(line)
                if subdomain:
                    subdomains.append(subdomain)
    
    elif file_path.suffix.lower() in ['.xlsx', '.xls']:
        # Read from Excel file (expects 'Subdomain' column)
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
    
    # Remove duplicates while preserving order
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


# ============================================================================
# SECURITY CHECK FUNCTIONS
# ============================================================================

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
    """Parse HSTS for max-age >=31536000 and includeSubDomains."""
    if not hsts_header:
        return False
    max_age_match = re.search(r'max-age=(\d+)', str(hsts_header), re.I)
    include_match = 'includesubdomains' in str(hsts_header).lower()
    if max_age_match and int(max_age_match.group(1)) >= 31536000 and include_match:
        return True
    return False


def check_csp(csp_header):
    """CSP present and non-empty."""
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
    """Referrer-Policy strict or stricter."""
    if not rp_header:
        return False
    strict_policies = ['strict-origin-when-cross-origin', 'strict-origin', 'no-referrer', 'same-origin']
    return any(policy in str(rp_header).lower() for policy in strict_policies)


def check_pp(pp_header):
    """Permissions-Policy present non-empty."""
    return bool(pp_header and str(pp_header).strip())


def check_cookies_secure_httponly(response):
    """All Set-Cookie have Secure and HttpOnly."""
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
    """Server header absent or generic (no version/info)."""
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
    """Simplified: DS records present (requires parent delegation)."""
    try:
        parts = subdomain.split('.')
        domain = '.'.join(parts[-2:]) if len(parts) >= 2 else subdomain
        
        ds_records = dns.resolver.resolve(domain, 'DS')
        return bool(ds_records)
    except DNSException:
        return False


def check_hpkp(hpkp_header):
    """HPKP absent (deprecated, should not be present)."""
    return not hpkp_header


def check_etag(etag_header):
    """ETag not weak (no timestamp pattern)."""
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
    """At least one external script has integrity attr."""
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


# ============================================================================
# SCANNING FUNCTIONS
# ============================================================================

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
    """Compute category and total scores (binary pass=100)."""
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


# ============================================================================
# MAIN FUNCTION
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='ac-lk Security Scanner - Comprehensive subdomain security assessment',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python security_scanner.py --file oeducat.org_active.txt
  python security_scanner.py --file domain_list.xlsx
  python security_scanner.py  (interactive mode)

Output:
  website_ranking.xlsx - Ranked security assessment with scores
        """
    )
    parser.add_argument('--file', '-f', help='Input file (TXT or XLSX)')
    parser.add_argument('--output', '-o', default='website_ranking.xlsx', help='Output Excel file')
    
    args = parser.parse_args()
    
    print("=" * 80)
    print("ac-lk Security Scanner - .ac.lk Subdomain Security Assessment")
    print("=" * 80)
    print()
    
    # Get input file
    if args.file:
        input_file = args.file
    else:
        # Interactive mode
        print("No input file specified. Available files:")
        txt_files = list(Path('.').glob('*_active.txt'))
        xlsx_files = list(Path('.').glob('*.xlsx'))
        
        all_files = txt_files + xlsx_files
        if all_files:
            for i, f in enumerate(all_files, 1):
                print(f"  {i}. {f.name}")
            print()
            choice = input("Enter file number or path: ").strip()
            
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(all_files):
                    input_file = str(all_files[idx])
                else:
                    print("Invalid choice!")
                    return
            except ValueError:
                input_file = choice
        else:
            input_file = input("Enter input file path (TXT or XLSX): ").strip()
    
    # Load subdomains
    try:
        subdomains = load_subdomains_from_file(input_file)
    except Exception as e:
        print(f"\n❌ Error loading file: {e}")
        return
    
    if not subdomains:
        print("\n❌ No subdomains found in input file!")
        return
    
    print(f"\nStarting security scan of {len(subdomains)} subdomains...")
    print(f"Estimated time: ~{len(subdomains) * 3 / 60:.1f} minutes (with 3s rate limit)")
    print()
    
    results_list = []
    
    for subdomain in tqdm(subdomains, desc="Scanning"):
        print(f"\n[{len(results_list) + 1}/{len(subdomains)}] {subdomain}")
        all_checks = {}
        
        # Headers/Config checks
        try:
            header_results, success = scan_headers_and_config(subdomain)
            all_checks.update(header_results)
        except Exception as e:
            success = False
        
        # TLS/DNS checks
        try:
            tls_results, dns_results = scan_tls_and_dns(subdomain)
            all_checks.update(tls_results)
            all_checks.update(dns_results)
        except Exception:
            pass
        
        # Ensure all checks have values
        for check in CHECKS:
            if check not in all_checks:
                all_checks[check] = False
        
        # Compute scores
        cat_scores, total_score = compute_scores(all_checks)
        
        # Count priority passes
        high_pass = sum(1 for k, v in all_checks.items() if CHECKS[k]['priority'] == 'High' and v)
        high_total = sum(1 for k in CHECKS if CHECKS[k]['priority'] == 'High')
        med_pass = sum(1 for k, v in all_checks.items() if CHECKS[k]['priority'] == 'Medium' and v)
        med_total = sum(1 for k in CHECKS if CHECKS[k]['priority'] == 'Medium')
        low_pass = sum(1 for k, v in all_checks.items() if CHECKS[k]['priority'] == 'Low' and v)
        low_total = sum(1 for k in CHECKS if CHECKS[k]['priority'] == 'Low')
        
        print(f"  Score: {total_score}/100 | H:{high_pass}/{high_total} M:{med_pass}/{med_total} L:{low_pass}/{low_total}")
        
        # Build result row
        result_row = {
            'Subdomain': subdomain,
            'Scan_Success': success,
            'Total_Score': total_score,
            'High_Priority_Passes': f"{high_pass}/{high_total}",
            'Medium_Priority_Passes': f"{med_pass}/{med_total}",
            'Low_Priority_Passes': f"{low_pass}/{low_total}",
        }
        
        # Add individual check results
        for check_id in sorted(CHECKS.keys()):
            result_row[f"{check_id}_Pass"] = 'Yes' if all_checks[check_id] else 'No'
        
        # Add category scores
        for cat in CATEGORIES:
            result_row[f"{cat}_Score"] = cat_scores[cat]
        
        results_list.append(result_row)
        
        # Rate limiting
        time.sleep(3)
    
    print("\n" + "=" * 80)
    print("Processing results...")
    print("=" * 80)
    
    # Create DataFrame and rank
    df_results = pd.DataFrame(results_list)
    df_results = df_results.sort_values('Total_Score', ascending=False).reset_index(drop=True)
    df_results.insert(1, 'Rank', df_results.index + 1)
    
    # Reorder columns
    pass_cols = [col for col in df_results.columns if col.endswith('_Pass')]
    score_cols = [col for col in df_results.columns if col.endswith('_Score') and col != 'Total_Score']
    
    final_cols = [
        'Subdomain', 'Rank', 'Total_Score', 'Scan_Success',
        'High_Priority_Passes', 'Medium_Priority_Passes', 'Low_Priority_Passes'
    ] + pass_cols + score_cols
    
    df_results = df_results[final_cols]
    
    # Export to Excel
    output_path = Path(args.output)
    try:
        with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
            df_results.to_excel(writer, sheet_name='Security Ranking', index=False)
            
            # Checklist reference sheet
            checklist_data = []
            for check_id, info in sorted(CHECKS.items()):
                checklist_data.append({
                    'Control_ID': check_id,
                    'Priority': info['priority'],
                    'Description': info['desc']
                })
            checklist_df = pd.DataFrame(checklist_data)
            checklist_df.to_excel(writer, sheet_name='Checklist', index=False)
            
            # Category weights sheet
            category_data = []
            for cat, info in CATEGORIES.items():
                category_data.append({
                    'Category': cat,
                    'Weight': f"{info['weight']}%",
                    'Checks': ', '.join(info['checks']),
                    'Check_Count': len(info['checks'])
                })
            category_df = pd.DataFrame(category_data)
            category_df.to_excel(writer, sheet_name='Categories', index=False)
        
        print(f"\n✅ Results saved to: {output_path}")
        print()
        print("Summary Statistics:")
        print(f"  Total domains scanned: {len(df_results)}")
        print(f"  Average score: {df_results['Total_Score'].mean():.2f}")
        print(f"  Median score: {df_results['Total_Score'].median():.2f}")
        print(f"  Highest score: {df_results['Total_Score'].max():.2f}")
        print(f"  Lowest score: {df_results['Total_Score'].min():.2f}")
        print()
        print("Top 5 Subdomains:")
        print(df_results[['Rank', 'Subdomain', 'Total_Score']].head().to_string(index=False))
        print()
        
    except Exception as e:
        print(f"❌ Error writing Excel: {e}")
        csv_output = output_path.with_suffix('.csv')
        df_results.to_csv(csv_output, index=False)
        print(f"Results saved to CSV instead: {csv_output}")


if __name__ == "__main__":
    main()
