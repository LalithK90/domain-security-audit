"""
build_security_checklist.py

Reads an existing <domain>_audit.csv (the output from subdomain_audit.py) and
builds a comprehensive security assessment Excel file with columns matching the
checklist you provided. The script will attempt to populate DNS and network
fields using `dig` and `whois` (both must be available on the system). For
fields that require deeper analysis (TLS cipher suites, open ports, WAF
fingerprinting) the script leaves placeholders so they can be filled manually
or by a more advanced scanner.

Usage:
  python build_security_checklist.py oeducat.org_audit.csv

Outputs:
  oeducat.org_security_checklist.xlsx

Notes:
- This script calls `dig` and `whois` via subprocess. Ensure those are present.
- The script is conservative and catches subprocess errors so it won't stop on
  missing commands; missing values will be left blank.
"""

import sys
import csv
import subprocess
import shlex
import os
import pandas as pd
import re
from typing import List


def run_cmd(cmd: List[str]) -> str:
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=15)
        return out.decode(errors='ignore').strip()
    except Exception:
        return ""


def dig_short(qtype: str, name: str) -> List[str]:
    # use: dig +short TYPE name
    cmd = ["dig", "+short", qtype, name]
    out = run_cmd(cmd)
    if not out:
        return []
    return [line.strip().strip('"') for line in out.splitlines() if line.strip()]


def reverse_ptr(ip: str) -> str:
    cmd = ["dig", "-x", ip, "+short"]
    out = run_cmd(cmd)
    return out.splitlines()[0].strip('.') if out else ""


def whois_domain(domain: str) -> dict:
    txt = run_cmd(["whois", domain])
    info = {"registrar": "", "creation_date": "", "expiration_date": "", "whois_raw": txt}
    if not txt:
        return info
    # common patterns
    reg = re.search(r"Registrar:\s*(.+)", txt, re.I)
    if reg:
        info["registrar"] = reg.group(1).strip()
    cd = re.search(r"Creation Date:\s*(.+)", txt, re.I)
    if cd:
        info["creation_date"] = cd.group(1).strip()
    ed = re.search(r"Expiration Date:\s*(.+)\n", txt, re.I)
    if ed:
        info["expiration_date"] = ed.group(1).strip()
    # fallback patterns
    cd2 = re.search(r"Created On:\s*(.+)", txt, re.I)
    if cd2 and not info["creation_date"]:
        info["creation_date"] = cd2.group(1).strip()
    return info


def whois_ip(ip: str) -> dict:
    txt = run_cmd(["whois", ip])
    info = {"asn": "", "org": "", "whois_raw": txt}
    if not txt:
        return info
    asn = re.search(r"OriginAS:\s*(AS\d+)", txt, re.I) or re.search(r"origin:\s*(AS\d+)", txt, re.I)
    if asn:
        info["asn"] = asn.group(1)
    org = re.search(r"OrgName:\s*(.+)", txt, re.I) or re.search(r"netname:\s*(.+)", txt, re.I)
    if org:
        info["org"] = org.group(1).strip()
    return info


def detect_cdn_or_waf(headers: str, tech_field: str) -> str:
    s = (headers or "") + " " + (tech_field or "")
    s = s.lower()
    if "cloudflare" in s:
        return "Cloudflare"
    if "akamai" in s:
        return "Akamai"
    if "fastly" in s:
        return "Fastly"
    if "cloudfront" in s or "amazon" in s:
        return "AWS CloudFront"
    return ""


def main():
    if len(sys.argv) < 2:
        print("Usage: python build_security_checklist.py <audit_csv_file>")
        sys.exit(1)

    audit_csv = sys.argv[1]
    base = os.path.basename(audit_csv).replace('_audit.csv', '')
    out_xlsx = f"{base}_security_checklist.xlsx"

    rows = []
    with open(audit_csv, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for r in reader:
            host = r.get('host')
            ips_field = r.get('ips', '')
            ips = [ip.strip() for ip in ips_field.split(',') if ip.strip()]

            a_records = dig_short('A', host)
            aaaa_records = dig_short('AAAA', host)
            cname = dig_short('CNAME', host)

            # For domain-level records use the second-level+TLD
            parts = host.split('.')
            domain = '.'.join(parts[-2:]) if len(parts) >= 2 else host

            mx = dig_short('MX', domain)
            txt = dig_short('TXT', domain)
            ns = dig_short('NS', domain)
            soa = dig_short('SOA', domain)
            caa = dig_short('CAA', domain)

            ptrs = []
            for ip in ips[:2]:
                try:
                    ptr = reverse_ptr(ip)
                    if ptr:
                        ptrs.append(ptr)
                except Exception:
                    pass

            whois_dom = whois_domain(domain)
            whois_ip_info = whois_ip(ips[0]) if ips else {"asn": "", "org": "", "whois_raw": ""}

            cdn = detect_cdn_or_waf(r.get('server', ''), r.get('tech', ''))

            row = {
                # Basic audit fields from CSV
                'Host': host,
                'IPs (from audit)': ips_field,
                'HTTP Status': r.get('status', ''),
                'URL (final)': r.get('url', ''),
                'Server Header': r.get('server', ''),
                'X-Powered-By': r.get('x_powered_by', ''),
                'Title': r.get('title', ''),
                'Detected Tech (audit)': r.get('tech', ''),
                # DNS & Network
                'A Records': ",".join(a_records),
                'AAAA Records': ",".join(aaaa_records),
                'CNAME Records': ",".join(cname),
                'MX Records': ",".join(mx),
                'TXT Records': ",".join(txt),
                'NS Records': ",".join(ns),
                'SOA Record': ",".join(soa),
                'PTR Records': ",".join(ptrs),
                'CAA Records': ",".join(caa),
                # Whois & hosting
                'Whois Registrar': whois_dom.get('registrar',''),
                'Whois Creation Date': whois_dom.get('creation_date',''),
                'Whois Expiration Date': whois_dom.get('expiration_date',''),
                'IP ASN': whois_ip_info.get('asn',''),
                'Hosting Org': whois_ip_info.get('org',''),
                'CDN/WAF': cdn,
                # TLS / Cert placeholders
                'SSL Issuer': '',
                'SSL Valid From': '',
                'SSL Valid To': '',
                'SSL SANs': '',
                # App / Security checks placeholders
                'HTTP Security Headers (CSP,HSTS etc)': '',
                'Robots.txt present': '',
                'Sitemap.xml present': '',
                'security.txt present': '',
                'Hidden Params / Comments': '',
                'Potential Subdomain Takeover': '',
                'Open Ports (basic)': '',
                'Notes': ''
            }
            rows.append(row)

    df = pd.DataFrame(rows)
    # Order columns to match checklist grouping (a practical subset)
    cols = [
        'Host','IPs (from audit)','A Records','AAAA Records','PTR Records','MX Records','TXT Records','NS Records','CNAME Records','SOA Record','CAA Records',
        'IP ASN','Hosting Org','CDN/WAF','Whois Registrar','Whois Creation Date','Whois Expiration Date',
        'HTTP Status','URL (final)','Server Header','X-Powered-By','Title','Detected Tech (audit)',
        'SSL Issuer','SSL Valid From','SSL Valid To','SSL SANs',
        'HTTP Security Headers (CSP,HSTS etc)','Robots.txt present','Sitemap.xml present','security.txt present',
        'Hidden Params / Comments','Potential Subdomain Takeover','Open Ports (basic)','Notes'
    ]
    cols = [c for c in cols if c in df.columns]
    df = df[cols]

    try:
        df.to_excel(out_xlsx, index=False)
        print("Wrote", out_xlsx)
    except Exception:
        csv_out = f"{base}_security_checklist.csv"
        df.to_csv(csv_out, index=False)
        print("openpyxl missing or write failed; wrote CSV instead:", csv_out)


if __name__ == '__main__':
    main()
