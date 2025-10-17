"""
subdomain_audit.py

Reads <domain>_active.txt (one hostname per line), probes each host to collect:
- IP addresses (A/AAAA)
- HTTP/HTTPS status code
- Server and X-Powered-By headers
- Title (if HTML)
- Simple technology fingerprints based on headers and HTML

Outputs:
- <domain>_audit.csv
- <domain>_audit.xlsx

Usage:
  pip install -r requirements.txt
  python subdomain_audit.py <domain_active_file>

If you pass just the domain name, the script will try to open <domain>_active.txt.
"""

import sys
import socket
import concurrent.futures
import requests
from requests.exceptions import RequestException
from urllib.parse import urljoin
import pandas as pd
import re
from typing import List, Dict

COMMON_PORTS = [443, 80]

TECH_REGEXPS = [
    (re.compile(r"wordpress", re.I), "WordPress"),
    (re.compile(r"wp-content", re.I), "WordPress"),
    (re.compile(r"shopify", re.I), "Shopify"),
    (re.compile(r"cdn\.cloudflare", re.I), "Cloudflare CDN"),
    (re.compile(r"wix", re.I), "Wix"),
    (re.compile(r"drupal", re.I), "Drupal"),
    (re.compile(r"joomla", re.I), "Joomla"),
]


def get_ips(host: str) -> List[str]:
    ips = set()
    try:
        for res in socket.getaddrinfo(host, None):
            ips.add(res[4][0])
    except Exception:
        pass
    return sorted(ips)


def fetch_head_and_title(host: str, timeout: int = 8) -> Dict:
    out = {
        "host": host,
        "url": "",
        "status": None,
        "server": None,
        "x_powered_by": None,
        "title": None,
        "tech": [],
    }

    urls = [f"https://{host}", f"http://{host}"]
    for url in urls:
        try:
            r = requests.get(url, timeout=timeout, allow_redirects=True)
            out["url"] = r.url
            out["status"] = r.status_code
            out["server"] = r.headers.get("Server")
            out["x_powered_by"] = r.headers.get("X-Powered-By") or r.headers.get("X-Powered-By")

            # title extraction
            content_type = r.headers.get("Content-Type", "")
            if "text/html" in content_type.lower() and r.text:
                m = re.search(r"<title>(.*?)</title>", r.text, re.I | re.S)
                if m:
                    out["title"] = m.group(1).strip()

                # simple tech heuristics from HTML
                for rx, name in TECH_REGEXPS:
                    if rx.search(r.text):
                        out["tech"].append(name)

            # headers-based tech heuristics
            server = out["server"] or ""
            xpb = out["x_powered_by"] or ""
            for rx, name in TECH_REGEXPS:
                if rx.search(server) or rx.search(xpb):
                    if name not in out["tech"]:
                        out["tech"].append(name)

            return out
        except RequestException:
            continue
    return out


def audit_hosts(hosts: List[str]) -> List[Dict]:
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(process_host, h): h for h in hosts}
        for fut in concurrent.futures.as_completed(futures):
            try:
                results.append(fut.result())
            except Exception:
                results.append({"host": futures[fut]})
    return results


def process_host(h: str) -> Dict:
    ips = get_ips(h)
    head = fetch_head_and_title(h)
    return {
        "host": h,
        "ips": ",".join(ips),
        "status": head.get("status"),
        "url": head.get("url"),
        "server": head.get("server"),
        "x_powered_by": head.get("x_powered_by"),
        "title": head.get("title"),
        "tech": ",".join(head.get("tech", [])),
    }


def write_outputs(domain: str, rows: List[Dict]):
    df = pd.DataFrame(rows)
    csv_file = f"{domain}_audit.csv"
    xlsx_file = f"{domain}_audit.xlsx"
    df.to_csv(csv_file, index=False)
    xlsx_written = False
    try:
        # only attempt to write Excel if openpyxl is available
        import openpyxl  # type: ignore
        df.to_excel(xlsx_file, index=False)
        xlsx_written = True
    except Exception:
        # If openpyxl not installed or writing failed, skip XLSX
        xlsx_file = None

    return csv_file, xlsx_file


def main():
    if len(sys.argv) < 2:
        print("Usage: python subdomain_audit.py <domain_active_file> OR <domain>")
        sys.exit(1)

    arg = sys.argv[1]
    if arg.endswith("_active.txt"):
        active_file = arg
        domain = arg.replace("_active.txt", "")
    else:
        domain = arg
        active_file = f"{domain}_active.txt"

    try:
        with open(active_file, "r", encoding="utf-8") as f:
            hosts = [l.strip() for l in f if l.strip()]
    except FileNotFoundError:
        print(f"Active file not found: {active_file}")
        sys.exit(1)

    print(f"Auditing {len(hosts)} hosts from {active_file}...")
    rows = audit_hosts(hosts)
    csv_file, xlsx_file = write_outputs(domain, rows)
    print("Wrote:", csv_file, xlsx_file)


if __name__ == "__main__":
    main()
