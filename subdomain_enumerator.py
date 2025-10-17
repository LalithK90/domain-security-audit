"""
subdomain_enumerator.py

Simple subdomain enumeration script that combines passive (crt.sh) and
lightweight active checks (DNS + HTTP/HTTPS) and writes three output files:

    - <domain>_all.txt               # all discovered subdomains
    - <domain>_active.txt            # subdomains responding on HTTP/HTTPS
    - <domain>_created_not_active.txt# discovered (e.g. in certs) but not HTTP-active

Usage:
    - Edit the `domain` local variable in `main()` to the domain you want to scan.
    - Run with your Python 3 environment (requests required):

            python subdomain_enumerator.py

Dependencies:
    - requests

Notes:
    - This script uses crt.sh (certificate transparency) and basic DNS and
        HTTP checks. It's intentionally lightweight and not a replacement for
        dedicated tools like `amass`, `subfinder`, `massdns` or full port scanners.
    - Be mindful of authorized usage and rate limits when scanning external
        networks.
"""

import requests
import json
import sys
import time
import concurrent.futures
import socket
from typing import List, Set


COMMON_SUBDOMAINS = [
    "www",
    "mail",
    "webmail",
    "admin",
    "m",
    "api",
    "dev",
    "staging",
    "test",
    "portal",
    "vpn",
    "crm",
    "shop",
    "beta",
    "smtp",
    "pop",
    "imap",
    "ns1",
    "ns2",
    "git",
    "gitlab",
    "support",
    "cdn",
    "static",
    "images",
    "docs",
    "status",
]


def fetch_crtsh(domain: str, retries: int = 3, backoff: float = 1.0) -> List[str]:
    """Fetch subdomains from crt.sh JSON output with simple retry/backoff.

    Returns list of hostnames found (may contain duplicates).
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    for attempt in range(1, retries + 1):
        try:
            resp = requests.get(url, timeout=15)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                except ValueError:
                    # sometimes crt.sh returns HTML error pages
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
                # non-200, wait and retry
                time.sleep(backoff * attempt)
        except requests.RequestException:
            time.sleep(backoff * attempt)
    return []


def resolve_host(host: str, timeout: float = 3.0) -> bool:
    """Return True if host resolves to an A or CNAME (basic check)."""
    try:
        # socket.getaddrinfo will raise on failure; limit to IPv4/IPv6
        socket.getaddrinfo(host, None, family=0, type=0)
        return True
    except socket.gaierror:
        return False


def probe_common_subdomains(domain: str, subdomains: List[str] = None) -> Set[str]:
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


def aggregate(domain: str) -> List[str]:
    # 1) passive from crt.sh
    crt_hosts = fetch_crtsh(domain)
    crt_set = set()
    for h in crt_hosts:
        # Accept only hosts that end with the domain
        if h.endswith(domain):
            crt_set.add(h)

    # 2) active probe common
    active = probe_common_subdomains(domain)

    combined = sorted(crt_set.union(active))
    return combined


def print_results(results: List[str]):
    print(json.dumps({"count": len(results), "subdomains": results}, indent=2))


def normalize_host(h: str) -> str:
    """Normalize hostnames: strip, lowercase, remove trailing dot."""
    if not h:
        return h
    h = h.strip().lower()
    if h.endswith('.'):
        h = h[:-1]
    return h


def write_unique_file(domain: str, hosts: List[str]) -> str:
    """Write normalized, unique hosts to a file and return the file path."""
    normalized = [normalize_host(h) for h in hosts if h]
    unique = sorted(set(normalized))
    filename = f"{domain}_unique_subdomains.txt"
    with open(filename, "w", encoding="utf-8") as f:
        for h in unique:
            f.write(h + "\n")
    return filename


def is_http_active(host: str, timeout: float = 5.0) -> bool:
    """Check if host responds on HTTP or HTTPS with a success code or redirect.

    Returns True if a request to http://host or https://host returns a 2xx/3xx status.
    """
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


def classify_hosts(domain: str, hosts: List[str]) -> dict:
    """Classify hosts into all, active (HTTP/HTTPS), and created-but-not-active.

    created-but-not-active = hosts discovered passively (crt.sh) but which do not respond to HTTP/HTTPS and do not resolve by DNS.
    For this classification we consider 'active' if DNS resolves or HTTP/HTTPS returns.
    """
    all_hosts = sorted(set([normalize_host(h) for h in hosts if h]))

    # Determine DNS resolution for each host concurrently
    resolved = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
        futures = {ex.submit(resolve_host, h): h for h in all_hosts}
        for fut in concurrent.futures.as_completed(futures):
            try:
                if fut.result():
                    resolved.add(futures[fut])
            except Exception:
                pass

    # Check HTTP/HTTPS responsiveness for resolved hosts
    active = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
        futures = {ex.submit(is_http_active, h): h for h in resolved}
        for fut in concurrent.futures.as_completed(futures):
            try:
                if fut.result():
                    active.add(futures[fut])
            except Exception:
                pass

    # Created-but-not-active: present in all_hosts (from crt.sh or probes) but not active
    created_not_active = set(all_hosts) - active

    return {
        "all": all_hosts,
        "resolved": sorted(resolved),
        "active": sorted(active),
        "created_not_active": sorted(created_not_active),
    }


def write_lists(domain: str, classified: dict) -> List[str]:
    """Write three files and return their paths."""
    files = []
    all_file = f"{domain}_all.txt"
    active_file = f"{domain}_active.txt"
    created_file = f"{domain}_created_not_active.txt"

    with open(all_file, "w", encoding="utf-8") as f:
        for h in classified["all"]:
            f.write(h + "\n")

    with open(active_file, "w", encoding="utf-8") as f:
        for h in classified["active"]:
            f.write(h + "\n")

    with open(created_file, "w", encoding="utf-8") as f:
        for h in classified["created_not_active"]:
            f.write(h + "\n")

    files.extend([all_file, active_file, created_file])
    return files


def main():
    # Set domain here as local variable per user request.
    domain = "oeducat.org"

    print(f"Enumerating subdomains for: {domain}")
    found = aggregate(domain)
    classified = classify_hosts(domain, found)

    print(json.dumps({k: len(v) for k, v in classified.items()}, indent=2))

    files = write_lists(domain, classified)
    print("Wrote files:")
    for p in files:
        print(" - ", p)

    # Also print active list summary
    if classified["active"]:
        print("\nActive subdomains (sample up to 20):")
        for h in classified["active"][:20]:
            print(" * ", h)
    else:
        print("\nNo active subdomains detected via HTTP/HTTPS.")


if __name__ == "__main__":
    main()
