"""
Subdomain Enumeration Script

Combines passive (crt.sh) and active (DNS + HTTP/HTTPS) discovery.
Outputs: <domain>_all.txt, <domain>_active.txt, <domain>_created_not_active.txt
Usage: Edit domain in main(), then run: python subdomain_handler.py
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
    """Combine passive (crt.sh) and active (DNS probing) subdomain discovery."""
    crt_hosts = fetch_crtsh(domain)
    crt_set = set()
    for h in crt_hosts:
        if h.endswith(domain):
            crt_set.add(h)

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


def classify_hosts(domain: str, hosts: List[str]) -> dict:
    """Classify hosts into all, active (HTTP/HTTPS), and created-but-not-active."""
    all_hosts = sorted(set([normalize_host(h) for h in hosts if h]))

    resolved = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
        futures = {ex.submit(resolve_host, h): h for h in all_hosts}
        for fut in concurrent.futures.as_completed(futures):
            try:
                if fut.result():
                    resolved.add(futures[fut])
            except Exception:
                pass

    active = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
        futures = {ex.submit(is_http_active, h): h for h in resolved}
        for fut in concurrent.futures.as_completed(futures):
            try:
                if fut.result():
                    active.add(futures[fut])
            except Exception:
                pass

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
    domain = "oeducat.org"  # Edit target domain here

    print(f"Enumerating subdomains for: {domain}")
    found = aggregate(domain)
    classified = classify_hosts(domain, found)

    print(json.dumps({k: len(v) for k, v in classified.items()}, indent=2))

    files = write_lists(domain, classified)
    print("Wrote files:")
    for p in files:
        print(" - ", p)

    if classified["active"]:
        print("\nActive subdomains (sample up to 20):")
        for h in classified["active"][:20]:
            print(" * ", h)
    else:
        print("\nNo active subdomains detected via HTTP/HTTPS.")


if __name__ == "__main__":
    main()
