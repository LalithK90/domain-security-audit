#!/usr/bin/env python3
"""
Async TCP + TLS scanner with JSON output.

Usage:
  python3 scan_ssl_async.py <hostname_or_ip>
  python3 scan_ssl_async.py --ip 1.2.3.4

- Scans top 100 common ports.
- Checks TLS on every open port.
- Outputs structured JSON with certificate info if available.
"""

import asyncio
import socket
import ssl
import sys
import json
import argparse
from typing import Dict

try:
    from cryptography import x509
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


# Top 100 most common ports (from nmap)
COMMON_PORTS: Dict[int, str] = {
    7:"echo", 20:"ftp-data", 21:"ftp", 22:"ssh", 23:"telnet", 25:"smtp", 26:"rsftp",
    37:"time", 53:"dns", 80:"http", 81:"http-alt", 88:"kerberos", 110:"pop3", 111:"rpcbind",
    113:"ident", 119:"nntp", 123:"ntp", 135:"msrpc", 139:"netbios-ssn", 143:"imap",
    161:"snmp", 162:"snmptrap", 179:"bgp", 389:"ldap", 443:"https", 445:"microsoft-ds",
    465:"smtps", 500:"isakmp", 514:"syslog", 515:"printer", 520:"rip", 587:"submission",
    593:"http-rpc-epmap", 623:"ipmi", 636:"ldaps", 873:"rsync", 902:"vmware-auth",
    990:"ftps", 993:"imaps", 995:"pop3s", 1025:"microsoft-ds-alt", 1026:"win-rpc",
    1433:"mssql", 1434:"mssql-monitor", 1521:"oracle", 1723:"pptp", 1883:"mqtt",
    2049:"nfs", 2121:"ftp-alt", 2222:"ssh-alt", 2375:"docker", 2483:"oracle-rdbms",
    2484:"oracle-rdbms-secure", 3000:"http-dev", 3128:"squid", 3306:"mysql",
    3389:"rdp", 3478:"stun", 3690:"svn", 4000:"icq", 4444:"metasploit", 4567:"tram",
    5000:"universal-plug", 5060:"sip", 5061:"sips", 5432:"postgresql", 5500:"vnc",
    5631:"pcanywhere", 5900:"vnc", 5985:"winrm", 5986:"winrm-https", 6000:"x11",
    6379:"redis", 6667:"irc", 7000:"afs", 7070:"realserver", 8080:"http-alt",
    8081:"http-alt2", 8443:"https-alt", 8888:"http-proxy", 9000:"samba", 9090:"http-alt3",
    9200:"elasticsearch", 9418:"git", 9999:"abyss", 10000:"webmin", 27017:"mongodb"
}

TLS_CONTEXT = ssl._create_unverified_context()


async def try_tcp(host: str, port: int, timeout=1.5) -> bool:
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def try_tls(host: str, port: int, timeout=3.0):
    info = {}
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=TLS_CONTEXT), timeout)
        sslobj = writer.get_extra_info("ssl_object")
        if not sslobj:
            writer.close()
            return False, {"error": "no ssl_object"}

        info["tls_version"] = sslobj.version()
        der = sslobj.getpeercert(binary_form=True)

        if der and CRYPTO_AVAILABLE:
            cert = x509.load_der_x509_certificate(der)
            info["subject"] = ", ".join(f"{n.oid._name}={n.value}" for n in cert.subject)
            info["issuer"] = ", ".join(f"{n.oid._name}={n.value}" for n in cert.issuer)
            info["not_before"] = cert.not_valid_before.isoformat()
            info["not_after"] = cert.not_valid_after.isoformat()
            info["x509_version"] = cert.version.name
            info["serial_number"] = hex(cert.serial_number)
        else:
            cert_dict = sslobj.getpeercert()
            if cert_dict:
                info["subject"] = cert_dict.get("subject")
                info["issuer"] = cert_dict.get("issuer")
                info["not_before"] = cert_dict.get("notBefore")
                info["not_after"] = cert_dict.get("notAfter")

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True, info
    except Exception as e:
        return False, {"error": str(e)}


async def scan(host: str, concurrency=200):
    sem = asyncio.Semaphore(concurrency)
    results = []

    async def worker(port):
        async with sem:
            tcp_open = await try_tcp(host, port)
            if not tcp_open:
                return
            tls_ok, tls_info = await try_tls(host, port)
            results.append({
                "port": port,
                "service": COMMON_PORTS.get(port, ""),
                "tcp_open": True,
                "tls_supported": tls_ok,
                "tls_info": tls_info
            })

    await asyncio.gather(*(worker(p) for p in COMMON_PORTS.keys()))
    return sorted(results, key=lambda x: x["port"])


def resolve_host(hostname: str) -> str:
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return hostname


def parse_args():
    p = argparse.ArgumentParser(description="Async TCP+TLS scanner (JSON output).")
    p.add_argument("host", nargs="?", help="hostname or IP (optional if using --ip)")
    p.add_argument("--ip", "-i", help="server IP address to scan (overrides hostname if provided)")
    p.add_argument("--concurrency", "-c", type=int, default=200, help="concurrency (default 200)")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()

    if not args.ip and not args.host:
        print("Usage: python3 scan_ssl_async.py <hostname_or_ip>  OR  python3 scan_ssl_async.py --ip 1.2.3.4")
        sys.exit(1)

    target = args.host or ""
    ip = args.ip or ""
    if args.ip:
        used_target = args.ip
    else:
        # resolve hostname to IP
        used_target = args.host
        ip = resolve_host(args.host)

    try:
        results = asyncio.run(scan(ip or used_target, concurrency=args.concurrency))
    except KeyboardInterrupt:
        print(json.dumps({"error": "scan cancelled"}))
        sys.exit(1)

    output = {
        "target": target if target else None,
        "ip": ip if ip else used_target,
        "port_count": len(COMMON_PORTS),
        "open_ports": results,
        "note": "Install 'cryptography' for detailed X.509 info." if not CRYPTO_AVAILABLE else None
    }

    print(json.dumps(output, indent=2))
