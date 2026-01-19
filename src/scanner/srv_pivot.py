"""SRV Record Pivoting - discover services via DNS SRV records.

WHY THIS EXISTS:
- SRV records reveal services running on subdomains
- Examples: _ldap._tcp.example.com, _sip._tcp.example.com
- Often points to admin/infrastructure subdomains
- Complements other enumeration methods

COMMON SRV RECORDS:
- _ldap._tcp (LDAP/Active Directory)
- _kerberos._tcp (Kerberos authentication)
- _sip._tcp, _sip._udp (VoIP/SIP)
- _xmpp-server._tcp (XMPP/Jabber)
- _caldav._tcp, _carddav._tcp (Calendar/Contacts)
- _imap._tcp, _imaps._tcp, _pop3._tcp (Email)
- _submission._tcp (Email submission)
- _autodiscover._tcp (Exchange/Office 365)

REFERENCE:
- RFC 2782 (SRV Records)
"""

import asyncio
import logging
import dns.resolver
import dns.exception
from typing import Set, List, Tuple

logger = logging.getLogger(__name__)


# Standard SRV service/protocol combinations
COMMON_SRV_RECORDS = [
    # Active Directory / LDAP
    ('_ldap', '_tcp'),
    ('_ldap', '_udp'),
    ('_ldaps', '_tcp'),
    ('_kerberos', '_tcp'),
    ('_kerberos', '_udp'),
    ('_kpasswd', '_tcp'),
    ('_kpasswd', '_udp'),
    ('_gc', '_tcp'),  # Global Catalog
    
    # Email
    ('_imap', '_tcp'),
    ('_imaps', '_tcp'),
    ('_pop3', '_tcp'),
    ('_pop3s', '_tcp'),
    ('_smtp', '_tcp'),
    ('_submission', '_tcp'),
    ('_autodiscover', '_tcp'),
    
    # VoIP / SIP
    ('_sip', '_tcp'),
    ('_sip', '_udp'),
    ('_sip', '_tls'),
    ('_sips', '_tcp'),
    
    # XMPP / Jabber
    ('_xmpp-client', '_tcp'),
    ('_xmpp-server', '_tcp'),
    ('_jabber', '_tcp'),
    
    # CalDAV / CardDAV
    ('_caldav', '_tcp'),
    ('_caldavs', '_tcp'),
    ('_carddav', '_tcp'),
    ('_carddavs', '_tcp'),
    
    # Web / HTTP
    ('_http', '_tcp'),
    ('_https', '_tcp'),
    
    # Other services
    ('_ftp', '_tcp'),
    ('_sftp', '_tcp'),
    ('_ssh', '_tcp'),
]


async def query_srv_record(service: str, protocol: str, domain: str, timeout: float = 3.0) -> List[str]:
    """Query a single SRV record.
    
    Args:
        service: Service name (e.g., "_ldap")
        protocol: Protocol (e.g., "_tcp")
        domain: Base domain
        timeout: Query timeout in seconds
        
    Returns:
        List of target hostnames from SRV records
        
    Example:
        query_srv_record("_ldap", "_tcp", "example.com")
        → ["ldap1.example.com", "ldap2.example.com"]
    """
    srv_name = f"{service}.{protocol}.{domain}"
    targets = []
    
    try:
        # Async DNS query
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        
        # Run blocking DNS query in thread pool
        loop = asyncio.get_event_loop()
        answers = await loop.run_in_executor(
            None,
            lambda: resolver.resolve(srv_name, 'SRV')
        )
        
        # Extract targets from SRV records
        for rdata in answers:
            # SRV record format: priority weight port target
            target = str(rdata.target).rstrip('.')
            if target and target != '.':
                targets.append(target)
        
        if targets:
            logger.debug(f"SRV {srv_name} → {len(targets)} targets: {targets}")
        
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        # No SRV record - this is expected for most services
        pass
    except dns.exception.Timeout:
        logger.debug(f"SRV query timeout: {srv_name}")
    except Exception as e:
        logger.debug(f"SRV query error for {srv_name}: {e}")
    
    return targets


async def discover_srv_subdomains(domain: str, timeout: float = 3.0) -> Set[str]:
    """Discover subdomains via SRV record enumeration.
    
    Args:
        domain: Base domain to enumerate
        timeout: Per-query timeout
        
    Returns:
        Set of discovered FQDNs from SRV records
    """
    logger.info(f"SRV Record Pivoting: testing {len(COMMON_SRV_RECORDS)} service records...")
    
    all_targets = set()
    
    # Query all common SRV records in parallel
    tasks = []
    for service, protocol in COMMON_SRV_RECORDS:
        task = query_srv_record(service, protocol, domain, timeout)
        tasks.append(task)
    
    # Gather results
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Collect all discovered targets
    for result in results:
        if isinstance(result, list):
            all_targets.update(result)
        elif isinstance(result, Exception):
            logger.debug(f"SRV query exception: {result}")
    
    logger.info(f"      ✓ SRV records: {len(all_targets)} subdomains discovered")
    
    return all_targets


def get_srv_records_sync(domain: str) -> Set[str]:
    """Synchronous wrapper for SRV discovery (for backward compatibility).
    
    Args:
        domain: Base domain
        
    Returns:
        Set of discovered FQDNs
    """
    return asyncio.run(discover_srv_subdomains(domain))
