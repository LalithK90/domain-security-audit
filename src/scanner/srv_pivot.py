"""SRV Record Discovery - finding services and infrastructure subdomains.

WHAT ARE SRV RECORDS:
SRV (Service) records are DNS records that specify the location of services.
Instead of just mapping a hostname to an IP, they answer: "where can I find
the LDAP service for this domain?" or "where's the SIP server?"

Example SRV records:
    _ldap._tcp.example.com SRV 0 0 389 ldap-server.example.com
    _sip._tcp.example.com SRV 0 0 5060 voip-server.example.com

This tells applications (LDAP clients, VoIP phones) exactly where those
services are hosted.

WHY THIS HELPS ENUMERATION:
SRV records often point to infrastructure subdomains that aren't in Certificate
Transparency logs (they might not have SSL certificates) and might not show
up in basic DNS brute-force:

    Example: mail.example.com might be an alias that's in CT logs and DNS brute-force
    But: _ldaps._tcp.example.com only appears in SRV records
    Query SRV: _ldaps._tcp → points to mail-internal.example.com

We discover subdomains by querying 34 common services and collecting the
target hostnames they point to.

COMMON SERVICES WE CHECK (34 total):

**Directory & Authentication:**
- _ldap._tcp, _ldaps._tcp (LDAP/Active Directory)
- _kerberos._tcp (Kerberos auth server)
- _gc._tcp (Active Directory Global Catalog)
- _kpasswd._tcp (Kerberos password server)

**Communication:**
- _xmpp-server._tcp, _xmpp._tcp (XMPP/Jabber)
- _sip._tcp, _sips._tcp (VoIP/SIP)

**Calendaring:**
- _caldav._tcp, _carddav._tcp (Calendar/contact sync)

**Email:**
- _imap._tcp, _imaps._tcp, _pop3._tcp (Email retrieval)
- _smtp._tcp (Email submission)
- _submission._tcp (Modern email submission)

**And many more: databases, Kubernetes, monitoring, VCS, etc.**

LIMITATIONS & CONSIDERATIONS:
- Many organizations don't use SRV records (older systems)
- Some intentionally hide services (security through obscurity)
- Misconfigured SRV records that point to non-existent targets
- Some services have multiple SRV records (redundancy)

EDUCATIONAL LESSON:
SRV discovery shows why defenders need layered security - administrators use
multiple DNS record types for different purposes. Enumeration needs to check
all of them to get complete visibility. This is one reason why domain security
is complex: you can't just check A records and assume you know all the services.

USAGE:
Call srv_pivot() with your base domain to get all SRV-discoverable targets.
Results are deduplicated and normalized before writing to the scan queue.
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
