"""Reverse DNS (PTR) discovery - finding subdomains via IP addresses.

THE TECHNIQUE:
Forward DNS tells us what IP a domain name resolves to:
    nslookup www.example.com → 192.168.1.1

Reverse DNS (PTR records) tells us what domain names an IP claims:
    nslookup 192.168.1.1 → www.example.com, cdn.example.com, mail.example.com

PTR discovery exploits this: after we resolve some subdomains to IPs, we ask
those IPs "what domain names do you belong to?" - often revealing other
subdomains we haven't discovered yet.

PRACTICAL SCENARIOS:

1. **Shared Hosting**: Multiple domains on one IP
   - We discover mail.example.com → resolves to 1.2.3.4
   - Query PTR for 1.2.3.4 → returns mail.example.com, admin.example.com,
     backup.example.com

2. **Load Balancing**: One service across multiple IPs
   - We discover api.example.com → resolves to 1.2.3.4
   - Query 1.2.3.4 → returns api1.example.com, api2.example.com (internal names)

3. **Content Delivery Networks (CDNs)**:
   - cdn.example.com → points to CDN IP range
   - Query CDN IP → might return cdn1, cdn2, cdn-backup, etc.

4. **Infrastructure Disclosure**:
   - Sometimes PTR reveals internal naming: prod-db-01.example.com, or
     shows admin infrastructure: admin-console, management-api, etc.

IMPORTANT LIMITATIONS:
- Not all IPs have PTR records (especially public cloud providers)
- PTR records aren't always accurate or maintained
- Some reverse DNS queries are intentionally disabled for security
- This is passive (queries public DNS), not intrusive

EDUCATIONAL VALUE:
PTR discovery demonstrates the importance of thinking about domain discovery
from multiple angles. Forward DNS, reverse DNS, CT logs, brute-force - each
method finds different targets. Combined, they give much better coverage
than any single method alone.

USAGE IN THIS CODEBASE:
We call PTR discovery after DNS enumeration completes, using all resolved
IPs from our discovered subdomains as input. It's one of 12+ enumeration
techniques we combine for comprehensive coverage.
"""

import asyncio
import logging
from typing import Set, Dict, List
import dns.resolver
import dns.reversename
import dns.exception

logger = logging.getLogger(__name__)


class PTRPivot:
    """Reverse DNS (PTR record) subdomain discovery."""
    
    def __init__(self, timeout: float = 3.0):
        """
        Initialize PTR pivot.
        
        Args:
            timeout: DNS query timeout in seconds
        """
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        
    async def query_ptr_record(self, ip_address: str) -> Set[str]:
        """
        Query PTR record for a single IP address.
        
        Args:
            ip_address: IPv4 or IPv6 address
            
        Returns:
            Set of hostnames found in PTR records
        """
        hostnames = set()
        
        try:
            # Convert IP to reverse DNS name (e.g., 1.2.3.4 -> 4.3.2.1.in-addr.arpa)
            rev_name = dns.reversename.from_address(ip_address)
            
            # Query PTR record synchronously (will run in executor)
            answers = self.resolver.resolve(rev_name, 'PTR')
            
            for rdata in answers:
                hostname = str(rdata.target).rstrip('.')
                if hostname:
                    hostnames.add(hostname)
                    logger.debug(f"PTR {ip_address} -> {hostname}")
                    
        except dns.resolver.NXDOMAIN:
            # No PTR record exists
            logger.debug(f"No PTR record for {ip_address}")
        except dns.resolver.NoAnswer:
            # PTR query returned no data
            logger.debug(f"PTR query returned no answer for {ip_address}")
        except dns.resolver.Timeout:
            logger.debug(f"PTR query timeout for {ip_address}")
        except dns.exception.DNSException as e:
            logger.debug(f"DNS error querying PTR for {ip_address}: {e}")
        except Exception as e:
            logger.debug(f"Unexpected error querying PTR for {ip_address}: {e}")
            
        return hostnames
    
    async def query_ptr_records_async(self, ip_addresses: Set[str]) -> Set[str]:
        """
        Query PTR records for multiple IP addresses in parallel.
        
        Args:
            ip_addresses: Set of IPv4/IPv6 addresses
            
        Returns:
            Set of discovered hostnames
        """
        if not ip_addresses:
            return set()
        
        all_hostnames = set()
        
        # Run PTR queries in thread pool (DNS resolver is sync)
        loop = asyncio.get_event_loop()
        tasks = []
        
        for ip in ip_addresses:
            task = loop.run_in_executor(None, lambda ip=ip: asyncio.run(self.query_ptr_record(ip)))
            tasks.append(task)
        
        # Wait for all queries with timeout
        try:
            results = await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=len(ip_addresses) * self.timeout + 10  # Total timeout with buffer
            )
            
            # Collect results
            for result in results:
                if isinstance(result, set):
                    all_hostnames.update(result)
                elif isinstance(result, Exception):
                    logger.debug(f"PTR query task failed: {result}")
                    
        except asyncio.TimeoutError:
            logger.warning(f"PTR queries timed out after processing {len(ip_addresses)} IPs")
            
        return all_hostnames


async def discover_ptr_subdomains(
    ip_to_fqdn_map: Dict[str, List[str]],
    domain: str,
    timeout: float = 3.0
) -> Set[str]:
    """
    Main entry point for PTR-based subdomain discovery.
    
    Args:
        ip_to_fqdn_map: Mapping of IP addresses to FQDNs that resolved to them
        domain: The base domain to filter results against
        timeout: DNS query timeout in seconds
        
    Returns:
        Set of newly discovered FQDNs matching the domain
    """
    if not ip_to_fqdn_map:
        logger.debug("No IP addresses to perform PTR lookups on")
        return set()
    
    ip_addresses = set(ip_to_fqdn_map.keys())
    logger.info(f"Performing reverse DNS (PTR) lookups on {len(ip_addresses)} unique IPs...")
    
    pivot = PTRPivot(timeout=timeout)
    all_hostnames = await pivot.query_ptr_records_async(ip_addresses)
    
    # Filter to only include subdomains of our target domain
    discovered_subdomains = set()
    for hostname in all_hostnames:
        # Normalize hostname (lowercase, remove trailing dot)
        hostname = hostname.lower().rstrip('.')
        
        # Check if it's a subdomain of our target domain
        if hostname.endswith(f'.{domain}') or hostname == domain:
            discovered_subdomains.add(hostname)
    
    logger.info(f"PTR reverse DNS discovered {len(discovered_subdomains)} subdomains from {len(ip_addresses)} IPs")
    
    if discovered_subdomains:
        logger.debug(f"PTR discoveries: {sorted(discovered_subdomains)[:10]}...")
    
    return discovered_subdomains


async def build_ip_to_fqdn_map(fqdns: Set[str]) -> Dict[str, List[str]]:
    """
    Build a mapping of IP addresses to FQDNs by resolving A/AAAA records.
    
    This is a helper function to prepare data for PTR lookups.
    
    Args:
        fqdns: Set of FQDNs to resolve
        
    Returns:
        Dictionary mapping IP addresses to lists of FQDNs that resolved to them
    """
    import dns.resolver
    
    ip_map: Dict[str, List[str]] = {}
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 2.0
    
    loop = asyncio.get_event_loop()
    
    async def resolve_fqdn(fqdn: str):
        """Resolve a single FQDN to its IPs."""
        ips = []
        try:
            # Resolve A records (IPv4)
            answers = await loop.run_in_executor(
                None,
                lambda: resolver.resolve(fqdn, 'A')
            )
            for rdata in answers:
                ips.append(str(rdata))
        except Exception:
            pass
        
        try:
            # Resolve AAAA records (IPv6)
            answers = await loop.run_in_executor(
                None,
                lambda: resolver.resolve(fqdn, 'AAAA')
            )
            for rdata in answers:
                ips.append(str(rdata))
        except Exception:
            pass
        
        return fqdn, ips
    
    # Resolve all FQDNs in parallel
    tasks = [resolve_fqdn(fqdn) for fqdn in fqdns]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Build IP -> FQDN mapping
    for result in results:
        if isinstance(result, tuple):
            fqdn, ips = result
            for ip in ips:
                if ip not in ip_map:
                    ip_map[ip] = []
                ip_map[ip].append(fqdn)
    
    logger.debug(f"Built IP map: {len(ip_map)} unique IPs from {len(fqdns)} FQDNs")
    
    return ip_map
