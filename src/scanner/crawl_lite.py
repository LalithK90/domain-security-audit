"""
Crawl-lite: Extract subdomains from HTTP/HTTPS responses.

This module performs lightweight crawling of discovered active HTTP/HTTPS sites
to extract additional subdomains from:
- HTML content (links, src attributes, meta tags)
- JavaScript code (URLs, API endpoints)
- CSP (Content-Security-Policy) headers

The goal is to discover subdomains that don't appear in CT logs or DNS brute-force
but are referenced in web application code or security headers.
"""

import asyncio
import logging
from typing import Set, Optional
import aiohttp
from aiohttp import ClientSession, ClientTimeout, ClientError

from .normalization import extract_subdomains_from_text

logger = logging.getLogger(__name__)


class CrawlLite:
    """Lightweight crawler for extracting subdomains from HTTP responses."""
    
    def __init__(self, timeout: int = 10, max_size: int = 2 * 1024 * 1024):
        """
        Initialize the crawler.
        
        Args:
            timeout: Request timeout in seconds
            max_size: Maximum response size to download (2MB default)
        """
        self.timeout = ClientTimeout(total=timeout)
        self.max_size = max_size
        
    async def crawl_url(
        self,
        url: str,
        domain: str,
        session: ClientSession
    ) -> Set[str]:
        """
        Crawl a single URL and extract subdomains.
        
        Args:
            url: The URL to crawl (http:// or https://)
            domain: The base domain to match subdomains against
            session: The aiohttp session to use
            
        Returns:
            Set of discovered FQDNs
        """
        discovered = set()
        
        headers = {
            'User-Agent': 'LK-Domain-Security-Research/1.0 (Academic Study; mailto:security-research@example.edu)'
        }

        try:
            async with session.get(
                url,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=True,
                max_redirects=3,
                ssl=False  # Don't verify SSL for this research context
            ) as response:
                # Check content length
                content_length = response.headers.get('Content-Length')
                if content_length and int(content_length) > self.max_size:
                    logger.debug(f"Skipping {url}: content too large ({content_length} bytes)")
                    return discovered
                
                # Extract from CSP header
                csp = response.headers.get('Content-Security-Policy', '')
                if csp:
                    csp_domains = extract_subdomains_from_text(csp, domain)
                    discovered.update(csp_domains)
                    if csp_domains:
                        logger.debug(f"Extracted {len(csp_domains)} domains from CSP header of {url}")
                
                # Extract from response body (HTML/JS)
                content_type = response.headers.get('Content-Type', '').lower()
                if any(t in content_type for t in ['text/html', 'text/javascript', 'application/javascript', 'application/json']):
                    try:
                        # Read with size limit
                        body = await response.text()
                        if len(body) > self.max_size:
                            body = body[:self.max_size]
                        
                        # Extract subdomains from body
                        body_domains = extract_subdomains_from_text(body, domain)
                        discovered.update(body_domains)
                        if body_domains:
                            logger.debug(f"Extracted {len(body_domains)} domains from body of {url}")
                            
                    except UnicodeDecodeError:
                        logger.debug(f"Could not decode response body from {url}")
                    except Exception as e:
                        logger.debug(f"Error reading body from {url}: {e}")
                
        except asyncio.TimeoutError:
            logger.debug(f"Timeout crawling {url}")
        except ClientError as e:
            logger.debug(f"Client error crawling {url}: {e}")
        except Exception as e:
            logger.debug(f"Unexpected error crawling {url}: {e}")
            
        return discovered
    
    async def crawl_sites(
        self,
        fqdns: Set[str],
        domain: str,
        protocols: list = None
    ) -> Set[str]:
        """
        Crawl multiple sites and extract subdomains.
        
        Args:
            fqdns: Set of FQDNs to crawl
            domain: The base domain to match subdomains against
            protocols: List of protocols to try (default: ['https', 'http'])
            
        Returns:
            Set of newly discovered FQDNs
        """
        if protocols is None:
            protocols = ['https', 'http']
        
        all_discovered = set()
        
        # Create connector with limits
        connector = aiohttp.TCPConnector(
            limit=50,  # Max 50 concurrent connections
            limit_per_host=2,  # Max 2 per host
            ttl_dns_cache=300,  # Cache DNS for 5 minutes
            force_close=True  # Close connections after each request
        )
        
        async with ClientSession(connector=connector, timeout=self.timeout) as session:
            tasks = []
            
            # Create tasks for each FQDN and protocol
            for fqdn in fqdns:
                for protocol in protocols:
                    url = f"{protocol}://{fqdn}/"
                    task = self.crawl_url(url, domain, session)
                    tasks.append(task)
            
            # Execute all tasks with progress logging
            if tasks:
                logger.info(f"Crawling {len(fqdns)} sites ({len(tasks)} URLs) for subdomain discovery...")
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Collect results
                for result in results:
                    if isinstance(result, set):
                        all_discovered.update(result)
                    elif isinstance(result, Exception):
                        logger.debug(f"Task failed with exception: {result}")
                
                logger.info(f"Crawl-lite discovered {len(all_discovered)} new candidates from {len(fqdns)} sites")
        
        return all_discovered


async def discover_from_crawling(
    active_fqdns: Set[str],
    domain: str,
    timeout: int = 10,
    max_size: int = 2 * 1024 * 1024
) -> Set[str]:
    """
    Main entry point for crawl-lite subdomain discovery.
    
    Args:
        active_fqdns: Set of active FQDNs that responded to HTTP/HTTPS
        domain: The base domain to match subdomains against
        timeout: Request timeout in seconds
        max_size: Maximum response size to download
        
    Returns:
        Set of newly discovered FQDNs
    """
    if not active_fqdns:
        logger.debug("No active FQDNs to crawl")
        return set()
    
    crawler = CrawlLite(timeout=timeout, max_size=max_size)
    discovered = await crawler.crawl_sites(active_fqdns, domain)
    
    # Remove any that were already in the input set
    new_discoveries = discovered - active_fqdns
    
    logger.info(f"Crawl-lite found {len(new_discoveries)} new subdomains from {len(active_fqdns)} active sites")
    
    return new_discoveries
