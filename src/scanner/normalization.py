"""FQDN normalization - standardizing domain names for consistent analysis.

WHY THIS MATTERS:
Domain names can be written many different ways that technically refer to the
same target, causing duplicate records and analysis problems:

    "www.Example.COM." vs "www.example.com" vs "WWW.EXAMPLE.COM"
    
All three refer to the same subdomain. Without normalization, we'd create 3
separate database records, waste time scanning the same target 3 times, and
skew our statistics.

Even trickier: international domains (IDN)
    "münchen.example.com" vs "xn--mnchen-3ya.example.com"

These are the same domain name, but one uses Unicode and one uses Punycode
(ASCII-compatible encoding). Our DNS system only understands Punycode, so we
need to convert. Without this, DNS lookups fail.

NORMALIZATION PIPELINE:
Our approach converts everything to a canonical form:
1. Strip URLs: "http://www.example.com/path?query=1" → "www.example.com"
2. Punycode: Convert IDN (Unicode) domains to ASCII-safe Punycode format
3. Lowercase: "EXAMPLE.COM" → "example.com"
4. Strip trailing dots: "example.com." → "example.com"
5. Validate format: Check it's a legal DNS name (RFC 1035)
6. Verify suffix: Ensure it ends with our base domain (no "random.com")

USAGE IN CODEBASE:
This is called early in enumeration, right after discovering new subdomains.
Invalid or out-of-scope FQDNs are rejected before writing to the database.
Prevents pollution of the scan queue with garbage data.

RESEARCH APPLICATIONS:
Normalization is often overlooked but critical for:
- Reproducibility: Same domain always produces same representation
- Deduplication: Comparing datasets from different tools
- International domain support: Real-world domains include non-ASCII chars
- Data quality: Preventing false statistics from duplicate records

REFERENCES:
- RFC 3492: Punycode (IDN encoding)
- RFC 1035: DNS name format rules
- RFC 5890: Internationalized domain names in applications
"""

import re
import logging
from typing import Set, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def normalize_fqdn(fqdn: str, base_domain: str) -> Optional[str]:
    """Normalize a single FQDN to canonical form.
    
    Args:
        fqdn: Raw FQDN (may have mixed case, trailing dot, punycode, etc.)
        base_domain: Base domain for suffix validation
        
    Returns:
        Normalized FQDN or None if invalid
        
    Examples:
        normalize_fqdn("WWW.Example.COM.", "example.com") → "www.example.com"
        normalize_fqdn("münchen.example.com", "example.com") → "xn--mnchen-3ya.example.com"
        normalize_fqdn("http://test.example.com/path", "example.com") → "test.example.com"
    """
    if not fqdn or not isinstance(fqdn, str):
        return None
    
    # Step 0: Strip protocol and path if present
    fqdn = _strip_protocol_and_path(fqdn)
    
    # Step 1: Convert to punycode (handles internationalized domains)
    try:
        fqdn = fqdn.encode('idna').decode('ascii')
    except (UnicodeError, UnicodeDecodeError):
        logger.debug(f"Punycode conversion failed for {fqdn}")
        # Continue anyway - might already be ASCII
    
    # Step 2: Convert to lowercase
    fqdn = fqdn.lower()
    
    # Step 3: Strip trailing dot
    fqdn = fqdn.rstrip('.')
    
    # Step 4: Validate DNS name format
    if not _is_valid_dns_name(fqdn):
        logger.debug(f"Invalid DNS name format: {fqdn}")
        return None
    
    # Step 5: Verify suffix matches base domain
    if not _matches_domain_suffix(fqdn, base_domain):
        logger.debug(f"FQDN {fqdn} does not match base domain {base_domain}")
        return None
    
    return fqdn


def normalize_fqdn_set(fqdns: Set[str], base_domain: str) -> Set[str]:
    """Normalize a set of FQDNs and remove duplicates.
    
    Args:
        fqdns: Set of raw FQDNs
        base_domain: Base domain for suffix validation
        
    Returns:
        Set of normalized, deduplicated FQDNs
    """
    normalized = set()
    invalid_count = 0
    duplicate_count = 0
    original_count = len(fqdns)
    
    for fqdn in fqdns:
        norm = normalize_fqdn(fqdn, base_domain)
        if norm:
            if norm in normalized:
                duplicate_count += 1
            else:
                normalized.add(norm)
        else:
            invalid_count += 1
    
    if invalid_count > 0:
        logger.info(f"Normalization: {invalid_count} invalid FQDNs filtered out")
    
    if duplicate_count > 0:
        logger.info(f"Normalization: {duplicate_count} duplicates removed")
    
    logger.info(f"Normalization: {original_count} → {len(normalized)} unique valid FQDNs")
    
    return normalized


def _strip_protocol_and_path(fqdn: str) -> str:
    """Strip protocol, port, and path from URL-like string.
    
    Examples:
        "https://example.com/path" → "example.com"
        "example.com:443" → "example.com"
        "example.com" → "example.com"
    """
    # Handle URL format
    if '://' in fqdn:
        parsed = urlparse(fqdn)
        fqdn = parsed.netloc or parsed.path
    
    # Remove port
    if ':' in fqdn:
        fqdn = fqdn.split(':')[0]
    
    # Remove path
    if '/' in fqdn:
        fqdn = fqdn.split('/')[0]
    
    return fqdn.strip()


def _is_valid_dns_name(fqdn: str) -> bool:
    """Validate DNS name format per RFC 1035.
    
    Rules:
    - Labels separated by dots
    - Each label: 1-63 characters
    - Total length: ≤253 characters
    - Characters: a-z, 0-9, hyphen (not at start/end)
    - No consecutive dots
    - No trailing/leading dots
    
    Args:
        fqdn: Normalized FQDN (already lowercase, no trailing dot)
        
    Returns:
        True if valid DNS name
    """
    # Total length check (RFC 1035: max 253 characters)
    if len(fqdn) > 253:
        return False
    
    # Must not be empty
    if not fqdn:
        return False
    
    # Must not start/end with dot or hyphen
    if fqdn.startswith('.') or fqdn.startswith('-'):
        return False
    if fqdn.endswith('.') or fqdn.endswith('-'):
        return False
    
    # No consecutive dots
    if '..' in fqdn:
        return False
    
    # Split into labels and validate each
    labels = fqdn.split('.')
    
    # Must have at least 2 labels (e.g., "example.com")
    if len(labels) < 2:
        return False
    
    for label in labels:
        # Label length: 1-63 characters
        if not (1 <= len(label) <= 63):
            return False
        
        # Must not start/end with hyphen
        if label.startswith('-') or label.endswith('-'):
            return False
        
        # Valid characters: a-z, 0-9, hyphen
        # Also allow underscore for SRV records like "_http._tcp.example.com"
        if not re.match(r'^[a-z0-9_-]+$', label):
            return False
    
    return True


def _matches_domain_suffix(fqdn: str, base_domain: str) -> bool:
    """Check if FQDN matches base domain suffix.
    
    Examples:
        _matches_domain_suffix("www.example.com", "example.com") → True
        _matches_domain_suffix("example.com", "example.com") → True
        _matches_domain_suffix("example.org", "example.com") → False
        _matches_domain_suffix("notexample.com", "example.com") → False
    
    Args:
        fqdn: Normalized FQDN
        base_domain: Base domain (already normalized)
        
    Returns:
        True if FQDN is base_domain or subdomain of base_domain
    """
    # Normalize base_domain too
    base_domain = base_domain.lower().rstrip('.')
    
    # Exact match
    if fqdn == base_domain:
        return True
    
    # Subdomain match: must end with ".base_domain"
    # This prevents "notexample.com" from matching "example.com"
    if fqdn.endswith('.' + base_domain):
        return True
    
    return False


def extract_subdomains_from_text(text: str, base_domain: str) -> Set[str]:
    """Extract and normalize subdomains from arbitrary text.
    
    Useful for crawl-lite: extract subdomains from HTML, JavaScript, CSP headers.
    
    Args:
        text: Raw text (HTML, JS, headers, etc.)
        base_domain: Base domain to filter for
        
    Returns:
        Set of normalized FQDNs found in text
    """
    if not text:
        return set()
    
    # Regex pattern to match FQDNs
    # Matches: subdomain.example.com, www.example.com, etc.
    # Must end with base_domain
    base_pattern = re.escape(base_domain)
    
    # Pattern: optional subdomain labels + base domain
    # Allows: a-z, 0-9, hyphen, underscore, dot
    pattern = r'\b([a-zA-Z0-9_-]+\.)*' + base_pattern + r'\b'
    
    matches = re.findall(pattern, text, re.IGNORECASE)
    
    # Extract the full match (pattern returns tuples)
    # Reconstruct FQDNs
    fqdns = set()
    for match in re.finditer(pattern, text, re.IGNORECASE):
        fqdn = match.group(0)
        fqdns.add(fqdn)
    
    # Normalize all matches
    return normalize_fqdn_set(fqdns, base_domain)


# Convenience functions for common use cases

def normalize_candidate(candidate: str, base_domain: str) -> Optional[str]:
    """Alias for normalize_fqdn - clearer name for candidate processing."""
    return normalize_fqdn(candidate, base_domain)


def deduplicate_candidates(candidates: Set[str], base_domain: str) -> Set[str]:
    """Alias for normalize_fqdn_set - clearer name for deduplication."""
    return normalize_fqdn_set(candidates, base_domain)
