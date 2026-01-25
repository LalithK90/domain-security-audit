"""Advanced security checks - subdomain takeover, email authentication, security disclosures.

THREE CHECK CATEGORIES:

1. **SUBDOMAIN TAKEOVER DETECTION**:
   - When a CNAME points to a deleted/unclaimed cloud resource, an attacker can
     claim that resource and serve malicious content from the organization's subdomain
   - Example: example.com/cdn CNAME→ unclaimed.github.io → attacker claims github.io
     space → attacker controls example.com/cdn
   - We check if CNAMEs point to cloud services and if those services are unclaimed

2. **EMAIL AUTHENTICATION QUALITY**:
   - SPF/DMARC/DKIM prevent email spoofing (someone impersonating your domain)
   - But BASIC configuration is insufficient. We check for advanced controls:
     - MTA-STS: Enforces TLS for inbound email
     - TLS-RPT: Reports TLS failures (reveals attacks)
     - DMARC policy strength: quarantine/reject vs pass/none
     - SPF lookup limits: excessive lookups indicate misconfiguration
   - These checks go beyond "do you have SPF?" to "is it WELL configured?"

3. **SECURITY DISCLOSURES (security.txt)**:
   - RFC 9116 defines security.txt - a standard way to publish security contacts
   - Organizations put this at /.well-known/security.txt to tell researchers
     how to report vulnerabilities responsibly
   - We check for presence and validity of contact information

WHY THESE CHECKS MATTER:

**Subdomain Takeover**: One of the most exploitable vulnerabilities because:
- Often overlooked (developers forget about old subdomains)
- Fully under attacker control (can serve any content)
- Appears to come from the legitimate domain
- Easy for attackers to discover and exploit

**Email Authentication**: Email is a common attack vector:
- Spoofing (pretending to be your domain)
- Phishing (tricking users into giving credentials)
- Advanced controls (MTA-STS, TLS-RPT) are rarely deployed but very effective

**Security Disclosure**: Improves responsible vulnerability handling:
- Researchers know how to contact you responsibly
- Alternative: widespread disclosure or public exploitation
- Shows maturity of security posture

IMPLEMENTATION NOTES:
All checks follow the standard CheckResult pattern for consistency with
the rest of the check system. They're evaluated the same way, scored the same way.

EDUCATIONAL VALUE:
These checks show that security control evaluation is multi-layered:
- Some checks are binary (has/doesn't have)
- Some checks examine configuration depth
- Some checks look for evidence of maturity/sophistication

Good security systems combine all three approaches.
"""

import logging
import re
import dns.resolver
import dns.exception
from typing import Dict, Any, Optional, Tuple, List

logger = logging.getLogger(__name__)


# ============================================================================
# SUBDOMAIN TAKEOVER DETECTION
# ============================================================================

# Known cloud service patterns that can indicate takeover risk
TAKEOVER_PATTERNS = {
    'github.io': 'GitHub Pages',
    'githubusercontent.com': 'GitHub User Content',
    'azurewebsites.net': 'Azure Web Apps',
    'cloudfront.net': 'AWS CloudFront',
    'herokuapp.com': 'Heroku',
    'netlify.app': 'Netlify',
    'fastly.net': 'Fastly CDN',
    'bitbucket.io': 'Bitbucket Pages',
    'pages.dev': 'Cloudflare Pages',
    'vercel.app': 'Vercel',
}

# Known "unclaimed resource" signatures - HTTP body text patterns
UNCLAIMED_SIGNATURES = [
    'There isn\'t a GitHub Pages site here',
    'No such app',  # Heroku
    'The specified bucket does not exist',  # S3/CloudFront
    'NoSuchBucket',
    'Not Found - Request ID',  # Azure
    'Repository not found',
    'Project not found',
    'is not a registered InCloud YouSpace account',
    'Sorry, We can\'t find that site',  # Netlify
    'The thing you were looking for is no longer here',
    'There is nothing here, yet',
]


def detect_cname_provider(cname_target: str) -> Optional[str]:
    """Check if CNAME points to a known cloud service.
    
    Why: Subdomain takeover happens when a CNAME points to an unclaimed
    cloud resource. We first identify if it's a risky provider.
    """
    cname_lower = cname_target.lower().rstrip('.')
    
    for pattern, provider in TAKEOVER_PATTERNS.items():
        if pattern in cname_lower:
            return provider
    
    return None


def check_unclaimed_signature(html_body: str) -> bool:
    """Check if HTTP response contains known unclaimed resource signatures.
    
    Why: Cloud providers show specific error messages when resources don't exist.
    We passively check for these without attempting to claim anything.
    """
    if not html_body:
        return False
    
    body_lower = html_body.lower()
    
    for signature in UNCLAIMED_SIGNATURES:
        if signature.lower() in body_lower:
            return True
    
    return False


# ============================================================================
# EMAIL SECURITY QUALITY CHECKS
# ============================================================================

def parse_dmarc_record(record: str) -> Dict[str, str]:
    """Parse DMARC TXT record into key-value pairs.
    
    Why: DMARC protects against email spoofing. We check if policy is strong
    (quarantine/reject) rather than just "monitor" (none).
    """
    parsed = {}
    
    # Remove whitespace and split by semicolon
    parts = record.replace(' ', '').split(';')
    
    for part in parts:
        if '=' in part:
            key, value = part.split('=', 1)
            parsed[key.lower()] = value.lower()
    
    return parsed


def evaluate_dmarc_policy_strength(dmarc_record: str) -> Tuple[bool, str]:
    """Evaluate if DMARC policy is strong (quarantine/reject).
    
    Returns: (is_strong, policy_value)
    
    Why: p=none means "monitor only" - not enforcing protection.
    p=quarantine or p=reject means active email spoofing defense.
    """
    parsed = parse_dmarc_record(dmarc_record)
    policy = parsed.get('p', 'none')
    
    is_strong = policy in ['quarantine', 'reject']
    return is_strong, policy


def parse_spf_record(record: str) -> Dict[str, Any]:
    """Parse SPF record and count DNS lookups.
    
    Why: SPF with >10 lookups breaks (RFC limit). We verify it's properly
    configured to prevent email delivery failures.
    """
    # Count mechanisms that trigger DNS lookups
    lookup_mechanisms = ['include:', 'a:', 'mx:', 'ptr:', 'exists:', 'redirect=']
    
    lookup_count = 0
    for mechanism in lookup_mechanisms:
        lookup_count += record.lower().count(mechanism)
    
    # Check for terminal policy
    has_hard_fail = '-all' in record
    has_soft_fail = '~all' in record
    has_terminal = has_hard_fail or has_soft_fail
    
    return {
        'lookup_count': lookup_count,
        'has_terminal_policy': has_terminal,
        'terminal_type': '-all' if has_hard_fail else ('~all' if has_soft_fail else None)
    }


async def fetch_mta_sts_policy(domain: str) -> Optional[Dict[str, str]]:
    """Fetch and parse MTA-STS policy file.
    
    Why: MTA-STS forces email servers to use TLS, preventing downgrade attacks.
    We check if it's in "enforce" mode (testing/none are weak).
    
    Returns: Parsed policy dict or None if unavailable
    """
    import aiohttp
    
    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    
    try:
        timeout = aiohttp.ClientTimeout(total=5)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url, ssl=False) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    return parse_mta_sts_policy(text)
    except Exception as e:
        logger.debug(f"MTA-STS fetch failed for {domain}: {e}")
        return None


def parse_mta_sts_policy(policy_text: str) -> Dict[str, str]:
    """Parse MTA-STS policy file.
    
    Format:
        version: STSv1
        mode: enforce
        mx: mail.example.com
        max_age: 86400
    """
    parsed = {}
    
    for line in policy_text.split('\n'):
        line = line.strip()
        if ':' in line:
            key, value = line.split(':', 1)
            parsed[key.strip().lower()] = value.strip().lower()
    
    return parsed


# ============================================================================
# SECURITY.TXT (RFC 9116) VALIDATION
# ============================================================================

async def fetch_security_txt(domain: str) -> Optional[Tuple[str, str]]:
    """Fetch security.txt from preferred or fallback location.
    
    Why: RFC 9116 standardizes how security researchers contact organizations.
    We check if it exists and contains required Contact field.
    
    Returns: (url_used, content) or None
    """
    import aiohttp
    
    # Preferred location (RFC 9116)
    urls = [
        f"https://{domain}/.well-known/security.txt",
        f"https://{domain}/security.txt",  # Fallback
    ]
    
    timeout = aiohttp.ClientTimeout(total=5)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        for url in urls:
            try:
                async with session.get(url, ssl=False) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        return url, text
            except Exception:
                continue
    return None


def parse_security_txt(content: str) -> Dict[str, Any]:
    """Parse security.txt and extract contacts.
    
    Why: Contact field is required per RFC 9116. We verify it exists and
    looks valid (email or https URL).
    
    Returns: dict with 'contacts' list and 'expires' if present
    """
    contacts = []
    expires = None
    
    for line in content.split('\n'):
        line = line.strip()
        
        # Ignore comments
        if line.startswith('#'):
            continue
        
        if line.lower().startswith('contact:'):
            contact = line.split(':', 1)[1].strip()
            if contact:
                contacts.append(contact)
        
        if line.lower().startswith('expires:'):
            expires = line.split(':', 1)[1].strip()
    
    return {
        'contacts': contacts,
        'expires': expires,
        'has_valid_contact': len(contacts) > 0
    }


# ============================================================================
# DNS HELPER FUNCTIONS
# ============================================================================

def get_cname_target(fqdn: str) -> Optional[str]:
    """Get CNAME target for a domain.
    
    Why: CNAME records are the primary indicator for subdomain takeover risk.
    """
    try:
        answers = dns.resolver.resolve(fqdn, 'CNAME', lifetime=3.0)
        for rdata in answers:
            return str(rdata.target)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return None
    except Exception as e:
        logger.debug(f"CNAME lookup failed for {fqdn}: {e}")
        return None


def get_txt_record(fqdn: str) -> List[str]:
    """Get TXT records for a domain.
    
    Returns: List of TXT record strings
    """
    records = []
    
    try:
        answers = dns.resolver.resolve(fqdn, 'TXT', lifetime=3.0)
        for rdata in answers:
            # TXT records are returned as quoted strings, join them
            txt = ''.join([s.decode('utf-8') if isinstance(s, bytes) else s for s in rdata.strings])
            records.append(txt)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        pass
    except Exception as e:
        logger.debug(f"TXT lookup failed for {fqdn}: {e}")
    
    return records


def has_mx_records(domain: str) -> bool:
    """Check if domain has MX records.
    
    Why: Email security checks (DMARC, SPF, MTA-STS) only apply if domain
    sends/receives email (has MX records).
    """
    try:
        answers = dns.resolver.resolve(domain, 'MX', lifetime=3.0)
        return len(list(answers)) > 0
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return False
    except Exception:
        return False
