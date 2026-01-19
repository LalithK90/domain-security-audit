"""Security checks registry and applicability rules.

Defines what checks we run and when they apply.
This is our catalog of measurable security controls.
"""

from typing import List, Dict, Any, Callable
from dataclasses import dataclass
from enum import Enum


class CheckCategory(Enum):
    """Categories of security checks for grouping."""
    TLS = "TLS/Certificate"
    HTTP_SECURITY = "HTTP Security Headers"
    COOKIES = "Cookie Security"
    EMAIL = "Email Authentication"
    REDIRECT = "HTTP to HTTPS Redirection"
    TAKEOVER = "Subdomain Takeover Risk"
    SECURITY_DISCLOSURE = "Security Disclosure"


@dataclass
class CheckDefinition:
    """Definition of a single security check.
    
    Includes metadata and applicability logic.
    """
    check_id: str
    name: str
    category: CheckCategory
    description: str
    applicability_rule: Callable[[Dict[str, Any]], bool]
    # The applicability_rule takes probe results and returns True if check should run
    
    def is_applicable(self, probe_data: Dict[str, Any]) -> bool:
        """Check if this control applies to the target based on probe results."""
        try:
            return self.applicability_rule(probe_data)
        except Exception:
            # If applicability check fails, assume not applicable
            return False


def _has_https(probe_data: Dict[str, Any]) -> bool:
    """Check if HTTPS probe succeeded."""
    https_result = probe_data.get('https')
    return https_result and https_result.success


def _has_http(probe_data: Dict[str, Any]) -> bool:
    """Check if HTTP probe succeeded."""
    http_result = probe_data.get('http')
    return http_result and http_result.success


def _has_set_cookie(probe_data: Dict[str, Any]) -> bool:
    """Check if response includes Set-Cookie header."""
    https_result = probe_data.get('https')
    if not https_result or not https_result.success:
        return False
    headers = https_result.data.get('headers', {})
    return 'Set-Cookie' in headers or 'set-cookie' in headers


def _is_apex_domain(probe_data: Dict[str, Any]) -> bool:
    """Check if this is the apex/root domain (not a subdomain).
    
    Email auth checks typically apply at domain level, not subdomain.
    """
    target = probe_data.get('target', '')
    # Simple heuristic: apex domain has exactly one dot
    return target.count('.') == 1


def _has_cname(probe_data: Dict[str, Any]) -> bool:
    """Check if domain has CNAME record in DNS probe results."""
    dns_result = probe_data.get('dns')
    if not dns_result or not dns_result.success:
        return False
    return bool(dns_result.data.get('cnames', []))


def _has_mx_records(probe_data: Dict[str, Any]) -> bool:
    """Check if domain has MX records (email capability)."""
    dns_result = probe_data.get('dns')
    if not dns_result or not dns_result.success:
        return False
    # Will be populated by DNS probe if we check MX
    return probe_data.get('has_mx', False)


# Registry of all checks we perform
CHECK_REGISTRY: List[CheckDefinition] = [
    # TLS/Certificate checks
    CheckDefinition(
        check_id="TLS_AVAILABLE",
        name="TLS Service Available",
        category=CheckCategory.TLS,
        description="HTTPS endpoint is reachable and accepts TLS connections",
        applicability_rule=lambda pd: True  # Always check
    ),
    CheckDefinition(
        check_id="TLS_MIN_VERSION",
        name="TLS Minimum Version",
        category=CheckCategory.TLS,
        description="TLS version is 1.2 or higher",
        applicability_rule=_has_https
    ),
    CheckDefinition(
        check_id="CERT_VALID_DATES",
        name="Certificate Validity Period",
        category=CheckCategory.TLS,
        description="Certificate is not expired and not yet valid",
        applicability_rule=_has_https
    ),
    CheckDefinition(
        check_id="CERT_HOSTNAME_MATCH",
        name="Certificate Hostname Match",
        category=CheckCategory.TLS,
        description="Certificate CN or SAN matches the target hostname",
        applicability_rule=_has_https
    ),
    
    # HTTP Security Headers
    CheckDefinition(
        check_id="HSTS_PRESENT",
        name="HSTS Header Present",
        category=CheckCategory.HTTP_SECURITY,
        description="Strict-Transport-Security header is present",
        applicability_rule=_has_https
    ),
    CheckDefinition(
        check_id="CSP_PRESENT",
        name="CSP Header Present",
        category=CheckCategory.HTTP_SECURITY,
        description="Content-Security-Policy header is present",
        applicability_rule=_has_https
    ),
    CheckDefinition(
        check_id="X_FRAME_OPTIONS",
        name="X-Frame-Options Present",
        category=CheckCategory.HTTP_SECURITY,
        description="X-Frame-Options header prevents clickjacking",
        applicability_rule=_has_https
    ),
    CheckDefinition(
        check_id="X_CONTENT_TYPE_OPTIONS",
        name="X-Content-Type-Options Present",
        category=CheckCategory.HTTP_SECURITY,
        description="X-Content-Type-Options: nosniff header is present",
        applicability_rule=_has_https
    ),
    CheckDefinition(
        check_id="REFERRER_POLICY",
        name="Referrer-Policy Present",
        category=CheckCategory.HTTP_SECURITY,
        description="Referrer-Policy header controls referrer information",
        applicability_rule=_has_https
    ),
    CheckDefinition(
        check_id="PERMISSIONS_POLICY",
        name="Permissions-Policy Present",
        category=CheckCategory.HTTP_SECURITY,
        description="Permissions-Policy header restricts browser features",
        applicability_rule=_has_https
    ),
    
    # Cookie Security
    CheckDefinition(
        check_id="COOKIE_SECURE",
        name="Cookie Secure Flag",
        category=CheckCategory.COOKIES,
        description="Cookies have Secure flag set",
        applicability_rule=_has_set_cookie
    ),
    CheckDefinition(
        check_id="COOKIE_HTTPONLY",
        name="Cookie HttpOnly Flag",
        category=CheckCategory.COOKIES,
        description="Cookies have HttpOnly flag set",
        applicability_rule=_has_set_cookie
    ),
    CheckDefinition(
        check_id="COOKIE_SAMESITE",
        name="Cookie SameSite Attribute",
        category=CheckCategory.COOKIES,
        description="Cookies have SameSite attribute set",
        applicability_rule=_has_set_cookie
    ),
    
    # Redirects
    CheckDefinition(
        check_id="HTTP_TO_HTTPS_REDIRECT",
        name="HTTP to HTTPS Redirect",
        category=CheckCategory.REDIRECT,
        description="HTTP requests redirect to HTTPS",
        applicability_rule=lambda pd: _has_http(pd) and _has_https(pd)
    ),
    
    # Email Authentication (domain-level only)
    CheckDefinition(
        check_id="SPF_PRESENT",
        name="SPF Record Present",
        category=CheckCategory.EMAIL,
        description="SPF record exists for email authentication",
        applicability_rule=_is_apex_domain
    ),
    CheckDefinition(
        check_id="SPF_POLICY",
        name="SPF Policy Strength",
        category=CheckCategory.EMAIL,
        description="SPF record has explicit all policy (-all or ~all)",
        applicability_rule=_is_apex_domain
    ),
    CheckDefinition(
        check_id="DMARC_PRESENT",
        name="DMARC Record Present",
        category=CheckCategory.EMAIL,
        description="DMARC record exists for email authentication",
        applicability_rule=_is_apex_domain
    ),
    CheckDefinition(
        check_id="DMARC_POLICY",
        name="DMARC Policy Strength",
        category=CheckCategory.EMAIL,
        description="DMARC policy is quarantine or reject (not none)",
        applicability_rule=_is_apex_domain
    ),
    
    # ========================================================================
    # SUBDOMAIN TAKEOVER RISK DETECTION (Non-Intrusive)
    # ========================================================================
    # Why: Dangling CNAME records can be hijacked by attackers to serve
    # malicious content under your domain. We passively detect risk signals.
    
    CheckDefinition(
        check_id="TAKEOVER_DANGLING_CNAME",
        name="Dangling CNAME Detection",
        category=CheckCategory.TAKEOVER,
        description="CNAME points to known cloud service that might be unclaimed",
        applicability_rule=_has_cname
    ),
    CheckDefinition(
        check_id="TAKEOVER_UNCLAIMED_SIGNATURE",
        name="Unclaimed Resource Signature",
        category=CheckCategory.TAKEOVER,
        description="HTTP response contains known unclaimed resource patterns",
        applicability_rule=_has_cname
    ),
    
    # ========================================================================
    # EMAIL SECURITY QUALITY (Beyond "exists" - measure strength)
    # ========================================================================
    # Why: Having DMARC/SPF is good, but weak policies don't protect against
    # email spoofing. We measure policy quality, not just presence.
    
    CheckDefinition(
        check_id="DMARC_POLICY_STRONG",
        name="DMARC Policy Enforcement",
        category=CheckCategory.EMAIL,
        description="DMARC policy is quarantine or reject (strong)",
        applicability_rule=_is_apex_domain
    ),
    CheckDefinition(
        check_id="SPF_SINGLE_RECORD",
        name="SPF Single Record",
        category=CheckCategory.EMAIL,
        description="Exactly one SPF record exists (not multiple)",
        applicability_rule=_is_apex_domain
    ),
    CheckDefinition(
        check_id="SPF_LOOKUP_LIMIT_OK",
        name="SPF Lookup Limit",
        category=CheckCategory.EMAIL,
        description="SPF record has ≤10 DNS lookups (RFC limit)",
        applicability_rule=_is_apex_domain
    ),
    CheckDefinition(
        check_id="SPF_TERMINAL_POLICY",
        name="SPF Terminal Policy",
        category=CheckCategory.EMAIL,
        description="SPF record has -all or ~all terminal policy",
        applicability_rule=_is_apex_domain
    ),
    CheckDefinition(
        check_id="MTA_STS_PRESENT",
        name="MTA-STS DNS Record",
        category=CheckCategory.EMAIL,
        description="MTA-STS DNS record exists for SMTP TLS enforcement",
        applicability_rule=lambda pd: _is_apex_domain(pd)
    ),
    CheckDefinition(
        check_id="MTA_STS_MODE_ENFORCE",
        name="MTA-STS Enforce Mode",
        category=CheckCategory.EMAIL,
        description="MTA-STS policy is in enforce mode (not testing/none)",
        applicability_rule=lambda pd: _is_apex_domain(pd)
    ),
    CheckDefinition(
        check_id="TLS_RPT_PRESENT",
        name="TLS-RPT Record",
        category=CheckCategory.EMAIL,
        description="TLS-RPT record exists for SMTP TLS reporting",
        applicability_rule=_is_apex_domain
    ),
    
    # ========================================================================
    # SECURITY.TXT (RFC 9116)
    # ========================================================================
    # Why: Security researchers need to know how to report vulnerabilities.
    # RFC 9116 standardizes this with /.well-known/security.txt
    
    CheckDefinition(
        check_id="SECURITY_TXT_PRESENT",
        name="Security.txt File Present",
        category=CheckCategory.SECURITY_DISCLOSURE,
        description="Security.txt file exists per RFC 9116",
        applicability_rule=_has_https
    ),
    CheckDefinition(
        check_id="SECURITY_TXT_CONTACT_VALID",
        name="Security.txt Contact Valid",
        category=CheckCategory.SECURITY_DISCLOSURE,
        description="Security.txt contains valid Contact field",
        applicability_rule=_has_https
    ),
]


def get_applicable_checks(probe_data: Dict[str, Any]) -> List[CheckDefinition]:
    """Get list of checks that apply to this target based on probe results."""
    applicable = []
    for check_def in CHECK_REGISTRY:
        if check_def.is_applicable(probe_data):
            applicable.append(check_def)
    return applicable


def get_check_by_id(check_id: str) -> CheckDefinition:
    """Get check definition by ID."""
    for check_def in CHECK_REGISTRY:
        if check_def.check_id == check_id:
            return check_def
    raise ValueError(f"Unknown check ID: {check_id}")
