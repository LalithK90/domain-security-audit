"""Domain profiles and configuration.

In our simplified model, DOMAIN is the only external variable.
This module handles extracting the base domain and any profile-specific logic.
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)


class DomainProfile:
    """Domain-specific configuration and metadata.
    
    Right now this is simple - just the domain name.
    Could expand later with domain-specific rules if needed.
    """
    
    def __init__(self, domain: str):
        """Initialize profile for a domain."""
        self.domain = domain.lower().strip()
        self.base_domain = self._extract_base_domain()
        
        logger.info(f"Domain profile: {self.domain}")
    
    def _extract_base_domain(self) -> str:
        """Extract base/apex domain from FQDN.
        
        For most cases, this is the domain itself.
        If it's a subdomain, extracts the base.
        """
        parts = self.domain.split('.')
        
        # If 2 parts, it's already a base domain
        if len(parts) == 2:
            return self.domain
        
        # If more, take last two parts as base domain
        # (This is simplistic - doesn't handle .co.uk etc, but works for .lk, .com, etc.)
        if len(parts) > 2:
            return '.'.join(parts[-2:])
        
        return self.domain
    
    def is_apex_domain(self) -> bool:
        """Check if this is the apex/base domain (not a subdomain)."""
        return self.domain == self.base_domain
    
    def get_report_name(self) -> str:
        """Get standard report filename for this domain."""
        return f"{self.domain}_security_report"
