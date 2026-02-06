"""
Subdomain Takeover Detection
============================
Detects vulnerable subdomains susceptible to:
- Dangling CNAME attacks
- Service provider evidence detection
- Subdomain takeover via expired services
"""

import dns.resolver
import dns.exception
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from enum import Enum


class TakeoverProvider(Enum):
    """Known vulnerable service providers"""
    GITHUB = "github"
    HEROKU = "heroku"
    NETLIFY = "netlify"
    VERCEL = "vercel"
    AWS = "aws"
    AZURE = "azure"
    DIGITALOCEAN = "digitalocean"
    FASTLY = "fastly"
    SHOPIFY = "shopify"
    SQUARESPACE = "squarespace"
    WORDPRESS = "wordpress"


@dataclass
class TakeoverSignature:
    """Fingerprint for service provider detection"""
    provider: TakeoverProvider
    dns_patterns: List[str]  # CNAME patterns to look for
    response_strings: List[str]  # HTTP response indicators
    characteristic_errors: List[str]  # Characteristic error messages


class SubdomainTakeoverChecker:
    """Detects subdomain takeover vulnerabilities"""
    
    # Database of known vulnerable CNAME targets
    VULNERABLE_CNAMES = {
        'github.io': TakeoverProvider.GITHUB,
        'github.com': TakeoverProvider.GITHUB,
        'heroku.com': TakeoverProvider.HEROKU,
        'herokuapp.com': TakeoverProvider.HEROKU,
        'netlify.app': TakeoverProvider.NETLIFY,
        'netlify.com': TakeoverProvider.NETLIFY,
        'vercel.app': TakeoverProvider.VERCEL,
        'vercel.com': TakeoverProvider.VERCEL,
        'elasticbeanstalk.com': TakeoverProvider.AWS,
        'cloudfront.net': TakeoverProvider.AWS,
        'azurewebsites.net': TakeoverProvider.AZURE,
        'cloudapp.azure.com': TakeoverProvider.AZURE,
        'digitaloceanspaces.com': TakeoverProvider.DIGITALOCEAN,
        'fastly.net': TakeoverProvider.FASTLY,
        'myshopify.com': TakeoverProvider.SHOPIFY,
        'squarespace.com': TakeoverProvider.SQUARESPACE,
        'wordpress.com': TakeoverProvider.WORDPRESS,
    }
    
    # Service-specific takeover signatures
    TAKEOVER_SIGNATURES = {
        TakeoverProvider.GITHUB: [
            'There isn',
            'repository not found',
            'github 404',
        ],
        TakeoverProvider.HEROKU: [
            'No such app',
            'heroku | application error',
            'Name already exists',
        ],
        TakeoverProvider.NETLIFY: [
            'page not found',
            'netlify',
            'site not found',
        ],
        TakeoverProvider.VERCEL: [
            'invalid host header',
            'does not exist',
            'vercel',
        ],
        TakeoverProvider.AWS: [
            'NoSuchBucket',
            'InvalidParameterValue',
            'does not exist',
        ],
        TakeoverProvider.AZURE: [
            'web app stopped',
            'invalid host',
            'resource not found',
        ],
    }
    
    def __init__(self, resolver: Optional[dns.resolver.Resolver] = None):
        """Initialize with optional custom DNS resolver"""
        self.resolver = resolver or dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 10
    
    def check_dangling_cname(self, subdomain: str) -> Tuple[bool, Optional[str], bool]:
        """
        Check if subdomain has a dangling CNAME
        
        Returns:
            (is_dangling, cname_target, is_vulnerable_service)
        """
        try:
            answers = self.resolver.resolve(subdomain, 'CNAME')
            for rdata in answers:
                cname_target = str(rdata.target).rstrip('.')
                
                # Check if CNAME points to known vulnerable service
                is_vulnerable = self._is_vulnerable_cname(cname_target)
                
                # Check if CNAME resolves
                try:
                    self.resolver.resolve(cname_target, 'A')
                    # CNAME resolves, not dangling
                    return False, cname_target, is_vulnerable
                except dns.exception.DNSException:
                    # CNAME doesn't resolve - potentially dangling
                    return True, cname_target, is_vulnerable
        
        except dns.exception.NXDOMAIN:
            # No CNAME record
            return False, None, False
        except dns.exception.DNSException:
            return False, None, False
        except Exception:
            return False, None, False
        
        return False, None, False
    
    def check_takeover_vulnerability(self, subdomain: str) -> Dict:
        """
        Comprehensive takeover vulnerability check
        
        Returns:
            {
                'subdomain': str,
                'vulnerable': bool,
                'cname': str or None,
                'is_dangling': bool,
                'service_provider': str or None,
                'can_takeover': bool,
                'risk_level': 'critical' | 'high' | 'medium' | 'low' | 'none',
                'evidence': [str],
                'remediation': str
            }
        """
        is_dangling, cname_target, is_vulnerable_service = self.check_dangling_cname(subdomain)
        
        evidence = []
        risk_level = 'none'
        service_provider = None
        can_takeover = False
        remediation = ""
        
        if is_vulnerable_service and cname_target:
            service_provider = self._get_service_provider(cname_target)
            evidence.append(f"CNAME points to known vulnerable service: {cname_target}")
            
            if is_dangling:
                evidence.append("CNAME target does not resolve (dangling)")
                risk_level = 'critical'
                can_takeover = True
                remediation = f"Remove CNAME record or update to point to active {service_provider.value} resource. " \
                             f"Claim the service at {service_provider.value} or delete the CNAME."
            else:
                # Not dangling but vulnerable service
                risk_level = 'medium'
                remediation = f"Ensure {service_provider.value} resource is active and properly configured. " \
                             f"Remove CNAME if service is discontinued."
        elif is_dangling and cname_target:
            evidence.append(f"CNAME target '{cname_target}' does not resolve")
            risk_level = 'high'
            remediation = "Remove or update the CNAME record to point to an active resource"
        
        return {
            'subdomain': subdomain,
            'vulnerable': can_takeover or is_dangling,
            'cname': cname_target,
            'is_dangling': is_dangling,
            'service_provider': service_provider.value if service_provider else None,
            'can_takeover': can_takeover,
            'risk_level': risk_level,
            'evidence': evidence,
            'remediation': remediation
        }
    
    def check_subdomain_batch(self, subdomains: List[str]) -> Dict[str, Dict]:
        """
        Check multiple subdomains for takeover vulnerabilities
        
        Returns:
            {
                'subdomain': {...takeover check result...},
                ...
            }
        """
        results = {}
        for subdomain in subdomains:
            results[subdomain] = self.check_takeover_vulnerability(subdomain)
        return results
    
    def detect_takeover_patterns(self, subdomains: List[str]) -> Dict:
        """
        Analyze subdomains for takeover patterns
        
        Returns:
            {
                'total_subdomains': int,
                'vulnerable_count': int,
                'dangling_count': int,
                'by_provider': {
                    'provider_name': count,
                    ...
                },
                'critical_subdomains': [str],
                'recommendations': [str]
            }
        """
        results = self.check_subdomain_batch(subdomains)
        
        vulnerable_count = sum(1 for r in results.values() if r['vulnerable'])
        dangling_count = sum(1 for r in results.values() if r['is_dangling'])
        critical_subdomains = [s for s, r in results.items() if r['risk_level'] == 'critical']
        
        # Count by provider
        by_provider = {}
        for result in results.values():
            if result['service_provider']:
                by_provider[result['service_provider']] = by_provider.get(result['service_provider'], 0) + 1
        
        recommendations = []
        if dangling_count > 0:
            recommendations.append(
                f"{dangling_count} subdomains have dangling CNAMEs - immediate remediation required"
            )
        if vulnerable_count > dangling_count:
            recommendations.append(
                f"{vulnerable_count - dangling_count} subdomains point to vulnerable services - verify they are active"
            )
        
        return {
            'total_subdomains': len(subdomains),
            'vulnerable_count': vulnerable_count,
            'dangling_count': dangling_count,
            'by_provider': by_provider,
            'critical_subdomains': critical_subdomains,
            'recommendations': recommendations
        }
    
    def _is_vulnerable_cname(self, cname: str) -> bool:
        """Check if CNAME points to known vulnerable service"""
        for pattern, _ in self.VULNERABLE_CNAMES.items():
            if pattern in cname.lower():
                return True
        return False
    
    def _get_service_provider(self, cname: str) -> Optional[TakeoverProvider]:
        """Determine service provider from CNAME"""
        cname_lower = cname.lower()
        for pattern, provider in self.VULNERABLE_CNAMES.items():
            if pattern in cname_lower:
                return provider
        return None
