"""
Risk Calculator
===============
Calculates risk scores and severity ratings for vulnerabilities
"""

from typing import Dict, List, Tuple
from enum import Enum
from dataclasses import dataclass


class RiskLevel(Enum):
    """Risk severity levels"""
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1


@dataclass
class RiskFactor:
    """Individual risk factor"""
    category: str
    weight: float
    current_value: float
    max_value: float
    
    @property
    def score(self) -> float:
        """Calculate this factor's contribution to overall score"""
        return (self.current_value / max(1, self.max_value)) * self.weight


class RiskCalculator:
    """Calculate domain security risk scores"""
    
    # Risk factor weights (higher = more important)
    WEIGHTS = {
        'ssl_tls': 25,
        'email_security': 20,
        'http_headers': 15,
        'subdomain_enumeration': 10,
        'takeover_risk': 20,
        'known_vulnerabilities': 10
    }
    
    # Vulnerability impact mappings
    VULNERABILITY_IMPACTS = {
        'expired_certificate': RiskLevel.HIGH,
        'weak_cipher': RiskLevel.MEDIUM,
        'missing_hsts': RiskLevel.MEDIUM,
        'missing_spf': RiskLevel.MEDIUM,
        'missing_dmarc': RiskLevel.MEDIUM,
        'dangling_cname': RiskLevel.CRITICAL,
        'weak_spf': RiskLevel.LOW,
        'open_redirect': RiskLevel.MEDIUM,
        'clickjacking': RiskLevel.MEDIUM,
        'csp_missing': RiskLevel.LOW,
    }
    
    def __init__(self):
        """Initialize risk calculator"""
        self.total_weight = sum(self.WEIGHTS.values())
    
    def calculate_domain_risk(self, scan_results: Dict) -> Dict:
        """
        Calculate overall domain risk score
        
        Returns:
            {
                'overall_score': 0-100,
                'risk_level': 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO',
                'factors': {
                    'category': score,
                    ...
                },
                'top_risks': [
                    {
                        'vulnerability': str,
                        'impact': str,
                        'subdomains_affected': int
                    },
                    ...
                ],
                'remediation_priority': [
                    {
                        'rank': 1,
                        'item': str,
                        'potential_score_improvement': float
                    },
                    ...
                ]
            }
        """
        factors = {}
        
        # Calculate TLS/SSL score
        ssl_score = self._calculate_ssl_score(scan_results.get('tls_checks', {}))
        factors['ssl_tls'] = ssl_score
        
        # Calculate email security score
        email_score = self._calculate_email_score(scan_results.get('email_security', {}))
        factors['email_security'] = email_score
        
        # Calculate HTTP headers score
        headers_score = self._calculate_headers_score(scan_results.get('http_headers', {}))
        factors['http_headers'] = headers_score
        
        # Calculate subdomain risk
        subdomain_score = self._calculate_subdomain_score(scan_results.get('enumeration', {}))
        factors['subdomain_enumeration'] = subdomain_score
        
        # Calculate takeover risk
        takeover_score = self._calculate_takeover_score(scan_results.get('takeover', {}))
        factors['takeover_risk'] = takeover_score
        
        # Calculate known vulnerabilities score
        vuln_score = self._calculate_vulnerability_score(scan_results.get('vulnerabilities', {}))
        factors['known_vulnerabilities'] = vuln_score
        
        # Calculate weighted overall score
        overall_score = self._calculate_weighted_score(factors)
        
        # Determine risk level
        risk_level = self._get_risk_level(overall_score)
        
        # Get top risks
        top_risks = self._identify_top_risks(scan_results)
        
        # Get remediation priorities
        priorities = self._calculate_remediation_priorities(factors, top_risks)
        
        return {
            'overall_score': round(overall_score, 2),
            'risk_level': risk_level.name,
            'factors': {k: round(v, 2) for k, v in factors.items()},
            'top_risks': top_risks[:5],
            'remediation_priority': priorities
        }
    
    def calculate_subdomain_risk(self, subdomain: str, subdomain_data: Dict) -> Dict:
        """
        Calculate risk for individual subdomain
        
        Returns:
            {
                'subdomain': str,
                'risk_score': 0-100,
                'risk_level': str,
                'vulnerabilities': [str],
                'remediation': [str]
            }
        """
        score = 0
        vulnerabilities = []
        
        # Check TLS
        if subdomain_data.get('expired_cert'):
            score += 30
            vulnerabilities.append('Expired SSL certificate')
        
        if subdomain_data.get('weak_cipher'):
            score += 15
            vulnerabilities.append('Weak cipher suites')
        
        # Check DNS
        if subdomain_data.get('dangling_cname'):
            score += 40
            vulnerabilities.append('Dangling CNAME (takeover risk)')
        
        # Check HTTP
        if subdomain_data.get('open_redirect'):
            score += 20
            vulnerabilities.append('Open redirect vulnerability')
        
        risk_level = self._get_risk_level(score)
        
        # Suggest remediations
        remediations = self._suggest_remediation(vulnerabilities)
        
        return {
            'subdomain': subdomain,
            'risk_score': min(100, score),
            'risk_level': risk_level.name,
            'vulnerabilities': vulnerabilities,
            'remediation': remediations
        }
    
    def _calculate_ssl_score(self, tls_data: Dict) -> float:
        """Calculate SSL/TLS security score"""
        if not tls_data:
            return 0
        
        score = 100
        
        # Deductions
        if tls_data.get('has_expired_certs'):
            score -= 50
        if tls_data.get('weak_ciphers'):
            score -= 20
        if not tls_data.get('has_hsts'):
            score -= 15
        if tls_data.get('tls_version') == 'TLS 1.0':
            score -= 30
        elif tls_data.get('tls_version') == 'TLS 1.1':
            score -= 15
        
        return max(0, score)
    
    def _calculate_email_score(self, email_data: Dict) -> float:
        """Calculate email security score"""
        if not email_data:
            return 0
        
        score = 0
        
        # SPF (0-30 points)
        if email_data.get('spf', {}).get('has_spf'):
            score += 15
            if email_data.get('spf', {}).get('has_hardfail'):
                score += 15
        
        # DMARC (0-40 points)
        if email_data.get('dmarc', {}).get('has_dmarc'):
            score += 20
            if email_data.get('dmarc', {}).get('policy_enforced'):
                score += 20
        
        # DKIM (0-30 points)
        dkim_count = sum(1 for v in email_data.get('dkim', {}).values() if v)
        if dkim_count > 0:
            score += min(30, dkim_count * 10)
        
        return min(100, score)
    
    def _calculate_headers_score(self, headers_data: Dict) -> float:
        """Calculate HTTP headers security score"""
        if not headers_data:
            return 0
        
        score = 100
        critical_headers = ['X-Frame-Options', 'X-Content-Type-Options', 'Content-Security-Policy']
        
        missing = sum(1 for h in critical_headers if not headers_data.get(h))
        score -= missing * 20
        
        return max(0, score)
    
    def _calculate_subdomain_score(self, enum_data: Dict) -> float:
        """Calculate subdomain enumeration risk"""
        subdomain_count = len(enum_data.get('subdomains', []))
        
        # More subdomains = larger attack surface
        if subdomain_count > 100:
            return 100
        elif subdomain_count > 50:
            return 80
        elif subdomain_count > 20:
            return 60
        elif subdomain_count > 10:
            return 40
        else:
            return 20
    
    def _calculate_takeover_score(self, takeover_data: Dict) -> float:
        """Calculate takeover vulnerability risk"""
        if not takeover_data:
            return 0
        
        score = 0
        
        # Critical vulnerabilities
        critical = takeover_data.get('critical', 0)
        score += critical * 20
        
        # High risk
        high = takeover_data.get('high', 0)
        score += high * 10
        
        return min(100, score)
    
    def _calculate_vulnerability_score(self, vuln_data: Dict) -> float:
        """Calculate known vulnerability risk"""
        if not vuln_data:
            return 0
        
        score = 0
        
        score += vuln_data.get('critical', 0) * 25
        score += vuln_data.get('high', 0) * 15
        score += vuln_data.get('medium', 0) * 8
        score += vuln_data.get('low', 0) * 2
        
        return min(100, score)
    
    def _calculate_weighted_score(self, factors: Dict[str, float]) -> float:
        """Calculate weighted overall score"""
        total_score = 0
        
        for category, weight in self.WEIGHTS.items():
            factor_score = factors.get(category, 0)
            total_score += factor_score * (weight / self.total_weight)
        
        return total_score
    
    def _get_risk_level(self, score: float) -> RiskLevel:
        """Determine risk level from score"""
        if score >= 80:
            return RiskLevel.CRITICAL
        elif score >= 60:
            return RiskLevel.HIGH
        elif score >= 40:
            return RiskLevel.MEDIUM
        elif score >= 20:
            return RiskLevel.LOW
        else:
            return RiskLevel.INFO
    
    def _identify_top_risks(self, scan_results: Dict) -> List[Dict]:
        """Identify top vulnerability risks"""
        risks = []
        
        # Check for critical vulnerabilities
        if scan_results.get('takeover', {}).get('critical', 0) > 0:
            risks.append({
                'vulnerability': 'Dangling CNAME (Subdomain Takeover)',
                'impact': 'CRITICAL',
                'subdomains_affected': scan_results.get('takeover', {}).get('critical', 0)
            })
        
        if scan_results.get('email_security', {}).get('dmarc', {}).get('policy') == 'none':
            risks.append({
                'vulnerability': 'DMARC policy not enforced',
                'impact': 'HIGH',
                'subdomains_affected': 1
            })
        
        if not scan_results.get('email_security', {}).get('spf', {}).get('has_spf'):
            risks.append({
                'vulnerability': 'Missing SPF record',
                'impact': 'MEDIUM',
                'subdomains_affected': 1
            })
        
        return risks
    
    def _calculate_remediation_priorities(self, factors: Dict[str, float], 
                                         risks: List[Dict]) -> List[Dict]:
        """Calculate remediation priority ranking"""
        priorities = []
        
        # Sort factors by lowest score
        sorted_factors = sorted(factors.items(), key=lambda x: x[1])
        
        for rank, (category, score) in enumerate(sorted_factors, 1):
            if score < 70:  # Focus on low-scoring areas
                improvement = 100 - score
                priorities.append({
                    'rank': rank,
                    'item': f"Improve {category.replace('_', ' ').title()}",
                    'potential_score_improvement': round(improvement, 2),
                    'current_score': round(score, 2)
                })
        
        return priorities[:5]  # Return top 5 priorities
    
    def _suggest_remediation(self, vulnerabilities: List[str]) -> List[str]:
        """Suggest remediation steps for vulnerabilities"""
        suggestions = []
        
        for vuln in vulnerabilities:
            if 'Expired' in vuln:
                suggestions.append('Renew SSL certificate immediately')
            elif 'cipher' in vuln.lower():
                suggestions.append('Update TLS configuration to use strong ciphers only')
            elif 'Dangling CNAME' in vuln:
                suggestions.append('Remove or update CNAME record to active service')
            elif 'SPF' in vuln:
                suggestions.append('Configure SPF record with proper authorization')
            elif 'DMARC' in vuln:
                suggestions.append('Deploy DMARC policy (start with p=none, graduate to p=reject)')
            elif 'redirect' in vuln.lower():
                suggestions.append('Validate and restrict redirect destinations')
        
        return suggestions
