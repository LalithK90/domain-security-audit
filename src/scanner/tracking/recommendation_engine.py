"""
Recommendation Engine
=====================
Generates actionable remediation recommendations based on scan findings
"""

from typing import Dict, List, Tuple
from enum import Enum
from dataclasses import dataclass


class Priority(Enum):
    """Recommendation priority levels"""
    IMMEDIATE = 1  # Fix within 24 hours
    URGENT = 2     # Fix within 1 week
    HIGH = 3       # Fix within 1 month
    MEDIUM = 4     # Fix within 3 months
    LOW = 5        # Fix when possible


@dataclass
class Recommendation:
    """Individual remediation recommendation"""
    id: str
    title: str
    description: str
    priority: Priority
    affected_items: List[str]
    steps: List[str]
    estimated_effort: str  # 'quick', 'moderate', 'complex'
    expected_impact: str   # 'critical', 'major', 'moderate', 'minor'
    dependencies: List[str]  # Other recommendations that should be done first


class RecommendationEngine:
    """Generate remediation recommendations"""
    
    def __init__(self):
        """Initialize recommendation engine"""
        self.recommendations: Dict[str, Recommendation] = {}
        self._populate_recommendations()
    
    def _populate_recommendations(self):
        """Populate standard remediation recommendations"""
        
        # TLS/SSL Recommendations
        self.recommendations['tls_expired_cert'] = Recommendation(
            id='tls_expired_cert',
            title='Renew Expired SSL Certificate',
            description='One or more SSL certificates have expired. This prevents secure connections.',
            priority=Priority.IMMEDIATE,
            affected_items=[],
            steps=[
                '1. Purchase or renew certificate from certificate authority',
                '2. Generate CSR (Certificate Signing Request)',
                '3. Receive and validate certificate',
                '4. Install certificate on server',
                '5. Verify certificate chain is complete',
                '6. Monitor certificate expiration (set 30-day alert)'
            ],
            estimated_effort='moderate',
            expected_impact='critical',
            dependencies=[]
        )
        
        self.recommendations['tls_weak_cipher'] = Recommendation(
            id='tls_weak_cipher',
            title='Update TLS Configuration for Strong Ciphers',
            description='Weak or deprecated cipher suites are enabled. Use TLS 1.2+.',
            priority=Priority.URGENT,
            affected_items=[],
            steps=[
                '1. Audit current TLS configuration',
                '2. Remove SSLv3, TLS 1.0, 1.1 support',
                '3. Disable weak cipher suites (DES, MD5, RC4)',
                '4. Keep only AEAD ciphers (AES-GCM, ChaCha20)',
                '5. Test with SSL Labs or Qualys',
                '6. Monitor for client compatibility issues'
            ],
            estimated_effort='moderate',
            expected_impact='major',
            dependencies=[]
        )
        
        self.recommendations['missing_hsts'] = Recommendation(
            id='missing_hsts',
            title='Enable HSTS (HTTP Strict Transport Security)',
            description='HSTS forces secure connections and prevents downgrade attacks.',
            priority=Priority.HIGH,
            affected_items=[],
            steps=[
                '1. Add HSTS header: Strict-Transport-Security: max-age=31536000',
                '2. Test with header validation tools',
                '3. Ensure all subdomains use HTTPS',
                '4. Consider using includeSubDomains directive',
                '5. Monitor browser enforcement',
                '6. After validation, submit domain to HSTS preload list'
            ],
            estimated_effort='quick',
            expected_impact='major',
            dependencies=[]
        )
        
        # Email Security Recommendations
        self.recommendations['email_missing_spf'] = Recommendation(
            id='email_missing_spf',
            title='Deploy SPF Record',
            description='SPF record is missing. Configure SPF to prevent email spoofing.',
            priority=Priority.URGENT,
            affected_items=[],
            steps=[
                '1. Identify all email servers (IP addresses)',
                '2. Create SPF record: v=spf1 ip4:YOUR_IP -all',
                '3. Include third-party mail services if used (include:sendgrid.net)',
                '4. Use -all (hard fail) instead of ~all (soft fail)',
                '5. Publish record in DNS TXT record',
                '6. Validate with SPF checking tools',
                '7. Monitor SPF query limits'
            ],
            estimated_effort='quick',
            expected_impact='major',
            dependencies=[]
        )
        
        self.recommendations['email_weak_spf'] = Recommendation(
            id='email_weak_spf',
            title='Strengthen SPF Policy',
            description='SPF record uses soft fail (~all). Switch to hard fail (-all).',
            priority=Priority.HIGH,
            affected_items=[],
            steps=[
                '1. Review current SPF record mechanisms',
                '2. Remove unused services from SPF',
                '3. Ensure all legitimate senders are included',
                '4. Change from ~all to -all',
                '5. Test email delivery to ensure no breakage',
                '6. Wait 24 hours before deploying',
                '7. Monitor bounce rates'
            ],
            estimated_effort='quick',
            expected_impact='major',
            dependencies=['email_missing_spf']
        )
        
        self.recommendations['email_missing_dmarc'] = Recommendation(
            id='email_missing_dmarc',
            title='Deploy DMARC Policy',
            description='DMARC record is missing. Configure DMARC to authenticate emails.',
            priority=Priority.URGENT,
            affected_items=[],
            steps=[
                '1. Set up email for DMARC reports (rua/ruf addresses)',
                '2. Start with p=none (monitor mode)',
                '3. Create DMARC record at _dmarc.yourdomain.com',
                '4. Monitor reports for 30 days',
                '5. Ensure SPF and DKIM are properly configured',
                '6. Graduate to p=quarantine',
                '7. After validation, use p=reject',
                '8. Enable forensic reporting (ruf)'
            ],
            estimated_effort='moderate',
            expected_impact='critical',
            dependencies=['email_missing_spf']
        )
        
        self.recommendations['email_missing_dkim'] = Recommendation(
            id='email_missing_dkim',
            title='Configure DKIM (DomainKeys Identified Mail)',
            description='DKIM records not found. DKIM cryptographically authenticates emails.',
            priority=Priority.HIGH,
            affected_items=[],
            steps=[
                '1. Generate DKIM key pair (RSA 2048-bit minimum)',
                '2. Use mail server DKIM setup wizard (Postfix, sendmail, etc)',
                '3. Add DKIM record with selector (default, mail, k1, etc)',
                '4. Publish public key in DNS',
                '5. Sign all outgoing emails with private key',
                '6. Test with DKIM validation tools',
                '7. Monitor key rotation (annual recommended)'
            ],
            estimated_effort='moderate',
            expected_impact='major',
            dependencies=['email_missing_dmarc']
        )
        
        # Subdomain Takeover Recommendations
        self.recommendations['takeover_dangling_cname'] = Recommendation(
            id='takeover_dangling_cname',
            title='Remove Dangling CNAME Records',
            description='CNAME records point to non-existent services. Attackers can claim these.',
            priority=Priority.IMMEDIATE,
            affected_items=[],
            steps=[
                '1. Identify all dangling CNAME records',
                '2. Check if service is still in use',
                '3. Option A: Re-activate service and point CNAME to active resource',
                '4. Option B: If service discontinued, delete CNAME record',
                '5. Verify DNS changes propagated (8-48 hours)',
                '6. Monitor for resurrection attempts',
                '7. Implement quarterly DNS audits'
            ],
            estimated_effort='quick',
            expected_impact='critical',
            dependencies=[]
        )
        
        # HTTP Headers Recommendations
        self.recommendations['headers_missing_csp'] = Recommendation(
            id='headers_missing_csp',
            title='Implement Content Security Policy (CSP)',
            description='CSP header missing. Prevents XSS and injection attacks.',
            priority=Priority.HIGH,
            affected_items=[],
            steps=[
                '1. Start with CSP in report-only mode',
                '2. Add header: Content-Security-Policy-Report-Only: default-src \'self\'',
                '3. Monitor reports for 1-2 weeks',
                '4. Adjust policy based on legitimate resource usage',
                '5. Remove -Report-Only directive',
                '6. Test with CSP validator',
                '7. Document any intentional exceptions'
            ],
            estimated_effort='moderate',
            expected_impact='major',
            dependencies=[]
        )
        
        self.recommendations['headers_missing_x_frame_options'] = Recommendation(
            id='headers_missing_x_frame_options',
            title='Add X-Frame-Options Header',
            description='Prevents clickjacking attacks. Set to DENY or SAMEORIGIN.',
            priority=Priority.MEDIUM,
            affected_items=[],
            steps=[
                '1. Add header: X-Frame-Options: DENY (most secure)',
                '2. Use X-Frame-Options: SAMEORIGIN if embedding needed',
                '3. Verify application isn\'t embedded in frames',
                '4. Test with browser developer tools',
                '5. Monitor for user complaints'
            ],
            estimated_effort='quick',
            expected_impact='major',
            dependencies=[]
        )
        
        self.recommendations['headers_missing_x_content_type'] = Recommendation(
            id='headers_missing_x_content_type',
            title='Add X-Content-Type-Options Header',
            description='Prevents MIME-type sniffing attacks.',
            priority=Priority.MEDIUM,
            affected_items=[],
            steps=[
                '1. Add header: X-Content-Type-Options: nosniff',
                '2. Ensure all resources have correct Content-Type',
                '3. Test with curl: curl -I [domain]',
                '4. Validate headers in browser'
            ],
            estimated_effort='quick',
            expected_impact='moderate',
            dependencies=[]
        )
    
    def generate_recommendations(self, scan_results: Dict) -> List[Recommendation]:
        """
        Generate recommendations based on scan results
        
        Returns:
            List of recommendations, sorted by priority
        """
        recommendations = []
        
        # Check TLS/SSL issues
        if scan_results.get('tls_checks', {}).get('expired_certs'):
            recommendations.append(self.recommendations['tls_expired_cert'])
        
        if scan_results.get('tls_checks', {}).get('weak_ciphers'):
            recommendations.append(self.recommendations['tls_weak_cipher'])
        
        if not scan_results.get('http_headers', {}).get('hsts'):
            recommendations.append(self.recommendations['missing_hsts'])
        
        # Check email security
        if not scan_results.get('email_security', {}).get('spf', {}).get('has_spf'):
            recommendations.append(self.recommendations['email_missing_spf'])
        elif scan_results.get('email_security', {}).get('spf', {}).get('has_softfail'):
            recommendations.append(self.recommendations['email_weak_spf'])
        
        if not scan_results.get('email_security', {}).get('dmarc', {}).get('has_dmarc'):
            recommendations.append(self.recommendations['email_missing_dmarc'])
        
        if not scan_results.get('email_security', {}).get('dkim'):
            recommendations.append(self.recommendations['email_missing_dkim'])
        
        # Check takeover risks
        if scan_results.get('takeover', {}).get('critical', 0) > 0:
            rec = self.recommendations['takeover_dangling_cname'].copy()
            rec.affected_items = scan_results.get('takeover', {}).get('critical_subdomains', [])
            recommendations.append(rec)
        
        # Check HTTP headers
        if not scan_results.get('http_headers', {}).get('csp'):
            recommendations.append(self.recommendations['headers_missing_csp'])
        
        if not scan_results.get('http_headers', {}).get('x_frame_options'):
            recommendations.append(self.recommendations['headers_missing_x_frame_options'])
        
        if not scan_results.get('http_headers', {}).get('x_content_type_options'):
            recommendations.append(self.recommendations['headers_missing_x_content_type'])
        
        # Sort by priority
        recommendations.sort(key=lambda x: x.priority.value)
        
        return recommendations
    
    def get_priority_matrix(self, recommendations: List[Recommendation]) -> Dict:
        """
        Get matrix of recommendations by priority and effort
        
        Returns:
            {
                'quick_wins': [...],      # Low effort, high impact
                'short_term': [...],      # Moderate effort, high impact
                'long_term': [...],       # Complex effort, high impact
                'low_priority': [...]     # Low impact regardless
            }
        """
        matrix = {
            'quick_wins': [],
            'short_term': [],
            'long_term': [],
            'low_priority': []
        }
        
        for rec in recommendations:
            if rec.priority in [Priority.IMMEDIATE, Priority.URGENT]:
                if rec.estimated_effort == 'quick':
                    matrix['quick_wins'].append(rec)
                elif rec.estimated_effort == 'moderate':
                    matrix['short_term'].append(rec)
                else:
                    matrix['long_term'].append(rec)
            else:
                matrix['low_priority'].append(rec)
        
        return matrix
    
    def format_recommendations_report(self, recommendations: List[Recommendation]) -> str:
        """
        Format recommendations as human-readable report
        
        Returns:
            Formatted text report
        """
        report = "=" * 70 + "\n"
        report += "DOMAIN SECURITY REMEDIATION RECOMMENDATIONS\n"
        report += "=" * 70 + "\n\n"
        
        priority_map = {
            Priority.IMMEDIATE: "🔴 IMMEDIATE (Fix within 24 hours)",
            Priority.URGENT: "🟠 URGENT (Fix within 1 week)",
            Priority.HIGH: "🟡 HIGH (Fix within 1 month)",
            Priority.MEDIUM: "🔵 MEDIUM (Fix within 3 months)",
            Priority.LOW: "⚪ LOW (Fix when possible)"
        }
        
        current_priority = None
        for i, rec in enumerate(recommendations, 1):
            if rec.priority != current_priority:
                current_priority = rec.priority
                report += "\n" + priority_map[rec.priority] + "\n"
                report += "-" * 70 + "\n"
            
            report += f"\n{i}. {rec.title}\n"
            report += f"   Description: {rec.description}\n"
            report += f"   Effort: {rec.estimated_effort.upper()}\n"
            report += f"   Impact: {rec.expected_impact.upper()}\n"
            
            if rec.affected_items:
                report += f"   Affected: {', '.join(rec.affected_items)}\n"
            
            report += "   Steps:\n"
            for step in rec.steps:
                report += f"      {step}\n"
        
        return report
