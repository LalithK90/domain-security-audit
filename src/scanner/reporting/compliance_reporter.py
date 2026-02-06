"""
Compliance Reporter
===================
Maps domain security findings to compliance frameworks
(NIST CSF, OWASP Top 10, CIS Controls)
"""

from typing import Dict, List
from enum import Enum


class ComplianceFramework(Enum):
    """Supported compliance frameworks"""
    NIST_CSF = "NIST Cybersecurity Framework"
    OWASP_TOP_10 = "OWASP Top 10"
    CIS_CONTROLS = "CIS Controls v8"
    ISO_27001 = "ISO 27001"


class NISTFunction(Enum):
    """NIST CSF Functions"""
    IDENTIFY = "Identify"
    PROTECT = "Protect"
    DETECT = "Detect"
    RESPOND = "Respond"
    RECOVER = "Recover"


class ComplianceReporter:
    """Generate compliance audit reports"""
    
    # NIST CSF Mapping
    NIST_MAPPING = {
        'spf_configured': {
            'function': NISTFunction.PROTECT,
            'category': 'PR.AT: Awareness and Training',
            'requirement': 'PR.AT-1: All users are informed and trained'
        },
        'dmarc_configured': {
            'function': NISTFunction.PROTECT,
            'category': 'PR.AC: Identity Management',
            'requirement': 'PR.AC-1: Identities and credentials are issued'
        },
        'dkim_configured': {
            'function': NISTFunction.PROTECT,
            'category': 'PR.AC: Access Control',
            'requirement': 'PR.AC-3: Access is managed using policies'
        },
        'ssl_valid': {
            'function': NISTFunction.PROTECT,
            'category': 'PR.DS: Data Security',
            'requirement': 'PR.DS-2: Data in transit is protected'
        },
        'hsts_enabled': {
            'function': NISTFunction.PROTECT,
            'category': 'PR.DS: Data Security',
            'requirement': 'PR.DS-2: Data in transit is protected'
        },
        'csp_enabled': {
            'function': NISTFunction.PROTECT,
            'category': 'PR.PT: Protective Technology',
            'requirement': 'PR.PT-1: Security functions are configured'
        },
        'x_frame_options': {
            'function': NISTFunction.PROTECT,
            'category': 'PR.PT: Protective Technology',
            'requirement': 'PR.PT-1: Security functions are configured'
        },
        'no_dangling_cname': {
            'function': NISTFunction.IDENTIFY,
            'category': 'ID.AM: Asset Management',
            'requirement': 'ID.AM-1: Physical devices are inventoried'
        }
    }
    
    # OWASP Top 10 Mapping
    OWASP_MAPPING = {
        'ssl_valid': {
            'owasp_id': 'A02:2021',
            'title': 'Cryptographic Failures',
            'description': 'Valid SSL certificates required for secure communication'
        },
        'hsts_enabled': {
            'owasp_id': 'A02:2021',
            'title': 'Cryptographic Failures',
            'description': 'HSTS forces secure transport'
        },
        'csp_enabled': {
            'owasp_id': 'A03:2021',
            'title': 'Injection',
            'description': 'CSP mitigates XSS injection attacks'
        },
        'dmarc_configured': {
            'owasp_id': 'A07:2021',
            'title': 'Identification and Authentication Failures',
            'description': 'Email authentication prevents spoofing'
        },
        'x_frame_options': {
            'owasp_id': 'A04:2021',
            'title': 'Insecure Design',
            'description': 'Clickjacking protection via frame options'
        }
    }
    
    # CIS Controls Mapping
    CIS_MAPPING = {
        'ssl_valid': {
            'control': 'CIS 2.4',
            'title': 'Address Unauthorized Software',
            'description': 'Maintain authorized software'
        },
        'csp_enabled': {
            'control': 'CIS 13.2',
            'title': 'Application Security Tools',
            'description': 'Deploy application-level protection'
        },
        'dmarc_configured': {
            'control': 'CIS 12.6',
            'title': 'Securely Manage Dedicated Admin Accounts',
            'description': 'Email authentication prevents impersonation'
        }
    }
    
    def __init__(self):
        """Initialize compliance reporter"""
        self.mappings = {
            ComplianceFramework.NIST_CSF: self.NIST_MAPPING,
            ComplianceFramework.OWASP_TOP_10: self.OWASP_MAPPING,
            ComplianceFramework.CIS_CONTROLS: self.CIS_MAPPING
        }
    
    def generate_nist_report(self, scan_results: Dict) -> Dict:
        """
        Generate NIST CSF compliance report
        
        Returns:
            {
                'framework': 'NIST CSF',
                'functions': {
                    'Identify': {...},
                    'Protect': {...},
                    'Detect': {...},
                    'Respond': {...},
                    'Recover': {...}
                },
                'overall_compliance': float,  # 0-100
                'gaps': [...]
            }
        """
        compliance_status = self._assess_compliance(scan_results)
        
        functions = {
            'Identify': {'status': 'compliant', 'items': []},
            'Protect': {'status': 'compliant', 'items': []},
            'Detect': {'status': 'compliant', 'items': []},
            'Respond': {'status': 'compliant', 'items': []},
            'Recover': {'status': 'compliant', 'items': []}
        }
        
        gaps = []
        total_items = 0
        compliant_items = 0
        
        for control, status in compliance_status.items():
            if control in self.NIST_MAPPING:
                mapping = self.NIST_MAPPING[control]
                func_name = mapping['function'].value
                
                total_items += 1
                if status['compliant']:
                    compliant_items += 1
                    functions[func_name]['items'].append({
                        'control': mapping['category'],
                        'requirement': mapping['requirement'],
                        'status': 'COMPLIANT'
                    })
                else:
                    functions[func_name]['status'] = 'non-compliant'
                    gaps.append({
                        'function': func_name,
                        'control': mapping['category'],
                        'requirement': mapping['requirement'],
                        'gap': status.get('description', 'Not configured')
                    })
        
        overall_compliance = (compliant_items / total_items * 100) if total_items > 0 else 0
        
        return {
            'framework': 'NIST CSF',
            'compliance_percentage': round(overall_compliance, 2),
            'functions': functions,
            'gaps': gaps,
            'recommendations': self._get_nist_recommendations(gaps)
        }
    
    def generate_owasp_report(self, scan_results: Dict) -> Dict:
        """
        Generate OWASP Top 10 compliance report
        
        Returns:
            {
                'framework': 'OWASP Top 10',
                'covered_vulnerabilities': int,
                'uncovered_vulnerabilities': int,
                'items': [...],
                'risk_summary': {...}
            }
        """
        compliance_status = self._assess_compliance(scan_results)
        
        covered = []
        uncovered = []
        
        for control, status in compliance_status.items():
            if control in self.OWASP_MAPPING:
                mapping = self.OWASP_MAPPING[control]
                
                if status['compliant']:
                    covered.append({
                        'owasp_id': mapping['owasp_id'],
                        'title': mapping['title'],
                        'control': control,
                        'status': 'MITIGATED'
                    })
                else:
                    uncovered.append({
                        'owasp_id': mapping['owasp_id'],
                        'title': mapping['title'],
                        'control': control,
                        'status': 'EXPOSED',
                        'description': status.get('description')
                    })
        
        return {
            'framework': 'OWASP Top 10 2021',
            'covered_vulnerabilities': len(covered),
            'uncovered_vulnerabilities': len(uncovered),
            'coverage_percentage': round(
                len(covered) / max(1, len(covered) + len(uncovered)) * 100, 2
            ),
            'covered': covered,
            'uncovered': uncovered
        }
    
    def generate_cis_report(self, scan_results: Dict) -> Dict:
        """
        Generate CIS Controls compliance report
        
        Returns:
            {
                'framework': 'CIS Controls v8',
                'controls_implemented': int,
                'controls_missing': int,
                'items': [...],
                'implementation_status': float
            }
        """
        compliance_status = self._assess_compliance(scan_results)
        
        implemented = []
        missing = []
        
        for control, status in compliance_status.items():
            if control in self.CIS_MAPPING:
                mapping = self.CIS_MAPPING[control]
                
                if status['compliant']:
                    implemented.append({
                        'control_id': mapping['control'],
                        'title': mapping['title'],
                        'description': mapping['description'],
                        'status': 'IMPLEMENTED'
                    })
                else:
                    missing.append({
                        'control_id': mapping['control'],
                        'title': mapping['title'],
                        'description': mapping['description'],
                        'status': 'NOT_IMPLEMENTED'
                    })
        
        total = len(implemented) + len(missing)
        
        return {
            'framework': 'CIS Controls v8',
            'controls_implemented': len(implemented),
            'controls_missing': len(missing),
            'implementation_percentage': round(
                len(implemented) / max(1, total) * 100, 2
            ),
            'implemented': implemented,
            'missing': missing
        }
    
    def generate_combined_compliance_report(self, scan_results: Dict) -> Dict:
        """
        Generate multi-framework compliance report
        
        Returns:
            {
                'frameworks': {...},
                'overall_compliance_score': float,
                'priority_actions': [...]
            }
        """
        nist_report = self.generate_nist_report(scan_results)
        owasp_report = self.generate_owasp_report(scan_results)
        cis_report = self.generate_cis_report(scan_results)
        
        # Calculate overall compliance
        overall_compliance = (
            nist_report['compliance_percentage'] * 0.4 +
            owasp_report['coverage_percentage'] * 0.3 +
            cis_report['implementation_percentage'] * 0.3
        ) / 100
        
        # Identify priority actions
        priority_actions = self._determine_priority_actions(
            nist_report.get('gaps', []),
            owasp_report.get('uncovered', []),
            cis_report.get('missing', [])
        )
        
        return {
            'overall_compliance_score': round(overall_compliance, 2),
            'nist_csf': nist_report,
            'owasp_top10': owasp_report,
            'cis_controls': cis_report,
            'priority_actions': priority_actions
        }
    
    def _assess_compliance(self, scan_results: Dict) -> Dict[str, Dict]:
        """Assess compliance status of each control"""
        status = {}
        
        email_sec = scan_results.get('email_security', {})
        tls = scan_results.get('tls_checks', {})
        headers = scan_results.get('http_headers', {})
        takeover = scan_results.get('takeover', {})
        
        status['spf_configured'] = {
            'compliant': email_sec.get('spf', {}).get('has_spf', False),
            'description': 'SPF record not configured'
        }
        
        status['dmarc_configured'] = {
            'compliant': email_sec.get('dmarc', {}).get('has_dmarc', False),
            'description': 'DMARC policy not deployed'
        }
        
        status['dkim_configured'] = {
            'compliant': bool(email_sec.get('dkim')),
            'description': 'DKIM keys not found'
        }
        
        status['ssl_valid'] = {
            'compliant': not tls.get('has_expired_certs', False),
            'description': 'SSL certificate expired or invalid'
        }
        
        status['hsts_enabled'] = {
            'compliant': headers.get('hsts', False),
            'description': 'HSTS header not configured'
        }
        
        status['csp_enabled'] = {
            'compliant': headers.get('csp', False),
            'description': 'Content Security Policy not enabled'
        }
        
        status['x_frame_options'] = {
            'compliant': headers.get('x_frame_options', False),
            'description': 'X-Frame-Options header missing'
        }
        
        status['no_dangling_cname'] = {
            'compliant': takeover.get('critical', 0) == 0,
            'description': f"{takeover.get('critical', 0)} dangling CNAME records found"
        }
        
        return status
    
    def _get_nist_recommendations(self, gaps: List[Dict]) -> List[str]:
        """Generate NIST remediation recommendations"""
        recommendations = []
        
        for gap in gaps:
            if 'Protect' in gap['function']:
                recommendations.append(
                    f"Implement {gap['control']} as part of Protect function"
                )
        
        return recommendations[:5]
    
    def _determine_priority_actions(self, nist_gaps: List[Dict], 
                                   owasp_uncovered: List[Dict],
                                   cis_missing: List[Dict]) -> List[Dict]:
        """Determine priority remediation actions"""
        actions = []
        
        # Map gaps to actions
        gap_controls = {g.get('control') for g in nist_gaps}
        
        if 'PR.DS: Data Security' in gap_controls:
            actions.append({
                'priority': 1,
                'action': 'Ensure valid SSL certificates and enable HSTS',
                'frameworks': ['NIST', 'OWASP']
            })
        
        if 'PR.AC: Identity Management' in gap_controls:
            actions.append({
                'priority': 2,
                'action': 'Deploy DMARC and strengthen email authentication',
                'frameworks': ['NIST', 'OWASP']
            })
        
        if len(owasp_uncovered) > 0:
            actions.append({
                'priority': 1,
                'action': f"Remediate {len(owasp_uncovered)} OWASP Top 10 exposures",
                'frameworks': ['OWASP']
            })
        
        if len(cis_missing) > 0:
            actions.append({
                'priority': 2,
                'action': f"Implement {len(cis_missing)} missing CIS Controls",
                'frameworks': ['CIS']
            })
        
        return sorted(actions, key=lambda x: x['priority'])[:5]
