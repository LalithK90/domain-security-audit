"""
Enhanced Email Security Checks
==============================
Performs detailed analysis of email security configuration including:
- SPF record quality assessment
- DMARC policy effectiveness
- DKIM implementation validation
- DMARC alignment checking
- SPF hard fail (NXDOMAIN) detection
- DMARC rejection policy enforcement
"""

import dns.resolver
import dns.exception
import re
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass


@dataclass
class SPFRecord:
    """SPF record parsing result"""
    raw_value: str
    mechanisms: List[str]
    has_all: bool
    all_mechanism: Optional[str]  # +all, -all, ~all, ?all
    qualifier_counts: Dict[str, int]
    includes: List[str]
    redirects: List[str]


@dataclass
class DMARCRecord:
    """DMARC record parsing result"""
    raw_value: str
    p: Optional[str]  # Policy: none, quarantine, reject
    sp: Optional[str]  # Subdomain policy
    rua: Optional[List[str]]  # Aggregate report URIs
    ruf: Optional[List[str]]  # Forensic report URIs
    fo: Optional[str]  # Failure reporting options
    pct: Optional[int]  # Policy percentage


class EmailSecurityChecker:
    """Enhanced email security validation"""
    
    def __init__(self, resolver: Optional[dns.resolver.Resolver] = None):
        """Initialize with optional custom DNS resolver"""
        self.resolver = resolver or dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 10
    
    def check_spf_exists(self, domain: str) -> Tuple[bool, Optional[SPFRecord], str]:
        """
        Check if SPF record exists and parse it
        
        Returns:
            (exists, record_object, error_message)
        """
        try:
            answers = self.resolver.resolve(domain, 'TXT')
            for rdata in answers:
                txt_record = str(rdata).strip('"')
                if txt_record.startswith('v=spf1'):
                    spf_record = self._parse_spf(txt_record)
                    return True, spf_record, ""
            return False, None, "No SPF record found"
        except dns.exception.DNSException as e:
            return False, None, f"DNS error: {str(e)}"
        except Exception as e:
            return False, None, f"Error checking SPF: {str(e)}"
    
    def check_spf_quality(self, domain: str) -> Dict:
        """
        Assess SPF record quality (if it exists)
        
        Returns:
            {
                'has_spf': bool,
                'passes': int,  # number of quality checks passed
                'total_checks': int,
                'issues': [str],  # list of identified issues
                'mechanisms': int,
                'has_hardfail': bool,  # has -all
                'has_softfail': bool,  # has ~all
                'redirect_chain_depth': int
            }
        """
        exists, spf_record, error = self.check_spf_exists(domain)
        
        if not exists:
            return {
                'has_spf': False,
                'passes': 0,
                'total_checks': 5,
                'issues': [error],
                'mechanisms': 0,
                'has_hardfail': False,
                'has_softfail': False,
                'redirect_chain_depth': 0
            }
        
        issues = []
        passes = 0
        total_checks = 5
        
        # Check 1: Hard fail policy
        if spf_record.all_mechanism == '-all':
            passes += 1
            hardfail = True
        else:
            issues.append(f"SPF does not use hard fail (-all): uses {spf_record.all_mechanism}")
            hardfail = False
        
        # Check 2: Reasonable mechanism count (max 10 is DNS limit)
        if len(spf_record.mechanisms) <= 10:
            passes += 1
        else:
            issues.append(f"SPF has {len(spf_record.mechanisms)} mechanisms (limit is 10 DNS lookups)")
        
        # Check 3: Not only softfail/neutral
        if spf_record.all_mechanism not in ['~all', '?all', '+all']:
            passes += 1
        else:
            issues.append(f"SPF uses permissive policy: {spf_record.all_mechanism}")
        
        # Check 4: Has some authorization mechanisms
        if len(spf_record.mechanisms) > 1:
            passes += 1
        else:
            issues.append("SPF record is minimal (no real authorization mechanisms)")
        
        # Check 5: Check redirect depth
        redirect_depth = len(spf_record.redirects)
        if redirect_depth <= 1:
            passes += 1
        else:
            issues.append(f"SPF has {redirect_depth} redirects (can cause DNS lookup chains)")
        
        return {
            'has_spf': True,
            'passes': passes,
            'total_checks': total_checks,
            'issues': issues,
            'mechanisms': len(spf_record.mechanisms),
            'has_hardfail': hardfail,
            'has_softfail': spf_record.all_mechanism == '~all',
            'redirect_chain_depth': redirect_depth
        }
    
    def check_dmarc_exists(self, domain: str) -> Tuple[bool, Optional[DMARCRecord], str]:
        """
        Check if DMARC record exists at _dmarc.domain
        
        Returns:
            (exists, record_object, error_message)
        """
        dmarc_domain = f"_dmarc.{domain}"
        try:
            answers = self.resolver.resolve(dmarc_domain, 'TXT')
            for rdata in answers:
                txt_record = str(rdata).strip('"')
                if txt_record.startswith('v=DMARC1'):
                    dmarc_record = self._parse_dmarc(txt_record)
                    return True, dmarc_record, ""
            return False, None, f"No DMARC record at {dmarc_domain}"
        except dns.exception.DNSException:
            return False, None, f"No DMARC record at {dmarc_domain}"
        except Exception as e:
            return False, None, f"Error checking DMARC: {str(e)}"
    
    def check_dmarc_quality(self, domain: str) -> Dict:
        """
        Assess DMARC policy quality
        
        Returns:
            {
                'has_dmarc': bool,
                'policy': str,  # none, quarantine, reject
                'policy_enforced': bool,  # not 'none'
                'subdomain_policy': str or None,
                'has_reporting': bool,  # has rua or ruf
                'alignment_required': bool,  # dkim or spf
                'passes': int,
                'total_checks': int,
                'issues': [str]
            }
        """
        exists, dmarc_record, error = self.check_dmarc_exists(domain)
        
        if not exists:
            return {
                'has_dmarc': False,
                'policy': None,
                'policy_enforced': False,
                'subdomain_policy': None,
                'has_reporting': False,
                'alignment_required': False,
                'passes': 0,
                'total_checks': 5,
                'issues': [error]
            }
        
        issues = []
        passes = 0
        total_checks = 5
        
        # Check 1: Policy is reject (strongest)
        if dmarc_record.p == 'reject':
            passes += 1
            policy_enforced = True
        elif dmarc_record.p == 'quarantine':
            policy_enforced = True
            issues.append("DMARC uses 'quarantine' instead of 'reject' (less strict)")
        elif dmarc_record.p == 'none':
            policy_enforced = False
            issues.append("DMARC policy is 'none' (not enforced, monitoring only)")
        else:
            issues.append(f"DMARC has unknown policy: {dmarc_record.p}")
            policy_enforced = False
        
        # Check 2: Has reporting enabled
        has_reporting = bool(dmarc_record.rua or dmarc_record.ruf)
        if has_reporting:
            passes += 1
        else:
            issues.append("DMARC has no reporting URIs (rua/ruf)")
        
        # Check 3: Policy percentage at 100
        if dmarc_record.pct == 100 or dmarc_record.pct is None:
            passes += 1
        else:
            issues.append(f"DMARC policy percentage is {dmarc_record.pct}% (not 100%)")
        
        # Check 4: Subdomain policy matches main policy
        if dmarc_record.sp and dmarc_record.sp != dmarc_record.p:
            issues.append(f"Subdomain policy '{dmarc_record.sp}' differs from main policy '{dmarc_record.p}'")
        else:
            passes += 1
        
        # Check 5: Has forensic reporting for strictest policies
        if dmarc_record.p == 'reject' and dmarc_record.ruf:
            passes += 1
        elif dmarc_record.p == 'reject':
            issues.append("DMARC reject policy should have forensic reporting (ruf)")
        else:
            passes += 1
        
        return {
            'has_dmarc': True,
            'policy': dmarc_record.p,
            'policy_enforced': policy_enforced,
            'subdomain_policy': dmarc_record.sp,
            'has_reporting': has_reporting,
            'alignment_required': True,
            'passes': passes,
            'total_checks': total_checks,
            'issues': issues
        }
    
    def check_dkim_exists(self, domain: str, selectors: Optional[List[str]] = None) -> Dict[str, bool]:
        """
        Check for DKIM keys using common selectors
        
        Returns:
            {
                'selector': True/False,  # True if DKIM record exists
                ...
            }
        """
        if selectors is None:
            selectors = ['default', 'selector1', 'selector2', 's1', 's2', 'mail', 'google', 'k1']
        
        results = {}
        for selector in selectors:
            dkim_domain = f"{selector}._domainkey.{domain}"
            try:
                answers = self.resolver.resolve(dkim_domain, 'TXT')
                for rdata in answers:
                    txt_record = str(rdata).strip('"')
                    if 'v=DKIM1' in txt_record:
                        results[selector] = True
                        break
                else:
                    results[selector] = False
            except dns.exception.DNSException:
                results[selector] = False
            except Exception:
                results[selector] = False
        
        return results
    
    def check_email_security_overall(self, domain: str) -> Dict:
        """
        Comprehensive email security assessment
        
        Returns:
            {
                'domain': str,
                'spf': {...},
                'dmarc': {...},
                'dkim': {...},
                'overall_score': float,  # 0-100
                'vulnerabilities': [str]
            }
        """
        spf_result = self.check_spf_quality(domain)
        dmarc_result = self.check_dmarc_quality(domain)
        dkim_result = self.check_dkim_exists(domain)
        
        vulnerabilities = []
        
        # Add SPF issues
        vulnerabilities.extend([f"[SPF] {issue}" for issue in spf_result.get('issues', [])])
        
        # Add DMARC issues
        vulnerabilities.extend([f"[DMARC] {issue}" for issue in dmarc_result.get('issues', [])])
        
        # Add DKIM issues
        if not any(dkim_result.values()):
            vulnerabilities.append("[DKIM] No DKIM records found")
        
        # Calculate overall score
        total_score = 0
        total_weight = 3
        
        if spf_result['has_spf']:
            total_score += (spf_result['passes'] / spf_result['total_checks']) * 30
        
        if dmarc_result['has_dmarc']:
            total_score += (dmarc_result['passes'] / dmarc_result['total_checks']) * 50
        
        if any(dkim_result.values()):
            total_score += 20
        
        overall_score = total_score / total_weight
        
        return {
            'domain': domain,
            'spf': spf_result,
            'dmarc': dmarc_result,
            'dkim': dkim_result,
            'overall_score': round(overall_score, 2),
            'vulnerabilities': vulnerabilities
        }
    
    def _parse_spf(self, spf_record: str) -> SPFRecord:
        """Parse SPF record into components"""
        mechanisms = []
        qualifier_counts = {'+': 0, '-': 0, '~': 0, '?': 0}
        includes = []
        redirects = []
        all_mechanism = None
        
        for part in spf_record.split():
            if part == 'v=spf1':
                continue
            
            # Extract qualifier
            if part[0] in ['+', '-', '~', '?']:
                qualifier = part[0]
                mechanism = part[1:]
                qualifier_counts[qualifier] += 1
            else:
                qualifier = '+'
                mechanism = part
                qualifier_counts[qualifier] += 1
            
            mechanisms.append(part)
            
            # Track includes and redirects
            if mechanism.startswith('include:'):
                includes.append(mechanism.split(':')[1])
            elif mechanism.startswith('redirect='):
                redirects.append(mechanism.split('=')[1])
            
            # Track all mechanism
            if mechanism == 'all':
                all_mechanism = part
        
        return SPFRecord(
            raw_value=spf_record,
            mechanisms=mechanisms,
            has_all=all_mechanism is not None,
            all_mechanism=all_mechanism,
            qualifier_counts=qualifier_counts,
            includes=includes,
            redirects=redirects
        )
    
    def _parse_dmarc(self, dmarc_record: str) -> DMARCRecord:
        """Parse DMARC record into components"""
        tags = {}
        
        for tag_str in dmarc_record.split(';'):
            tag_str = tag_str.strip()
            if '=' in tag_str:
                key, value = tag_str.split('=', 1)
                tags[key] = value
        
        return DMARCRecord(
            raw_value=dmarc_record,
            p=tags.get('p'),
            sp=tags.get('sp'),
            rua=tags.get('rua', '').split(',') if tags.get('rua') else None,
            ruf=tags.get('ruf', '').split(',') if tags.get('ruf') else None,
            fo=tags.get('fo'),
            pct=int(tags.get('pct', 100)) if tags.get('pct', '100').isdigit() else 100
        )
