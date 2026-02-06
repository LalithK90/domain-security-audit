"""Check evaluator - runs security checks on probe results.

Takes probe data and evaluates it against security requirements.
Returns explicit CheckResult for each applicable check.
"""

import logging
from typing import Dict, Any, List
from datetime import datetime
from dateutil import parser as date_parser

from util.types import CheckResult, CheckStatus, ReasonCode, ProbeResult
from util.time import now_utc
from scanner.checks.registry import get_applicable_checks, CheckDefinition
from scanner.checks import advanced_checks

logger = logging.getLogger(__name__)


class CheckEvaluator:
    """Evaluates security checks based on probe results.
    
    This is where we turn raw probe data into pass/fail/error judgments.
    Each check gets its own evaluation function.
    """
    
    def __init__(self):
        """Initialize evaluator."""
        # Map check IDs to evaluation functions
        self.evaluators = {
            'TLS_AVAILABLE': self._eval_tls_available,
            'TLS_MIN_VERSION': self._eval_tls_min_version,
            'CERT_VALID_DATES': self._eval_cert_valid_dates,
            'CERT_HOSTNAME_MATCH': self._eval_cert_hostname_match,
            'HSTS_PRESENT': self._eval_hsts_present,
            'CSP_PRESENT': self._eval_csp_present,
            'X_FRAME_OPTIONS': self._eval_x_frame_options,
            'X_CONTENT_TYPE_OPTIONS': self._eval_x_content_type_options,
            'REFERRER_POLICY': self._eval_referrer_policy,
            'PERMISSIONS_POLICY': self._eval_permissions_policy,
            'COOKIE_SECURE': self._eval_cookie_secure,
            'COOKIE_HTTPONLY': self._eval_cookie_httponly,
            'COOKIE_SAMESITE': self._eval_cookie_samesite,
            'HTTP_TO_HTTPS_REDIRECT': self._eval_http_to_https_redirect,
            'SPF_PRESENT': self._eval_spf_present,
            'SPF_POLICY': self._eval_spf_policy,
            'DMARC_PRESENT': self._eval_dmarc_present,
            'DMARC_POLICY': self._eval_dmarc_policy,
            # Subdomain Takeover Checks
            'TAKEOVER_DANGLING_CNAME': self._eval_takeover_dangling_cname,
            'TAKEOVER_UNCLAIMED_SIGNATURE': self._eval_takeover_unclaimed_signature,
            # Email Quality Checks
            'DMARC_POLICY_STRONG': self._eval_dmarc_policy_strong,
            'SPF_SINGLE_RECORD': self._eval_spf_single_record,
            'SPF_LOOKUP_LIMIT_OK': self._eval_spf_lookup_limit_ok,
            'SPF_TERMINAL_POLICY': self._eval_spf_terminal_policy,
            'MTA_STS_PRESENT': self._eval_mta_sts_present,
            'MTA_STS_MODE_ENFORCE': self._eval_mta_sts_mode_enforce,
            'TLS_RPT_PRESENT': self._eval_tls_rpt_present,
            # Security Disclosure Checks
            'SECURITY_TXT_PRESENT': self._eval_security_txt_present,
            'SECURITY_TXT_CONTACT_VALID': self._eval_security_txt_contact_valid,
        }
    
    async def evaluate_all_async(self, target: str, probe_data: Dict[str, Any]) -> List[CheckResult]:
        """Evaluate all applicable checks for a target (async version).
        
        DESIGN RATIONALE:
        Some security checks require additional network requests beyond the base
        probes (DNS, HTTP, TLS, Email). Examples:
        - MTA-STS check needs to fetch and parse the MTA-STS policy document
        - TLS-RPT check needs to fetch the TLS reporting policy
        - security.txt check needs to fetch /.well-known/security.txt
        
        Running these synchronously (one at a time) would be very slow for many
        targets. Using async/await lets us run all additional checks in parallel,
        dramatically improving performance. This is why the evaluator itself is async.
        
        Args:
            target: The target being checked (FQDN)
            probe_data: Dict of probe results (keys: 'dns', 'http', 'https', 'tls', 'email')
        
        Returns:
            List of CheckResult objects, one per applicable check
        """
        # Add target to probe_data for applicability rules
        probe_data['target'] = target
        
        # Get applicable checks
        applicable_checks = get_applicable_checks(probe_data)
        
        results = []
        for check_def in applicable_checks:
            result = await self._evaluate_check_async(check_def, target, probe_data)
            results.append(result)
        
        return results
    
    async def evaluate_selective_async(self, target: str, probe_data: Dict[str, Any], 
                                       should_run_check) -> List[CheckResult]:
        """Evaluate only selected checks for a target (smart profiling mode).
        
        DESIGN RATIONALE:
        Smart profiling allows skipping irrelevant checks based on subdomain purpose.
        For example, mail.example.com doesn't need web security header checks.
        This can reduce scan time by 60-80% without losing relevant security coverage.
        
        Args:
            target: The target being checked (FQDN)
            probe_data: Dict of probe results (keys: 'dns', 'http', 'https', 'tls', 'email')
            should_run_check: Callable that takes check_id and returns True/False
        
        Returns:
            List of CheckResult objects, one per applicable and recommended check
        """
        # Add target to probe_data for applicability rules
        probe_data['target'] = target
        
        # Get applicable checks
        applicable_checks = get_applicable_checks(probe_data)
        
        results = []
        for check_def in applicable_checks:
            # Smart profiling: skip checks that aren't recommended for this target
            if not should_run_check(check_def.check_id):
                logger.debug(f"  ⏩ {target}: Skipping {check_def.check_id} (profiler recommendation)")
                continue
            
            result = await self._evaluate_check_async(check_def, target, probe_data)
            results.append(result)
        
        return results
    
    def get_all_check_names(self) -> List[str]:
        """Get list of all available check IDs.
        
        WHY: Used by smart profiling to report skipped checks.
        """
        return list(self.evaluators.keys())
    
    def evaluate_all(self, target: str, probe_data: Dict[str, Any]) -> List[CheckResult]:
        """Synchronous wrapper for evaluate_all_async (for backward compatibility).
        
        WHY: Some code may still call this synchronously.
        """
        import asyncio
        
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Already in async context - create task
                return asyncio.create_task(self.evaluate_all_async(target, probe_data))
            else:
                return loop.run_until_complete(self.evaluate_all_async(target, probe_data))
        except RuntimeError:
            # No event loop
            return asyncio.run(self.evaluate_all_async(target, probe_data))
    
    async def _evaluate_check_async(self, check_def: CheckDefinition, target: str, probe_data: Dict[str, Any]) -> CheckResult:
        """Evaluate a single check (async version).
        
        WHY: Handles both sync and async evaluators.
        """
        evaluator = self.evaluators.get(check_def.check_id)
        
        if not evaluator:
            # No evaluator defined - this shouldn't happen
            return CheckResult(
                check_id=check_def.check_id,
                target=target,
                status=CheckStatus.ERROR,
                reason_code=ReasonCode.UNKNOWN_ERROR,
                evidence={},
                message=f"No evaluator for {check_def.check_id}"
            )
        
        try:
            # Check if evaluator is async
            import inspect
            if inspect.iscoroutinefunction(evaluator):
                result = await evaluator(target, probe_data)
            else:
                result = evaluator(target, probe_data)
            
            return result
        except Exception as e:
            logger.error(f"Error evaluating {check_def.check_id} for {target}: {e}")
            return CheckResult(
                check_id=check_def.check_id,
                target=target,
                status=CheckStatus.ERROR,
                reason_code=ReasonCode.UNKNOWN_ERROR,
                evidence={'error': str(e)},
                message=f"Evaluator error: {e}"
            )
    
    def _evaluate_check(self, check_def: CheckDefinition, target: str, probe_data: Dict[str, Any]) -> CheckResult:
        """Evaluate a single check (sync version - deprecated).
        
        WHY: Backward compatibility only. Use _evaluate_check_async instead.
        """
        evaluator = self.evaluators.get(check_def.check_id)
        
        if not evaluator:
            # No evaluator defined - this shouldn't happen
            return CheckResult(
                check_def=check_def.check_id,
                target=target,
                status=CheckStatus.ERROR,
                reason_code=ReasonCode.UNKNOWN_ERROR,
                evidence={},
                message=f"No evaluator for {check_def.check_id}"
            )
        
        try:
            return evaluator(target, probe_data)
        except Exception as e:
            logger.error(f"Error evaluating {check_def.check_id} for {target}: {e}")
            return CheckResult(
                check_id=check_def.check_id,
                target=target,
                status=CheckStatus.ERROR,
                reason_code=ReasonCode.UNKNOWN_ERROR,
                evidence={'error': str(e)},
                message=f"Evaluation error: {str(e)}"
            )
    
    # Evaluation functions for each check
    
    def _eval_tls_available(self, target: str, probe_data: Dict[str, Any]) -> CheckResult:
        """Check if TLS service is available."""
        tls_result = probe_data.get('tls')
        
        if not tls_result:
            return CheckResult(
                check_id='TLS_AVAILABLE',
                target=target,
                status=CheckStatus.NOT_TESTED,
                reason_code=ReasonCode.NO_EVIDENCE,
                evidence={},
                message="No TLS probe result"
            )
        
        if tls_result.success:
            return CheckResult(
                check_id='TLS_AVAILABLE',
                target=target,
                status=CheckStatus.PASS,
                reason_code=ReasonCode.OK,
                evidence={'tls_version': tls_result.data.get('tls_version')},
                message="TLS service available"
            )
        else:
            # Network error (timeout, connection refused, DNS failure)
            # This is a measurement error, NOT a security policy failure
            return CheckResult(
                check_id='TLS_AVAILABLE',
                target=target,
                status=CheckStatus.ERROR,
                reason_code=ReasonCode.SERVICE_UNREACHABLE,
                evidence={'error': tls_result.error},
                message=f"TLS probe failed (network error): {tls_result.error}"
            )
    
    def _eval_tls_min_version(self, target: str, probe_data: Dict[str, Any]) -> CheckResult:
        """Check if TLS version is 1.2 or higher."""
        tls_result = probe_data.get('tls')
        
        if not tls_result or not tls_result.success:
            return CheckResult(
                check_id='TLS_MIN_VERSION',
                target=target,
                status=CheckStatus.NOT_TESTED,
                reason_code=ReasonCode.SERVICE_UNREACHABLE,
                evidence={},
                message="TLS service not reachable"
            )
        
        tls_version = tls_result.data.get('tls_version', '')
        
        # Check if version is 1.2 or higher
        if 'TLSv1.2' in tls_version or 'TLSv1.3' in tls_version:
            return CheckResult(
                check_id='TLS_MIN_VERSION',
                target=target,
                status=CheckStatus.PASS,
                reason_code=ReasonCode.COMPLIANT,
                evidence={'tls_version': tls_version},
                message=f"TLS version {tls_version} meets minimum requirement"
            )
        else:
            return CheckResult(
                check_id='TLS_MIN_VERSION',
                target=target,
                status=CheckStatus.FAIL,
                reason_code=ReasonCode.WEAK,
                evidence={'tls_version': tls_version},
                message=f"TLS version {tls_version} is below minimum (TLS 1.2)"
            )
    
    def _eval_cert_valid_dates(self, target: str, probe_data: Dict[str, Any]) -> CheckResult:
        """Check certificate validity dates."""
        tls_result = probe_data.get('tls')
        
        if not tls_result or not tls_result.success:
            return CheckResult(
                check_id='CERT_VALID_DATES',
                target=target,
                status=CheckStatus.NOT_TESTED,
                reason_code=ReasonCode.SERVICE_UNREACHABLE,
                evidence={},
                message="TLS service not reachable"
            )
        
        cert = tls_result.data.get('cert', {})
        not_before = cert.get('notBefore')
        not_after = cert.get('notAfter')
        
        if not not_before or not not_after:
            return CheckResult(
                check_id='CERT_VALID_DATES',
                target=target,
                status=CheckStatus.ERROR,
                reason_code=ReasonCode.PARSE_ERROR,
                evidence={},
                message="Could not parse certificate dates"
            )
        
        try:
            # Parse dates
            not_before_dt = date_parser.parse(not_before)
            not_after_dt = date_parser.parse(not_after)
            now = now_utc()
            
            if now < not_before_dt:
                return CheckResult(
                    check_id='CERT_VALID_DATES',
                    target=target,
                    status=CheckStatus.FAIL,
                    reason_code=ReasonCode.INVALID,
                    evidence={'not_before': not_before, 'not_after': not_after},
                    message=f"Certificate not yet valid (starts {not_before})"
                )
            elif now > not_after_dt:
                return CheckResult(
                    check_id='CERT_VALID_DATES',
                    target=target,
                    status=CheckStatus.FAIL,
                    reason_code=ReasonCode.EXPIRED,
                    evidence={'not_before': not_before, 'not_after': not_after},
                    message=f"Certificate expired on {not_after}"
                )
            else:
                return CheckResult(
                    check_id='CERT_VALID_DATES',
                    target=target,
                    status=CheckStatus.PASS,
                    reason_code=ReasonCode.OK,
                    evidence={'not_before': not_before, 'not_after': not_after},
                    message="Certificate is valid"
                )
        
        except Exception as e:
            return CheckResult(
                check_id='CERT_VALID_DATES',
                target=target,
                status=CheckStatus.ERROR,
                reason_code=ReasonCode.PARSE_ERROR,
                evidence={'error': str(e)},
                message=f"Error parsing dates: {e}"
            )
    
    def _eval_cert_hostname_match(self, target: str, probe_data: Dict[str, Any]) -> CheckResult:
        """Check if certificate hostname matches target."""
        tls_result = probe_data.get('tls')
        
        if not tls_result or not tls_result.success:
            return CheckResult(
                check_id='CERT_HOSTNAME_MATCH',
                target=target,
                status=CheckStatus.NOT_TESTED,
                reason_code=ReasonCode.SERVICE_UNREACHABLE,
                evidence={},
                message="TLS service not reachable"
            )
        
        cert = tls_result.data.get('cert', {})
        subject = cert.get('subject', {})
        san_list = cert.get('subjectAltName', [])
        
        cn = subject.get('commonName', '')
        
        # Check if target matches CN or any SAN
        matches = [cn] + san_list
        
        # Simple match (could be more sophisticated with wildcards)
        if target in matches:
            return CheckResult(
                check_id='CERT_HOSTNAME_MATCH',
                target=target,
                status=CheckStatus.PASS,
                reason_code=ReasonCode.OK,
                evidence={'cn': cn, 'san': san_list},
                message="Certificate hostname matches"
            )
        else:
            return CheckResult(
                check_id='CERT_HOSTNAME_MATCH',
                target=target,
                status=CheckStatus.FAIL,
                reason_code=ReasonCode.MISMATCH,
                evidence={'cn': cn, 'san': san_list, 'target': target},
                message=f"Hostname {target} not in certificate"
            )
    
    def _check_header_present(self, check_id: str, header_name: str, target: str, probe_data: Dict[str, Any]) -> CheckResult:
        """Generic header presence check."""
        https_result = probe_data.get('https')
        
        if not https_result or not https_result.success:
            return CheckResult(
                check_id=check_id,
                target=target,
                status=CheckStatus.NOT_TESTED,
                reason_code=ReasonCode.SERVICE_UNREACHABLE,
                evidence={},
                message="HTTPS service not reachable"
            )
        
        headers = https_result.data.get('headers', {})
        
        # Case-insensitive header lookup
        header_value = None
        for h, v in headers.items():
            if h.lower() == header_name.lower():
                header_value = v
                break
        
        if header_value:
            return CheckResult(
                check_id=check_id,
                target=target,
                status=CheckStatus.PASS,
                reason_code=ReasonCode.OK,
                evidence={header_name: header_value},
                message=f"{header_name} header present"
            )
        else:
            return CheckResult(
                check_id=check_id,
                target=target,
                status=CheckStatus.FAIL,
                reason_code=ReasonCode.MISSING,
                evidence={},
                message=f"{header_name} header missing"
            )
    
    def _eval_hsts_present(self, target: str, probe_data: Dict[str, Any]) -> CheckResult:
        return self._check_header_present('HSTS_PRESENT', 'Strict-Transport-Security', target, probe_data)
    
    def _eval_csp_present(self, target: str, probe_data: Dict[str, Any]) -> CheckResult:
        return self._check_header_present('CSP_PRESENT', 'Content-Security-Policy', target, probe_data)
    
    def _eval_x_frame_options(self, target: str, probe_data: Dict[str, Any]) -> CheckResult:
        return self._check_header_present('X_FRAME_OPTIONS', 'X-Frame-Options', target, probe_data)
    
    def _eval_x_content_type_options(self, target: str, probe_data: Dict[str, Any]) -> CheckResult:
        return self._check_header_present('X_CONTENT_TYPE_OPTIONS', 'X-Content-Type-Options', target, probe_data)
    
    def _eval_referrer_policy(self, target: str, probe_data: Dict[str, Any]) -> CheckResult:
        return self._check_header_present('REFERRER_POLICY', 'Referrer-Policy', target, probe_data)
    
    def _eval_permissions_policy(self, target: str, probe_data: Dict[str, Any]) -> CheckResult:
        return self._check_header_present('PERMISSIONS_POLICY', 'Permissions-Policy', target, probe_data)
    
    def _eval_cookie_secure(self, target: str, probe_data: Dict[str, Any]) -> CheckResult:
        """Check if cookies have Secure flag."""
        https_result = probe_data.get('https')
        
        if not https_result or not https_result.success:
            return CheckResult(
                check_id='COOKIE_SECURE',
                target=target,
                status=CheckStatus.NOT_TESTED,
                reason_code=ReasonCode.SERVICE_UNREACHABLE,
                evidence={},
                message="HTTPS service not reachable"
            )
        
        headers = https_result.data.get('headers', {})
        set_cookie = headers.get('Set-Cookie') or headers.get('set-cookie', '')
        
        if not set_cookie:
            return CheckResult(
                check_id='COOKIE_SECURE',
                target=target,
                status=CheckStatus.NOT_TESTED,
                reason_code=ReasonCode.NO_EVIDENCE,
                evidence={},
                message="No Set-Cookie header"
            )
        
        # Simple check for Secure flag
        if 'Secure' in set_cookie or 'secure' in set_cookie:
            return CheckResult(
                check_id='COOKIE_SECURE',
                target=target,
                status=CheckStatus.PASS,
                reason_code=ReasonCode.OK,
                evidence={'set_cookie': set_cookie[:100]},
                message="Cookie has Secure flag"
            )
        else:
            return CheckResult(
                check_id='COOKIE_SECURE',
                target=target,
                status=CheckStatus.FAIL,
                reason_code=ReasonCode.INSECURE,
                evidence={'set_cookie': set_cookie[:100]},
                message="Cookie missing Secure flag"
            )
    
    def _eval_cookie_httponly(self, target: str, probe_data: Dict[str, Any]) -> CheckResult:
        """Check if cookies have HttpOnly flag."""
        https_result = probe_data.get('https')
        
        if not https_result or not https_result.success:
            return CheckResult(
                check_id='COOKIE_HTTPONLY',
                target=target,
                status=CheckStatus.NOT_TESTED,
                reason_code=ReasonCode.SERVICE_UNREACHABLE,
                evidence={},
                message="HTTPS service not reachable"
            )
        
        headers = https_result.data.get('headers', {})
        set_cookie = headers.get('Set-Cookie') or headers.get('set-cookie', '')
        
        if not set_cookie:
            return CheckResult(
                check_id='COOKIE_HTTPONLY',
                target=target,
                status=CheckStatus.NOT_TESTED,
                reason_code=ReasonCode.NO_EVIDENCE,
                evidence={},
                message="No Set-Cookie header"
            )
        
        if 'HttpOnly' in set_cookie or 'httponly' in set_cookie:
            return CheckResult(
                check_id='COOKIE_HTTPONLY',
                target=target,
                status=CheckStatus.PASS,
                reason_code=ReasonCode.OK,
                evidence={'set_cookie': set_cookie[:100]},
                message="Cookie has HttpOnly flag"
            )
        else:
            return CheckResult(
                check_id='COOKIE_HTTPONLY',
                target=target,
                status=CheckStatus.FAIL,
                reason_code=ReasonCode.INSECURE,
                evidence={'set_cookie': set_cookie[:100]},
                message="Cookie missing HttpOnly flag"
            )
    
    def _eval_cookie_samesite(self, target: str, probe_data: Dict[str, Any]) -> CheckResult:
        """Check if cookies have SameSite attribute."""
        https_result = probe_data.get('https')
        
        if not https_result or not https_result.success:
            return CheckResult(
                check_id='COOKIE_SAMESITE',
                target=target,
                status=CheckStatus.NOT_TESTED,
                reason_code=ReasonCode.SERVICE_UNREACHABLE,
                evidence={},
                message="HTTPS service not reachable"
            )
        
        headers = https_result.data.get('headers', {})
        set_cookie = headers.get('Set-Cookie') or headers.get('set-cookie', '')
        
        if not set_cookie:
            return CheckResult(
                check_id='COOKIE_SAMESITE',
                target=target,
                status=CheckStatus.NOT_TESTED,
                reason_code=ReasonCode.NO_EVIDENCE,
                evidence={},
                message="No Set-Cookie header"
            )
        
        if 'SameSite' in set_cookie or 'samesite' in set_cookie:
            return CheckResult(
                check_id='COOKIE_SAMESITE',
                target=target,
                status=CheckStatus.PASS,
                reason_code=ReasonCode.OK,
                evidence={'set_cookie': set_cookie[:100]},
                message="Cookie has SameSite attribute"
            )
        else:
            return CheckResult(
                check_id='COOKIE_SAMESITE',
                target=target,
                status=CheckStatus.FAIL,
                reason_code=ReasonCode.MISSING,
                evidence={'set_cookie': set_cookie[:100]},
                message="Cookie missing SameSite attribute"
            )
    
    def _eval_http_to_https_redirect(self, target: str, probe_data: Dict[str, Any]) -> CheckResult:
        """Check if HTTP redirects to HTTPS."""
        http_result = probe_data.get('http')
        
        if not http_result or not http_result.success:
            return CheckResult(
                check_id='HTTP_TO_HTTPS_REDIRECT',
                target=target,
                status=CheckStatus.NOT_TESTED,
                reason_code=ReasonCode.SERVICE_UNREACHABLE,
                evidence={},
                message="HTTP service not reachable"
            )
        
        status = http_result.data.get('status')
        redirect_to = http_result.data.get('redirect_to', '')
        
        # Check if it's a redirect status
        if status in (301, 302, 303, 307, 308):
            # Check if redirect target is HTTPS
            if redirect_to.startswith('https://'):
                return CheckResult(
                    check_id='HTTP_TO_HTTPS_REDIRECT',
                    target=target,
                    status=CheckStatus.PASS,
                    reason_code=ReasonCode.OK,
                    evidence={'redirect_to': redirect_to, 'status': status},
                    message=f"HTTP redirects to HTTPS ({status})"
                )
            else:
                return CheckResult(
                    check_id='HTTP_TO_HTTPS_REDIRECT',
                    target=target,
                    status=CheckStatus.FAIL,
                    reason_code=ReasonCode.INSECURE,
                    evidence={'redirect_to': redirect_to, 'status': status},
                    message=f"HTTP redirects but not to HTTPS: {redirect_to}"
                )
        else:
            return CheckResult(
                check_id='HTTP_TO_HTTPS_REDIRECT',
                target=target,
                status=CheckStatus.FAIL,
                reason_code=ReasonCode.MISSING,
                evidence={'status': status},
                message=f"HTTP does not redirect (status {status})"
            )
    
    def _eval_spf_present(self, target: str, probe_data: Dict[str, Any]) -> CheckResult:
        """Check if SPF record is present."""
        email_results = probe_data.get('email', {})
        spf_result = email_results.get('spf')
        
        if not spf_result:
            return CheckResult(
                check_id='SPF_PRESENT',
                target=target,
                status=CheckStatus.NOT_TESTED,
                reason_code=ReasonCode.NO_EVIDENCE,
                evidence={},
                message="No SPF probe result"
            )
        
        if spf_result.success:
            return CheckResult(
                check_id='SPF_PRESENT',
                target=target,
                status=CheckStatus.PASS,
                reason_code=ReasonCode.OK,
                evidence={'record': spf_result.data.get('record', '')[:100]},
                message="SPF record present"
            )
        else:
            # Distinguish between DNS error vs confirmed absence
            error_msg = spf_result.error or ''
            
            # If it's a DNS timeout, server failure, or network error -> ERROR
            if any(keyword in error_msg.lower() for keyword in ['timeout', 'server', 'network', 'connection']):
                return CheckResult(
                    check_id='SPF_PRESENT',
                    target=target,
                    status=CheckStatus.ERROR,
                    reason_code=ReasonCode.NO_EVIDENCE,
                    evidence={'error': error_msg},
                    message=f"SPF check failed due to DNS error: {error_msg}"
                )
            
            # Otherwise, treat as confirmed absence -> FAIL
            return CheckResult(
                check_id='SPF_PRESENT',
                target=target,
                status=CheckStatus.FAIL,
                reason_code=ReasonCode.MISSING,
                evidence={},
                message="SPF record missing (NXDOMAIN)"
            )
    
    def _eval_spf_policy(self, target: str, probe_data: Dict[str, Any]) -> CheckResult:
        """Check SPF policy strength."""
        email_results = probe_data.get('email', {})
        spf_result = email_results.get('spf')
        
        if not spf_result or not spf_result.success:
            return CheckResult(
                check_id='SPF_POLICY',
                target=target,
                status=CheckStatus.NOT_TESTED,
                reason_code=ReasonCode.NO_EVIDENCE,
                evidence={},
                message="No SPF record available"
            )
        
        has_all = spf_result.data.get('has_all', False)
        record = spf_result.data.get('record', '')
        
        if has_all:
            return CheckResult(
                check_id='SPF_POLICY',
                target=target,
                status=CheckStatus.PASS,
                reason_code=ReasonCode.OK,
                evidence={'record': record[:100]},
                message="SPF has explicit all policy"
            )
        else:
            return CheckResult(
                check_id='SPF_POLICY',
                target=target,
                status=CheckStatus.FAIL,
                reason_code=ReasonCode.WEAK,
                evidence={'record': record[:100]},
                message="SPF missing explicit all policy"
            )
    
    def _eval_dmarc_present(self, target: str, probe_data: Dict[str, Any]) -> CheckResult:
        """Check if DMARC record is present."""
        email_results = probe_data.get('email', {})
        dmarc_result = email_results.get('dmarc')
        
        if not dmarc_result:
            return CheckResult(
                check_id='DMARC_PRESENT',
                target=target,
                status=CheckStatus.NOT_TESTED,
                reason_code=ReasonCode.NO_EVIDENCE,
                evidence={},
                message="No DMARC probe result"
            )
        
        if dmarc_result.success:
            return CheckResult(
                check_id='DMARC_PRESENT',
                target=target,
                status=CheckStatus.PASS,
                reason_code=ReasonCode.OK,
                evidence={'record': dmarc_result.data.get('record', '')[:100]},
                message="DMARC record present"
            )
        else:
            # Distinguish between DNS error vs confirmed absence
            error_msg = dmarc_result.error or ''
            
            # If it's a DNS timeout, server failure, or network error -> ERROR
            if any(keyword in error_msg.lower() for keyword in ['timeout', 'server', 'network', 'connection']):
                return CheckResult(
                    check_id='DMARC_PRESENT',
                    target=target,
                    status=CheckStatus.ERROR,
                    reason_code=ReasonCode.NO_EVIDENCE,
                    evidence={'error': error_msg},
                    message=f"DMARC check failed due to DNS error: {error_msg}"
                )
            
            # Otherwise, treat as confirmed absence -> FAIL
            return CheckResult(
                check_id='DMARC_PRESENT',
                target=target,
                status=CheckStatus.FAIL,
                reason_code=ReasonCode.MISSING,
                evidence={},
                message="DMARC record missing (NXDOMAIN)"
            )
    
    def _eval_dmarc_policy(self, target: str, probe_data: Dict[str, Any]) -> CheckResult:
        """Check DMARC policy strength."""
        email_results = probe_data.get('email', {})
        dmarc_result = email_results.get('dmarc')
        
        if not dmarc_result or not dmarc_result.success:
            return CheckResult(
                check_id='DMARC_POLICY',
                target=target,
                status=CheckStatus.NOT_TESTED,
                reason_code=ReasonCode.NO_EVIDENCE,
                evidence={},
                message="No DMARC record available"
            )
        
        policy = dmarc_result.data.get('policy', 'none')
        record = dmarc_result.data.get('record', '')
        
        if policy in ('quarantine', 'reject'):
            return CheckResult(
                check_id='DMARC_POLICY',
                target=target,
                status=CheckStatus.PASS,
                reason_code=ReasonCode.OK,
                evidence={'policy': policy, 'record': record},
                message=f"DMARC policy is {policy}"
            )
        else:
            return CheckResult(
                check_id='DMARC_POLICY',
                target=target,
                status=CheckStatus.FAIL,
                reason_code=ReasonCode.MISMATCH,
                evidence={'policy': policy, 'record': record},
                message=f"Weak DMARC policy: {policy} (should be quarantine or reject)"
            )

    # ========================================================================
    # NEW CHECK EVALUATORS - Subdomain Takeover
    # ========================================================================
    
    def _eval_takeover_dangling_cname(self, target: str, probe_data: Dict[str, Any]) -> CheckResult:
        """Check if CNAME points to a known takeover-vulnerable cloud service.
        
        Why: Dangling CNAMEs can be exploited for subdomain takeover if the target
        service is unclaimed (e.g., deleted S3 bucket, unclaimed Azure website).
        """
        dns_data = probe_data.get('dns', {})
        cname_target = advanced_checks.get_cname_target(dns_data)
        
        if not cname_target:
            return CheckResult(
                check_id='TAKEOVER_DANGLING_CNAME',
                target=target,
                status=CheckStatus.NOT_APPLICABLE,
                reason_code=ReasonCode.NO_EVIDENCE,
                evidence={},
                message="No CNAME record found"
            )
        
        provider = advanced_checks.detect_cname_provider(cname_target)
        
        if provider:
            return CheckResult(
                check_id='TAKEOVER_DANGLING_CNAME',
                target=target,
                status=CheckStatus.FAIL,
                reason_code=ReasonCode.MISMATCH,
                evidence={
                    'cname_target': cname_target,
                    'detected_provider': provider
                },
                message=f"CNAME points to potentially vulnerable service: {provider} ({cname_target}). Verify target is claimed."
            )
        else:
            return CheckResult(
                check_id='TAKEOVER_DANGLING_CNAME',
                target=target,
                status=CheckStatus.PASS,
                reason_code=ReasonCode.OK,
                evidence={'cname_target': cname_target},
                message=f"CNAME target not recognized as common takeover service: {cname_target}"
            )
    
    def _eval_takeover_unclaimed_signature(self, target: str, probe_data: Dict[str, Any]) -> CheckResult:
        """Check if HTTP(S) response contains unclaimed service signatures.
        
        Why: Error messages like 'NoSuchBucket' or 'Repository not found' indicate
        the underlying service is unclaimed, enabling subdomain takeover.
        """
        dns_data = probe_data.get('dns', {})
        cname_target = advanced_checks.get_cname_target(dns_data)
        
        if not cname_target:
            return CheckResult(
                check_id='TAKEOVER_UNCLAIMED_SIGNATURE',
                target=target,
                status=CheckStatus.NOT_APPLICABLE,
                reason_code=ReasonCode.NO_EVIDENCE,
                evidence={},
                message="No CNAME record found"
            )
        
        # Check HTTP and HTTPS responses
        http_data = probe_data.get('http', {})
        https_data = probe_data.get('https', {})
        
        http_body = http_data.get('body', '') if http_data else ''
        https_body = https_data.get('body', '') if https_data else ''
        combined_body = http_body + ' ' + https_body
        
        is_unclaimed, signature = advanced_checks.check_unclaimed_signature(combined_body)
        
        if is_unclaimed:
            return CheckResult(
                check_id='TAKEOVER_UNCLAIMED_SIGNATURE',
                target=target,
                status=CheckStatus.FAIL,
                reason_code=ReasonCode.MISMATCH,
                evidence={
                    'cname_target': cname_target,
                    'unclaimed_signature': signature
                },
                message=f"Unclaimed service detected! Signature: '{signature}'. SUBDOMAIN TAKEOVER RISK."
            )
        else:
            return CheckResult(
                check_id='TAKEOVER_UNCLAIMED_SIGNATURE',
                target=target,
                status=CheckStatus.PASS,
                reason_code=ReasonCode.OK,
                evidence={'cname_target': cname_target},
                message="No unclaimed service signatures detected in HTTP response"
            )

    # ========================================================================
    # NEW CHECK EVALUATORS - Email Security Quality
    # ========================================================================
    
    def _eval_dmarc_policy_strong(self, target: str, probe_data: Dict[str, Any]) -> CheckResult:
        """Check DMARC policy strength with alignment strictness.
        
        Why: DMARC p=reject with strict alignment (s) provides maximum email
        spoofing protection. Relaxed alignment (r) is weaker.
        """
        email_results = probe_data.get('email', {})
        dmarc_result = email_results.get('dmarc')
        
        if not dmarc_result or not dmarc_result.success:
            return CheckResult(
                check_id='DMARC_POLICY_STRONG',
                target=target,
                status=CheckStatus.NOT_TESTED,
                reason_code=ReasonCode.NO_EVIDENCE,
                evidence={},
                message="No DMARC record available"
            )
        
        record = dmarc_result.data.get('record', '')
        
        # Ensure record is a string (handle case where it might be a dict)
        if isinstance(record, dict):
            record = record.get('record', '')
        if not isinstance(record, str):
            record = str(record) if record else ''
        
        dmarc_data = advanced_checks.parse_dmarc_record(record)
        
        is_strong, policy_value = advanced_checks.evaluate_dmarc_policy_strength(dmarc_data)
        
        if is_strong:
            return CheckResult(
                check_id='DMARC_POLICY_STRONG',
                target=target,
                status=CheckStatus.PASS,
                reason_code=ReasonCode.COMPLIANT,
                evidence={
                    'policy': policy_value,
                    'dkim_alignment': dmarc_data.get('adkim', 'r'),
                    'spf_alignment': dmarc_data.get('aspf', 'r'),
                    'record': record
                },
                message=f"Strong DMARC: p={policy_value}"
            )
        else:
            return CheckResult(
                check_id='DMARC_POLICY_STRONG',
                target=target,
                status=CheckStatus.FAIL,
                reason_code=ReasonCode.MISMATCH,
                evidence={
                    'policy': policy_value,
                    'dkim_alignment': dmarc_data.get('adkim', 'r'),
                    'spf_alignment': dmarc_data.get('aspf', 'r'),
                    'record': record
                },
                message=f"Weak DMARC: p={policy_value} (should be quarantine or reject)"
            )
    
    def _eval_spf_single_record(self, target: str, probe_data: Dict[str, Any]) -> CheckResult:
        """Check that exactly one SPF record exists.
        
        Why: RFC 7208 requires exactly one SPF record. Multiple records cause
        validation failures and email delivery issues.
        """
        dns_result = probe_data.get('dns')
        if not dns_result or not hasattr(dns_result, 'data'):
            # No DNS result or wrong format
            txt_records = []
        else:
            txt_records = dns_result.data.get('txt', [])
        
        spf_records = [r for r in txt_records if r.startswith('v=spf1 ')]
        count = len(spf_records)
        
        if count == 0:
            return CheckResult(
                check_id='SPF_SINGLE_RECORD',
                target=target,
                status=CheckStatus.NOT_APPLICABLE,
                reason_code=ReasonCode.NO_EVIDENCE,
                evidence={},
                message="No SPF record found"
            )
        elif count == 1:
            return CheckResult(
                check_id='SPF_SINGLE_RECORD',
                target=target,
                status=CheckStatus.PASS,
                reason_code=ReasonCode.COMPLIANT,
                evidence={'spf_record': spf_records[0]},
                message="Exactly one SPF record found (RFC compliant)"
            )
        else:
            return CheckResult(
                check_id='SPF_SINGLE_RECORD',
                target=target,
                status=CheckStatus.FAIL,
                reason_code=ReasonCode.MISMATCH,
                evidence={'spf_count': count, 'spf_records': spf_records},
                message=f"Multiple SPF records found ({count}). RFC 7208 violation!"
            )
    
    def _eval_spf_lookup_limit_ok(self, target: str, probe_data: Dict[str, Any]) -> CheckResult:
        """Check SPF DNS lookup count is within RFC 7208 limit (≤10).
        
        Why: SPF records with >10 DNS lookups cause 'permerror', breaking email
        validation and causing delivery failures.
        """
        dns_result = probe_data.get('dns')
        if not dns_result or not hasattr(dns_result, 'data'):
            txt_records = []
        else:
            txt_records = dns_result.data.get('txt', [])
        
        spf_records = [r for r in txt_records if r.startswith('v=spf1 ')]
        
        if not spf_records:
            return CheckResult(
                check_id='SPF_LOOKUP_LIMIT_OK',
                target=target,
                status=CheckStatus.NOT_APPLICABLE,
                reason_code=ReasonCode.NO_EVIDENCE,
                evidence={},
                message="No SPF record found"
            )
        
        spf_data = advanced_checks.parse_spf_record(spf_records[0])
        lookup_count = spf_data.get('lookup_count', 0)
        
        if lookup_count <= 10:
            return CheckResult(
                check_id='SPF_LOOKUP_LIMIT_OK',
                target=target,
                status=CheckStatus.PASS,
                reason_code=ReasonCode.COMPLIANT,
                evidence={'lookup_count': lookup_count, 'spf_record': spf_records[0]},
                message=f"SPF lookup count OK: {lookup_count}/10 (RFC compliant)"
            )
        else:
            return CheckResult(
                check_id='SPF_LOOKUP_LIMIT_OK',
                target=target,
                status=CheckStatus.FAIL,
                reason_code=ReasonCode.MISMATCH,
                evidence={'lookup_count': lookup_count, 'spf_record': spf_records[0]},
                message=f"SPF lookup count exceeds limit: {lookup_count}/10 (causes permerror!)"
            )
    
    def _eval_spf_terminal_policy(self, target: str, probe_data: Dict[str, Any]) -> CheckResult:
        """Check SPF record has a terminal policy (-all, ~all, ?all).
        
        Why: SPF records without terminal policy default to neutral (?all),
        providing no protection against email spoofing.
        """
        dns_result = probe_data.get('dns')
        if not dns_result or not hasattr(dns_result, 'data'):
            txt_records = []
        else:
            txt_records = dns_result.data.get('txt', [])
        
        spf_records = [r for r in txt_records if r.startswith('v=spf1 ')]
        
        if not spf_records:
            return CheckResult(
                check_id='SPF_TERMINAL_POLICY',
                target=target,
                status=CheckStatus.NOT_APPLICABLE,
                reason_code=ReasonCode.NO_EVIDENCE,
                evidence={},
                message="No SPF record found"
            )
        
        spf_data = advanced_checks.parse_spf_record(spf_records[0])
        has_terminal = spf_data.get('has_terminal_policy', False)
        terminal_type = spf_data.get('terminal_type', 'none')
        
        if has_terminal and terminal_type in ('-all', '~all'):
            return CheckResult(
                check_id='SPF_TERMINAL_POLICY',
                target=target,
                status=CheckStatus.PASS,
                reason_code=ReasonCode.COMPLIANT,
                evidence={'terminal_policy': terminal_type, 'spf_record': spf_records[0]},
                message=f"SPF has strict terminal policy: {terminal_type}"
            )
        elif has_terminal and terminal_type == '?all':
            return CheckResult(
                check_id='SPF_TERMINAL_POLICY',
                target=target,
                status=CheckStatus.FAIL,
                reason_code=ReasonCode.MISMATCH,
                evidence={'terminal_policy': terminal_type, 'spf_record': spf_records[0]},
                message="SPF neutral policy (?all) provides no protection"
            )
        else:
            return CheckResult(
                check_id='SPF_TERMINAL_POLICY',
                target=target,
                status=CheckStatus.FAIL,
                reason_code=ReasonCode.MISSING,
                evidence={'spf_record': spf_records[0]},
                message="SPF record missing terminal policy (-all, ~all, or ?all)"
            )
    
    async def _eval_mta_sts_present(self, target: str, probe_data: Dict[str, Any]) -> CheckResult:
        """Check if MTA-STS policy is published (RFC 8461).
        
        Why: MTA-STS prevents SMTP MitM attacks by enforcing TLS and certificate
        validation for email delivery. Without it, email can be intercepted.
        """
        # Check for _mta-sts TXT record
        mta_sts_txt = advanced_checks.get_txt_record(f'_mta-sts.{target}')
        
        if not mta_sts_txt:
            return CheckResult(
                check_id='MTA_STS_PRESENT',
                target=target,
                status=CheckStatus.FAIL,
                reason_code=ReasonCode.MISSING,
                evidence={},
                message="MTA-STS TXT record not found at _mta-sts subdomain"
            )
        
        # Fetch policy file
        policy_content = await advanced_checks.fetch_mta_sts_policy(target)
        
        if policy_content:
            return CheckResult(
                check_id='MTA_STS_PRESENT',
                target=target,
                status=CheckStatus.PASS,
                reason_code=ReasonCode.OK,
                evidence={
                    'txt_record': mta_sts_txt,
                    'policy_url': f'https://mta-sts.{target}/.well-known/mta-sts.txt'
                },
                message="MTA-STS policy found"
            )
        else:
            return CheckResult(
                check_id='MTA_STS_PRESENT',
                target=target,
                status=CheckStatus.FAIL,
                reason_code=ReasonCode.MISSING,
                evidence={'txt_record': mta_sts_txt},
                message="MTA-STS TXT record exists but policy file not accessible"
            )
    
    async def _eval_mta_sts_mode_enforce(self, target: str, probe_data: Dict[str, Any]) -> CheckResult:
        """Check if MTA-STS policy mode is 'enforce'.
        
        Why: MTA-STS mode must be 'enforce' for protection. 'testing' mode only
        reports violations without enforcing TLS, providing no real security.
        """
        policy_content = await advanced_checks.fetch_mta_sts_policy(target)
        
        if not policy_content:
            return CheckResult(
                check_id='MTA_STS_MODE_ENFORCE',
                target=target,
                status=CheckStatus.NOT_APPLICABLE,
                reason_code=ReasonCode.NO_EVIDENCE,
                evidence={},
                message="No MTA-STS policy found"
            )
        
        policy_data = advanced_checks.parse_mta_sts_policy(policy_content)
        mode = policy_data.get('mode', 'none')
        
        if mode == 'enforce':
            return CheckResult(
                check_id='MTA_STS_MODE_ENFORCE',
                target=target,
                status=CheckStatus.PASS,
                reason_code=ReasonCode.COMPLIANT,
                evidence={'mode': mode, 'max_age': policy_data.get('max_age')},
                message="MTA-STS mode is 'enforce' (full protection)"
            )
        elif mode == 'testing':
            return CheckResult(
                check_id='MTA_STS_MODE_ENFORCE',
                target=target,
                status=CheckStatus.FAIL,
                reason_code=ReasonCode.MISMATCH,
                evidence={'mode': mode},
                message="MTA-STS mode is 'testing' (not enforced, no protection)"
            )
        else:
            return CheckResult(
                check_id='MTA_STS_MODE_ENFORCE',
                target=target,
                status=CheckStatus.FAIL,
                reason_code=ReasonCode.MISMATCH,
                evidence={'mode': mode},
                message=f"Invalid MTA-STS mode: {mode}"
            )
    
    def _eval_tls_rpt_present(self, target: str, probe_data: Dict[str, Any]) -> CheckResult:
        """Check if TLS-RPT reporting is enabled (RFC 8460).
        
        Why: TLS-RPT provides visibility into SMTP TLS failures, helping detect
        MitM attacks and configuration issues. Essential for monitoring email security.
        """
        # Check for _smtp._tls TXT record in DNS data
        # The DNS probe should have queried this already
        dns_result = probe_data.get('dns')
        
        # Look for TLS-RPT record in TXT records
        # ProbeResult is an object with .data attribute, not a dict
        txt_records = []
        if dns_result and hasattr(dns_result, 'data'):
            txt_records = dns_result.data.get('txt', [])
        
        tls_rpt_txt = None
        
        for record in txt_records:
            if isinstance(record, str) and record.startswith('v=TLSRPTv1'):
                tls_rpt_txt = record
                break
        
        if tls_rpt_txt:
            # Extract reporting email
            rua_match = tls_rpt_txt.split('rua=')
            rua = rua_match[1].split(';')[0].strip() if len(rua_match) > 1 else 'unknown'
            
            return CheckResult(
                check_id='TLS_RPT_PRESENT',
                target=target,
                status=CheckStatus.PASS,
                reason_code=ReasonCode.OK,
                evidence={'txt_record': tls_rpt_txt, 'reporting_email': rua},
                message=f"TLS-RPT enabled, reports to: {rua}"
            )
        else:
            return CheckResult(
                check_id='TLS_RPT_PRESENT',
                target=target,
                status=CheckStatus.FAIL,
                reason_code=ReasonCode.MISSING,
                evidence={},
                message="TLS-RPT not configured at _smtp._tls subdomain"
            )

    # ========================================================================
    # NEW CHECK EVALUATORS - Security Disclosure (RFC 9116)
    # ========================================================================
    
    async def _eval_security_txt_present(self, target: str, probe_data: Dict[str, Any]) -> CheckResult:
        """Check if security.txt file exists (RFC 9116).
        
        Why: security.txt provides standardized security contact info and
        vulnerability disclosure policy, enabling responsible disclosure.
        """
        result = await advanced_checks.fetch_security_txt(target)
        
        if result:
            location, content = result
            parsed = advanced_checks.parse_security_txt(content)
            
            return CheckResult(
                check_id='SECURITY_TXT_PRESENT',
                target=target,
                status=CheckStatus.PASS,
                reason_code=ReasonCode.OK,
                evidence={
                    'location': location,
                    'contacts': parsed.get('contacts', []),
                    'expires': parsed.get('expires')
                },
                message="security.txt found"
            )
        else:
            return CheckResult(
                check_id='SECURITY_TXT_PRESENT',
                target=target,
                status=CheckStatus.FAIL,
                reason_code=ReasonCode.MISSING,
                evidence={},
                message="security.txt not found (RFC 9116 not implemented)"
            )
    
    async def _eval_security_txt_contact_valid(self, target: str, probe_data: Dict[str, Any]) -> CheckResult:
        """Check if security.txt has valid contact information.
        
        Why: security.txt must contain at least one valid contact (email/URL/phone).
        Without valid contacts, researchers cannot report vulnerabilities.
        """
        result = await advanced_checks.fetch_security_txt(target)
        
        if not result:
            return CheckResult(
                check_id='SECURITY_TXT_CONTACT_VALID',
                target=target,
                status=CheckStatus.NOT_APPLICABLE,
                reason_code=ReasonCode.NO_EVIDENCE,
                evidence={},
                message="No security.txt file found"
            )
        
        location, content = result
        parsed = advanced_checks.parse_security_txt(content)
        has_valid_contact = parsed.get('has_valid_contact', False)
        contacts = parsed.get('contacts', [])
        expires = parsed.get('expires')
        
        if has_valid_contact:
            return CheckResult(
                check_id='SECURITY_TXT_CONTACT_VALID',
                target=target,
                status=CheckStatus.PASS,
                reason_code=ReasonCode.COMPLIANT,
                evidence={
                    'contacts': contacts,
                    'contact_count': len(contacts),
                    'expires': expires
                },
                message=f"Valid contact(s) found: {', '.join(contacts[:2])}"
            )
        else:
            return CheckResult(
                check_id='SECURITY_TXT_CONTACT_VALID',
                target=target,
                status=CheckStatus.FAIL,
                reason_code=ReasonCode.MISSING,
                evidence={'raw_content': content[:200]},
            message="No valid Contact: field found in security.txt (RFC 9116 violation)"
        )
