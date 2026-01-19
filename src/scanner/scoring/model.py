"""Scoring model and confidence metrics.

Computes pass rates and risk scores with explicit confidence metrics.
Only tested controls count toward the score - no penalties for "Not Tested".
"""

import logging
from typing import List, Dict, Any
from dataclasses import dataclass, field
from collections import Counter

from util.types import CheckResult, CheckStatus

logger = logging.getLogger(__name__)


@dataclass
class SubdomainScore:
    """Security score for a single subdomain.
    
    Includes both the score and confidence metrics.
    """
    target: str
    total_checks: int  # All checks that were attempted
    tested_checks: int  # Checks that produced Pass/Fail
    passed_checks: int
    failed_checks: int
    not_tested_checks: int
    not_applicable_checks: int
    error_checks: int
    
    # Computed metrics
    pass_rate: float = 0.0  # passed / tested (0-100)
    attempt_rate: float = 0.0  # tested / total (0-100)
    error_rate: float = 0.0  # errors / total (0-100)
    
    # Risk categorization
    risk_level: str = "Unknown"  # Low, Medium, High, Critical, Unknown
    
    # Breakdown by category
    category_scores: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    
    def __post_init__(self):
        """Compute derived metrics."""
        # Pass rate: only count tested checks
        if self.tested_checks > 0:
            self.pass_rate = (self.passed_checks / self.tested_checks) * 100
        else:
            self.pass_rate = 0.0
        
        # Attempt rate: how many checks did we actually test
        if self.total_checks > 0:
            self.attempt_rate = (self.tested_checks / self.total_checks) * 100
            self.error_rate = (self.error_checks / self.total_checks) * 100
        else:
            self.attempt_rate = 0.0
            self.error_rate = 0.0
        
        # Risk level based on pass rate (only if we have enough tested checks)
        if self.tested_checks >= 3:  # Need at least 3 tests for meaningful score
            if self.pass_rate >= 90:
                self.risk_level = "Low"
            elif self.pass_rate >= 70:
                self.risk_level = "Medium"
            elif self.pass_rate >= 50:
                self.risk_level = "High"
            else:
                self.risk_level = "Critical"
        else:
            self.risk_level = "Unknown"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dict for output."""
        return {
            'target': self.target,
            'total_checks': self.total_checks,
            'tested_checks': self.tested_checks,
            'passed_checks': self.passed_checks,
            'failed_checks': self.failed_checks,
            'not_tested_checks': self.not_tested_checks,
            'not_applicable_checks': self.not_applicable_checks,
            'error_checks': self.error_checks,
            'pass_rate': round(self.pass_rate, 2),
            'attempt_rate': round(self.attempt_rate, 2),
            'error_rate': round(self.error_rate, 2),
            'risk_level': self.risk_level,
            'category_scores': self.category_scores
        }


class ScoringModel:
    """Computes security scores from check results.
    
    Clear rules:
    - Only Pass/Fail count toward score
    - Not Tested = insufficient evidence (don't count as fail)
    - Error = something broke (track separately)
    - Not Applicable = control doesn't apply (exclude from scoring)
    """
    
    def score_subdomain(self, target: str, results: List[CheckResult]) -> SubdomainScore:
        """Compute score for a single subdomain from its check results."""
        # Count statuses
        status_counts = Counter([r.status for r in results])
        
        passed = status_counts[CheckStatus.PASS]
        failed = status_counts[CheckStatus.FAIL]
        not_tested = status_counts[CheckStatus.NOT_TESTED]
        not_applicable = status_counts[CheckStatus.NOT_APPLICABLE]
        errors = status_counts[CheckStatus.ERROR]
        
        # Tested = Pass + Fail (the ones we can score)
        tested = passed + failed
        
        # Total = everything except Not Applicable
        total = passed + failed + not_tested + errors
        
        score = SubdomainScore(
            target=target,
            total_checks=total,
            tested_checks=tested,
            passed_checks=passed,
            failed_checks=failed,
            not_tested_checks=not_tested,
            not_applicable_checks=not_applicable,
            error_checks=errors
        )
        
        # Compute category breakdown
        score.category_scores = self._compute_category_scores(results)
        
        return score
    
    def _compute_category_scores(self, results: List[CheckResult]) -> Dict[str, Dict[str, Any]]:
        """Compute pass rates by check category."""
        from scanner.checks.registry import get_check_by_id
        
        # Group results by category
        by_category = {}
        for result in results:
            try:
                check_def = get_check_by_id(result.check_id)
                category = check_def.category.value
                
                if category not in by_category:
                    by_category[category] = []
                by_category[category].append(result)
            except:
                continue
        
        # Compute scores for each category
        category_scores = {}
        for category, cat_results in by_category.items():
            passed = sum(1 for r in cat_results if r.status == CheckStatus.PASS)
            failed = sum(1 for r in cat_results if r.status == CheckStatus.FAIL)
            tested = passed + failed
            
            if tested > 0:
                pass_rate = (passed / tested) * 100
            else:
                pass_rate = 0.0
            
            category_scores[category] = {
                'passed': passed,
                'failed': failed,
                'tested': tested,
                'pass_rate': round(pass_rate, 2)
            }
        
        return category_scores
    
    def aggregate_domain_score(self, subdomain_scores: List[SubdomainScore]) -> Dict[str, Any]:
        """Aggregate scores across all subdomains for domain-level summary.
        
        Returns overall stats and distribution.
        """
        if not subdomain_scores:
            return {
                'total_subdomains': 0,
                'avg_pass_rate': 0.0,
                'avg_attempt_rate': 0.0,
                'risk_distribution': {}
            }
        
        total = len(subdomain_scores)
        
        # Average metrics
        avg_pass_rate = sum(s.pass_rate for s in subdomain_scores) / total
        avg_attempt_rate = sum(s.attempt_rate for s in subdomain_scores) / total
        avg_error_rate = sum(s.error_rate for s in subdomain_scores) / total
        
        # Risk distribution
        risk_counts = Counter([s.risk_level for s in subdomain_scores])
        
        return {
            'total_subdomains': total,
            'avg_pass_rate': round(avg_pass_rate, 2),
            'avg_attempt_rate': round(avg_attempt_rate, 2),
            'avg_error_rate': round(avg_error_rate, 2),
            'risk_distribution': dict(risk_counts),
            'total_checks_run': sum(s.total_checks for s in subdomain_scores),
            'total_passed': sum(s.passed_checks for s in subdomain_scores),
            'total_failed': sum(s.failed_checks for s in subdomain_scores),
        }
