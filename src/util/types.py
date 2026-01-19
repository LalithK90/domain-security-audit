"""Core data types and enums used across the scanner.

These types make our measurement results explicit and consistent.
No magic strings floating around - every status and reason has a defined meaning.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Any, Optional
from datetime import datetime


class CheckStatus(Enum):
    """Explicit status for every security check.
    
    Pass: Control passed the measurement
    Fail: Control failed the measurement
    Not_Tested: We never attempted this check (e.g., service unreachable)
    Not_Applicable: Control doesn't apply to this target (by design)
    Error: We tried but something broke (network, parse error, etc.)
    """
    PASS = "Pass"
    FAIL = "Fail"
    NOT_TESTED = "Not Tested"
    NOT_APPLICABLE = "Not Applicable"
    ERROR = "Error"


class ReasonCode(Enum):
    """Standardized reason codes for check results.
    
    Makes analysis easier - we can aggregate by reason across all domains.
    """
    # Success reasons
    OK = "ok"
    COMPLIANT = "compliant"
    
    # Failure reasons
    MISSING = "missing"
    INVALID = "invalid"
    EXPIRED = "expired"
    WEAK = "weak"
    INSECURE = "insecure"
    MISMATCH = "mismatch"
    
    # Non-test reasons
    NO_EVIDENCE = "no_evidence"
    SERVICE_UNREACHABLE = "service_unreachable"
    NOT_APPLICABLE_BY_DESIGN = "not_applicable_by_design"
    
    # Error reasons
    NETWORK_ERROR = "network_error"
    TIMEOUT = "timeout"
    PARSE_ERROR = "parse_error"
    UNKNOWN_ERROR = "unknown_error"


@dataclass
class CheckResult:
    """Result of a single security check on a single target.
    
    This is our atomic unit of measurement. Every check produces one of these.
    Clean, explicit, and JSON-serializable.
    """
    check_id: str  # e.g., "TLS_MIN_VERSION", "HSTS_PRESENT"
    target: str  # subdomain or service being checked
    status: CheckStatus
    reason_code: ReasonCode
    evidence: Dict[str, Any] = field(default_factory=dict)  # Small JSON-able proof
    duration_ms: float = 0.0
    timestamp: Optional[datetime] = None
    message: str = ""  # Human-readable detail
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dict for CSV/JSON output."""
        return {
            'check_id': self.check_id,
            'target': self.target,
            'status': self.status.value,
            'reason_code': self.reason_code.value,
            'evidence': self.evidence,
            'duration_ms': round(self.duration_ms, 2),
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'message': self.message
        }


@dataclass
class ProbeResult:
    """Result from a probe (DNS, HTTP, TLS, etc.).
    
    Probes are lower-level than checks - they gather raw data.
    Checks then evaluate this data against security requirements.
    """
    target: str
    probe_type: str  # 'dns', 'http', 'tls', 'email'
    success: bool
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    duration_ms: float = 0.0
    timestamp: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dict for caching/logging."""
        return {
            'target': self.target,
            'probe_type': self.probe_type,
            'success': self.success,
            'data': self.data,
            'error': self.error,
            'duration_ms': round(self.duration_ms, 2),
            'timestamp': self.timestamp.isoformat() if self.timestamp else None
        }


@dataclass
class ScanTarget:
    """A target to be scanned (typically a subdomain)."""
    fqdn: str  # Fully qualified domain name
    discovered_from: str = "unknown"  # Where we found this target
    priority: int = 100  # Lower = higher priority
    
    def __hash__(self):
        return hash(self.fqdn)
    
    def __eq__(self, other):
        if isinstance(other, ScanTarget):
            return self.fqdn == other.fqdn
        return False


@dataclass
class ScanConfig:
    """Runtime configuration for the scanner.
    
    All values come from .env with sane defaults.
    No CLI flags needed - everything lives in .env.
    """
    domain: str
    out_dir: str = "out"
    enable_excel: bool = False
    force_rescan: bool = False
    cache_ttl_hours: int = 24
    wordlist_enum: bool = False
    
    # Performance tuning
    max_workers: int = 60
    rate_limit_delay: float = 0.05  # seconds between requests per worker
    dns_timeout: float = 4.0
    http_timeout: float = 8.0
    tls_timeout: float = 8.0
    
    # Enumeration settings
    use_ct_logs: bool = False
    wordlist_path: Optional[str] = None
    
    def __post_init__(self):
        """Auto-tune workers based on CPU if not explicitly set."""
        import os
        if self.max_workers == 60:  # Default wasn't overridden
            cpu_count = os.cpu_count() or 4
            # M1 Mac can handle good concurrency, but don't go crazy
            self.max_workers = min(120, max(30, cpu_count * 8))
