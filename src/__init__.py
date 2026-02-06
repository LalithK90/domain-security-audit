"""
Security Audit Framework - Core modules
"""

__version__ = "2.0"
__author__ = "Security Team"

# Import modules dynamically to avoid import errors during testing
__all__ = []

try:
    from .security_scanner import SecurityScanner
    __all__.append('SecurityScanner')
except ImportError:
    pass

try:
    from .security_dashboard import create_dashboard
    __all__.append('create_dashboard')
except ImportError:
    pass
