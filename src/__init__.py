"""
Security Audit Framework - Core modules
"""

__version__ = "2.0"
__author__ = "Security Team"

from .security_scanner import SecurityScanner
from .security_dashboard import create_dashboard

__all__ = ['SecurityScanner', 'create_dashboard']
