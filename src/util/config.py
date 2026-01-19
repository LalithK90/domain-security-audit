"""Enhanced configuration for persistent state management.

Loads all settings from .env with sensible defaults.
Extends existing config with new state management settings.
"""

import os
import multiprocessing
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv


class Config:
    """Configuration for persistent scanning system.
    
    WHY this exists: Single source of truth for all config.
    All defaults are production-ready for M1 Mac with 16GB RAM.
    """
    
    def __init__(self):
        """Load configuration from .env file."""
        # Load .env from repo root
        repo_root = Path(__file__).parent.parent.parent
        env_file = repo_root / ".env"
        
        if env_file.exists():
            load_dotenv(env_file)
        
        # ===== REQUIRED SETTINGS =====
        self.domain = os.getenv("DOMAIN")
        if not self.domain:
            raise ValueError("DOMAIN must be set in .env file (e.g., DOMAIN=ac.lk)")
        
        # ===== STATE MANAGEMENT =====
        self.state_dir = Path(os.getenv("STATE_DIR", "state"))
        self.out_dir = Path(os.getenv("OUT_DIR", "out"))
        
        # Rescan policy
        self.rescan_hours = int(os.getenv("RESCAN_HOURS", "24"))
        self.error_retry_hours = int(os.getenv("ERROR_RETRY_HOURS", "6"))
        self.lease_minutes = int(os.getenv("LEASE_MINUTES", "30"))
        
        # ===== PARALLEL EXECUTION =====
        # Auto-detect CPU count
        cpu_count = multiprocessing.cpu_count()
        
        # Scanner workers (for probing/checking)
        default_workers = min(64, max(16, cpu_count * 4))
        self.workers = int(os.getenv("WORKERS", default_workers))
        
        # Enumerator workers (for DNS brute-force)
        default_enum_workers = min(128, max(32, cpu_count * 8))
        self.enum_workers = int(os.getenv("ENUM_WORKERS", default_enum_workers))
        
        # Batch sizes
        self.max_scan_batch = int(os.getenv("MAX_SCAN_BATCH", "200"))
        
        # Poll intervals (seconds)
        self.enum_poll_seconds = int(os.getenv("ENUM_POLL_SECONDS", "5"))
        self.scan_poll_seconds = int(os.getenv("SCAN_POLL_SECONDS", "5"))
        
        # ===== NETWORK SETTINGS =====
        self.rate_limit = float(os.getenv("RATE_LIMIT", "0.05"))
        self.dns_timeout = float(os.getenv("DNS_TIMEOUT", "4.0"))
        self.http_timeout = float(os.getenv("HTTP_TIMEOUT", "8.0"))
        self.tls_timeout = float(os.getenv("TLS_TIMEOUT", "8.0"))
        
        # ===== ENUMERATION =====
        self.use_ct_logs = os.getenv("USE_CT_LOGS", "true").lower() == "true"
        self.use_public_dbs = os.getenv("USE_PUBLIC_DBS", "true").lower() == "true"
        self.use_dns_brute = os.getenv("USE_DNS_BRUTE", "true").lower() == "true"
        
        # ===== OUTPUT =====
        self.enable_excel = os.getenv("ENABLE_EXCEL", "false").lower() == "true"
        
        # Create directories
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.out_dir.mkdir(parents=True, exist_ok=True)
    
    def to_dict(self) -> dict:
        """Convert config to dict for serialization."""
        return {
            'domain': self.domain,
            'rescan_hours': self.rescan_hours,
            'error_retry_hours': self.error_retry_hours,
            'workers': self.workers,
            'enum_workers': self.enum_workers,
            'max_scan_batch': self.max_scan_batch,
            'rate_limit': self.rate_limit,
            'use_ct_logs': self.use_ct_logs,
            'use_public_dbs': self.use_public_dbs,
            'use_dns_brute': self.use_dns_brute,
        }
    
    def __repr__(self) -> str:
        """Human-readable config summary."""
        return (
            f"Config(\n"
            f"  domain={self.domain}\n"
            f"  rescan_policy={self.rescan_hours}h\n"
            f"  workers={self.workers}\n"
            f"  state_dir={self.state_dir}\n"
            f"  out_dir={self.out_dir}\n"
            f")"
        )
