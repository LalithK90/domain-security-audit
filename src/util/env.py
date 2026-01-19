"""Load and validate environment configuration from .env file.

This is the single source of truth for configuration.
No CLI parsing, no magic - just read .env and validate.
"""

import os
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv
from .types import ScanConfig


def load_config() -> ScanConfig:
    """Load configuration from .env file at repo root.
    
    Returns a validated ScanConfig with all settings ready to use.
    Crashes early if DOMAIN is missing - that's our only hard requirement.
    """
    # Find .env at repo root (one level up from src/)
    repo_root = Path(__file__).parent.parent.parent
    env_file = repo_root / ".env"
    
    if not env_file.exists():
        raise FileNotFoundError(
            f"Missing .env file at {env_file}\n"
            "Create .env with at minimum: DOMAIN=your-domain.com"
        )
    
    load_dotenv(env_file)
    
    # DOMAIN is the only required variable
    domain = os.getenv("DOMAIN")
    if not domain:
        raise ValueError("DOMAIN must be set in .env file (e.g., DOMAIN=ac.lk)")
    
    # Everything else has sensible defaults
    config = ScanConfig(
        domain=domain,
        out_dir=os.getenv("OUT_DIR", "out"),
        enable_excel=os.getenv("ENABLE_EXCEL", "false").lower() == "true",
        force_rescan=os.getenv("FORCE_RESCAN", "false").lower() == "true",
        cache_ttl_hours=int(os.getenv("CACHE_TTL_HOURS", "24")),
        wordlist_enum=os.getenv("WORDLIST_ENUM", "false").lower() == "true",
        
        # Performance settings (optional overrides)
        max_workers=int(os.getenv("MAX_WORKERS", "60")),
        rate_limit_delay=float(os.getenv("RATE_LIMIT_DELAY", "0.05")),
        dns_timeout=float(os.getenv("DNS_TIMEOUT", "4.0")),
        http_timeout=float(os.getenv("HTTP_TIMEOUT", "8.0")),
        tls_timeout=float(os.getenv("TLS_TIMEOUT", "8.0")),
        
        # Enumeration settings
        use_ct_logs=os.getenv("USE_CT_LOGS", "false").lower() == "true",
        wordlist_path=os.getenv("WORDLIST_PATH") or None,
    )
    
    return config


def get_repo_root() -> Path:
    """Return the repository root directory."""
    return Path(__file__).parent.parent.parent
