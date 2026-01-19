"""Timestamp and duration utilities.

Simple helpers to keep time handling consistent across the scanner.
"""

from datetime import datetime, timezone
from typing import Optional


def now_utc() -> datetime:
    """Return current UTC time with timezone info.
    
    Always use UTC for measurement timestamps - makes analysis easier.
    """
    return datetime.now(timezone.utc)


def timestamp_str(dt: Optional[datetime] = None) -> str:
    """Format timestamp for filenames and logs.
    
    Returns: YYYYMMDD_HHMMSS format (filesystem-safe)
    """
    if dt is None:
        dt = now_utc()
    return dt.strftime("%Y%m%d_%H%M%S")


def date_str(dt: Optional[datetime] = None) -> str:
    """Format date for directory names.
    
    Returns: YYYY-MM-DD format
    """
    if dt is None:
        dt = now_utc()
    return dt.strftime("%Y-%m-%d")


def duration_ms(start: datetime, end: Optional[datetime] = None) -> float:
    """Calculate duration in milliseconds between two timestamps.
    
    If end is None, uses current time.
    """
    if end is None:
        end = now_utc()
    delta = end - start
    return delta.total_seconds() * 1000
