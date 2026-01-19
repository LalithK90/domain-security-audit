"""Safe file I/O utilities.

Helper functions for reading/writing files with proper error handling.
"""

import json
import csv
from pathlib import Path
from typing import List, Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


def ensure_dir(path: Path) -> Path:
    """Ensure directory exists, create if needed. Returns the path."""
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    return path


def write_json(path: Path, data: Any, indent: int = 2) -> None:
    """Write data to JSON file safely."""
    path = Path(path)
    ensure_dir(path.parent)
    
    try:
        with open(path, 'w') as f:
            json.dump(data, f, indent=indent, default=str)
        logger.debug(f"Wrote JSON to {path}")
    except Exception as e:
        logger.error(f"Failed to write JSON to {path}: {e}")
        raise


def read_json(path: Path) -> Optional[Any]:
    """Read JSON file safely. Returns None if file doesn't exist or is invalid."""
    path = Path(path)
    
    if not path.exists():
        return None
    
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.warning(f"Failed to read JSON from {path}: {e}")
        return None


def write_csv(path: Path, rows: List[Dict[str, Any]], fieldnames: Optional[List[str]] = None) -> None:
    """Write rows to CSV file safely.
    
    If fieldnames not provided, uses keys from first row.
    """
    path = Path(path)
    ensure_dir(path.parent)
    
    if not rows:
        logger.warning(f"No rows to write to {path}")
        return
    
    if fieldnames is None:
        fieldnames = list(rows[0].keys())
    
    try:
        with open(path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        logger.debug(f"Wrote {len(rows)} rows to {path}")
    except Exception as e:
        logger.error(f"Failed to write CSV to {path}: {e}")
        raise


def read_csv(path: Path) -> List[Dict[str, str]]:
    """Read CSV file safely. Returns empty list if file doesn't exist or is invalid."""
    path = Path(path)
    
    if not path.exists():
        return []
    
    try:
        with open(path, 'r', newline='') as f:
            reader = csv.DictReader(f)
            return list(reader)
    except Exception as e:
        logger.warning(f"Failed to read CSV from {path}: {e}")
        return []


def read_text_lines(path: Path) -> List[str]:
    """Read text file and return non-empty lines, stripped.
    
    Useful for wordlists, domain lists, etc.
    """
    path = Path(path)
    
    if not path.exists():
        return []
    
    try:
        with open(path, 'r') as f:
            lines = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        return lines
    except Exception as e:
        logger.warning(f"Failed to read text file {path}: {e}")
        return []
