"""Simple JSON-based cache for probe results.

Avoids hitting the same subdomain twice when results are fresh.
Cache lives in out/<domain>/cache/ and respects TTL from config.
"""

import json
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from .time import now_utc


class Cache:
    """File-based cache with TTL support.
    
    Each cache entry is a JSON file with the data + timestamp.
    Simple but effective - no database needed for our scale.
    """
    
    def __init__(self, cache_dir: Path, ttl_hours: int = 24):
        """Initialize cache in the given directory with specified TTL."""
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.ttl = timedelta(hours=ttl_hours)
    
    def _cache_file(self, key: str) -> Path:
        """Generate cache file path for a given key.
        
        Use hash to avoid filesystem issues with weird characters in keys.
        """
        # Simple sanitization - replace unsafe chars
        safe_key = key.replace("/", "_").replace(":", "_").replace("?", "_")
        return self.cache_dir / f"{safe_key}.json"
    
    def get(self, key: str) -> Optional[Dict[str, Any]]:
        """Retrieve cached data if it exists and hasn't expired.
        
        Returns None if cache miss or expired.
        """
        cache_file = self._cache_file(key)
        
        if not cache_file.exists():
            return None
        
        try:
            with open(cache_file, 'r') as f:
                cached = json.load(f)
            
            # Check if expired
            cached_time = datetime.fromisoformat(cached['timestamp'])
            age = now_utc() - cached_time
            
            if age > self.ttl:
                # Expired - delete it
                cache_file.unlink()
                return None
            
            return cached['data']
        
        except (json.JSONDecodeError, KeyError, ValueError):
            # Corrupted cache file - delete it
            cache_file.unlink()
            return None
    
    def set(self, key: str, data: Dict[str, Any]) -> None:
        """Store data in cache with current timestamp."""
        cache_file = self._cache_file(key)
        
        cached = {
            'timestamp': now_utc().isoformat(),
            'data': data
        }
        
        with open(cache_file, 'w') as f:
            json.dump(cached, f, indent=2)
    
    def clear(self) -> int:
        """Clear all cache files. Returns number of files deleted."""
        count = 0
        for cache_file in self.cache_dir.glob("*.json"):
            cache_file.unlink()
            count += 1
        return count
    
    def stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        files = list(self.cache_dir.glob("*.json"))
        valid = 0
        expired = 0
        
        for cache_file in files:
            try:
                with open(cache_file, 'r') as f:
                    cached = json.load(f)
                cached_time = datetime.fromisoformat(cached['timestamp'])
                age = now_utc() - cached_time
                
                if age > self.ttl:
                    expired += 1
                else:
                    valid += 1
            except:
                expired += 1
        
        return {
            'total_files': len(files),
            'valid': valid,
            'expired': expired,
            'cache_dir': str(self.cache_dir)
        }
