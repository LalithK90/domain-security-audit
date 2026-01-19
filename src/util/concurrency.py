"""Concurrency primitives for controlled parallel execution.

We want speed but not chaos - use semaphores and rate limiting
to keep from overwhelming targets or our own network stack.
"""

import asyncio
import time
from typing import Optional
from contextlib import asynccontextmanager


class RateLimiter:
    """Token bucket rate limiter for async operations.
    
    Ensures we don't hammer targets too fast.
    Each worker waits a bit between requests.
    """
    
    def __init__(self, delay: float = 0.05):
        """Initialize rate limiter with delay in seconds between operations."""
        self.delay = delay
        self._last_call = 0.0
        self._lock = asyncio.Lock()
    
    async def acquire(self):
        """Wait if needed to respect rate limit."""
        async with self._lock:
            now = time.monotonic()
            time_since_last = now - self._last_call
            
            if time_since_last < self.delay:
                await asyncio.sleep(self.delay - time_since_last)
            
            self._last_call = time.monotonic()


class ConcurrencyController:
    """Controls concurrent execution with semaphore + rate limiting.
    
    Combines both: limit total concurrent operations AND rate per operation.
    """
    
    def __init__(self, max_workers: int = 60, rate_limit_delay: float = 0.05):
        """Initialize with max concurrent workers and rate limit delay."""
        self.semaphore = asyncio.Semaphore(max_workers)
        self.rate_limiter = RateLimiter(delay=rate_limit_delay)
        self.max_workers = max_workers
    
    @asynccontextmanager
    async def acquire(self):
        """Acquire both semaphore and rate limit before proceeding.
        
        Usage:
            async with controller.acquire():
                await do_network_call()
        """
        async with self.semaphore:
            await self.rate_limiter.acquire()
            yield
