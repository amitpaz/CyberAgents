"""Rate limiter utility for controlling API requests."""
import time
from typing import Optional
import os

class RateLimiter:
    """Rate limiter for controlling API request frequency."""
    
    def __init__(self, max_requests: Optional[int] = None, time_window: int = 60):
        """Initialize rate limiter.
        
        Args:
            max_requests: Maximum number of requests allowed in the time window.
                        If None, reads from MAX_API_REQUESTS_PER_MINUTE env var.
            time_window: Time window in seconds (default: 60 seconds)
        """
        self.max_requests = max_requests or int(os.getenv("MAX_API_REQUESTS_PER_MINUTE", "10"))
        self.time_window = time_window
        self.requests = []
        
    async def acquire(self) -> None:
        """Acquire a rate limit token.
        
        Raises:
            Exception: If rate limit is exceeded
        """
        now = time.time()
        
        # Remove old requests outside the time window
        self.requests = [req_time for req_time in self.requests 
                        if now - req_time < self.time_window]
        
        if len(self.requests) >= self.max_requests:
            # Calculate wait time
            wait_time = self.requests[0] + self.time_window - now
            if wait_time > 0:
                await asyncio.sleep(wait_time)
                return await self.acquire()
        
        self.requests.append(now)
        
    def reset(self) -> None:
        """Reset the rate limiter."""
        self.requests = [] 