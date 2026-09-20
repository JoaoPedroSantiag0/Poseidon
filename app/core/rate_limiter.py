"""Token-Bucket Rate Limiter with Exponential Backoff and 429 Cooldown."""
import asyncio
import time
from dataclasses import dataclass


@dataclass
class TokenBucket:
    capacity: float
    tokens: float
    fill_rate: float  # tokens per second
    last_update: float
    cooldown_until: float = 0.0


class RateLimiter:
    """Asynchronous in-memory Token Bucket rate limiter for external CTI APIs."""

    def __init__(self):
        self._buckets: dict[str, TokenBucket] = {}
        self._lock = asyncio.Lock()

    def register_source(
        self,
        source_id: str,
        requests_per_minute: int = 60,
        burst_capacity: int = 5,
    ) -> None:
        """Configures or updates a rate-limiting bucket for a given source."""
        capacity = max(float(burst_capacity), 1.0)
        fill_rate = max(float(requests_per_minute) / 60.0, 0.01)
        now = time.monotonic()
        self._buckets[source_id] = TokenBucket(
            capacity=capacity,
            tokens=capacity,
            fill_rate=fill_rate,
            last_update=now,
            cooldown_until=0.0,
        )

    async def acquire(self, source_id: str, max_wait_seconds: float = 5.0) -> bool:
        """Acquires permission to execute a request against source_id, waiting if necessary."""
        async with self._lock:
            if source_id not in self._buckets:
                self.register_source(source_id)

            bucket = self._buckets[source_id]
            now = time.monotonic()

            # Check 429 active cooldown
            if now < bucket.cooldown_until:
                return False

            # Replenish tokens based on elapsed time
            elapsed = now - bucket.last_update
            bucket.tokens = min(bucket.capacity, bucket.tokens + (elapsed * bucket.fill_rate))
            bucket.last_update = now

            if bucket.tokens >= 1.0:
                bucket.tokens -= 1.0
                return True

            # Calculate wait time needed for 1 token
            deficit = 1.0 - bucket.tokens
            wait_time = deficit / bucket.fill_rate

            if wait_time > max_wait_seconds:
                return False

        # Wait outside the global lock
        await asyncio.sleep(wait_time)

        async with self._lock:
            bucket = self._buckets[source_id]
            now = time.monotonic()
            elapsed = now - bucket.last_update
            bucket.tokens = min(bucket.capacity, bucket.tokens + (elapsed * bucket.fill_rate))
            bucket.last_update = now

            if bucket.tokens >= 1.0:
                bucket.tokens -= 1.0
                return True
            return False

    def trigger_cooldown(self, source_id: str, cooldown_seconds: float = 60.0) -> None:
        """Enforces a temporary cooldown period following an HTTP 429 Rate Limit error."""
        if source_id in self._buckets:
            self._buckets[source_id].cooldown_until = time.monotonic() + cooldown_seconds


# Global singleton instance
rate_limiter = RateLimiter()
