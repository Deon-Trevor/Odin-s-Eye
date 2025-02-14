import time
import redis
from fastapi import Request, HTTPException, Depends
from functools import lru_cache
import os

REDIS_HOST = os.getenv(
    "REDIS_HOST", "redis"
)  # ✅ Use Docker service name as the Redis hostname
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))  # Default Redis port


class Limiter:
    def __init__(self, limit_per_minute=60, limit_per_hour=1000, limit_per_day=10000):
        self.redis_client = redis.StrictRedis(
            host=REDIS_HOST, port=REDIS_PORT, db=0, decode_responses=True
        )

        self.limit_per_minute = limit_per_minute
        self.limit_per_hour = limit_per_hour
        self.limit_per_day = limit_per_day

    def _get_redis_key(self, client_id, timeframe):
        """Generate a Redis key based on timeframe and client."""
        return f"rate_limit:{client_id}:{timeframe}"

    def _redis_update(self, client_id, timeframe, limit, expiry):
        """Handle rate limiting using Redis."""
        key = self._get_redis_key(client_id, timeframe)
        current_count = self.redis_client.get(key)

        if current_count is None:
            self.redis_client.setex(key, expiry, 1)
            return True
        elif int(current_count) < limit:
            self.redis_client.incr(key)
            return True
        return False

    def check_limit(self, client_id):
        """Check if the client has remaining requests."""
        if not self._redis_update(client_id, "minute", self.limit_per_minute, 60):
            raise HTTPException(
                status_code=429,
                detail="Rate limit exceeded: Too many requests per minute",
            )
        if not self._redis_update(client_id, "hour", self.limit_per_hour, 3600):
            raise HTTPException(
                status_code=429,
                detail="Rate limit exceeded: Too many requests per hour",
            )
        if not self._redis_update(client_id, "day", self.limit_per_day, 86400):
            raise HTTPException(
                status_code=429, detail="Rate limit exceeded: Too many requests per day"
            )


@lru_cache()
def get_rate_limiter():
    """Return a cached instance of the rate limiter."""
    return Limiter()
