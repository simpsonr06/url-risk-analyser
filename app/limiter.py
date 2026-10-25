import time
from collections import defaultdict, deque
from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from config.settings import RATE_LIMIT_ENABLED, RATE_LIMIT_PER_MINUTE

# In-memory rate limiting store: client_ip -> deque of timestamps
_client_requests = defaultdict(deque)

def check_rate_limit(request: Request):
    """
    In-memory rate limiter checking client IP against configured requests/minute.
    """
    if not RATE_LIMIT_ENABLED:
        return

    # Extract client IP safely (respecting X-Forwarded-For if reverse-proxied)
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        client_ip = forwarded.split(",")[0].strip()
    elif request.client:
        client_ip = request.client.host
    else:
        client_ip = "127.0.0.1"

    now = time.time()
    window_start = now - 60.0
    queue = _client_requests[client_ip]

    # Remove timestamps older than 60 seconds
    while queue and queue[0] < window_start:
        queue.popleft()

    if len(queue) >= RATE_LIMIT_PER_MINUTE:
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded. Too many requests. Please wait before scanning again.",
            headers={"Retry-After": "60"}
        )

    queue.append(now)

def reset_rate_limits():
    """Helper to reset rate limits (useful for testing)."""
    _client_requests.clear()
