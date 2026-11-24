"""Token-bucket rate control: per target and global."""
import threading
import time

MAX_RATE = 10  # hard ceiling (queries/second) for any rate the user can choose


class TokenBucket:
    def __init__(self, rate, burst=1):
        self.rate, self.cap, self.tokens = rate, burst, burst
        self.t = time.monotonic()
        self.lock = threading.Lock()

    def acquire(self, stop=None):
        while True:
            with self.lock:
                now = time.monotonic()
                self.tokens = min(self.cap, self.tokens + (now - self.t) * self.rate)
                self.t = now
                if self.tokens >= 1:
                    self.tokens -= 1
                    return True
                wait = (1 - self.tokens) / self.rate
            if stop is not None and stop.is_set():
                return False
            time.sleep(min(wait, 0.2))


class RateController:
    def __init__(self, per_target=1.0, global_rate=5.0):
        if not (0 < per_target <= MAX_RATE and 0 < global_rate <= MAX_RATE):
            raise ValueError(f"rates must be between 0 and {MAX_RATE} queries/second")
        self.per_target_rate = per_target
        self.target = {}
        self.glob = TokenBucket(global_rate, burst=1)

    def acquire(self, ip, stop=None):
        b = self.target.setdefault(ip, TokenBucket(self.per_target_rate, burst=1))
        return b.acquire(stop) and self.glob.acquire(stop)
