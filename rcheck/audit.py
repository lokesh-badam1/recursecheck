import json
import threading


class Audit:
    """Append-only JSONL log of every query (or planned query in dry-run)."""

    def __init__(self, path):
        self.f = open(path, "a", buffering=1)
        self.lock = threading.Lock()

    def write(self, rec):
        with self.lock:
            self.f.write(json.dumps(rec) + "\n")

    def close(self):
        self.f.close()
