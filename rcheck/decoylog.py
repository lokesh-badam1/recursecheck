"""Reads the decoy server's log. Only lines written after mark() count as evidence."""
import os
import time


class DecoyLog:
    def __init__(self, path):
        self.path = path
        self.offset = 0

    def exists(self):
        return os.path.exists(self.path)

    def mark(self):
        self.offset = os.path.getsize(self.path) if self.exists() else 0

    def seen(self, label):
        try:
            size = os.path.getsize(self.path)
            with open(self.path, "rb") as f:
                f.seek(self.offset if self.offset <= size else 0)
                data = f.read().decode(errors="ignore").lower()
        except FileNotFoundError:
            return False
        return label.lower() in data

    def wait_seen(self, label, patient=False):
        """Short pause for the log to flush; poll up to 2 s when we expect to see it."""
        time.sleep(0.3)
        if self.seen(label):
            return True
        if patient:
            deadline = time.monotonic() + 2.0
            while time.monotonic() < deadline:
                time.sleep(0.25)
                if self.seen(label):
                    return True
        return False
