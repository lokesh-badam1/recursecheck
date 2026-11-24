"""Control client. Run it from the control container (10.10.1.10), inside the allowed range.

    docker compose exec control python -m rcheck.control

It sends one plain recursive query per target (ctl- prefix, so it never counts as probe evidence).
Policy-refusing targets must answer here even though they REFUSE the external probe.
"""
import random
import sys

import dns.exception
import dns.message
import dns.query
import dns.rcode

from . import config
from .guard import ScopeGuard


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "targets.yaml"
    cfg = config.load(path)
    zone = cfg["decoy"]["zone"]
    guard = ScopeGuard([t["ip"] for t in cfg["targets"]], cfg["lab_net"])
    rng = random.Random()
    print(f"{'target':6s} {'ip':12s} {'type':10s} result")
    for t in cfg["targets"]:
        guard.check(t["ip"], "A")
        name = f"ctl-{rng.getrandbits(32):08x}.{zone}"
        try:
            r = dns.query.udp(dns.message.make_query(name, "A"), t["ip"], timeout=3)
            res = dns.rcode.to_text(r.rcode()) + (" +answer" if r.answer else "")
        except dns.exception.Timeout:
            res = "TIMEOUT"
        except Exception as e:
            res = "ERROR " + repr(e)
        print(f"{t['name']:6s} {t['ip']:12s} {t['type']:10s} {res}")


if __name__ == "__main__":
    main()
