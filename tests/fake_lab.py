"""Local end-to-end test without Docker: fake DNS servers on 127.0.0.x:53 (needs root).

    python tests/fake_lab.py <decoy_log>     # starts servers, runs rcheck, prints result
"""
import datetime
import os
import socket
import subprocess
import sys
import time

from dnslib import A, QTYPE, RCODE, RR
from dnslib.server import BaseResolver, DNSServer

LOG = sys.argv[1]
MARKER = "192.0.2.123"


class Fake(BaseResolver):
    def __init__(self, name, kind):
        self.name, self.kind = name, kind

    def resolve(self, request, handler):
        q = str(request.q.qname).lower().rstrip(".")
        r = request.reply()
        if self.kind == "refusing":
            r.header.rcode = RCODE.REFUSED
            return r
        if q == f"www.{self.name}.lab":
            r.header.aa, r.header.ra = 1, int(self.kind != "auth")
            r.add_answer(RR(request.q.qname, QTYPE.A, rdata=A("127.0.0.1"), ttl=60))
            return r
        if q.endswith(".decoy.lab"):
            if self.kind == "rec":
                with open(LOG, "a") as f:
                    f.write(f"{datetime.datetime.now().isoformat()} 127.0.0.1 {q}\n")
                r.header.ra = 1
                r.add_answer(RR(request.q.qname, QTYPE.A, rdata=A(MARKER), ttl=5))
            elif self.kind == "liar":  # claims an answer without ever asking the decoy
                r.header.ra = 1
                r.add_answer(RR(request.q.qname, QTYPE.A, rdata=A(MARKER), ttl=5))
            elif self.kind == "servfail":
                r.header.rcode = RCODE.SERVFAIL
            else:  # auth: recursion off
                r.header.rcode = RCODE.REFUSED
            return r
        r.header.rcode = RCODE.REFUSED
        return r


specs = [("f01", "rec", "Recursive"), ("f02", "rec", "Recursive"),
         ("f03", "refusing", "Refused"), ("f04", "auth", "Authoritative-only"),
         ("f05", "servfail", "Inconclusive"), ("f06", "silent", "Inconclusive"),
         ("f07", "liar", "Inconclusive")]
servers, socks = [], []
yaml = ["decoy: {ip: 127.0.0.5, zone: decoy.lab}", "lab_net: 127.0.0.0/8", "targets:"]
for i, (name, kind, exp) in enumerate(specs):
    ip = f"127.0.0.{10 + i}"
    yaml.append(f"  - {{name: {name}, ip: {ip}, type: {kind}, expected: {exp}}}")
    if kind == "silent":  # bound socket that never answers
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((ip, 53))
        socks.append(s)
    else:
        srv = DNSServer(Fake(name, kind), port=53, address=ip)
        srv.start_thread()
        servers.append(srv)
open("/tmp/targets_test.yaml", "w").write("\n".join(yaml) + "\n")
open(LOG, "a").close()
time.sleep(0.5)

if os.environ.get("FAKE_LAB_HOLD"):
    time.sleep(int(os.environ["FAKE_LAB_HOLD"]))
    sys.exit(0)

root = os.path.join(os.path.dirname(__file__), "..")
args = [sys.executable, "-m", "rcheck.run", "--targets", "/tmp/targets_test.yaml",
        "--decoy-log", LOG, "--out", "/tmp/rl_results", "--seed", "42",
        "--timeout", "1", "--target-rate", "5", "--global-rate", "20"] + sys.argv[2:]
rc = subprocess.call(args, cwd=root)
for s in servers:
    s.stop()
sys.exit(rc)
