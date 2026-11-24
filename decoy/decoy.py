"""Decoy DNS server: logs every query and answers names under decoy.lab with a marker."""
import datetime
import time

from dnslib import A, QTYPE, RCODE, RR
from dnslib.server import BaseResolver, DNSServer

ZONE = "decoy.lab"
MARKER_IP = "192.0.2.123"  # reserved documentation address
LOG = "/logs/decoy.log"


class Decoy(BaseResolver):
    def resolve(self, request, handler):
        qname = str(request.q.qname).lower().rstrip(".")
        with open(LOG, "a") as f:
            f.write(f"{datetime.datetime.now().isoformat()} {handler.client_address[0]} {qname}\n")
        reply = request.reply()
        if qname == ZONE or qname.endswith("." + ZONE):
            reply.header.aa = 1
            if QTYPE[request.q.qtype] == "A":
                reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A(MARKER_IP), ttl=5))
        else:
            reply.header.rcode = RCODE.REFUSED
        return reply


if __name__ == "__main__":
    open(LOG, "a").close()
    resolver = Decoy()
    DNSServer(resolver, port=53, address="0.0.0.0").start_thread()
    DNSServer(resolver, port=53, address="0.0.0.0", tcp=True).start_thread()
    print("decoy listening on :53 (udp+tcp)", flush=True)
    while True:
        time.sleep(3600)
