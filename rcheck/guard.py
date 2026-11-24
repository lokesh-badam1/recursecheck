"""Scope guard: nothing is sent unless the target is allow-listed and inside the lab network."""
import ipaddress


class ScopeViolation(Exception):
    pass


class ScopeGuard:
    ALLOWED_QTYPES = {"A", "TXT"}  # small queries only: never ANY

    def __init__(self, ips, lab_net, max_targets=20, sources=()):
        if len(ips) > max_targets:
            raise ScopeViolation(f"{len(ips)} targets exceeds the limit of {max_targets}")
        net = ipaddress.ip_network(lab_net)
        for ip in ips:
            if ipaddress.ip_address(ip) not in net:
                raise ScopeViolation(f"{ip} is outside the lab network {lab_net}")
        for s in sources:
            if ipaddress.ip_address(s) not in net:
                raise ScopeViolation(f"source {s} is outside the lab network {lab_net}")
        self.ips = set(ips)
        self.sources = set(sources)  # source addresses the tool may send from

    def check(self, ip, qtype, source=None):
        if source is not None and source not in self.sources:
            raise ScopeViolation(f"source address {source} is not an approved vantage point")
        if ip not in self.ips:
            raise ScopeViolation(f"{ip} is not in the allow-list")
        if qtype not in self.ALLOWED_QTYPES:
            raise ScopeViolation(f"query type {qtype} is not permitted")
