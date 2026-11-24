#!/usr/bin/env python3
"""Reads targets.yaml and writes generated/<target>/ configs plus docker-compose.yml."""
import pathlib
import shutil

import yaml

ROOT = pathlib.Path(__file__).parent
cfg = yaml.safe_load((ROOT / "targets.yaml").read_text())
cfg.setdefault("web_ip", "10.10.2.20")
cfg.setdefault("web_internal_ip", "10.10.1.20")

DECOY_IP = cfg["decoy"]["ip"]
DECOY_ZONE = cfg["decoy"]["zone"]
CONTROL_NET = cfg["control_net"]
DEAD_IP = "10.10.0.99"  # nothing lives here: used by the "broken" target

GEN = ROOT / "generated"
if GEN.exists():
    shutil.rmtree(GEN)
GEN.mkdir()
(ROOT / "logs").mkdir(exist_ok=True)


def zone_file(t):
    n = t["name"]
    return f"""$TTL 60
@   IN SOA ns.{n}.lab. admin.{n}.lab. (1 3600 600 86400 60)
@   IN NS  ns.{n}.lab.
ns  IN A   {t['ip']}
www IN A   {t['ip']}
"""


def named_conf(t):
    kind, n = t["type"], t["name"]
    allow = CONTROL_NET if kind == "refusing" else "any"
    recursion = "no" if kind == "auth_only" else "yes"

    opts = [
        'directory "/var/cache/bind";',
        'pid-file "/run/named/named.pid";',
        "listen-on { any; };",
        "listen-on-v6 { none; };",
        "dnssec-validation no;",
        "allow-transfer { none; };",
        f"recursion {recursion};",
        f"allow-query {{ {allow}; }};",
    ]
    if recursion == "yes":
        opts.append(f"allow-recursion {{ {allow}; }};")
    if kind == "forwarder":
        opts.append(f"forwarders {{ {t['upstream']}; }};")
        opts.append("forward only;")

    conf = "options {\n    " + "\n    ".join(opts) + "\n};\n\n"

    # Option A: tell this target where the decoy zone lives.
    stub_ip = None
    if kind in ("open", "refusing", "lossy", "silent"):
        stub_ip = DECOY_IP
    elif kind == "broken":
        stub_ip = DEAD_IP
    if stub_ip:
        conf += (
            f'zone "{DECOY_ZONE}" {{\n'
            f"    type static-stub;\n"
            f"    server-addresses {{ {stub_ip}; }};\n"
            f"}};\n\n"
        )

    conf += f'zone "{n}.lab" {{\n    type master;\n    file "/etc/bind/db.{n}.lab";\n}};\n'
    return conf


def pre_sh(t):
    kind = t["type"]
    # try nft-based iptables first, then legacy (Docker Desktop VM kernels vary)
    def ipt(args):
        return f"iptables {args} || iptables-legacy {args}\n"

    if kind == "lossy":
        return ipt(
            f"-A INPUT -p udp --dport 53 -m statistic --mode random "
            f"--probability {t['loss']} -j DROP"
        )
    if t.get("max_qps"):
        # Resolver-side query limit: accept at most N UDP queries per second, drop the rest before
        # the resolver sees them. Burst 1 keeps the limit strict (no extra queries slip through).
        n = int(t["max_qps"])
        return (ipt(f"-A INPUT -p udp --dport 53 -m limit --limit {n}/second --limit-burst 1 -j ACCEPT")
                + ipt("-A INPUT -p udp --dport 53 -j DROP"))
    if kind == "silent":
        return ipt("-A INPUT -p udp --dport 53 -j DROP") + ipt("-A INPUT -p tcp --dport 53 -j DROP")
    return None


services = {
    "decoy": {
        "build": "./decoy",
        "image": "recursecheck-decoy",
        "networks": {"lab": {"ipv4_address": DECOY_IP}},
        "volumes": ["./logs:/logs"],
    }
}

for t in cfg["targets"]:
    n = t["name"]
    d = GEN / n
    d.mkdir()
    (d / "named.conf").write_text(named_conf(t))
    (d / f"db.{n}.lab").write_text(zone_file(t))
    vols = [
        f"./generated/{n}/named.conf:/etc/bind/named.conf:ro",
        f"./generated/{n}/db.{n}.lab:/etc/bind/db.{n}.lab:ro",
    ]
    svc = {
        "build": "./target",
        "image": "recursecheck-target",
        "networks": {"lab": {"ipv4_address": t["ip"]}},
        "volumes": vols,
    }
    pre = pre_sh(t)
    if pre:
        (d / "pre.sh").write_text(pre)
        vols.append(f"./generated/{n}/pre.sh:/etc/bind/pre.sh:ro")
        svc["cap_add"] = ["NET_ADMIN"]
    services[n] = svc

services["probe"] = {
    "build": "./probe",
    "image": "recursecheck-probe",
    "command": "sleep infinity",
    "networks": {"lab": {"ipv4_address": cfg["probe_ip"]}},
    "volumes": [".:/work", "./logs:/logs:ro"],
    "working_dir": "/work",
}
services["control"] = {
    "image": "recursecheck-probe",
    "command": "sleep infinity",
    "networks": {"lab": {"ipv4_address": cfg["control_ip"]}},
    "volumes": [".:/work"],
    "working_dir": "/work",
    "depends_on": ["probe"],
}

# Web UI. "web" stays on the isolated lab network (outside the control range, so policy-refusing
# servers treat it as an external client). Docker cannot publish ports from an internal network,
# so a tiny nginx "gateway" bridges 127.0.0.1:8080 on your Mac to web. It only proxies HTTP.
WEB_IP, GATEWAY_IP = cfg["web_ip"], "10.10.2.30"
WEB_INT_IP = cfg["web_internal_ip"]
services["web"] = {
    "image": "recursecheck-probe",
    # The UI can probe from two source addresses: WEB_IP (outside the control range) and an alias
    # WEB_INT_IP (inside it). The alias needs NET_ADMIN to be added to the interface.
    "command": ["sh", "-c",
                "ip addr add " + WEB_INT_IP + "/16 dev $(ip -o -4 addr show | awk '/" + WEB_IP + "\\// {print $2}'); "
                "exec python -m rcheck.web --host 0.0.0.0 --port 8080"],
    "cap_add": ["NET_ADMIN"],
    "networks": {"lab": {"ipv4_address": WEB_IP}},
    "volumes": [".:/work", "./logs:/logs:ro"],
    "working_dir": "/work",
    "depends_on": ["probe"],
}
(GEN / "gateway.conf").write_text(
    "server {\n    listen 8080;\n    location / {\n"
    f"        proxy_pass http://{WEB_IP}:8080;\n"
    "        proxy_read_timeout 120s;\n    }\n}\n"
)
services["gateway"] = {
    "image": "nginx:alpine",
    "networks": {"lab": {"ipv4_address": GATEWAY_IP}, "ui": {}},
    "ports": ["127.0.0.1:8080:8080"],
    "volumes": ["./generated/gateway.conf:/etc/nginx/conf.d/default.conf:ro"],
    "depends_on": ["web"],
}

compose = {
    "services": services,
    "networks": {
        "lab": {
            "internal": True,  # no Internet access
            "ipam": {"config": [{"subnet": "10.10.0.0/16"}]},
        },
        "ui": {},  # ordinary bridge, used only by the gateway to publish the UI port
    },
}
(ROOT / "docker-compose.yml").write_text(yaml.safe_dump(compose, sort_keys=False))
print(f"Generated {len(cfg['targets'])} targets -> generated/ and docker-compose.yml")
