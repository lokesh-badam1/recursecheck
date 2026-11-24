# Test lab (ground truth)

The lab is generated from `targets.yaml` by `generate_lab.py`. It contains 20 target DNS servers (all BIND), one decoy
server, an external probe client, a control client (inside the allowed range), a web container and a gateway.

## The 20 targets and their ground truth

| Targets | Count | Configuration | Expected label |
|---|---|---|---|
| t01-t05 | 5 | `recursion yes`, open to anyone, stub zone for `decoy.lab`. t04 and t05 also drop incoming DNS above 5 and 3 queries per second (iptables `limit`) | Recursive |
| t06-t09 | 4 | recursion and queries allowed only from `10.10.1.0/24` | Refused |
| t10-t13 | 4 | `recursion no`, own zone only | Authoritative-only |
| t14-t16 | 3 | forward everything to an open target (t01-t03) | Recursive |
| t17-t18 | 2 | open, but iptables randomly drops 60% / 90% of incoming DNS | Inconclusive |
| t19 | 1 | open, but a firewall drops all DNS | Inconclusive |
| t20 | 1 | open, but its stub zone for `decoy.lab` points at a dead address | Inconclusive |

Every target also hosts a small zone `<name>.lab` containing `www`, which is the target of the baseline query.

## Vantage points

| Client | Address | Role |
|---|---|---|
| probe | 10.10.2.10 | external; the command-line run (`rcheck.run`) always uses this |
| web (external) | 10.10.2.20 | external; default in the web UI |
| web (internal alias) | 10.10.1.20 | inside `control_net`; chosen with the UI toggle |
| control | 10.10.1.10 | inside `control_net`; `rcheck.control` shows that refusals are policy |

Ground truth by vantage point: t06-t09 are Refused from outside and Recursive from inside; all other targets behave the same from both.

## Key configuration lines (BIND)

Open recursive:
```
options { recursion yes; allow-query { any; }; allow-recursion { any; }; dnssec-validation no; };
zone "decoy.lab" { type static-stub; server-addresses { 10.10.0.5; }; };
```
Policy-refusing: the same, with `allow-query` and `allow-recursion` limited to `10.10.1.0/24`.
Authoritative-only: `recursion no;` and no stub zone. Forwarder: `forwarders { <open target>; }; forward only;`.
Lossy and silent targets run `iptables` rules at start-up (`pre.sh`, needs `NET_ADMIN`).

## Expected behaviour of each class (checked by `verify.sh`)

1. Open target: baseline answers with `aa`; a decoy name returns the marker with `ra`, and the name is in `logs/decoy.log`.
2. Refusing target: REFUSED to the probe client, a normal answer to the control client.
3. Authoritative-only target: REFUSED for the decoy name, and nothing in the log.
4. Forwarder: answers, and the decoy log shows the **upstream** target's address as the source.
5. Silent target: timeout.

## Adding or changing targets

Edit `targets.yaml` (up to 20 entries, set `expected`), run `python generate_lab.py`, then `docker compose up -d --build`.
