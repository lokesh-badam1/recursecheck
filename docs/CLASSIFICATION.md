# Classification rules

RecurseCheck never decides from a single flag. It combines the reply flags (RD, RA, AA), the response code
(NOERROR, SERVFAIL, REFUSED), timeouts, and the decoy server's log.

## Evidence collected per server

| Query | Name asked | Purpose |
|---|---|---|
| Baseline (1) | `www.<server>.lab` A, a name in the server's **own** zone | Is the server alive? Is it authoritative (AA=1)? Does it refuse us? |
| Decoy (3) | `rc<random>.decoy.lab` A, a **fresh unique name** each time | Does the server really perform a recursive lookup? The decoy server logs every name it receives. |

All queries have RD=1 and are small A queries. A truncated reply (TC=1) is retried over TCP; if that fails the
attempt is a `TC_FAIL`. Each decoy attempt records: reply status, RCODE, RA, AA, whether the marker answer
(`192.0.2.123`) came back, and whether the unique name **appears in the decoy log**.

## Per-attempt categories

| Category | Meaning |
|---|---|
| RECURSIVE | NOERROR, RA=1, marker answer, **and** the name is in the decoy log |
| REFUSED | RCODE REFUSED |
| NOANSWER | NOERROR/NXDOMAIN, no marker, name not in the decoy log |
| NO_DECOY_EVIDENCE | marker answer returned but the decoy never saw the name (fabricated or injected answer) |
| SERVFAIL, TIMEOUT, TC_FAIL, ERROR | failures, kept as reasons |

## Ordered rules (first match wins)

| # | Label | Condition | Evidence strength |
|---|---|---|---|
| 1 | **Recursive** | all 3 attempts are RECURSIVE and the baseline got a usable reply | high (positive proof) |
| 2 | **Refused** | baseline REFUSED and all 3 attempts REFUSED | high (explicit denial) |
| 3 | **Authoritative-only** | baseline answered with AA=1, and every attempt got no answer or REFUSED and never reached the decoy | medium (absence of evidence) |
| 4 | **Inconclusive** | anything else, with a reason code | n/a |

## Inconclusive reason codes

| Reason | Cause |
|---|---|
| `TIMEOUT` | no reply to any decoy attempt |
| `SERVFAIL` | every attempt returned SERVFAIL |
| `TC_FAIL` | truncated reply and the TCP retry failed |
| `CONFLICT` | the three attempts disagreed (typical for lossy servers) |
| `NO_DECOY_EVIDENCE` | marker answer without a decoy-log entry |
| `BASELINE_<x>` | the baseline gave no usable reply |
| `ERROR`, `OTHER`, `ABORTED` | transport error, unmatched evidence, run stopped by Ctrl+C |

## Why a baseline and a control client

- Without the **baseline**, "Authoritative-only" (does not recurse) and "Refused" (policy denial) look alike: both give a refusal to the decoy query.
- The **control client** sits inside the allowed network (`10.10.1.0/24`). A policy-refusing server must answer it, which shows that a REFUSED to the external probe is a policy decision, not a fault. It is used to validate the lab and explain results, and is not one of the four rules.

## Naive comparison scanner

For comparison, each run also scores a scanner that reads only the **first** decoy reply: REFUSED gives Refused,
NOERROR with RA=1 and an answer gives Recursive, other NOERROR gives Authoritative-only, anything else Inconclusive.
It has no baseline, no decoy log and no repeats. It confuses authoritative-only with refused, and it is fooled by a
server that returns RA=1 and a marker answer without recursing.

## Two decision policies

- **Strict (command line, scored runs):** Recursive needs every decoy attempt proven, so a flaky server stays Inconclusive.
- **First proof (web UI):** one RECURSIVE attempt is enough. A unique name that reached the decoy server could only have
  been looked up by recursion, so one such name is proof even if other queries were dropped (for example by a resolver
  that limits its own query rate). The UI shows YES as soon as the first proof arrives. If no query is proven, the normal
  rules above decide.

The UI also lets the user choose 1 to 10 queries, sent within one second. The rate controller is set to the chosen
rate, never above the hard cap of 10, and each query uses a different unique name.
