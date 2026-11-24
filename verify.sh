#!/bin/sh
# Manual checks. Run from the project folder on your Mac AFTER `docker compose up -d --build`.
P="docker compose exec -T probe"
C="docker compose exec -T control"
D="dig +tries=1 +time=2 +noall +comments +answer"
R=$(date +%s)

section() { printf '\n=== %s ===\n' "$1"; }

section "1. t01 baseline (expect: flags with aa, NOERROR, answer 10.10.0.11)"
$P $D @10.10.0.11 www.t01.lab

section "2. t01 decoy (expect: flags with ra, NOERROR, answer 192.0.2.123)"
$P $D @10.10.0.11 chk${R}a.decoy.lab
sleep 1
echo "--- decoy log (expect chk${R}a.decoy.lab) ---"
grep "chk${R}a" logs/decoy.log || echo "NOT FOUND (problem!)"

section "3a. t06 refusing, from PROBE (expect: status REFUSED)"
$P $D @10.10.0.16 chk${R}b.decoy.lab
section "3b. t06 refusing, from CONTROL (expect: NOERROR + answer)"
$C $D @10.10.0.16 chk${R}c.decoy.lab

section "4. t10 auth-only decoy (expect: REFUSED, no log entry)"
$P $D @10.10.0.20 chk${R}d.decoy.lab
sleep 1
grep "chk${R}d" logs/decoy.log && echo "FOUND (problem!)" || echo "not in log (good)"

section "5. t14 forwarder decoy (expect: answer; log source is t01 = 10.10.0.11)"
$P $D @10.10.0.24 chk${R}e.decoy.lab
sleep 1
grep "chk${R}e" logs/decoy.log || echo "NOT FOUND (problem!)"

section "6. t19 silent (expect: timeout, no reply)"
$P $D @10.10.0.29 chk${R}f.decoy.lab || echo "timed out (good)"
