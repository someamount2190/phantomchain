#!/bin/bash
# Network-layer adversarial probe against a live local cluster (the guards NOT in commitBlock:
# verifyQC proposer-schedule + quorum, prod-gating, body cap, malformed input), then prove the
# honest cluster still converges after the attacks (garbage rejected, liveness preserved).
cd "$(dirname "$0")"
B=https://127.0.0.1:9190
pass=0; fail=0
chk(){ if [ "$2" = "1" ]; then pass=$((pass+1)); echo "  PASS $1"; else fail=$((fail+1)); echo "  ** FAIL ** $1  ($3)"; fi; }

echo "== rebuild fresh 3-node cluster =="
for p in $(netstat -ano 2>/dev/null | grep -E ':919[0-2] ' | grep LISTEN | awk '{print $5}' | sort -u); do taskkill //F //PID $p >/dev/null 2>&1; done
bash beacon-test.sh >/dev/null 2>&1
sleep 10
# drive a few blocks (control)
for n in 1 2 3 4; do curl -sk --max-time 5 -X POST "$B/submit?amount=$n" >/dev/null; sleep 1; done
sleep 3
H0=$(curl -sk --max-time 4 $B/status | grep -o 'height=[0-9]*' | head -1 | cut -d= -f2)
LAST=$(curl -sk --max-time 4 $B/status | grep -o 'last=[0-9a-f]*' | cut -d= -f2)
echo "  control height=$H0 last=${LAST:0:12}"
chk "cluster produces blocks (control)" "$([ "${H0:-0}" -ge 3 ] && echo 1 || echo 0)" "h=$H0"

NH=$((H0+1))
echo "== N1: /vote with off-schedule proposer=99 =="
R=$(curl -sk --max-time 5 -X POST -H "Content-Type: application/json" "$B/vote" --data "{\"height\":$NH,\"view\":0,\"prevHash\":\"$LAST\",\"hash\":\"00\",\"proposer\":99,\"txs\":[],\"ts\":1}")
chk "N1 off-schedule proposer rejected" "$(echo "$R" | grep -qi 'reject' && echo 1 || echo 0)" "$R"

echo "== N2: /commit with no QC / bogus proposer =="
R=$(curl -sk --max-time 5 -X POST -H "Content-Type: application/json" "$B/commit" --data "{\"height\":$NH,\"view\":0,\"prevHash\":\"$LAST\",\"hash\":\"00\",\"proposer\":99,\"txs\":[],\"ts\":1}")
chk "N2 unquorumed commit rejected" "$(echo "$R" | grep -qi 'reject\|insufficient' && echo 1 || echo 0)" "$R"

echo "== N3: /commit with a forged single-signer QC =="
R=$(curl -sk --max-time 5 -X POST -H "Content-Type: application/json" "$B/commit" --data "{\"height\":$NH,\"view\":0,\"prevHash\":\"$LAST\",\"hash\":\"00\",\"proposer\":0,\"txs\":[],\"ts\":1,\"qc\":[{\"i\":0,\"sig\":\"deadbeef\"}]}")
chk "N3 forged/low QC rejected" "$(echo "$R" | grep -qi 'reject\|insufficient' && echo 1 || echo 0)" "$R"

echo "== N4: /byz/equivocate must be prod-gated (404) =="
R=$(curl -sk --max-time 5 -o /dev/null -w '%{http_code}' -X POST "$B/byz/equivocate")
chk "N4 debug endpoint 404 in prod" "$([ "$R" = "404" ] && echo 1 || echo 0)" "http=$R"

echo "== N5: oversized body (>1MiB) refused =="
python -c "print('x'*1200000)" > /tmp/big.txt 2>/dev/null || head -c 1200000 /dev/zero | tr '\0' 'x' > /tmp/big.txt
R=$(curl -sk --max-time 8 -X POST -H "Content-Type: application/json" "$B/gossip/tx" --data @/tmp/big.txt)
chk "N5 oversized body not accepted" "$(echo "$R" | grep -qvi 'accepted\|ok' && echo 1 || echo 0)" "$R"

echo "== N6: malformed JSON does not crash the node =="
curl -sk --max-time 5 -X POST -H "Content-Type: application/json" "$B/gossip/tx" --data "{not json" >/dev/null 2>&1
curl -sk --max-time 5 -X POST -H "Content-Type: application/json" "$B/vote" --data "garbage" >/dev/null 2>&1
ALIVE=$(curl -sk --max-time 4 $B/status | grep -c 'height=')
chk "N6 node survives malformed input" "$([ "${ALIVE:-0}" -ge 1 ] && echo 1 || echo 0)" "alive=$ALIVE"

echo "== POST-ATTACK liveness: honest cluster still converges =="
for n in 5 6 7 8; do curl -sk --max-time 5 -X POST "$B/submit?amount=$n" >/dev/null; sleep 1; done
sleep 4
H1=$(curl -sk --max-time 4 $B/status | grep -o 'height=[0-9]*' | head -1 | cut -d= -f2)
chk "chain advanced past attacks ($H0 -> $H1)" "$([ "${H1:-0}" -gt "${H0:-0}" ] && echo 1 || echo 0)" "h0=$H0 h1=$H1"
# all three agree?
L0=$(curl -sk --max-time 4 https://127.0.0.1:9190/status | grep -o 'last=[0-9a-f]*')
L1=$(curl -sk --max-time 4 https://127.0.0.1:9191/status | grep -o 'last=[0-9a-f]*')
L2=$(curl -sk --max-time 4 https://127.0.0.1:9192/status | grep -o 'last=[0-9a-f]*')
chk "all 3 nodes converged on same head" "$([ "$L0" = "$L1" ] && [ "$L1" = "$L2" ] && echo 1 || echo 0)" "$L0|$L1|$L2"
SLASH=$(curl -sk --max-time 4 $B/status | grep -o 'slashed=\[[^]]*\]')
chk "no honest node falsely slashed" "$([ "$SLASH" = "slashed=[]" ] && echo 1 || echo 0)" "$SLASH"

echo ""
echo "adversary-net: $pass passed, $fail failed"
for p in $(netstat -ano 2>/dev/null | grep -E ':919[0-2] ' | grep LISTEN | awk '{print $5}' | sort -u); do taskkill //F //PID $p >/dev/null 2>&1; done
exit $fail
