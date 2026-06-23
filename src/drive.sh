B=https://127.0.0.1:9091
for i in $(seq 1 20); do curl -sk --max-time 4 $B/peers 2>/dev/null | grep -q '"2"' && break; sleep 2; done
echo PEERS=$(curl -sk $B/peers)
t=1
for n in 1 2 3; do
  curl -sk -X POST "$B/submit?amount=$((n*10))" >/dev/null
  for w in $(seq 1 30); do h=$(curl -sk --max-time 4 $B/status | grep -o "height=[0-9]*" | head -1 | cut -d= -f2); [ -n "$h" ] && [ "$h" -ge "$t" ] && break; sleep 1; done
  echo block$t height=$h
  t=$((t+1))
done
echo ECON; curl -sk $B/econ