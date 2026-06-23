#!/bin/bash
# Fresh 3-validator local testnet to exercise the commit-reveal RANDAO beacon end to end,
# then restart a node to prove beaconCtr resync does not stall consensus.
set -e
cd "$(dirname "$0")"
CP="out;../lib/*"
ROOT=bt
rm -rf $ROOT; mkdir -p $ROOT
J() { java -cp "$CP" com.phantomchain.debug.NodeMain "$@"; }

echo "== keygen 3 validators =="
PUBS=(); BC0=()
for i in 0 1 2; do
  out=$(J keygen $ROOT/n$i.key)
  PUBS+=("$(echo "$out" | grep '^pubkey=' | cut -d= -f2)")
  BC0+=("$(echo "$out" | grep '^beaconCommit0=' | cut -d= -f2)")
done

echo "== assemble genesis spec (with beaconCommit0 binding the first reveal) =="
cat > $ROOT/spec.json <<EOF
{ "chainId":"pc-beacon","genesisTime":0,"validators":[
 {"pubkey":"${PUBS[0]}","stake":1000000,"identity":1,"verified":true,"alloc":1000000,"beaconCommit0":"${BC0[0]}"},
 {"pubkey":"${PUBS[1]}","stake":1000000,"identity":1,"verified":true,"alloc":1000000,"beaconCommit0":"${BC0[1]}"},
 {"pubkey":"${PUBS[2]}","stake":1000000,"identity":1,"verified":true,"alloc":1000000,"beaconCommit0":"${BC0[2]}"}]}
EOF
J genesis $ROOT/spec.json $ROOT/gen >/dev/null
echo "genesis minted"

echo "== lay out node dirs =="
for i in 0 1 2; do
  d=$ROOT/n$i; mkdir -p $d/pcdata/certs
  cp $ROOT/gen/genesis.json $d/genesis.json
  cp $ROOT/n$i.key $d/node.key
  cp $ROOT/gen/tls/truststore.p12 $d/pcdata/certs/
  cp $ROOT/gen/tls/node-$i.p12 $d/pcdata/certs/
  port=$((9190+i))
  cat > $d/config.json <<EOF
{ "rpcPort":$port,"selfAddr":"127.0.0.1:$port","seeds":["127.0.0.1:9190"],"dataDir":"$ROOT/n$i/pcdata","keyFile":"$ROOT/n$i/node.key","certIndex":$i }
EOF
done

echo "== launch nodes =="
for i in 0 1 2; do
  java -cp "$CP" com.phantomchain.debug.NodeMain run $ROOT/n$i/config.json $ROOT/n$i/genesis.json > $ROOT/n$i/log.txt 2>&1 &
  echo "node$i pid=$!"
  sleep 4
done
echo "launched"
