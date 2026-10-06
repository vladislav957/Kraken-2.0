#!/usr/bin/env bash
# Drive the regtest lab and run every auditor against it. Read-only and local —
# this attacks nothing.
#
#   ./run-audit.sh              # audit all config samples + start hardened node
#   ./run-audit.sh --insecure   # also start the insecure bitcoind demo node
#   ./run-audit.sh --miner      # also start the fake-miner emulator and audit it
set -euo pipefail
cd "$(dirname "$0")"

NODE_AUDIT="../node_audit.py"
LN_AUDIT="../lightning_audit.py"
MINER_AUDIT="../miner_audit.py"
WITH_INSECURE=0; WITH_MINER=0
for a in "$@"; do
  [[ "$a" == "--insecure" ]] && WITH_INSECURE=1
  [[ "$a" == "--miner" ]] && WITH_MINER=1
done

echo "==> 1/5  Auditing Bitcoin Core config samples"
python3 "$NODE_AUDIT" --conf conf/hardened.bitcoin.conf --no-sockets --output ../report-node-hardened.md
python3 "$NODE_AUDIT" --conf conf/insecure.bitcoin.conf --no-sockets --output ../report-node-insecure.md
echo "    -> report-node-hardened.md, report-node-insecure.md"

echo "==> 2/5  Auditing Lightning config samples (lnd + CLN)"
python3 "$LN_AUDIT" --impl lnd --conf conf/lnd.hardened.conf --no-sockets --output ../report-lnd-hardened.md
python3 "$LN_AUDIT" --impl lnd --conf conf/lnd.insecure.conf --no-sockets --output ../report-lnd-insecure.md
python3 "$LN_AUDIT" --impl cln --conf conf/cln.hardened.conf --no-sockets --output ../report-cln-hardened.md
python3 "$LN_AUDIT" --impl cln --conf conf/cln.insecure.conf --no-sockets --output ../report-cln-insecure.md
echo "    -> report-lnd-*.md, report-cln-*.md"

echo "==> 3/5  Starting the hardened regtest node"
docker compose up -d node-hardened

echo "==> 4/5  Waiting for RPC, then proving it works via its OWN cookie auth"
for i in $(seq 1 30); do
  if docker compose exec -T node-hardened bitcoin-cli -regtest getblockchaininfo >/dev/null 2>&1; then
    docker compose exec -T node-hardened bitcoin-cli -regtest getblockchaininfo | sed -n '1,12p'
    break
  fi
  sleep 1
  [[ $i -eq 30 ]] && echo "   (node not ready in time — check 'docker compose logs node-hardened')"
done

if [[ $WITH_MINER -eq 1 ]]; then
  echo "==> (extra) Starting the fake-miner emulator on 127.0.0.1:4028"
  docker compose up -d miner-emulator
  sleep 2
  python3 "$MINER_AUDIT" --target 127.0.0.1:4028 --output ../report-miner.md
  echo "    -> report-miner.md"
fi

if [[ $WITH_INSECURE -eq 1 ]]; then
  echo "==> (extra) Starting the INSECURE bitcoind node on 127.0.0.1:18444"
  docker compose --profile insecure up -d node-insecure
  echo "    Run the auditor on THIS host to catch the exposed socket:"
  echo "      python3 ../node_audit.py --conf conf/insecure.bitcoin.conf"
fi

echo "==> 5/5  Tear down when done:  docker compose --profile insecure down"
