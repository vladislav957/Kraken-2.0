#!/usr/bin/env bash
# Spin up the regtest lab, prove the hardened node works, and audit both
# config files. Read-only and local — this attacks nothing.
#
#   ./run-audit.sh            # audit configs + start hardened node
#   ./run-audit.sh --insecure # also start the insecure demo node
set -euo pipefail
cd "$(dirname "$0")"

AUDIT="../node_audit.py"
WITH_INSECURE=0
[[ "${1:-}" == "--insecure" ]] && WITH_INSECURE=1

echo "==> 1/4  Auditing config files (no running node required)"
python3 "$AUDIT" --conf conf/hardened.bitcoin.conf --no-sockets \
        --output ../report-hardened.md
echo
python3 "$AUDIT" --conf conf/insecure.bitcoin.conf --no-sockets \
        --output ../report-insecure.md
echo

echo "==> 2/4  Starting the hardened regtest node"
docker compose up -d node-hardened

echo "==> 3/4  Waiting for RPC, then proving it works via its OWN cookie auth"
for i in $(seq 1 30); do
  if docker compose exec -T node-hardened \
        bitcoin-cli -regtest getblockchaininfo >/dev/null 2>&1; then
    docker compose exec -T node-hardened \
        bitcoin-cli -regtest getblockchaininfo | sed -n '1,12p'
    break
  fi
  sleep 1
  [[ $i -eq 30 ]] && echo "   (node did not become ready in time — check 'docker compose logs')"
done

if [[ $WITH_INSECURE -eq 1 ]]; then
  echo
  echo "==> (extra) Starting the INSECURE demo node on 127.0.0.1:18444"
  docker compose --profile insecure up -d node-insecure
  echo "    Now run the auditor on THIS host to catch the exposed socket:"
  echo "      python3 ../node_audit.py --conf conf/insecure.bitcoin.conf"
fi

echo
echo "==> 4/4  Tear down when you are done:"
echo "      docker compose --profile insecure down"
echo
echo "Reports written: report-hardened.md, report-insecure.md"
