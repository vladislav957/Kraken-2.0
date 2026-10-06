# Regtest Node Lab

A safe, legal practice ground for `node_audit.py`: a real `bitcoind` running on
the **regtest** network (its own private chain — no real coins, no real peers,
nothing that touches anyone else's system). Break it, audit it, fix it, repeat.

## Why this is safe

Everything here is your own node on your own machine:

- **regtest** is an isolated local network. It never connects to the Bitcoin
  mainnet or to other people.
- The insecure demo node is published **only to `127.0.0.1`** on your host.
- `node_audit.py` only ever reads local config and local sockets.

No part of this scans, probes, or touches a third party.

## Prerequisites

- Docker + Docker Compose
- Python 3 (for the auditor)

## Quickstart

```bash
cd lab
./run-audit.sh            # audits both configs, starts the hardened node
```

You'll get two reports in the repo root:

- `report-hardened.md` — should be clean (cookie auth, localhost-only).
- `report-insecure.md` — should light up with CRITICAL/HIGH findings.

Talk to the hardened node the correct way (its own cookie, no password):

```bash
docker compose exec node-hardened bitcoin-cli -regtest getblockchaininfo
docker compose exec node-hardened bitcoin-cli -regtest createwallet test
ADDR=$(docker compose exec -T node-hardened bitcoin-cli -regtest getnewaddress)
docker compose exec node-hardened bitcoin-cli -regtest generatetoaddress 101 "$ADDR"
```

## See the auditor catch a live exposed port

```bash
./run-audit.sh --insecure          # also starts the insecure node on 127.0.0.1:18444
python3 ../node_audit.py --conf conf/insecure.bitcoin.conf
```

On a host with `ss`/`netstat`, the socket check will report the regtest RPC
port listening off-loopback — exactly the kind of exposure you want to find
before anyone else does.

## Learn the loop: break → detect → fix

1. Edit `conf/hardened.bitcoin.conf` and reintroduce a mistake, e.g.
   `rpcallowip=0.0.0.0/0`.
2. Re-run `python3 ../node_audit.py --conf conf/hardened.bitcoin.conf`.
3. Watch it flag the exposure and tell you the fix.
4. Revert, confirm the report goes green.

## Cleanup

```bash
docker compose --profile insecure down
```

## Scope

Use this only on your own machine. Auditing your own node is always fine;
pointing any tool at infrastructure you don't own or aren't authorized to test
is not. This lab is built so there's nothing to point anywhere else.
