# Regtest Node Lab

A safe, legal practice ground for the Kraken audit suite: real `bitcoind` on the
isolated **regtest** network, a fake Lightning config set, and a fake CGMiner
API — so you can run `node_audit.py`, `lightning_audit.py` and `miner_audit.py`
against live-ish targets without touching anyone else's system.

## Why this is safe

Everything here is your own, on your own machine:

- **regtest** is an isolated local chain — no mainnet, no real peers, no funds.
- The insecure demo node and the fake miner are published **only to
  `127.0.0.1`** on your host.
- The miner "device" is an emulator that returns canned, read-only data.
- The auditors only read local config/sockets, or (for the miner) make a single
  read-only query to the one host you name. Nothing scans, probes, or touches a
  third party.

## Prerequisites

- Docker + Docker Compose
- Python 3

## Quickstart

```bash
cd lab
./run-audit.sh            # audit all config samples + start the hardened node
./run-audit.sh --miner    # also start the fake miner and audit it
./run-audit.sh --insecure # also start the insecure bitcoind node
```

Reports land in the repo root:

| Report | Expectation |
| --- | --- |
| `report-node-hardened.md` | clean (cookie auth, localhost-only) |
| `report-node-insecure.md` | CRITICAL/HIGH exposure findings |
| `report-lnd-hardened.md` / `report-cln-hardened.md` | clean |
| `report-lnd-insecure.md` / `report-cln-insecure.md` | CRITICAL/HIGH findings |
| `report-miner.md` (with `--miner`) | API reachable + identity |

## Bitcoin Core

Talk to the hardened node the correct way (its own cookie, no password):

```bash
docker compose exec node-hardened bitcoin-cli -regtest getblockchaininfo
docker compose exec node-hardened bitcoin-cli -regtest createwallet test
ADDR=$(docker compose exec -T node-hardened bitcoin-cli -regtest getnewaddress)
docker compose exec node-hardened bitcoin-cli -regtest generatetoaddress 101 "$ADDR"
```

See the socket check catch a live exposed port (needs `ss`/`netstat`):

```bash
./run-audit.sh --insecure
python3 ../node_audit.py --conf conf/insecure.bitcoin.conf
```

## Lightning (lnd / CLN)

Audit the sample configs directly — no daemon needed:

```bash
python3 ../lightning_audit.py --impl lnd --conf conf/lnd.insecure.conf --no-sockets
python3 ../lightning_audit.py --impl cln --conf conf/cln.hardened.conf --no-sockets
```

Point it at your real node to also check macaroon / socket permissions:

```bash
python3 ../lightning_audit.py --impl lnd --conf ~/.lnd/lnd.conf --dir ~/.lnd
python3 ../lightning_audit.py --impl cln --conf ~/.lightning/config --dir ~/.lightning
```

## Miner (CGMiner API)

The emulator gives `miner_audit.py` a safe target on `127.0.0.1:4028`:

```bash
docker compose up -d miner-emulator
python3 ../miner_audit.py --target 127.0.0.1:4028
```

Against a real miner you own, pass its single address (ranges/CIDRs are
refused by design):

```bash
python3 ../miner_audit.py --target 192.168.1.50
```

## Learn the loop: break → detect → fix

1. Edit a hardened config (e.g. set `rpcallowip=0.0.0.0/0`, or `no-macaroons=true`).
2. Re-run the matching auditor.
3. Watch it flag the exposure and name the fix.
4. Revert, confirm the report goes green.

## Cleanup

```bash
docker compose --profile insecure down
```

## Scope

Use this only on your own machine / your own devices. Auditing your own
infrastructure is always fine; pointing any tool at systems you don't own or
aren't authorized to test is not. This lab is built so there's nothing to point
anywhere else.
