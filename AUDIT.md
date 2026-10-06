# Kraken Audit Suite

A set of **defensive, read-only** auditors for infrastructure you own or are
explicitly authorized to test. None of them scan networks, run exploits, cause
denial of service, or brute-force credentials.

| Tool | Audits | How |
| --- | --- | --- |
| `node_audit.py` | Bitcoin Core | local config + file perms + local sockets |
| `lightning_audit.py` | lnd / Core Lightning | local config + credential-file perms + local sockets |
| `miner_audit.py` | one ASIC/GPU miner | single-target, read-only API query + TCP reachability |
| `audit_common.py` | — | shared severity model, reporting, helpers |

Shared conventions:

- **Severities:** 🔴 CRITICAL · 🟠 HIGH · 🟡 MEDIUM · 🔵 LOW · ⚪ INFO · 🟢 OK
- **Output:** terminal by default; `--output report.md` for Markdown; `--json`
  for machine-readable.
- **Exit code:** non-zero if any CRITICAL/HIGH finding — wire it into cron/CI.
- **No weaponization:** `miner_audit.py` takes a single host and refuses
  ranges/CIDRs/lists; nothing here tests passwords or sends control commands.

Practice safely in [`lab/`](./lab/README.md): regtest `bitcoind`, sample
Lightning configs, and a fake-miner emulator.

---

## `node_audit.py` — Bitcoin Core

```bash
python3 node_audit.py                                   # auto-detect bitcoin.conf
python3 node_audit.py --conf ~/.bitcoin/bitcoin.conf --output report.md
python3 node_audit.py --json
```

| Check | Severity | Why |
| --- | --- | --- |
| `rpcallowip=0.0.0.0/0` | CRITICAL | RPC reachable from the whole internet |
| public / wildcard `rpcbind` | CRITICAL / HIGH | full-control RPC exposed off-box |
| RPC port listening off-loopback | CRITICAL | the port is actually open |
| plaintext `rpcpassword` | HIGH | secret leaks via backups / other users |
| weak RPC password | HIGH / MEDIUM | low entropy falls to a dictionary attempt |
| `bitcoin.conf` readable by others + secrets | HIGH | any local user lifts the credential |
| broad `rpcallowip` (`/0`–`/7`) | HIGH | trusts far more hosts than needed |
| `rpcauth` / cookie auth | OK | no plaintext secret stored |
| P2P port (8333) public | INFO | normal for a reachable node |

## `lightning_audit.py` — lnd / Core Lightning

```bash
python3 lightning_audit.py --impl lnd --conf ~/.lnd/lnd.conf --dir ~/.lnd
python3 lightning_audit.py --impl cln --conf ~/.lightning/config --dir ~/.lightning
python3 lightning_audit.py                               # auto-detect
```

| Check | Severity | Why |
| --- | --- | --- |
| lnd `rpclisten` public (10009) | CRITICAL | gRPC full-control interface exposed |
| lnd `no-macaroons=true` | CRITICAL | authentication disabled |
| lnd `restlisten` public (8080) | HIGH | REST control API exposed |
| `admin.macaroon` readable by others | HIGH | anyone local can control the node |
| CLN gRPC/clnrest with public bind | HIGH | control API reachable off-box |
| `lightning-rpc` socket accessible by others | CRITICAL | local users control the node |
| exposed LN control port on a socket | CRITICAL / HIGH | the port is actually open |
| LN P2P port (9735) public | INFO | normal for a routing node |

`--dir` points at the node home (`~/.lnd` or `~/.lightning`) so the tool can
check `admin.macaroon` / `lightning-rpc` permissions.

## `miner_audit.py` — one miner you own

```bash
python3 miner_audit.py --target 192.168.1.50                 # CGMiner API + web reachability
python3 miner_audit.py --target 192.168.1.50 --api-port 4028 --output report.md
```

- **Single target only.** Ranges/CIDRs/lists are rejected — it can audit your
  miner, not sweep a network.
- **Read-only.** It reads the CGMiner API's public `version` (what monitoring
  dashboards read) and makes a bare TCP connect to 80/443. It sends no control
  commands and **tests no passwords** — where a default-password risk exists it
  tells you to verify it yourself.

| Check | Severity | Why |
| --- | --- | --- |
| CGMiner API reachable on a routable address | MEDIUM | unauthenticated API exposed beyond localhost |
| web admin reachable | LOW | panels often ship with default credentials (verify + restrict) |
| miner identity / firmware | INFO | confirm the unit and keep firmware current |
| API not reachable | OK | desired state for an unexposed device |

## Fixing what they find

- **Bitcoin Core:** [`bitcoin.conf.hardened.example`](./bitcoin.conf.hardened.example)
  — localhost RPC, cookie/`rpcauth`, SSH tunnel for remote admin, tight file perms.
- **Lightning:** bind gRPC/REST to localhost, keep macaroons on, hand out scoped
  macaroons (never `admin.macaroon`), `chmod 600` credential files, `0700` dirs.
- **Miner:** restrict the CGMiner API with `api-allow`/`api-network`, change
  default web passwords, keep both on your management VLAN behind a VPN.

## Tests

The suite ships with stdlib `unittest` tests (no dependencies, no network):

```bash
./run-tests.sh                       # or: python3 -m unittest discover -s tests
./run-tests.sh -v                    # verbose
```

They cover the single-target guard, address/entropy/reporting helpers, each
auditor's findings on insecure vs hardened inputs, file-permission checks, and
the miner API against a tiny in-process fake CGMiner server.

## Scope / ethics

Run these only against infrastructure you own or have **written authorization**
to test. Auditing your own config is always fine; probing, scanning, or
attempting access against someone else's systems without permission is
unauthorized access regardless of intent — these tools are built so they
can't do that.
