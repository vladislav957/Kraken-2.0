# Node Security Audit (`node_audit.py`)

A **defensive, read-only** auditor for a Bitcoin Core node you own or are
explicitly authorized to audit.

It is deliberately *not* an attack tool:

| It does | It does **not** |
| --- | --- |
| Read your local `bitcoin.conf` | Scan remote hosts or IP ranges |
| Check that file's permissions | Connect to the network or send traffic |
| List **this machine's** listening sockets | Guess, test, or brute-force any credential |
| Print findings + how to fix them | Run exploits, DoS, or "stealth" anything |

Because it only ever touches local files and local sockets, it cannot be
pointed at a third party — which is the point. "Find the holes before an
attacker does, then close them" is done by **inspecting your own
configuration**, not by attacking anyone.

## Usage

```bash
# Auto-detect bitcoin.conf in the usual locations
python3 node_audit.py

# Audit a specific node's config
python3 node_audit.py --conf ~/.bitcoin/bitcoin.conf

# Write a Markdown report (good for keeping a record / CI artifact)
python3 node_audit.py --conf ~/.bitcoin/bitcoin.conf --output audit-report.md

# Machine-readable output
python3 node_audit.py --json

# Skip the local socket check (e.g. no ss/netstat available)
python3 node_audit.py --no-sockets
```

The process exits non-zero if any **CRITICAL** or **HIGH** finding is present,
so you can wire it into a cron job or CI check:

```bash
python3 node_audit.py --conf ~/.bitcoin/bitcoin.conf || echo "node needs attention"
```

## What it checks

| Check | Severity | Why it matters |
| --- | --- | --- |
| `rpcallowip=0.0.0.0/0` (or `::/0`) | CRITICAL | RPC reachable from the whole internet |
| `rpcbind` on a public / wildcard interface | CRITICAL / HIGH | Full-control RPC exposed off-box |
| RPC port listening on a non-loopback address | CRITICAL | The port is actually open, not just configured |
| Plaintext `rpcpassword` in config | HIGH | Secret leaks via backups / other users |
| Weak RPC password (low entropy) | HIGH / MEDIUM | Falls to a dictionary attempt if ever reachable |
| `bitcoin.conf` readable by group/other with secrets | HIGH | Any local user can lift the credential |
| Broad `rpcallowip` range (`/0`–`/7`) | HIGH | Trusts far more hosts than needed |
| `rpcauth` / cookie auth in use | OK | No plaintext secret stored |
| P2P port (8333) public | INFO | Normal and expected for a reachable node |

## Fixing what it finds

Start from [`bitcoin.conf.hardened.example`](./bitcoin.conf.hardened.example).
The essentials:

1. **Bind RPC to localhost** — `rpcbind=127.0.0.1`, `rpcallowip=127.0.0.1`.
2. **No plaintext secret** — use cookie auth (the default) or a salted
   `rpcauth` line, never `rpcpassword`.
3. **Reach RPC remotely over SSH**, not a public bind:
   `ssh -N -L 8332:127.0.0.1:8332 you@your-node`.
4. **Lock down files** — `chmod 700 ~/.bitcoin`, `chmod 600 bitcoin.conf`.
5. **Firewall the ports** you don't serve publicly.

## Scope / ethics

Run this only against infrastructure you own or have **written authorization**
to test. Auditing your own node's configuration is always fine; probing,
scanning, or attempting access against someone else's systems without
permission is unauthorized access regardless of intent — this tool is built so
that it simply can't do that.
