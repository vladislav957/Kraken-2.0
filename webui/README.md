# Web UI

A local, dependency-free GUI for the Kraken Audit tools — the same read-only
auditors, driven from a browser instead of the terminal, with a **Security
Score** widget.

## Run

```bash
python3 webui/server.py          # → http://127.0.0.1:8787
```

Open the printed URL. No `pip install` needed — it uses only the Python
standard library.

## What you get

- **Security Score widget** — overall status (worst severity + per-severity
  counts) across every audit you've run.
- **Bitcoin Core** — point it at a `bitcoin.conf` (blank = auto-detect) and run
  config + permission + local-socket checks.
- **Lightning** — lnd / Core Lightning config, macaroon/socket permissions, and
  local sockets.
- **Miner** — one host you own; read-only CGMiner API query + reachability.
  Ranges/CIDRs are rejected, same as the CLI.

Each finding shows its severity and a concrete fix.

## Safety

- Binds to **127.0.0.1** by default. Keep it local — this UI controls the
  auditors on your own machine. Binding to a public address prints a warning.
- It only calls the read-only auditors. Nothing here scans networks,
  brute-forces, or attacks anything.

The UI is a thin shell over `node_audit.py`, `lightning_audit.py` and
`miner_audit.py`; the audit logic lives there and is covered by the tests.
