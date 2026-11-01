# Kraken Audit — defensive security toolkit

A small suite of **defensive, read-only** auditors for Bitcoin and Lightning
infrastructure you own or are explicitly authorized to test. It helps you find
and close exposure on **your own** nodes and miners before someone else does.

> **Scope:** these tools inspect local configuration, file permissions and
> local sockets, or make a single read-only query to one host you name. They do
> **not** scan networks, brute-force credentials, run exploits, or cause denial
> of service. Use them only on systems you own or have written authorization to
> test. Unauthorized scanning or access is illegal regardless of intent.
>
> Full scope and acceptable-use statement: [COMPLIANCE.md](./COMPLIANCE.md).

## What's inside

| Tool | Audits | How |
| --- | --- | --- |
| [`node_audit.py`](./node_audit.py) | Bitcoin Core | local `bitcoin.conf` + file perms + local sockets |
| [`lightning_audit.py`](./lightning_audit.py) | lnd / Core Lightning | local config + macaroon/socket perms + local sockets |
| [`miner_audit.py`](./miner_audit.py) | one ASIC/GPU miner | single-target, read-only CGMiner API + TCP reachability |
| [`exposure_audit.py`](./exposure_audit.py) | this host's network exposure | lists local sockets, flags anything reachable off-box (never scans other hosts) |
| [`audit_common.py`](./audit_common.py) | — | shared severity model, reporting, single-target guard |
| [`kraken_core.py`](./kraken_core.py) | — | the audit engine: one API every front-end calls |
| [`kraken_app.py`](./kraken_app.py) | — | native desktop app (Tkinter) with a Security Score widget |
| [`kraken_report.py`](./kraken_report.py) | — | run several audits → one Markdown / JSON report |

Each tool prints findings with a severity (🔴 CRITICAL … 🟢 OK) and a concrete
fix, supports `--output report.md` and `--json`, and exits non-zero on
CRITICAL/HIGH findings for use in cron/CI.

Full reference: **[AUDIT.md](./AUDIT.md)**.

## Install

Two ways — full details in **[INSTALL.md](./INSTALL.md)**:

- **No Python required** — a single standalone binary bundling every auditor
  *and* the desktop app. Build once with `./packaging/build.sh`, then copy
  `dist/kraken` to any machine of the same OS/arch and run it — the target
  needs no Python, pip or Tk:

  ```bash
  git clone -b claude/amazing-turing-qerm47 https://github.com/vladislav957/Kraken-2.0.git
  cd Kraken-2.0
  ./packaging/build.sh            # -> dist/kraken  (self-contained)
  ./dist/kraken                   # launch the desktop app
  ./dist/kraken node --conf ~/.bitcoin/bitcoin.conf
  ```

- **From source** — pure Python standard library, no pip dependencies
  (`python3 node_audit.py …`). See the Quickstart below.

## Quickstart

```bash
# Audit a Bitcoin Core node
python3 node_audit.py --conf ~/.bitcoin/bitcoin.conf

# Audit a Lightning node (lnd or CLN)
python3 lightning_audit.py --impl lnd --conf ~/.lnd/lnd.conf --dir ~/.lnd

# Audit one miner you own (single host only — ranges/CIDRs are refused)
python3 miner_audit.py --target 192.168.1.50

# Combine several into one report (Markdown + JSON) with an overall score
python3 kraken_report.py --node ~/.bitcoin/bitcoin.conf --miner 192.168.1.50 --output report.md

# What of THIS host is reachable off-box (local sockets only; never scans others)
python3 exposure_audit.py
```

Diagrams and sample output are in [docs/](./docs/README.md).

## Desktop app

Prefer a GUI? A native desktop app (Tkinter — standard library, no browser, no
dependencies) wraps the same auditors, with a **Security Score** widget:

```bash
python3 kraken_app.py
```

It is built on [`kraken_core.py`](./kraken_core.py), the shared audit engine
that every front-end (CLI, app) calls. If Tk is missing, install it
(e.g. `sudo apt install python3-tk`).

## Practice safely

A regtest lab is included so you can run the auditors against live-ish targets
without touching anyone else's systems — real `bitcoind` on the isolated
regtest network, sample Lightning configs, and a fake CGMiner emulator:

```bash
cd lab
./run-audit.sh            # audit all samples + start the hardened node
```

See **[lab/README.md](./lab/README.md)**.

## Tests

```bash
./run-tests.sh            # stdlib unittest, no dependencies, no network
```

## Hardening references

- [`bitcoin.conf.hardened.example`](./bitcoin.conf.hardened.example) — a
  localhost-only, cookie-auth Bitcoin Core config.
- Lightning / miner hardening notes are in [AUDIT.md](./AUDIT.md).

## License / use

For defensive security assessment of your own infrastructure, or
infrastructure you are explicitly authorized to test. Nothing here is intended
for, or capable of, attacking third-party systems.
