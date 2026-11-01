# Docs

Diagrams and sample output for the Kraken Audit toolkit.

## Architecture

One engine (the core), many front-ends — all read-only.

![Architecture](./architecture.png)

## How one audit runs

Step by step: input → single-target guard → read-only collect → parse → checks
→ score → report. The red branch (guard) and the exit codes show where the
process stops.

![Audit flow](./audit-flow.png)

## Sample run

`node_audit.py` on an insecure config (findings + fixes, exit 1) and on a
hardened one (clean, exit 0):

![Sample run](./sample-run.png)

## Sample combined report

`kraken_report.py` gathering Bitcoin Core, Lightning and a miner into one
document with an overall Security Score:

![Sample report](./sample-report.png)

## Desktop app — all tabs

The four tabs of `kraken_app.py` — Bitcoin Core, Lightning, Miner and Exposure —
each with a live audit and the shared Security Score widget (sample data):

![Desktop app](./desktop-app.png)
