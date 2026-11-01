# Compliance & Scope

**Kraken Audit is a defensive, read-only security toolkit.** Its only purpose is
to help an operator harden infrastructure they own, or are explicitly authorized
to test, by finding misconfigurations before an attacker would.

## What this project does

- Reads a machine's **own** local configuration (e.g. `bitcoin.conf`, `lnd.conf`)
  and reports settings that would expose it.
- Checks the permissions of local credential files.
- Inspects the **local** machine's own listening sockets.
- Produces a report (terminal / Markdown / JSON) with a severity and a concrete
  remediation step for each finding.

## What this project does NOT do

- It does **not** scan networks or sweep IP ranges.
- It does **not** brute-force, guess, or test credentials.
- It does **not** run exploits or cause denial of service.
- It does **not** connect to or act against any system the operator does not own.

The single-target miner check (`miner_audit.py`) **refuses ranges, CIDRs and
lists by design** and performs only a read-only status query — it never attempts
to authenticate. This is enforced in code (`audit_common.parse_single_target`)
and covered by unit tests, so the tool cannot be repurposed as a mass scanner.

## History

Earlier components that did not fit this defensive scope were **removed** from
the project. The current tree contains only the read-only auditors
(`node_audit.py`, `lightning_audit.py`, `miner_audit.py`, `audit_common.py`),
their unit tests, documentation, and a local `regtest` practice lab that runs
entirely on an isolated test network.

## Acceptable use

Use this only on infrastructure you own, or have **written authorization** to
test. Unauthorized scanning or access is prohibited and may be illegal
regardless of intent.

This project is maintained in good-faith compliance with the
[GitHub Acceptable Use Policies](https://docs.github.com/site-policy/acceptable-use-policies/github-acceptable-use-policies).
