#!/usr/bin/env bash
# Run the Kraken audit suite's unit tests (stdlib unittest, no dependencies).
set -euo pipefail
cd "$(dirname "$0")"
exec python3 -m unittest discover -s tests -p "test_*.py" "$@"
