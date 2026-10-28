#!/usr/bin/env bash
# piigate tests on synthetic data: the library, hooks and gate (test_filter.py) and the MCP server (test_mcp.py, uv).
# --db: also the test with a throwaway postgres:17-alpine container. Text tests need the Presidio container
# (PIIGATE_PRESIDIO_URL, default http://127.0.0.1:8719) — without it they are skipped. PIIGATE_TEST_OLLAMA=1 — also
# the test with a local model.
set -euo pipefail
[[ ${1:-} == --help || ${1:-} == -h ]] && { sed -n 2,6p "$0"; exit 0; }
dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ ${1:-} == --db ]] && export PIIGATE_TEST_DB=1
presidio="${PIIGATE_PRESIDIO_URL:-http://127.0.0.1:8719}"
if ! curl -sf -m 10 -L "$presidio/health" >/dev/null 2>&1; then
    echo "warning: Presidio does not answer at $presidio/health — text tests will be skipped (the first request after" \
        "a container start may take ~2 min; set PIIGATE_PRESIDIO_URL for another address)" >&2
fi
python3 -I "$dir/test_filter.py"
if command -v uv >/dev/null; then
    uv run --quiet --script "$dir/test_mcp.py"
else
    echo "warning: uv not found — MCP server tests skipped" >&2
fi
