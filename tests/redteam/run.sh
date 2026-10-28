#!/usr/bin/env bash
# Red teaming of `piigate analyze` with promptfoo: prompt injection in files, mail and questions, synthetic data only.
# Usage: tests/redteam/run.sh --agent 'COMMAND [ARGS…]' [--engine URL] [--out DIR] [--filter TEXT]
#   --agent   the local agent command (`analysis.agent_command`, e.g. 'my-agent --model gpt-oss:20b')
#   --engine  Presidio container URL (default http://127.0.0.1:8719); --out — directory for wynik.html/json
#   --filter  only tests whose description matches TEXT. Needs promptfoo and python3; one case takes ~1–3 min.
set -euo pipefail
[[ ${1:-} == --help || ${1:-} == -h ]] && { sed -n 2,7p "$0"; exit 0; }
dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
agent="" engine="http://127.0.0.1:8719" out="" filter=()
while [[ $# -gt 0 ]]; do
    case $1 in
        --agent) agent=${2:?}; shift 2 ;;
        --engine) engine=${2:?}; shift 2 ;;
        --out) out=${2:?}; shift 2 ;;
        --filter) filter=(--filter-pattern "${2:?}"); shift 2 ;;
        *) echo "run.sh: unknown option $1" >&2; exit 2 ;;
    esac
done
[[ -n $agent ]] || { echo "run.sh: --agent is required (see --help)" >&2; exit 2; }
command -v promptfoo >/dev/null || { echo "run.sh: promptfoo not found" >&2; exit 2; }
curl -sf -m 200 -L "$engine/health" >/dev/null || { echo "run.sh: the engine does not answer at $engine/health" >&2; exit 2; }
REDTEAM_AGENT=$(python3 -c 'import json, shlex, sys; print(json.dumps(shlex.split(sys.argv[1])))' "$agent")
REDTEAM_ENGINE_URL=$engine
export REDTEAM_AGENT REDTEAM_ENGINE_URL
outputs=()
if [[ -n $out ]]; then
    mkdir -p "$out"
    outputs=(-o "$out/wynik.html" "$out/wynik.json")
fi
cd "$dir"
promptfoo eval -c promptfooconfig.yaml --no-cache --no-share "${filter[@]}" "${outputs[@]}"
