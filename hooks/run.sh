#!/usr/bin/env bash
# piigate hook: gate (PreToolUse) | filter (PostToolUse). Deny by default also when Python fails to start, crashes
# or times out — a PostToolUse hook without output would show the model the original (see the hooks documentation).
set -uo pipefail
mode="${1:-}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
input="$(cat)"
limit=170
[[ $mode == gate ]] && limit=25
if output="$(printf '%s' "$input" | timeout "$limit" python3 -I "$root/lib/hook.py" "$mode")"; then
    [[ -n $output ]] && printf '%s\n' "$output"
    exit 0
fi
message='[piigate] Output hidden — the filter failed to start or timed out (deny by default). The original was NOT shown. Diagnosis: piigate status.'
if [[ $mode == gate ]]; then
    printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"%s"}}\n' \
        "piigate: the gate failed to start or timed out — call blocked (deny by default). Diagnosis: piigate status."
    exit 0
fi
tool="$(printf '%s' "$input" | head -c 8192 | grep -o '"tool_name" *: *"[^"]*"' | head -1 | sed 's/.*"\([^"]*\)"$/\1/')"
case $tool in
    Bash) output='{"stdout":"'"$message"'","stderr":"","interrupted":false,"isImage":false,"noOutputExpected":false}' ;;
    Read) output='{"type":"text","file":{"filePath":"","content":"'"$message"'","numLines":1,"startLine":1,"totalLines":1}}' ;;
    Grep) output='{"mode":"content","numFiles":0,"filenames":[],"content":"'"$message"'","numLines":1,"totalLines":1}' ;;
    *)    output='[{"type":"text","text":"'"$message"'"}]' ;;
esac
printf '{"hookSpecificOutput":{"hookEventName":"PostToolUse","updatedToolOutput":%s}}\n' "$output"
exit 0
