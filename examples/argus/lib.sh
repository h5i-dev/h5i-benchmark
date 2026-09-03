# Helpers shared by the Argus worked examples. Source it; do not run it.
#
# Three functions, and each exists because of a seam in the workbench rather
# than because of anything the benchmarks have in common.
#
#   send    `websec replay` answers with what it changed and how the response
#           looked — status, size, headers — and not with the body, which is
#           right for a verb that may have just pulled down a database dump.
#           An exploit almost always wants the body, so it has to name the
#           message the replay created. That is two calls, and this is them.
#   flag    the corpus's flags are `FLAG{lower_snake_case}`, and a response
#           that holds one usually holds it inside JSON inside JSON.
#   ready   several of these applications answer on the port before they have
#           finished seeding, and a run that started too early reads as a
#           benchmark that resists rather than as one that was not up yet.

H5I="${H5I:-h5i}"

# send SESSION ID [replay flags...] — resend a captured request, print the
# response as an HTTP message.
send() {
    local session="$1" id="$2"
    shift 2
    local reply seq
    reply="$("$H5I" websec replay "$id" --session "$session" "$@")" || return 1
    seq="$(printf '%s' "$reply" | python3 -c \
        'import json,sys; print(json.load(sys.stdin).get("seq",""))')"
    [ -n "$seq" ] || { printf '%s\n' "$reply" >&2; return 1; }
    "$H5I" websec show "res_$seq" --session "$session" --raw
}

# The first flag in whatever is on standard input.
flag() {
    python3 -c '
import re, sys
found = re.search(r"FLAG\{[A-Za-z0-9_.-]+\}", sys.stdin.read())
print(found.group(0) if found else "no flag found")
'
}

# The newest request this session made, as a `req_N` id.
#
# A multi-origin exploit navigates to each service in turn and then resends
# against the one it just reached, because a stored request carries the
# authority the socket dials. What it needs each time is "the request I just
# made", and that is the only thing `requests` does not name directly.
last() {
    "$H5I" websec requests --session "$1" | python3 -c '
import json, sys
rows = json.load(sys.stdin)["requests"]
print("req_%d" % max(row["seq"] for row in rows))
'
}

# The body of an HTTP message printed by `send` or `show --raw`. Either line
# ending: h5i writes the request half with CRLF, because that half is a file
# `resend --raw-request` can read back, and the response half with LF.
body() {
    python3 -c '
import re, sys
print(re.split(r"\r?\n\r?\n", sys.stdin.read(), maxsplit=1)[-1], end="")
'
}

# ready URL [SECONDS] — wait until the target answers at all.
ready() {
    local url="$1" seconds="${2:-60}" waited=0
    while [ "$waited" -lt "$seconds" ]; do
        curl -fsS -o /dev/null --max-time 3 "$url" 2>/dev/null && return 0
        sleep 2
        waited=$((waited + 2))
    done
    return 1
}
