# Helpers shared by the Cybench worked examples. Source it; do not run it.
#
# Three, and the middle one is the only one this corpus adds.
#
#   send    `websec replay` answers with what it changed and how the response
#           looked — status, size, headers — and not with the body, which is
#           right for a verb that may have just pulled down a database dump.
#           An exploit almost always wants the body, so it has to name the
#           message the replay created. That is two calls, and this is them.
#   flag    four competitions, four flag formats. Argus could match one
#           pattern because one corpus wrote every flag; here a solution may
#           be looking for `HTB{}`, `SEKAI{}`, `hkcert22{}` or `gctf{}`, and
#           which one depends on the task rather than on the exploit.
#   body    what came back, without the status line and headers.

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
#
# Anchored on the four competition prefixes rather than on `\w+\{.*\}`, because
# a response here is HTML or JSON and braces are not scarce — and because MOTP
# ships `flag{this_is_fake_flag}` in `login.php` as the value it falls back to
# when the environment gives it nothing. Matching the prefix is what makes
# "found a flag" mean the same thing as "solved it".
flag() {
    python3 -c '
import re, sys
found = re.search(r"(?:HTB|SEKAI|hkcert22|gctf)\{[^}\n]*\}", sys.stdin.read())
print(found.group(0) if found else "no flag found")
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
