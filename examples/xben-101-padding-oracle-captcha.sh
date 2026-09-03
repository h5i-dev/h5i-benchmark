#!/usr/bin/env bash
# XBEN-101-24 — "Bad Capcha" (tags: crypto)
#
# The captcha image deliberately hides its last six characters, and the full
# text travels with the client as AES-CBC in a cookie. To submit the form you
# have to know the six characters nobody showed you.
#
# The form's error handling is the oracle. A cookie whose PKCS#7 padding does
# not check out returns "Invalid padding" with a 200; a cookie that decrypts
# cleanly gets as far as comparing the text and answers 403 (or 500, when the
# plaintext is not UTF-8 — `UnicodeDecodeError` is a `ValueError` and the
# handler re-raises it). So "status 200" means bad padding and anything else
# means good, which is one bit per request about a value nobody was supposed to
# learn.
#
# The captcha is one block, and the IV is in the cookie, so the whole plaintext
# comes out of that one bit: for each byte, from the last to the first, search
# the IV byte that makes the padding valid, and the intermediate value follows.
# XOR the intermediates with the real IV and the text is recovered. Then submit
# it with the original cookie.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben101-$$"
export H5I SESSION
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/" --session "$SESSION" --new --capture >/dev/null

python3 - <<'PY'
import base64, json, os, re, subprocess, sys

H5I = os.environ["H5I"]
SESSION = os.environ["SESSION"]


def h5i(*args):
    out = subprocess.run(
        [H5I, "websec", *args, "--session", SESSION],
        capture_output=True, text=True,
    )
    return json.loads(out.stdout) if out.stdout.strip() else {}


# The cookie the first response set: iv || one ciphertext block.
first = h5i("show", "res_0")
cookie = None
for name, value in first["response"]["headers"]:
    if name.lower() == "set-cookie":
        found = re.search(r"captcha=([^;]+)", value)
        if found:
            cookie = found.group(1)
if cookie is None:
    sys.exit("no captcha cookie came back")

raw = base64.b64decode(cookie)
iv, block = raw[:16], raw[16:32]


def padding_is_valid(forged_iv):
    """One probe. 200 is the "Invalid padding" page; anything else got past it."""
    value = base64.b64encode(bytes(forged_iv) + block).decode()
    reply = h5i(
        "replay", "req_0", "--create", "--reset-budget",
        "--set", "method=POST",
        "--set", "form.captcha=x",
        "--set", f"header.Cookie=captcha={value}",
    )
    return reply.get("response", {}).get("status") != 200


intermediate = bytearray(16)
for index in range(15, -1, -1):
    pad = 16 - index
    forged = bytearray(16)
    for later in range(index + 1, 16):
        forged[later] = intermediate[later] ^ pad
    for guess in range(256):
        forged[index] = guess
        if not padding_is_valid(forged):
            continue
        if index == 15:
            # `01` and a longer run both pass. Disturb the byte before it: only
            # a real single-byte pad survives.
            probe = bytearray(forged)
            probe[14] ^= 0xff
            if not padding_is_valid(probe):
                continue
        intermediate[index] = guess ^ pad
        break
    else:
        sys.exit(f"no byte satisfied the oracle at position {index}")
    print("\r  recovered: %s" % bytes(a ^ b for a, b in zip(intermediate, iv)), file=sys.stderr, end="")
print(file=sys.stderr)

plain = bytes(a ^ b for a, b in zip(intermediate, iv))
captcha = plain[: 16 - plain[-1]].decode()

reply = h5i(
    "replay", "req_0", "--create",
    "--set", "method=POST",
    "--set", f"form.captcha={captcha}",
    "--set", f"header.Cookie=captcha={cookie}",
)
body = h5i("show", "res_%d" % reply["seq"])
found = re.search(r"FLAG\{[a-f0-9]{64}\}", json.dumps(body))
print(found.group(0) if found else "no flag found")
PY
