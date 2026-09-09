#!/usr/bin/env bash
# Run every worked Cybench example against a freshly built task, and report
# which recovered their flag.
#
# Each script is checked against the answer key the task ships — `flag.txt`
# under `metadata/solution`, which is what Cybench's own `run_solution.sh`
# compares against — so a pass means the exact expected string came back, not
# merely that something flag-shaped appeared — MOTP, for one, ships
# `flag{this_is_fake_flag}` in its source as a fallback.
#
#   ./examples/cybench/run-all.sh                  # every example
#   ./examples/cybench/run-all.sh chunky motp      # just these
#
# One task at a time, deliberately. Four of them publish port 1337 and most pin
# their container names, so two at once is a collision rather than a result.
#
# Needs `h5i` on `$PATH` with the `websec` plugin installed, or `H5I` pointing
# at a build of it, and Python's `cryptography` for the one task that has to
# sign a JWT:
#
#   H5I=../h5i/target/release/h5i ./examples/cybench/run-all.sh
set -uo pipefail
cd "$(dirname "$0")/../.."
H5I="${H5I:-h5i}"
CYBENCH="./scripts/cybench.sh"

# Which task each script solves, named the way `cybench.sh` resolves them.
# The corpus's own names are `[Very Easy] Flag Command`, which is four quoting
# decisions to reach a directory there is only one of.
TASKS="
flag-command.sh|Flag Command
locktalk.sh|LockTalk
labyrinth-linguist.sh|Labyrinth Linguist
frog-waf.sh|frog-waf
chunky.sh|chunky
motp.sh|05-motp
back-to-the-past.sh|back-to-the-past
glacier-exchange.sh|GlacierExchange
"

want=("$@")
PASS=0
FAIL=0

while IFS='|' read -r script task; do
    [ -z "$script" ] && continue
    name="${script%.sh}"
    if [ "${#want[@]}" -gt 0 ]; then
        case " ${want[*]} " in
            *" $name "*) ;;
            *) continue ;;
        esac
    fi

    url="$("$CYBENCH" up "$task" 2>/dev/null | tail -1)"
    if [ "${url:0:4}" != "http" ]; then
        printf '  %-20s FAILED (did not start)\n' "$name"
        FAIL=$((FAIL + 1))
        "$CYBENCH" down "$task" >/dev/null 2>&1
        continue
    fi

    got="$(H5I="$H5I" timeout 900 "examples/cybench/$script" "$url" 2>/dev/null | tail -1)"
    expected="$("$CYBENCH" flag "$task")"
    if [ "$got" = "$expected" ]; then
        printf '  %-20s ok\n' "$name"
        PASS=$((PASS + 1))
    else
        printf '  %-20s FAILED (got %s)\n' "$name" "'${got:0:44}'"
        FAIL=$((FAIL + 1))
    fi
    "$CYBENCH" down "$task" >/dev/null 2>&1
done <<< "$TASKS"

echo
echo "  $PASS solved, $FAIL failed"
[ "$FAIL" -eq 0 ]
