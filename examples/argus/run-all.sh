#!/usr/bin/env bash
# Run every worked Argus example against a freshly built benchmark, and report
# which recovered their flag.
#
# Each script is checked against the flag `scripts/apex.sh` gave that
# benchmark's build, so a pass means the exact expected string came back, not
# merely that something flag-shaped appeared. Several of these applications
# ship a decoy flag in their source, which is the reason for insisting.
#
#   ./examples/argus/run-all.sh            # every example
#   ./examples/argus/run-all.sh 001 004    # just these
#
# One benchmark at a time, deliberately. Most of the corpus pins its host port,
# a good half of it pins container names, and the later ones bring up eight
# services at once; two builds in parallel is how this ends in an OOM kill
# rather than a result.
#
# Needs `h5i` on `$PATH` with the `websec` plugin installed, or `H5I` pointing
# at a build of it:
#
#   H5I=../h5i/target/release/h5i ./examples/argus/run-all.sh
set -uo pipefail
cd "$(dirname "$0")/../.."
H5I="${H5I:-h5i}"
APEX="./scripts/apex.sh"

want=("$@")
PASS=0
FAIL=0
SKIP=0

for script in examples/argus/apex-*; do
    name="$(basename "$script")"
    number="${name#apex-}"
    number="${number%%-*}"
    if [ "${#want[@]}" -gt 0 ]; then
        case " ${want[*]} " in
            *" $number "*) ;;
            *) continue ;;
        esac
    fi
    bench="APEX-$number-25"

    url="$("$APEX" up "$bench" 2>/dev/null | tail -1)"
    if [ "${url:0:4}" != "http" ]; then
        printf '  %-14s skipped: does not start here\n' "$bench"
        SKIP=$((SKIP + 1))
        "$APEX" down "$bench" >/dev/null 2>&1
        continue
    fi

    got="$(H5I="$H5I" APEX_URL="$url" timeout 900 "$script" "$url" 2>/dev/null | tail -1)"
    expected="$("$APEX" flag "$bench")"
    if [ "$got" = "$expected" ]; then
        printf '  %-14s ok\n' "$bench"
        PASS=$((PASS + 1))
    else
        printf '  %-14s FAILED (got %s)\n' "$bench" "'${got:0:44}'"
        FAIL=$((FAIL + 1))
    fi
    "$APEX" down "$bench" >/dev/null 2>&1
done

echo
echo "  $PASS solved, $FAIL failed, $SKIP skipped"
[ "$FAIL" -eq 0 ]
