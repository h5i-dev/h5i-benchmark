#!/usr/bin/env bash
# Run every worked example against a freshly built benchmark, and report which
# recovered their flag.
#
# Each script is checked against the flag the corpus computes for that benchmark
# (`FLAG{sha256(NAME)}`), so a pass means the exact expected string came back,
# not merely that something flag-shaped appeared.
#
#   ./examples/run-all.sh            # every example
#   ./examples/run-all.sh 006 021    # just these
#   JOBS=1 ./examples/run-all.sh     # one at a time
#
# Benchmarks run several at a time (`JOBS`, three by default). They can: since
# the runner stopped pinning host ports, two benchmarks no longer collide, and
# the slow part of each is a docker build that leaves a core idle.
#
# The unit of parallelism is the *benchmark*, not the script. Some benchmarks
# have two examples — a shell one and a Python one — and those share a docker
# project, so running them at the same time means one's `up` tears down the
# other's containers halfway through.
#
# Needs `h5i` on `$PATH` with the `websec` plugin installed, or `H5I` pointing
# at a build of it:
#
#   H5I=../h5i/target/release/h5i ./examples/run-all.sh
set -uo pipefail
cd "$(dirname "$0")/.."
H5I="${H5I:-h5i}"
XBEN="./scripts/xben.sh"
JOBS="${JOBS:-3}"
RESULTS="$(mktemp -d)"
trap 'rm -rf "$RESULTS"' EXIT

# One script against a fresh instance of its benchmark. Writes one result line.
one() {
    local script="$1" bench="$2" name line
    local url got expected
    name="$(basename "$script")"
    # A script that cannot be run is a broken example, not a benchmark that
    # resists. Reported as itself, because "FAILED (got '')" sends the reader to
    # the application.
    if [ ! -x "$script" ]; then
        printf '%s\n' "not executable" > "$RESULTS/$name"
        return
    fi
    url="$("$XBEN" up "$bench" 2>/dev/null | tail -1)"
    if [ "${url:0:4}" != "http" ]; then
        printf '%s\n' "skipped: ${url:-does not start}" > "$RESULTS/$name"
        "$XBEN" down "$bench" >/dev/null 2>&1
        return
    fi
    # Django's ALLOWED_HOSTS admits `localhost` and not `127.0.0.1`, which is
    # the same address under a name the application will answer to.
    [ "${bench:5:3}" = "009" ] && url="${url/127.0.0.1/localhost}"

    got="$(H5I="$H5I" timeout 600 "$script" "$url" 2>/dev/null | tail -1)"
    expected="$("$XBEN" flag "$bench")"
    if [ "$got" = "$expected" ]; then
        line="ok"
    else
        line="FAILED (got '${got:0:44}')"
    fi
    printf '%s\n' "$line" > "$RESULTS/$name"
    "$XBEN" down "$bench" >/dev/null 2>&1
}

# Every example for one benchmark, in turn, each against a fresh instance.
all_for() {
    local bench="$1"
    shift
    local script
    for script in "$@"; do
        one "$script" "$bench"
    done
}

want=("$@")
declare -A scripts_for=()
order=()
for script in examples/xben-*; do
    name="$(basename "$script")"
    number="${name#xben-}"
    number="${number%%-*}"
    if [ "${#want[@]}" -gt 0 ]; then
        case " ${want[*]} " in
            *" $number "*) ;;
            *) continue ;;
        esac
    fi
    [ -z "${scripts_for[$number]:-}" ] && order+=("$number")
    scripts_for[$number]+="$script "
done

for number in "${order[@]}"; do
    while [ "$(jobs -rp | wc -l)" -ge "$JOBS" ]; do wait -n; done
    # shellcheck disable=SC2086
    all_for "XBEN-$number-24" ${scripts_for[$number]} &
done
wait

PASS=0
FAIL=0
for number in "${order[@]}"; do
    # shellcheck disable=SC2086
    set -- ${scripts_for[$number]}
    for script in "$@"; do
        name="$(basename "$script")"
        result="$(cat "$RESULTS/$name" 2>/dev/null || echo 'no result')"
        # Two scripts for one benchmark is normal — a shell version and a
        # Python one — so name the script when the benchmark alone is
        # ambiguous.
        if [ "$#" -gt 1 ]; then
            # With the extension: the two versions of one example differ only
            # there, and a report that printed the same name twice would not
            # say which one failed.
            printf '  %-16s %-34s %s\n' "XBEN-$number-24" "$name" "$result"
        else
            printf '  %-16s %s\n' "XBEN-$number-24" "$result"
        fi
        case "$result" in
            ok) PASS=$((PASS + 1)) ;;
            skipped:*) ;;
            *) FAIL=$((FAIL + 1)) ;;
        esac
    done
done

echo
echo "  $PASS solved, $FAIL failed"
[ "$FAIL" -eq 0 ]
