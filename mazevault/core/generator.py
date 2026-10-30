"""Password generator: the OS CSPRNG (secrets), no modulo bias, every chosen
character class guaranteed to appear."""
from __future__ import annotations

import math
import secrets
import string

LOWER = string.ascii_lowercase
UPPER = string.ascii_uppercase
DIGITS = string.digits
SYMBOLS = "!@#$%^&*-_=+?"
AMBIGUOUS = set("Il1O0o")


def password(length: int = 20, lower: bool = True, upper: bool = True, digits: bool = True,
             symbols: bool = True, avoid_ambiguous: bool = False) -> str:
    classes = [c for c, on in ((LOWER, lower), (UPPER, upper), (DIGITS, digits), (SYMBOLS, symbols)) if on]
    if not classes:
        classes = [LOWER]
    if avoid_ambiguous:
        classes = ["".join(ch for ch in c if ch not in AMBIGUOUS) for c in classes]
    length = max(length, len(classes), 4)
    length = min(length, 128)
    chars = [secrets.choice(c) for c in classes]           # one of each class
    pool = "".join(classes)
    chars += [secrets.choice(pool) for _ in range(length - len(chars))]
    # Fisher-Yates with the CSPRNG, so the guaranteed characters are not at the front.
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]
    return "".join(chars)


def entropy_bits(pw: str) -> float:
    pool = 0
    if any(c in LOWER for c in pw):
        pool += 26
    if any(c in UPPER for c in pw):
        pool += 26
    if any(c in DIGITS for c in pw):
        pool += 10
    if any(not c.isalnum() and c.isascii() for c in pw):
        pool += 33
    if any(not c.isascii() for c in pw):
        pool += 60
    return len(pw) * math.log2(pool) if pool else 0.0
