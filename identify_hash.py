#!/usr/bin/env python3
"""
identify_hash.py

Heuristic hash type identifier.

Usage:
    python identify_hash.py <hash>
    python identify_hash.py -f list_of_hashes.txt
    python identify_hash.py -i   # interactive

Notes:
 - This is heuristic: many hashes share lengths/character sets, so results are possible matches.
 - Recognizes many common formats: MD5, SHA1, SHA2 family, SHA3, bcrypt, argon2, pbkdf2, crypt ($1$, $5$, $6$), NTLM, LDAP{SSHA,SMD5}, CRC32, Base64-encoded blobs, JWT-like tokens and more.
"""

import re
import sys
import argparse
import base64
from typing import List, Tuple

HEX_RE = re.compile(r'^[0-9a-fA-F]+$')
B64_RE = re.compile(r'^[A-Za-z0-9+/]+=*$')

# Map of exact hex lengths to likely algorithms (length in hex chars)
LENGTH_MAP = {
    8:  ["crc32"],
    32: ["md5", "ntlm", "md4"],
    40: ["sha1", "ripemd160"],
    56: ["sha224"],
    64: ["sha256", "sha3_256"],
    96: ["sha384", "sha3_384"],
    128: ["sha512", "sha3_512"],
    # other lengths sometimes encountered:
    16: ["mysql323"],  # 16 hex chars sometimes seen in legacy
}

# Common prefix patterns for well-known schemes
PREFIX_PATTERNS = [
    (re.compile(r'^\$2[aby]\$'), 'bcrypt'),
    (re.compile(r'^\$argon2i\$'), 'argon2i'),
    (re.compile(r'^\$argon2id\$'), 'argon2id'),
    (re.compile(r'^\$argon2d\$'), 'argon2d'),
    (re.compile(r'^\$pbkdf2-sha1\$'), 'pbkdf2-sha1'),
    (re.compile(r'^\$pbkdf2-sha256\$'), 'pbkdf2-sha256'),
    (re.compile(r'^\$1\$'), 'md5crypt'),        # Apache MD5 crypt ($1$)
    (re.compile(r'^\$5\$'), 'sha256crypt'),     # SHA-256 crypt ($5$)
    (re.compile(r'^\$6\$'), 'sha512crypt'),     # SHA-512 crypt ($6$)
    (re.compile(r'^\{SSHA\}'), 'ssha (ldap)'),
    (re.compile(r'^\{SMD5\}'), 'smd5 (ldap)'),
    (re.compile(r'^[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+$'), 'jwt-like (three dot parts)'),
]

# Some formats use base64 inside e.g. {SSHA}<base64>
SSHA_RE = re.compile(r'^\{SSHA\}([A-Za-z0-9+/]+=*)$')
SMD5_RE = re.compile(r'^\{SMD5\}([A-Za-z0-9+/]+=*)$')

def is_base64(s: str) -> bool:
    # Quick check: length divisible by 4 (or padded) and matches b64 charset
    if not B64_RE.match(s):
        return False
    try:
        base64.b64decode(s, validate=True)
        return True
    except Exception:
        return False

def guess_from_hex(s: str) -> List[Tuple[str, float]]:
    """Return list of (algorithm, confidence) guesses for hex strings."""
    L = len(s)
    guesses = []
    if L in LENGTH_MAP:
        for alg in LENGTH_MAP[L]:
            guesses.append((alg, 0.95))
    # Ambiguities
    if L == 32:
        guesses.append(("md5 (or NTLM/MD4)", 0.5))
    if L == 40:
        guesses.append(("sha1 or ripemd160", 0.6))
    if L == 64:
        guesses.append(("sha256 or sha3_256", 0.6))
    if L == 128:
        guesses.append(("sha512 or sha3_512", 0.6))
    # Very low-confidence fallback for odd lengths
    if not guesses:
        guesses.append((f"hex ({L} chars) - unknown algorithm", 0.2))
    return guesses

def analyze_token(token: str) -> List[Tuple[str, float]]:
    token = token.strip()
    results: List[Tuple[str, float]] = []

    # Check prefix-based structured formats first
    for pat, name in PREFIX_PATTERNS:
        if pat.match(token):
            results.append((name, 0.99))

    # LDAP SSHA / SMD5
    m = SSHA_RE.match(token)
    if m:
        b64 = m.group(1)
        if is_base64(b64):
            results.append(("SSHA (LDAP salted SHA1)", 0.97))
    m2 = SMD5_RE.match(token)
    if m2:
        if is_base64(m2.group(1)):
            results.append(("SMD5 (LDAP salted MD5)", 0.97))

    # bcrypt (common hash format example $2b$12$...)
    if token.startswith("$2a$") or token.startswith("$2b$") or token.startswith("$2y$"):
        results.append(("bcrypt", 0.99))

    # Argon2 common header handled above by prefix patterns

    # If token is hex
    if HEX_RE.match(token):
        hex_guesses = guess_from_hex(token)
        results.extend(hex_guesses)
        return sorted(results, key=lambda x: -x[1])

    # If token is base64
    if is_base64(token):
        # base64 length in bytes
        raw = base64.b64decode(token)
        b_len = len(raw)
        # heuristics based on decoded length
        if b_len == 20:
            results.append(("sha1 (base64)", 0.7))
        elif b_len == 16:
            results.append(("md5 (base64)", 0.7))
        elif b_len == 32:
            results.append(("sha256 (base64)", 0.8))
        elif b_len == 64:
            results.append(("sha512 (base64)", 0.8))
        else:
            results.append((f"base64 blob ({b_len} bytes) - unknown digest", 0.3))
        return sorted(results, key=lambda x: -x[1])

    # If contains only [A-Za-z0-9./] and length ~ 60: could be crypt-style with salt (modular crypt)
    if re.match(r'^[A-Za-z0-9./\$=\-_:]+$', token):
        L = len(token)
        if 50 <= L <= 80 and token.count('$') >= 2:
            results.append(("modular crypt / password hash (bcrypt/sha512-crypt/pbkdf2-like)", 0.7))
        elif L == 32 and re.match(r'^[A-Za-z0-9]{32}$', token):
            results.append(("possible raw hex/base32/md5-like (not hex)", 0.25))
    
    # If it looks like a JWT (three dot-separated parts)
    if token.count('.') == 2 and all(len(part) > 0 for part in token.split('.')):
        results.append(("JWT or JWS (base64url three-part token)", 0.95))

    # Fallback
    if not results:
        results.append(("unknown/unsupported format; could be salted/encoded or custom", 0.05))

    return sorted(results, key=lambda x: -x[1])

def pretty_print_guesses(token: str):
    token = token.strip()
    print(f"\nHash: {token}")
    guesses = analyze_token(token)
    for alg, conf in guesses:
        print(f"  - {alg}  (confidence {conf*100:.0f}%)")

def main():
    parser = argparse.ArgumentParser(description="Heuristic hash type identifier")
    parser.add_argument("hash", nargs="?", help="Single hash/token to analyze")
    parser.add_argument("-f", "--file", help="File with one hash per line")
    parser.add_argument("-i", "--interactive", action="store_true", help="Interactive mode")
    args = parser.parse_args()

    if args.file:
        try:
            with open(args.file, 'r', encoding='utf-8') as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    pretty_print_guesses(line)
        except Exception as e:
            print("Error reading file:", e)
            sys.exit(1)
        return

    if args.hash:
        pretty_print_guesses(args.hash)
        return

    if args.interactive:
        print("Interactive mode. Type hashes (empty line to quit).")
        while True:
            try:
                tok = input("> ").strip()
            except EOFError:
                break
            if not tok:
                break
            pretty_print_guesses(tok)
        return

    parser.print_help()

if __name__ == "__main__":
    main()
