#!/usr/bin/env python3
"""
identify_hash_upgraded.py

Heuristic hash type identifier (upgraded).

Features:
 - Better ambiguity handling for 128-hex (512-bit) outputs:
   lists SHA-512, SHA3-512, Whirlpool, BLAKE2b-512, Skein-512, etc.
 - Verification mode: supply a plaintext (or a file of plaintexts) to compute many digests
   and check whether any match the target hash (hex or base64 variants).
 - Attempts to use Whirlpool via pycryptodome if available; otherwise still lists Whirlpool as a candidate.

Usage:
   python identify_hash_upgraded.py <hash>
   python identify_hash_upgraded.py -f hashes.txt
   python identify_hash_upgraded.py <hash> -t "password123"       # test candidate plaintext
   python identify_hash_upgraded.py <hash> --test-file words.txt
   python identify_hash_upgraded.py -i   # interactive

Notes:
 - This is heuristic for identification; verification is exact (if digest algorithm available).
 - To enable Whirlpool computation, install pycryptodome: pip install pycryptodome
"""

import re
import sys
import argparse
import base64
import hashlib
from typing import List, Tuple

# Try to import Whirlpool from pycryptodome if available
WHIRLPOOL_AVAILABLE = False
try:
    from Crypto.Hash import WHIRLPOOL  # type: ignore
    WHIRLPOOL_AVAILABLE = True
except Exception:
    WHIRLPOOL_AVAILABLE = False

HEX_RE = re.compile(r'^[0-9a-fA-F]+$')
B64_RE = re.compile(r'^[A-Za-z0-9+/]+=*$')
B64URL_RE = re.compile(r'^[A-Za-z0-9_\-]+=*$')

# Base mapping for hex lengths (in hex chars)
LENGTH_MAP = {
    8:  ["crc32"],
    16: ["mysql323"],
    32: ["md5", "ntlm", "md4"],
    40: ["sha1", "ripemd160"],
    56: ["sha224"],
    64: ["sha256", "sha3_256", "blake2s-256"],
    96: ["sha384", "sha3_384"],
    128: ["sha512", "sha3_512", "blake2b-512", "whirlpool", "skein-512"],
}

PREFIX_PATTERNS = [
    (re.compile(r'^\$2[aby]\$'), 'bcrypt'),
    (re.compile(r'^\$argon2i\$'), 'argon2i'),
    (re.compile(r'^\$argon2id\$'), 'argon2id'),
    (re.compile(r'^\$argon2d\$'), 'argon2d'),
    (re.compile(r'^\$pbkdf2-sha1\$'), 'pbkdf2-sha1'),
    (re.compile(r'^\$pbkdf2-sha256\$'), 'pbkdf2-sha256'),
    (re.compile(r'^\$1\$'), 'md5crypt'),
    (re.compile(r'^\$5\$'), 'sha256crypt'),
    (re.compile(r'^\$6\$'), 'sha512crypt'),
    (re.compile(r'^\{SSHA\}'), 'ssha (ldap)'),
    (re.compile(r'^\{SMD5\}'), 'smd5 (ldap)'),
    (re.compile(r'^[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+$'), 'jwt-like (three dot parts)'),
]

SSHA_RE = re.compile(r'^\{SSHA\}([A-Za-z0-9+/]+=*)$')
SMD5_RE = re.compile(r'^\{SMD5\}([A-Za-z0-9+/]+=*)$')

def is_base64(s: str) -> bool:
    if not B64_RE.match(s):
        return False
    try:
        base64.b64decode(s, validate=True)
        return True
    except Exception:
        return False

def is_base64url(s: str) -> bool:
    if not B64URL_RE.match(s):
        return False
    # try padding to multiple of 4
    padding = (-len(s)) % 4
    try:
        base64.urlsafe_b64decode(s + ('=' * padding))
        return True
    except Exception:
        return False

def guess_from_hex(s: str) -> List[Tuple[str, float]]:
    L = len(s)
    results: List[Tuple[str, float]] = []
    if L in LENGTH_MAP:
        # Higher confidence for common ones
        common = LENGTH_MAP[L]
        base_conf = 0.9
        # Spread confidence across options; common first gets a little more
        for i, alg in enumerate(common):
            conf = base_conf - i * 0.12
            if conf < 0.25:
                conf = 0.25
            results.append((alg, conf))
    else:
        # heuristics for odd lengths or unknown
        if L % 2 == 0 and 64 <= L <= 256:
            results.append((f"unknown 0x{L//2*8}-bit hex (maybe custom/concat)", 0.25))
        else:
            results.append((f"hex ({L} chars) - unknown algorithm", 0.15))
    # Add ambiguous notes for MD5/NTLM etc.
    if L == 32:
        results.append(("md5 (or NTLM/MD4) - ambiguous", 0.45))
    if L == 128:
        # add explicit common modern choices if not present
        extras = ["sha512", "sha3_512", "blake2b-512", "whirlpool", "skein-512"]
        for alg in extras:
            if alg not in [r[0] for r in results]:
                results.append((alg, 0.35))
    return sorted(results, key=lambda x: -x[1])

def analyze_token(token: str) -> List[Tuple[str, float]]:
    token = token.strip()
    results: List[Tuple[str, float]] = []

    for pat, name in PREFIX_PATTERNS:
        if pat.match(token):
            results.append((name, 0.99))

    # LDAP SSHA / SMD5 detection
    if SSHA_RE.match(token):
        results.append(("SSHA (LDAP salted SHA1)", 0.97))
    if SMD5_RE.match(token):
        results.append(("SMD5 (LDAP salted MD5)", 0.97))

    # bcrypt quick detection
    if token.startswith("$2a$") or token.startswith("$2b$") or token.startswith("$2y$"):
        results.append(("bcrypt", 0.99))

    # Hex
    if HEX_RE.match(token):
        results.extend(guess_from_hex(token))
        return sorted(results, key=lambda x: -x[1])

    # Base64 / base64url
    if is_base64(token) or is_base64url(token):
        try:
            raw = base64.b64decode(token + ('=' * ((4 - len(token) % 4) % 4)))
            b_len = len(raw)
        except Exception:
            b_len = None
        if b_len is not None:
            if b_len == 16:
                results.append(("md5 (base64)", 0.8))
            elif b_len == 20:
                results.append(("sha1 (base64)", 0.8))
            elif b_len == 32:
                results.append(("sha256 / blake2b-256 (base64)", 0.8))
            elif b_len == 64:
                results.append(("sha512 / sha3-512 / blake2b-512 (base64)", 0.75))
            else:
                results.append((f"base64 blob ({b_len} bytes) - unknown digest", 0.3))
        return sorted(results, key=lambda x: -x[1])

    # JWT-like
    if token.count('.') == 2:
        results.append(("JWT / JWS (base64url three parts)", 0.95))

    # Fallback
    if not results:
        results.append(("unknown/unsupported format; could be salted/encoded or custom", 0.05))

    return sorted(results, key=lambda x: -x[1])

# ---------------- Verification helpers ----------------

def hexdigest(b: bytes) -> str:
    return b.hex()

def b64digest(b: bytes) -> str:
    return base64.b64encode(b).decode('ascii')

def b64urldigest(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode('ascii').rstrip('=')

def compute_common_hashes(plaintext: bytes) -> dict:
    """
    Compute many common digests for a given plaintext (raw bytes).
    Returns mapping name -> (hex, b64, b64url)
    """
    out = {}
    # builtin hashes
    hashes = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha224': hashlib.sha224,
        'sha256': hashlib.sha256,
        'sha384': hashlib.sha384,
        'sha512': hashlib.sha512,
        'sha3_256': hashlib.sha3_256,
        'sha3_384': hashlib.sha3_384,
        'sha3_512': hashlib.sha3_512,
        'blake2b-512': lambda data=b'': hashlib.blake2b(data, digest_size=64),
        'blake2b-256': lambda data=b'': hashlib.blake2b(data, digest_size=32),
        'blake2s-256': lambda data=b'': hashlib.blake2s(data, digest_size=32),
    }
    for name, func in hashes.items():
        try:
            h = func(plaintext)
            digest = h.digest()
            out[name] = (hexdigest(digest), b64digest(digest), b64urldigest(digest))
        except Exception:
            pass

    # Whirlpool if available
    if WHIRLPOOL_AVAILABLE:
        try:
            h = WHIRLPOOL.new(data=plaintext)
            d = h.digest()
            out['whirlpool'] = (hexdigest(d), b64digest(d), b64urldigest(d))
        except Exception:
            pass
    else:
        out['whirlpool'] = None  # mark as not computed

    # Note: Skein / Skein512 / others not available by default
    return out

def verify_against(hash_str: str, plaintext: bytes) -> List[Tuple[str, str]]:
    """
    Check plaintext against many hash computations.
    Returns list of (algorithm, matched_representation) for matches.
    """
    matches = []
    # normalize hash_str: allow hex (lower/upper), base64, base64url
    hs = hash_str.strip()
    lowered = hs.lower()
    computed = compute_common_hashes(plaintext)

    # compare hex variants (case-insensitive)
    for alg, reps in computed.items():
        if reps is None:
            continue
        hexv, b64v, b64urlv = reps
        if lowered == hexv.lower():
            matches.append((alg, 'hex'))
        if hs == b64v:
            matches.append((alg, 'base64'))
        if hs.rstrip('=') == b64urlv:  # compare ignoring padding
            matches.append((alg, 'base64url'))
    # also check common encodings of plaintext (utf-8 vs utf-16le for NTLM)
    # NTLM is MD4 of UTF-16LE; we can test MD4 via hashlib.new('md4') if available
    try:
        import hashlib as _hashlib
        # some Python builds support 'md4' via OpenSSL; try it
        md4 = _hashlib.new('md4', plaintext.decode('utf-8').encode('utf-16le'))
        if hs.lower() == md4.digest().hex():
            matches.append(('ntlm/md4(utf-16le)', 'hex'))
    except Exception:
        # not available; skip
        pass

    return matches

# ---------------- CLI / Main ----------------

def pretty_print_guesses(token: str):
    token = token.strip()
    print(f"\nHash/token: {token}")
    guesses = analyze_token(token)
    for alg, conf in guesses:
        print(f"  - {alg:18s} (confidence {conf*100:.0f}%)")
    print()

def main():
    parser = argparse.ArgumentParser(description="Upgraded heuristic hash type identifier + verifier")
    parser.add_argument("hash", nargs="?", help="Single hash/token to analyze")
    parser.add_argument("-f", "--file", help="File with one hash per line")
    parser.add_argument("-i", "--interactive", action="store_true", help="Interactive mode")
    parser.add_argument("-t", "--test", help="Test single plaintext against the hash (verify)")
    parser.add_argument("--test-file", help="File with candidate plaintexts (one per line) to test/verify")
    args = parser.parse_args()

    if args.file:
        try:
            with open(args.file, 'r', encoding='utf-8') as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    pretty_print_guesses(line)
            return
        except Exception as e:
            print("Error reading file:", e)
            sys.exit(1)

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
            if args.test:
                pass
        return

    if not args.hash:
        parser.print_help()
        return

    token = args.hash.strip()
    pretty_print_guesses(token)

    # If verification requested
    if args.test:
        pt = args.test.encode('utf-8')
        matches = verify_against(token, pt)
        if matches:
            print("Matches found for provided plaintext:")
            for alg, rep in matches:
                print(f"  - {alg} as {rep}")
        else:
            print("No matches found for provided plaintext with available algorithms.")
            if not WHIRLPOOL_AVAILABLE:
                print("  Note: Whirlpool unavailable for computation (install pycryptodome to enable).")
        print()

    if args.test_file:
        try:
            with open(args.test_file, 'r', encoding='utf-8') as fh:
                for line in fh:
                    cand = line.rstrip('\n')
                    if not cand:
                        continue
                    matches = verify_against(token, cand.encode('utf-8'))
                    if matches:
                        print(f"[MATCH] plaintext: {cand}")
                        for alg, rep in matches:
                            print(f"   -> {alg} ({rep})")
                        # optionally stop on first match
        except Exception as e:
            print("Error reading test-file:", e)

if __name__ == "__main__":
    main()
