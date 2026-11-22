"""Per-VERSION BuildKey derivation from global-metadata.dat.

Method (verified on 7.9.102 AND 7.11.102):
  1. Scan the metadata string-literal table for the unique 64-char base64 entry
     decoding to exactly 48 bytes  (= [12B salt header][36B ChaCha20 ciphertext]).
  2. info = "EncryptStream/v2/Data/BuildKey_" + salt12.hex().upper()
     (single slash: empty secret!)
  3. km = HKDF-SHA256(MK, EpochSalt, info, 44) -> ChaCha20(counter=0) -> 36B UUID.
  4. MK / EpochSalt are cross-version PID constants (proven: 7.9 blob decrypts
     with the 7.11 constants and vice versa).

Track record:
  7.11 blob G2KA3lDa... -> bda24e6c-a05c-4687-b82e-39d886b5d3fa
  7.9  blob hAoYhZLa... -> de5c33f6-3fa3-4f8a-aa2f-159017d7dc52
"""
from __future__ import annotations

import base64
import struct


# ---- 自包含 primitives（與 src/ck_downloader/infrastructure/crypto.py 相同實作）----
import hashlib, hmac, struct

MK_DEFAULT = bytes.fromhex("73a345be1285412550fdffe182247cc4d95478f6fb6aa47556cc9c0ae5f32d58")
EPOCH_SALT = bytes.fromhex("96289932d7d420186eef6f25362e40ca")

def hkdf_sha256(ikm, salt, info, length=44):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]

def _rotl32(v, n):
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF

def _quarter(x, a, b, c, d):
    x[a] = (x[a] + x[b]) & 0xFFFFFFFF; x[d] ^= x[a]; x[d] = _rotl32(x[d], 16)
    x[c] = (x[c] + x[d]) & 0xFFFFFFFF; x[b] ^= x[c]; x[b] = _rotl32(x[b], 12)
    x[a] = (x[a] + x[b]) & 0xFFFFFFFF; x[d] ^= x[a]; x[d] = _rotl32(x[d], 8)
    x[c] = (x[c] + x[d]) & 0xFFFFFFFF; x[b] ^= x[c]; x[b] = _rotl32(x[b], 7)

def chacha20_keystream(key, nonce, counter, nbytes):
    base = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574] + list(struct.unpack("<8I", key))
    nz = list(struct.unpack("<3I", nonce))
    out = b""
    block = 0
    while len(out) < nbytes:
        st = base + [(counter + block) & 0xFFFFFFFF] + nz
        w = st[:]
        for _ in range(10):
            _quarter(w, 0, 4, 8, 12); _quarter(w, 1, 5, 9, 13)
            _quarter(w, 2, 6, 10, 14); _quarter(w, 3, 7, 11, 15)
            _quarter(w, 0, 5, 10, 15); _quarter(w, 1, 6, 11, 12)
            _quarter(w, 2, 7, 8, 13); _quarter(w, 3, 4, 9, 14)
        out += struct.pack("<16I", *[(x + y) & 0xFFFFFFFF for x, y in zip(w, st)])
        block += 1
    return out[:nbytes]



def find_blob_candidates(mdf: bytes) -> list[tuple[int, str, bytes]]:
    """Scan the string-literal table (header-driven, v29/v31 compatible)."""
    sl_off, sl_cnt = struct.unpack_from("<II", mdf, 8)
    sld = struct.unpack_from("<I", mdf, 0x10)[0]
    found = []
    for i in range(sl_cnt):
        ln, di = struct.unpack_from("<II", mdf, sl_off + i * 8)
        if ln != 64:
            continue
        s = mdf[sld + di : sld + di + ln]
        try:
            raw = base64.b64decode(s, validate=True)
        except Exception:
            continue
        if len(raw) == 48:
            found.append((i, s.decode("ascii"), raw))
    return found


def is_uuid36(b: bytes) -> bool:
    try:
        s = b.decode("ascii")
    except Exception:
        return False
    return (
        len(s) == 36
        and all(c in "0123456789abcdef-" for c in s)
        and s[8] == s[13] == s[18] == s[23] == "-"
    )


def derive_buildkey_from_blob(blob48: bytes,
                              mk: bytes = MK_DEFAULT,
                              salt: bytes = EPOCH_SALT) -> str | None:
    """Derive buildKey from one 48-byte blob; None if not UUID-shaped."""
    salt12 = blob48[:12]
    name = "BuildKey_" + salt12.hex().upper()
    info = b"EncryptStream/v2/Data/" + name.encode()
    km = hkdf_sha256(mk, salt, info)
    ks = chacha20_keystream(km[:32], km[32:44], 0, 36)
    pt = bytes(a ^ b for a, b in zip(blob48[12:], ks))
    return pt.decode() if is_uuid36(pt) else None


def extract_buildkey(mdf: bytes,
                     mk: bytes = MK_DEFAULT,
                     salt: bytes = EPOCH_SALT) -> str:
    """Derive the buildKey from a full global-metadata.dat; raises ValueError."""
    for _i, _s, raw in find_blob_candidates(mdf):
        key = derive_buildkey_from_blob(raw, mk, salt)
        if key:
            return key
    raise ValueError("no UUID-shaped buildKey found; constants may differ for this version")


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    key = extract_buildkey(open(sys.argv[1], "rb").read())
    print("buildKey =", key)
