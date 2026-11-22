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

from .crypto import MK_DEFAULT, EPOCH_SALT, hkdf_sha256, chacha20_keystream


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
