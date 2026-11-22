"""EncryptStream cryptography for CookieRun: Kingdom (CRK 7.9.102+).

Reverse-engineered from libil2cpp.so (EncryptStream / EncryptStream.ChaCha20):

  Legacy (EncryptScheme.Legacy = 0):
      key   = SHA512(gpart_utf8 + b"qjtjtqjrjd!")          # 64 bytes, _encryptKey
      [0, 16384):        dec[x] = enc[x] ^ key[x % 64]
      [16384, 16400):    gap (passthrough)
      x >= 16400, x % 1025 == 0:
                         dec[x] = ROTL8(enc[x] ^ key[x % 64], x % 8)
      everywhere else:   passthrough

  gpart = Path.GetFileNameWithoutExtension(encryptPath)
          (program-level proof: CreateEncryptKey @0x5D4CAD8 -> Path.GetFileNameWithoutExtension)

  ZipCrypto default password (GetZipDefaultPassword, `new Random(0)` derived):
      6yC&Gq#HgmbQ6JQ6CktijiJK9?SjM!K8!zrd$trDc4
"""
from __future__ import annotations

import hashlib
import hmac
import struct
import zlib

SALT = b"qjtjtqjrjd!"
ZIP_PASSWORD = b"6yC&Gq#HgmbQ6JQ6CktijiJK9?SjM!K8!zrd$trDc4"

# --------------------------------------------------------------------------- #
# Legacy scheme
# --------------------------------------------------------------------------- #


def gpart_of(encrypt_path: str) -> str:
    """Path.GetFileNameWithoutExtension equivalent."""
    base = encrypt_path.replace("\\", "/").rsplit("/", 1)[-1]
    return base.rsplit(".", 1)[0] if "." in base else base


def legacy_key(gpart: str) -> bytes:
    return hashlib.sha512(gpart.encode("utf-8") + SALT).digest()


def _rotl8(v: int, r: int) -> int:
    r &= 7
    return ((v << r) | (v >> (8 - r))) & 0xFF if r else v


def decrypt_legacy(enc: bytes, gpart: str) -> bytes:
    """Decrypt an EncryptStream Legacy (scheme 0) payload."""
    key = legacy_key(gpart)
    buf = bytearray(enc)
    n = len(buf)
    for x in range(min(n, 16384)):
        buf[x] ^= key[x & 63]
    x = 16400
    while x < n:
        buf[x] = _rotl8(buf[x] ^ key[x & 63], x & 7)
        x += 1025
    return bytes(buf)


# --------------------------------------------------------------------------- #
# ZipCrypto (Info-ZIP compatible)
# --------------------------------------------------------------------------- #

_CRC_TABLE = []
for _n in range(256):
    _c = _n
    for _ in range(8):
        _c = (_c >> 1) ^ (0xEDB88320 if _c & 1 else 0)
    _CRC_TABLE.append(_c)


def _update_keys(k0: int, k1: int, k2: int, c: int) -> tuple[int, int, int]:
    k0 = (k0 >> 8) ^ _CRC_TABLE[(k0 ^ c) & 0xFF]
    k1 = ((k1 + (k0 & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
    k2 = (k2 >> 8) ^ _CRC_TABLE[(k2 ^ (k1 >> 24)) & 0xFF]
    return k0, k1, k2


def zipcrypto_decrypt(data: bytes, password: bytes = ZIP_PASSWORD) -> bytes:
    """Decrypt ZipCrypto bytes INCLUDING the 12-byte header."""
    k0, k1, k2 = 0x12345678, 0x23456789, 0x34567890
    for b in password:
        k0, k1, k2 = _update_keys(k0, k1, k2, b)
    out = bytearray()
    for c in data:
        t = (k2 | 2) & 0xFFFF
        d = c ^ (((t * (t ^ 1)) >> 8) & 0xFF)
        out.append(d)
        k0, k1, k2 = _update_keys(k0, k1, k2, d)
    return bytes(out[12:])  # strip encryption header


def crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


# --------------------------------------------------------------------------- #
# ZIP container (local entries, ZIP64-aware, ZipCrypto-aware)
# --------------------------------------------------------------------------- #


class ZipEntry:
    __slots__ = ("name", "data", "crc", "crc_ok", "method")

    def __init__(self, name: bytes, data: bytes, crc: int, crc_ok: bool, method: int):
        self.name = name
        self.data = data
        self.crc = crc
        self.crc_ok = crc_ok
        self.method = method


def _zip64_sizes(extra: bytes, usize: int, csize: int) -> tuple[int, int]:
    """Resolve ZIP64 sizes from extra field 0x0001 (local-header order: usize, csize)."""
    p = 0
    while p + 4 <= len(extra):
        tid, sz = struct.unpack("<HH", extra[p : p + 4])
        body = extra[p + 4 : p + 4 + sz]
        if tid == 1:
            vals = [struct.unpack("<Q", body[i : i + 8])[0] for i in range(0, len(body) // 8 * 8, 8)]
            if usize == 0xFFFFFFFF and vals:
                usize = vals.pop(0)
            if csize == 0xFFFFFFFF and vals:
                csize = vals.pop(0)
            break
        p += 4 + sz
    return usize, csize


def parse_zip(data: bytes, password: bytes = ZIP_PASSWORD) -> list[ZipEntry]:
    """Parse local file entries sequentially (handles ZIP64 + data descriptor)."""
    entries: list[ZipEntry] = []
    p = 0
    while True:
        p = data.find(b"PK\x03\x04", p)
        if p < 0 or p + 30 > len(data):
            break
        _ver, flg, method, _t, _d, crc, csize, usize, nlen, elen = struct.unpack(
            "<HHHHHIIIHH", data[p + 4 : p + 30]
        )
        name = data[p + 30 : p + 30 + nlen]
        extra = data[p + 30 + nlen : p + 30 + nlen + elen]
        usize, csize = _zip64_sizes(extra, usize, csize)
        off = p + 30 + nlen + elen
        raw = data[off : off + csize] if csize else data[off:]
        if csize == 0 and not raw:
            raw = b""
        if flg & 1:
            raw = zipcrypto_decrypt(raw, password)
        if method == 8:
            try:
                out = zlib.decompress(raw, -15)
            except zlib.error:
                # tolerate truncated/trailing-garbage streams: keep partial output
                d = zlib.decompressobj(-15)
                try:
                    out = d.decompress(raw)
                except zlib.error:
                    out = b""
        elif method == 0:
            out = raw
        else:
            out = b""
        entries.append(ZipEntry(name, out, crc, crc32(out) == crc, method))
        p = off + max(csize, 1)
    return entries


# --------------------------------------------------------------------------- #
# ChaCha20 scheme ("v2") — fully reversed 2026-11-22 from decrypted 1.6.5 .text
# (EncryptStream.CreateChaCha20Key / ApplyChaCha20 / ApplySparseEncryption /
#  GetSparseRangeOffset @0xa6d3a80; verified: 41/41 CDN bundles pass UnityPy)
#
#   dataKey  = HKDF-SHA256(MK, EpochSalt, "EncryptStream/v2/{secret}/Data/{gpart}", 44)
#   schedKey = HKDF-SHA256(MK, EpochSalt, "EncryptStream/v2/{secret}/Schedule/{gpart}", 44)
#   key = km[:32], nonce = km[32:44]
#   [0, 16384)  (.bank: 524288):  continuous ChaCha20, counter = pos // 64
#   beyond: per 16384-byte page, ONE 64-byte window:
#       off = uint32le(schedule_chacha20(counter=page)[0:4]) % 16321
#       window decrypted with dataKey at ABSOLUTE position (counter = ws // 64)
#   everything else outside windows: PLAINTEXT
#
#   MK = MasterKeyPartA ^ MasterKeyPartB, EpochSalt = 16B — cross-version constants:
#       MK   = 73a345be1285412550fdffe182247cc4d95478f6fb6aa47556cc9c0ae5f32d58
#       salt = 96289932d7d420186eef6f25362e40ca
# --------------------------------------------------------------------------- #

MK_DEFAULT = bytes.fromhex("73a345be1285412550fdffe182247cc4d95478f6fb6aa47556cc9c0ae5f32d58")
EPOCH_SALT = bytes.fromhex("96289932d7d420186eef6f25362e40ca")


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 44) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


def _rotl32(v: int, n: int) -> int:
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF


def _quarter(x, a, b, c, d):
    x[a] = (x[a] + x[b]) & 0xFFFFFFFF; x[d] ^= x[a]; x[d] = _rotl32(x[d], 16)
    x[c] = (x[c] + x[d]) & 0xFFFFFFFF; x[b] ^= x[c]; x[b] = _rotl32(x[b], 12)
    x[a] = (x[a] + x[b]) & 0xFFFFFFFF; x[d] ^= x[a]; x[d] = _rotl32(x[d], 8)
    x[c] = (x[c] + x[d]) & 0xFFFFFFFF; x[b] ^= x[c]; x[b] = _rotl32(x[b], 7)


def chacha20_keystream(key: bytes, nonce: bytes, counter: int, nbytes: int) -> bytes:
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


def v2_info(secret: str, gpart: str, kind: str = "Data") -> bytes:
    pre = b"EncryptStream/v2"
    if secret:
        return pre + f"/{secret}/{kind}/{gpart}".encode()
    return pre + f"/{kind}/{gpart}".encode()


def decrypt_v2(enc: bytes, secret: str, gpart: str,
               mk: bytes = MK_DEFAULT, salt: bytes = EPOCH_SALT) -> bytes:
    """Decrypt an EncryptStream v2 (ChaCha20) payload, continuous + sparse regions."""
    dkm = hkdf_sha256(mk, salt, v2_info(secret, gpart, "Data"), 44)
    skm = hkdf_sha256(mk, salt, v2_info(secret, gpart, "Schedule"), 44)
    dkey, dnonce = dkm[:32], dkm[32:44]
    skey, snonce = skm[:32], skm[32:44]
    out = bytearray(enc)
    n = len(out)
    cont = 524288 if gpart.endswith(".bank") else 16384
    cont = min(cont, n)
    if cont:
        ks = chacha20_keystream(dkey, dnonce, 0, cont)
        for i in range(cont):
            out[i] ^= ks[i]
    first_page = (cont + 16383) // 16384
    last_page = (n - 1) // 16384 if n > cont else 0
    for p in range(first_page, last_page + 1):
        r = struct.unpack_from("<I", chacha20_keystream(skey, snonce, p, 64), 0)[0]
        off = r % 16321
        ws = p * 16384 + off
        if ws >= n:
            continue
        ln = min(64, n - ws)
        blk = chacha20_keystream(dkey, dnonce, ws // 64, ((ws % 64) + ln + 63) // 64 * 64)
        blk = blk[ws % 64 : ws % 64 + ln]
        for j in range(ln):
            out[ws + j] ^= blk[j]
    return bytes(out)


def sniff_container(pt: bytes) -> str | None:
    if pt[:8] == b"UnityFS\x00" or pt[:7] == b"UnityFS":
        return "unityfs"
    if pt[:4] == b"PK\x03\x04":
        return "zip"
    if pt[:4] in (b"RIFF", b"FSB5", b"OggS"):
        return pt[:4].decode().lower()
    if pt[:2] in (b'{"', b"[{"):
        return "json"
    return None
