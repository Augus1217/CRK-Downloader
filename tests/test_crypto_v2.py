"""EncryptStream 加解密單元測試（固定已知向量，不依賴遊戲檔）。"""
import pytest

from ck_downloader.infrastructure.crypto import (
    decrypt_legacy as dec_legacy,
    decrypt_v2 as dec_v2,
    sniff_container as sniff,
    hkdf_sha256 as hkdf,
    chacha20_keystream as cc20_ks,
    gpart_of as gpart,
    MK_DEFAULT,
    EPOCH_SALT as S_DEFAULT,
)
from ck_downloader.infrastructure.buildkey import derive_buildkey_from_blob


# ---------- helpers ----------
def xor_all(data, ks):
    return bytes(a ^ b for a, b in zip(data, ks))


# ---------- gpart ----------
@pytest.mark.parametrize("key,expect", [
    ("files/direct-upload/android/bundle_pass.zson", "bundle_pass"),
    ("files/PatchBinarySetSplit", "PatchBinarySetSplit"),
    ("plain", "plain"),
    ("a/b/c.name.ext", "c.name"),
])
def test_gpart(key, expect):
    assert gpart(key) == expect


# ---------- sniff ----------
def test_sniff_kinds():
    assert sniff(b"UnityFS\x00...") == "unityfs"
    assert sniff(b"PK\x03\x04...") == "zip"
    assert sniff(b"RIFF....") == "riff"
    assert sniff(b'{"a":1}') == "json"
    assert sniff(b"\x00\x01\x02") is None


# ---------- ChaCha20 keystream ----------
def test_cc20_block_is_deterministic():
    ks1 = cc20_ks(b"\x01" * 32, b"\x02" * 12, 0, 64)
    ks2 = cc20_ks(b"\x01" * 32, b"\x02" * 12, 0, 64)
    assert ks1 == ks2 and len(ks1) == 64


def test_cc20_counter_advances():
    a = cc20_ks(b"\x01" * 32, b"\x02" * 12, 0, 64)
    b = cc20_ks(b"\x01" * 32, b"\x02" * 12, 1, 64)
    assert a != b


# ---------- HKDF (RFC 5869 test vector 1) ----------
def test_hkdf_rfc5869():
    ikm = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    okm = hkdf(ikm, salt, info, 42)
    assert okm.hex() == (
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )


# ---------- legacy scheme ----------
def test_legacy_roundtrip():
    """加密->解密 應還原（用演算法自身做 roundtrip）。"""
    import hashlib
    name = "townstructure_test_bundle"
    K = hashlib.sha512((name + "qjtjtqjrjd!").encode()).digest()

    plain = bytearray(b"UnityFS\x00" + bytes(0x5000))
    # 加密（decrypt 的逆）：dense XOR；sparse 點 enc = ror8(plain, k%8) ^ K[(16+k)%64]
    cipher = bytearray(plain)
    for p in range(0x4000):
        cipher[p] ^= K[p % 64]
    k = 0
    while True:
        p = 16400 + 1025 * k
        if p >= len(cipher):
            break
        v = plain[p]
        r = k % 8
        cipher[p] = ((v >> r) | (v << (8 - r))) & 0xFF ^ K[(16 + k) % 64] if r else v ^ K[(16 + k) % 64]
        k += 1
    out = dec_legacy(bytes(cipher), name)
    assert out == bytes(plain)


# ---------- v2 scheme ----------
def test_v2_roundtrip_small():
    """小檔（<16384）只有連續區。"""
    secret, name = "testsecret", "test_bundle"
    dkm = hkdf(MK_DEFAULT, S_DEFAULT, f"EncryptStream/v2/{secret}/Data/{name}".encode(), 44)
    plain = b"UnityFS\x00" + bytes(100)
    ks = cc20_ks(dkm[:32], dkm[32:44], 0, len(plain))
    cipher = xor_all(plain, ks)
    assert dec_v2(cipher, secret, name) == plain


def test_v2_sparse_window():
    """>16384 檔：頁外明文 + 頁內 64B 視窗。"""
    secret, name = "testsecret", "test_bundle"
    dkm = hkdf(MK_DEFAULT, S_DEFAULT, f"EncryptStream/v2/{secret}/Data/{name}".encode(), 44)
    skm = hkdf(MK_DEFAULT, S_DEFAULT, f"EncryptStream/v2/{secret}/Schedule/{name}".encode(), 44)
    dkey, dnonce = dkm[:32], dkm[32:44]

    import struct
    n = 40000
    plain = bytearray(b"\x41" * n)                       # 頁外恆為 'A'（明文區）
    cipher = bytearray(plain)
    # 連續區
    ks = cc20_ks(dkey, dnonce, 0, 16384)
    for i in range(16384):
        cipher[i] ^= ks[i]
    # sparse
    for p in range(1, (n + 16383) // 16384):
        r = struct.unpack_from("<I", cc20_ks(skm[:32], skm[32:44], p, 64), 0)[0]
        off = r % 16321
        ws = p * 16384 + off
        if ws >= n:
            continue
        ln = min(64, n - ws)
        blk = cc20_ks(dkey, dnonce, ws // 64, ((ws % 64) + ln + 63) // 64 * 64)
        blk = blk[ws % 64 : ws % 64 + ln]
        for j in range(ln):
            cipher[ws + j] ^= blk[j]
    out = dec_v2(bytes(cipher), secret, name)
    assert out == bytes(plain)


def test_v2_bundle_pass_vector():
    """真實向量：7.11 bundle_pass（56B）。"""
    cipher = bytes.fromhex(
        "627275fc5a3b1909eeb2d03280255f1d"
        "b3381385f6619a1fbfde1eb496a398c7"
        "3dff965951935317ea415857e29d9601"
        "073daa10ad886501"
    )
    pt = dec_v2(cipher, "bda24e6c-a05c-4687-b82e-39d886b5d3fa", "bundle_pass")
    assert pt == b'{"current":"adfogiepeeiworu","previous":"rewqewraerwer"}'


# ---------- buildkey ----------
def test_buildkey_vectors():
    """兩版 blob（b64 字面值）都應推導出正確 buildKey。"""
    import base64

    blob11 = base64.b64decode("G2KA3lDaZy4UCqukGDhWUYT8Z0D4FLKRyhev2zv2/CnCsFKWNI/5K458k/dq5KEg")
    blob79 = base64.b64decode("hAoYhZLaCOLBSe8YOKKyGd/03j+/JLtt1VN7ViA7yw0VN5vROC6JjYuleuw+o2j2")
    assert derive_buildkey_from_blob(blob11) == "bda24e6c-a05c-4687-b82e-39d886b5d3fa"
    assert derive_buildkey_from_blob(blob79) == "de5c33f6-3fa3-4f8a-aa2f-159017d7dc52"
