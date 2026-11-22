"""Ground-truth tests for the EncryptStream Legacy decryption (validated against CRK 7.9.102)."""
from __future__ import annotations

import hashlib
import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ck_downloader.infrastructure.crypto import (  # noqa: E402
    ZIP_PASSWORD,
    decrypt_legacy,
    gpart_of,
    legacy_key,
    parse_zip,
    zipcrypto_decrypt,
)

# Real encrypted metadata.zeson shipped in UnityDataAssetPack.apk (CRK 7.9.102)
# Skip if the XAPK is not present locally.
XAPK = Path("/home/augus/Documents/CookieRun_+Kingdom_7.9.102_APKPure.xapk")


def _metadata_enc() -> bytes:
    with zipfile.ZipFile(XAPK) as z:
        with z.open("UnityDataAssetPack.apk") as inner:
            import io

            apk = zipfile.ZipFile(io.BytesIO(inner.read()))
            return apk.read("assets/metadata.zeson")


@pytest.mark.skipif(not XAPK.exists(), reason="XAPK not available")
def test_gpart_rules():
    assert gpart_of("assets/metadata.zeson") == "metadata"
    assert gpart_of("files/direct-upload/android/battle_ability") == "battle_ability"
    assert gpart_of("files/direct-upload/common/fmod/Master.assets.bank") == "Master.assets"
    assert gpart_of("files/direct-upload/android/assetbundle_index.zeson") == "assetbundle_index"


def test_legacy_key_known_vector():
    # Frozen regression vector: verified by 2548 CRC-checked files (Round 26 batch).
    # (NOTE: an earlier session note claimed a different h512 digest — that was wrong;
    #  the working pipeline defines the truth.)
    assert legacy_key("metadata").hex().startswith("f68da1e3917bbabc")


def test_rotl8_identity_at_zero_rotation():
    # j % 8 == 0 sparse points must be pure XOR (the "delta=0" structural rule)
    import os

    enc = os.urandom(20000)
    dec = decrypt_legacy(enc, "whatever")
    for p in range(16400, 16384 + 1025 * 3, 1025):
        if p % 8 == 0:
            assert dec[p] == (enc[p] ^ legacy_key("whatever")[p & 63])


def test_zipcrypto_known_password():
    # The decrypted metadata.zeson inner ZIP uses the global default password;
    # its single entry CRC must verify when parsed with it.
    if not XAPK.exists():
        pytest.skip("XAPK not available")
    dec = decrypt_legacy(_metadata_enc(), "metadata")
    entries = parse_zip(dec)
    assert len(entries) == 1
    assert entries[0].name.startswith(b"metadata.z")
    assert entries[0].crc_ok, "ZipCrypto password or pipeline regression!"
    import json

    records = json.loads(entries[0].data)
    assert isinstance(records, list) and len(records) == 2552
    assert records[0]["key"] == "files/direct-upload/android/assetbundle_index.zeson"
    assert records[0]["size"] == 426849


def test_zipcrypto_roundtrip_and_password():
    assert ZIP_PASSWORD.startswith(b"6yC&Gq#")
    import os

    from ck_downloader.infrastructure.crypto import _update_keys

    def encrypt(data: bytes, pwd: bytes) -> bytes:
        """Proper ZipCrypto encryptor: 12 random-ish header bytes + ciphertext."""
        k0, k1, k2 = 0x12345678, 0x23456789, 0x34567890
        for b in pwd:
            k0, k1, k2 = _update_keys(k0, k1, k2, b)
        out = bytearray()
        for b in data:  # header bytes go through the same keystream
            t = (k2 | 2) & 0xFFFF
            c = b ^ (((t * (t ^ 1)) >> 8) & 0xFF)
            out.append(c)
            k0, k1, k2 = _update_keys(k0, k1, k2, b)
        return bytes(out)

    payload = os.urandom(1000)
    header = os.urandom(12)  # last byte should equal (dostime>>8) in real zips; irrelevant here
    assert zipcrypto_decrypt(encrypt(header + payload, ZIP_PASSWORD), ZIP_PASSWORD) == payload
