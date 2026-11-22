"""XAPK / APK unpacking: locate metadata.zeson + the 2552 encrypted .resource files.

XAPK layout (APKPure):
    com.devsisters.ck.apk        # base APK (code, global-metadata.dat)
    UnityDataAssetPack.apk       # assets/metadata.zeson + assets/android/*.resource (1.2 GB)
    config.armeabi_v7a.apk       # native libs
    manifest.json

Inside UnityDataAssetPack.apk:
    assets/metadata.zeson        # Legacy-encrypted download manifest (2552 records)
    assets/android/<SHA1>.resource  # 2552 encrypted asset files
"""
from __future__ import annotations

import json
import zipfile
from dataclasses import dataclass
from pathlib import Path

from .crypto import decrypt_legacy, gpart_of

METADATA_MEMBER = "assets/metadata.zeson"
RESOURCE_PREFIX = "assets/android/"


@dataclass
class ResourceMember:
    """One encrypted .resource member inside the asset pack."""

    hash: str          # SHA1-named file stem == manifest["hash"]
    size: int          # compressed member size in the APK
    apk_path: Path     # path to UnityDataAssetPack.apk


@dataclass
class XapkContents:
    xapk: Path
    asset_pack: Path            # extracted UnityDataAssetPack.apk
    metadata_zeson: bytes       # still ENCRYPTED
    records: list[dict]         # decrypted manifest records (2552)
    resources: list[ResourceMember]


def unpack_xapk(xapk_path: Path, workdir: Path) -> tuple[Path, Path]:
    """Extract UnityDataAssetPack.apk (+ base APK) from an .xapk into workdir.

    Returns (asset_pack_path, base_apk_path).
    """
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    pack = workdir / "UnityDataAssetPack.apk"
    base = workdir / "base.apk"
    with zipfile.ZipFile(xapk_path) as z:
        names = z.namelist()
        if pack.name not in names:
            raise ValueError(f"{xapk_path} does not look like a CRK XAPK (no UnityDataAssetPack.apk)")
        if not pack.exists() or pack.stat().st_size == 0:
            z.extract(pack.name, workdir)
        if "com.devsisters.ck.apk" in names and not base.exists():
            z.extract("com.devsisters.ck.apk", workdir)
            if base.exists():
                base.rename(workdir / "com.devsisters.ck.apk")
    return pack, workdir / "com.devsisters.ck.apk"


def load_manifest(pack: Path) -> tuple[bytes, list[dict]]:
    """Read + decrypt assets/metadata.zeson from the asset pack.

    Layer 1: EncryptStream Legacy (scheme 0)  -> ZIP
    Layer 2: inner entry is ZipCrypto'd       -> manifest JSON
    Returns (encrypted_bytes, decrypted_records).
    """
    from .crypto import parse_zip

    with zipfile.ZipFile(pack) as z:
        enc = z.read(METADATA_MEMBER)
    dec = decrypt_legacy(enc, gpart_of(METADATA_MEMBER))
    entries = parse_zip(dec)
    if not entries:
        raise ValueError("metadata.zeson: inner ZIP has no entries")
    return enc, json.loads(entries[0].data)


def iter_resources(pack: Path, records: list[dict]) -> list[ResourceMember]:
    """Match manifest records to APK members by SHA1 name (1:1, verified 2552/2552)."""
    with zipfile.ZipFile(pack) as z:
        present = {}
        for info in z.infolist():
            if info.filename.startswith(RESOURCE_PREFIX) and info.filename.endswith(".resource"):
                present[info.filename[len(RESOURCE_PREFIX) : -len(".resource")]] = info.file_size
    out = []
    for r in records:
        h = r.get("hash", "")
        if h in present:
            out.append(ResourceMember(hash=h, size=present[h], apk_path=pack))
    return out


def read_resource(pack: Path, hash_name: str) -> bytes:
    with zipfile.ZipFile(pack) as z:
        return z.read(RESOURCE_PREFIX + hash_name + ".resource")


def open_xapk(xapk_path: Path, workdir: Path) -> XapkContents:
    pack, _base = unpack_xapk(Path(xapk_path), Path(workdir))
    _enc, records = load_manifest(pack)
    res = iter_resources(pack, records)
    return XapkContents(
        xapk=Path(xapk_path), asset_pack=pack, metadata_zeson=b"", records=records, resources=res
    )
