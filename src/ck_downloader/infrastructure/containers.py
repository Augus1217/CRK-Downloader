"""Container classification + extraction for decrypted CRK assets.

Decrypted .resource payloads are one of:
  ZIP      — ZipCrypto'd container; .zeml = localization strings.xml, indices = *.json
  UnityFS  — Unity asset bundle (v8 / 2022.3.62f2), parsed with UnityPy
  FMOD     — RIFF/FEV sound bank
  OTHER    — unknown (4 known files are EncryptScheme.ChaCha20, server-gated)
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

from .crypto import parse_zip

UNITYFS_MAGIC = b"UnityFS\x00"
RIFF_MAGIC = b"RIFF"


@dataclass
class Classified:
    kind: str                     # ZIP | UnityFS | FMOD | OTHER
    detail: str = ""
    ok: bool = False              # validation result (CRC for ZIP, header/size for UnityFS)
    zip_entries: list = field(default_factory=list)
    raw: bytes = b""


def classify(dec: bytes) -> Classified:
    if dec[:8] == UNITYFS_MAGIC:
        return _classify_unityfs(dec)
    if dec[:2] == b"PK":
        return _classify_zip(dec)
    if dec[:4] == RIFF_MAGIC and dec[8:12] == b"FEV ":
        return Classified(kind="FMOD", ok=True, detail="RIFF/FEV bank", raw=dec)
    return Classified(kind="OTHER", ok=False, detail=dec[:8].hex(), raw=dec)


def _classify_zip(dec: bytes) -> Classified:
    try:
        entries = parse_zip(dec)
    except Exception as e:  # pragma: no cover
        return Classified(kind="ZIP", ok=False, detail=f"parse error: {e}", raw=dec)
    names = [e.name.decode("utf-8", "replace") for e in entries]
    all_ok = all(e.crc_ok for e in entries) if entries else False
    return Classified(kind="ZIP", ok=all_ok, detail=f"{len(entries)} entries", zip_entries=entries, raw=dec)


def _classify_unityfs(dec: bytes) -> Classified:
    p = 8
    try:
        ver = struct.unpack(">I", dec[p : p + 4])[0]
        p += 4
        p = dec.index(b"\x00", p) + 1          # unity version
        p = dec.index(b"\x00", p) + 1          # target version
        size = struct.unpack(">Q", dec[p : p + 8])[0]
        ok = size == len(dec)
        return Classified(kind="UnityFS", ok=ok, detail=f"v{ver} size={size}", raw=dec)
    except Exception as e:
        return Classified(kind="UnityFS", ok=False, detail=f"header error: {e}", raw=dec)


# --------------------------------------------------------------------------- #
# UnityFS extraction via UnityPy
# --------------------------------------------------------------------------- #

DEFAULT_TYPES = ("texture", "sprite", "text")


def extract_unityfs(
    dec: bytes,
    out_dir: Path,
    types: tuple[str, ...] = DEFAULT_TYPES,
    search: list[str] | None = None,
) -> dict:
    """Extract objects from a decrypted UnityFS bundle.

    types: subset of {"texture", "sprite", "text", "audio", "mesh"}
    search: keep only objects whose name contains any of the terms (case-insensitive).
    Returns stats dict.
    """
    import UnityPy  # local import: heavy

    stats = {"objects": 0, "saved": 0, "skipped": 0, "errors": 0}
    out_dir = Path(out_dir)
    terms = [s.lower() for s in search] if search else None

    def keep(name: str) -> bool:
        if not terms:
            return True
        low = name.lower()
        return any(t in low for t in terms)

    try:
        env = UnityPy.load(dec)
    except Exception as e:
        stats["errors"] += 1
        stats["error"] = str(e)
        return stats

    for _path, bundle in getattr(env, "files", {}).items():
        cab = getattr(bundle, "cab_file", None) or "bundle"
        cab_dir = out_dir / str(cab)[:64].replace("/", "_")
        try:
            objs = list(bundle.files.values()) if hasattr(bundle, "files") else []
        except Exception:
            objs = []
        for f in objs:
            if type(f).__name__ != "SerializedFile":
                continue
            for obj in f.objects.values():
                tname = obj.type.name
                stats["objects"] += 1
                try:
                    if tname in ("Texture2D", "Sprite") and ("texture" in types or "sprite" in types):
                        if tname == "Sprite" and "sprite" not in types:
                            continue
                        if tname == "Texture2D" and "texture" not in types:
                            continue
                        data = obj.read()
                        name = data.m_Name or f"obj_{obj.path_id}"
                        if not keep(name):
                            stats["skipped"] += 1
                            continue
                        img = data.image
                        if img is None:
                            stats["skipped"] += 1
                            continue
                        cab_dir.mkdir(parents=True, exist_ok=True)
                        img.save(cab_dir / f"{_safe(name)}.png")
                        stats["saved"] += 1
                    elif tname == "TextAsset" and "text" in types:
                        data = obj.read()
                        name = data.m_Name or f"obj_{obj.path_id}"
                        if not keep(name):
                            stats["skipped"] += 1
                            continue
                        script = data.m_Script
                        raw = script.encode("utf-8", "surrogateescape") if isinstance(script, str) else bytes(script)
                        cab_dir.mkdir(parents=True, exist_ok=True)
                        (cab_dir / f"{_safe(name)}.bin").write_bytes(raw)
                        stats["saved"] += 1
                    elif tname == "AudioClip" and "audio" in types:
                        data = obj.read()
                        name = data.m_Name or f"obj_{obj.path_id}"
                        if not keep(name):
                            stats["skipped"] += 1
                            continue
                        for aname, adata in data.samples.items():
                            cab_dir.mkdir(parents=True, exist_ok=True)
                            (cab_dir / f"{_safe(name)}_{_safe(aname)}").write_bytes(adata)
                            stats["saved"] += 1
                    elif tname == "Mesh" and "mesh" in types:
                        data = obj.read()
                        name = data.m_Name or f"obj_{obj.path_id}"
                        if not keep(name):
                            stats["skipped"] += 1
                            continue
                        cab_dir.mkdir(parents=True, exist_ok=True)
                        (cab_dir / f"{_safe(name)}.obj").write_text(data.export(), encoding="utf-8")
                        stats["saved"] += 1
                except Exception:
                    stats["errors"] += 1
    return stats


def _safe(name: str) -> str:
    return "".join(c if c.isalnum() or c in "._- " else "_" for c in name)[:120] or "unnamed"
