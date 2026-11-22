"""ingest use case — absorb device-cached assets into the mirror.

Source: `adb pull /sdcard/Android/data/com.devsisters.ck/ <dir>` from ANY
Android device with CRK installed (no root needed for external cache).
The pulled tree contains the CDN-downloaded assets (2-3 GB) that never ship
in the APK, plus cached copies of APK-delivered files.

Files arrive either:
  - still EncryptStream-encrypted (.resource-like) -> decrypted with Legacy
    formula when the gpart can be resolved (EncLegacy); EncNew (ChaCha20)
    payloads are kept as-is and reported
  - already-decrypted UnityFS / ZIP / FMOD -> classified directly
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from ..infrastructure.containers import DEFAULT_TYPES, classify, extract_unityfs
from ..infrastructure.crypto import decrypt_legacy, gpart_of

SCHEME_HINTS = {"EncLegacy", "EncNew", "NotEncrypt"}


def _try_gpart_names(path: Path) -> list[str]:
    """Candidate gparts derivable from a cached file's name/path."""
    stem = path.name
    for suf in (".resource", ".bin", ".bytes", ".asset", ""):
        if stem.endswith(suf):
            stem = stem[: -len(suf)] if suf else stem
            break
    cands = [stem]
    # also the parent dir name (some caches organize by bundle name)
    if path.parent.name and path.parent.name not in ("files", "cache", "0"):
        cands.append(path.parent.name)
    return cands


def run_ingest(
    pulled_dir: Path,
    out_dir: Path,
    types: tuple[str, ...] = DEFAULT_TYPES,
    search: list[str] | None = None,
    limit: int | None = None,
) -> dict:
    pulled_dir = Path(pulled_dir)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    files = [p for p in sorted(pulled_dir.rglob("*")) if p.is_file()]
    if limit:
        files = files[:limit]
    stats = {"files": len(files), "UnityFS": 0, "ZIP": 0, "FMOD": 0, "OTHER": 0,
             "decrypted": 0, "encnew": 0, "saved": 0, "errors": 0}
    records = []
    t0 = time.time()

    terms = [s.lower() for s in search] if search else None
    for i, p in enumerate(files):
        rel = str(p.relative_to(pulled_dir))
        if terms and not any(t in rel.lower() for t in terms):
            continue
        try:
            raw = p.read_bytes()
        except OSError:
            continue
        if len(raw) < 16:
            continue

        cls = classify(raw)
        dec_note = "plain"
        if not cls.ok and cls.kind in ("OTHER", "UnityFS"):
            # try Legacy decryption with name-derived gparts
            for gpart in _try_gpart_names(p):
                dec = decrypt_legacy(raw, gpart)
                cls2 = classify(dec)
                if cls2.ok:
                    raw, cls = dec, cls2
                    dec_note = f"decrypted(gpart={gpart})"
                    stats["decrypted"] += 1
                    break

        kind = cls.kind
        stats[kind] = stats.get(kind, 0) + 1
        rec = {"path": rel, "size": len(raw), "container": kind,
               "valid": cls.ok, "detail": cls.detail, "decrypt": dec_note}
        if "EncNew" in rel or "encnew" in dec_note:
            stats["encnew"] += 1

        try:
            if kind == "UnityFS":
                gpart = p.stem
                sub = out_dir / "bundles" / gpart
                s2 = extract_unityfs(raw, sub, types=types, search=search)
                rec["unity"] = s2
                stats["saved"] += s2["saved"]
            elif kind == "ZIP":
                from ..infrastructure.crypto import parse_zip
                sub = out_dir / "zip"
                sub.mkdir(parents=True, exist_ok=True)
                for e in parse_zip(raw):
                    (sub / f"{p.stem}__{e.name.decode('utf-8','replace')}").write_bytes(e.data)
            elif kind == "FMOD":
                sub = out_dir / "fmod"
                sub.mkdir(parents=True, exist_ok=True)
                (sub / f"{p.stem}.bank").write_bytes(raw)
        except Exception as e:
            rec["error"] = repr(e)
            stats["errors"] += 1
        records.append(rec)
        if i % 200 == 0:
            print(f"[ingest {i}/{len(files)}] {time.time()-t0:.0f}s {stats}", flush=True)

    (out_dir / "ingest_index.json").write_text(
        json.dumps({"records": records, "stats": stats}, indent=1, ensure_ascii=False))
    return stats
