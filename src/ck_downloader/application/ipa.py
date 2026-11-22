"""ipa use case — the iOS App Store route.

CookieRun: Kingdom ships ~3.9 GB on iOS (no Play Asset Delivery 1-2 GB cap),
i.e. the FULL asset set inside a single IPA — including the bundles Android
excludes (NotIncludeAndroidBuild) and the CDN-only content.

Pipeline:
  ipatool (Apple ID, MIT-licensed CLI)  ->  .ipa (FairPlay protects only the
  executable; data files are plain)  ->  locate metadata.zeson + asset files
  ->  the same Legacy decryption (C# is cross-platform)  ->  extract + index.

One-time setup: create an Apple ID, `ipatool auth login` (2FA once),
`ipatool purchase --bundle-identifier com.devsisters.ck`.
"""
from __future__ import annotations

import json
import subprocess
import time
import zipfile
from pathlib import Path

from ..infrastructure.containers import DEFAULT_TYPES, classify, extract_unityfs
from ..infrastructure.crypto import decrypt_legacy, gpart_of, parse_zip

BUNDLE_ID = "com.devsisters.ck"


def ipatool_available() -> bool:
    try:
        subprocess.run(["ipatool", "--version"], capture_output=True, timeout=10)
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def download_ipa(out_path: Path, keychain_pass: str | None = None) -> Path:
    """Fetch the latest CRK IPA via ipatool (requires prior `ipatool auth login`)."""
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["ipatool", "download", "--bundle-identifier", BUNDLE_ID,
           "--output", str(out_path), "--non-interactive"]
    if keychain_pass:
        cmd += ["--keychain-passphrase", keychain_pass]
    print("[ipa] downloading via ipatool (App Store, ~3.9 GB) ...", flush=True)
    t0 = time.time()
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
    if r.returncode != 0 or not out_path.exists():
        raise RuntimeError(f"ipatool failed: {r.stdout[-500:]}\n{r.stderr[-500:]}")
    print(f"[ipa] downloaded {out_path.stat().st_size/1e9:.2f} GB in {time.time()-t0:.0f}s")
    return out_path


def _index_ipa_files(zf: zipfile.ZipFile) -> dict[str, list[str]]:
    """name-suffix -> [zip members] index for fast lookup."""
    idx: dict[str, list[str]] = {}
    for info in zf.infolist():
        if info.is_dir():
            continue
        stem = info.filename.rsplit("/", 1)[-1]
        idx.setdefault(stem, []).append(info.filename)
        # also index without extension
        base = stem.rsplit(".", 1)[0] if "." in stem else stem
        idx.setdefault(base, []).append(info.filename)
    return idx


def run_ipa(
    ipa_path: Path,
    out_dir: Path,
    types: tuple[str, ...] = DEFAULT_TYPES,
    search: list[str] | None = None,
    limit: int | None = None,
    save_dec: bool = False,
    only_hashes: set[str] | None = None,
    save_other: bool = True,
) -> dict:
    t0 = time.time()
    ipa_path = Path(ipa_path)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    zf = zipfile.ZipFile(ipa_path)
    idx = _index_ipa_files(zf)
    print(f"[ipa] members: {len(zf.infolist())}")

    # 1. locate + decrypt the iOS manifest (metadata.zeson)
    meta_members = idx.get("metadata.zeson", [])
    if not meta_members:
        raise RuntimeError("metadata.zeson not found in the IPA — layout may have changed")
    enc = zf.read(meta_members[0])
    records = json.loads(parse_zip(decrypt_legacy(enc, "metadata"))[0].data)
    print(f"[ipa] manifest records: {len(records)}")

    if search:
        low = [s.lower() for s in search]
        records = [r for r in records
                   if any(t in r.get("key", "").lower() for t in low)]
    if limit:
        records = records[:limit]
    if only_hashes is not None:
        # batch-archive mode: only process records whose hash is not in the
        # cumulative already-seen set (i.e. content unique to this version)
        records = [r for r in records if r.get("hash") in only_hashes]
        print(f"[ipa] hash filter: {len(records)} records to process")

    stats = {"records": len(records), "ZIP": 0, "UnityFS": 0, "FMOD": 0, "OTHER": 0,
             "zip_ok": 0, "unityfs_ok": 0, "saved": 0, "errors": 0, "missing": 0}
    index_records = []

    for i, r in enumerate(records):
        key = r["key"]
        gpart = gpart_of(key)
        # locate the file: try the basename candidates in the IPA
        base = key.rsplit("/", 1)[-1]
        candidates = idx.get(base) or idx.get(r["hash"]) or idx.get(base.rsplit(".", 1)[0])
        if not candidates:
            stats["missing"] += 1
            index_records.append({"key": key, "gpart": gpart, "missing": True})
            continue
        raw = zf.read(candidates[0])
        cls = classify(raw)
        if not cls.ok and cls.kind in ("OTHER", "UnityFS"):
            dec = decrypt_legacy(raw, gpart)
            cls2 = classify(dec)
            if cls2.ok:
                raw, cls = dec, cls2
        kind = cls.kind
        stats[kind] = stats.get(kind, 0) + 1
        rec = {"key": key, "hash": r.get("hash"), "gpart": gpart,
               "container": kind, "valid": cls.ok, "member": candidates[0]}
        try:
            if kind == "UnityFS":
                if cls.ok:
                    stats["unityfs_ok"] += 1
                s2 = extract_unityfs(raw, out_dir / "bundles" / gpart, types=types, search=search)
                rec["unity"] = s2
                stats["saved"] += s2["saved"]
                stats["errors"] += s2["errors"]
            elif kind == "ZIP":
                if cls.ok:
                    stats["zip_ok"] += 1
                if gpart in ("assetbundle_index", "assetlinker_index"):
                    for e in parse_zip(raw):
                        (out_dir / f"{gpart}.json").write_bytes(e.data)
                        rec["extracted"] = [f"{gpart}.json"]
                else:
                    sub = out_dir / "zip"
                    sub.mkdir(parents=True, exist_ok=True)
                    for e in parse_zip(raw):
                        (sub / f"{gpart}__{e.name.decode('utf-8','replace')}").write_bytes(e.data)
            elif kind == "FMOD":
                (out_dir / "fmod").mkdir(parents=True, exist_ok=True)
                (out_dir / "fmod" / f"{gpart}.bank").write_bytes(raw)
            else:
                if save_other:
                    bad = out_dir / "_other"
                    bad.mkdir(parents=True, exist_ok=True)
                    (bad / f"{r['hash']}.raw").write_bytes(raw)
        except Exception as e:
            rec["error"] = repr(e)
            stats["errors"] += 1
        index_records.append(rec)
        if i % 200 == 0:
            print(f"[{i}/{len(records)}] {stats}", flush=True)

    (out_dir / "ipa_extract_index.json").write_text(
        json.dumps({"records": index_records, "stats": stats}, indent=1, ensure_ascii=False))
    stats["elapsed_sec"] = round(time.time() - t0, 1)
    return stats
