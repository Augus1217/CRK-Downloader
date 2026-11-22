"""Extract use case: XAPK -> decrypt -> classify -> extract -> index."""
from __future__ import annotations

import json
import time
from pathlib import Path

from ..infrastructure import xapk
from ..infrastructure.containers import DEFAULT_TYPES, classify, extract_unityfs
from ..infrastructure.crypto import decrypt_legacy, gpart_of

INDEX_KEYS = {"assetbundle_index", "assetlinker_index"}


def run_extract(
    xapk_path: Path,
    out_dir: Path = Path("Extracted"),
    work_dir: Path | None = None,
    types: tuple[str, ...] = DEFAULT_TYPES,
    search: list[str] | None = None,
    limit: int | None = None,
    save_raw: bool = False,
    save_dec: bool = False,
) -> dict:
    t0 = time.time()
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    work_dir = Path(work_dir) if work_dir else out_dir / "_work"
    contents = xapk.open_xapk(xapk_path, work_dir)

    records = contents.records
    if limit:
        records = records[:limit]
    if search:
        low = [s.lower() for s in search]
        records = [
            r for r in records
            if any(t in r.get("key", "").lower() or t in r.get("hash", "").lower() for t in low)
        ]

    stats = {
        "records": len(records), "ZIP": 0, "UnityFS": 0, "FMOD": 0, "OTHER": 0,
        "zip_ok": 0, "unityfs_ok": 0, "saved": 0, "errors": 0,
    }
    index_records = []

    for i, r in enumerate(records):
        key = r["key"]
        gpart = gpart_of(key)
        try:
            enc = xapk.read_resource(contents.asset_pack, r["hash"])
        except KeyError:
            stats["errors"] += 1
            continue
        dec = decrypt_legacy(enc, gpart)
        cls = classify(dec)
        kind = cls.kind
        stats[kind] = stats.get(kind, 0) + 1

        base = out_dir / key.rsplit("/", 1)[-1]
        rec = {
            "key": key, "hash": r["hash"], "size": r.get("size"),
            "gpart": gpart, "container": kind, "valid": cls.ok, "detail": cls.detail,
        }

        if save_dec:
            raw_dir = out_dir / "_decrypted"
            raw_dir.mkdir(parents=True, exist_ok=True)
            (raw_dir / f"{r['hash']}.dec").write_bytes(dec)

        try:
            if kind == "ZIP":
                if cls.ok:
                    stats["zip_ok"] += 1
                if gpart in INDEX_KEYS:
                    for e in cls.zip_entries:
                        (out_dir / f"{gpart}.json").write_bytes(e.data)
                        rec["extracted"] = [f"{gpart}.json"]
                else:
                    sub = out_dir / "zeml" if key.endswith(".zeml") else out_dir / "zip"
                    sub.mkdir(parents=True, exist_ok=True)
                    names = []
                    for e in cls.zip_entries:
                        name = e.name.decode("utf-8", "replace")
                        if search and not any(s in name.lower() for s in [s.lower() for s in search]):
                            continue
                        (sub / f"{gpart}__{name}").write_bytes(e.data)
                        names.append(name)
                    rec["extracted"] = names
            elif kind == "UnityFS":
                if cls.ok:
                    stats["unityfs_ok"] += 1
                sub = out_dir / "bundles" / gpart
                s2 = extract_unityfs(dec, sub, types=types, search=search)
                rec["unity"] = s2
                stats["saved"] += s2["saved"]
                stats["errors"] += s2["errors"]
            elif kind == "FMOD":
                (out_dir / "fmod").mkdir(parents=True, exist_ok=True)
                (out_dir / "fmod" / f"{gpart}.bank").write_bytes(dec)
                rec["extracted"] = [f"fmod/{gpart}.bank"]
            else:
                bad = out_dir / "_other"
                bad.mkdir(parents=True, exist_ok=True)
                (bad / f"{r['hash']}.raw").write_bytes(dec)
                rec["extracted"] = [f"_other/{r['hash']}.raw"]
        except Exception as e:  # extraction must never kill the batch
            rec["error"] = repr(e)
            stats["errors"] += 1

        index_records.append(rec)
        if i % 100 == 0:
            print(
                f"[{i}/{len(records)}] zip={stats['ZIP']}(ok{stats['zip_ok']}) "
                f"ufs={stats['UnityFS']}(ok{stats['unityfs_ok']}) fmod={stats['FMOD']} "
                f"other={stats['OTHER']} saved={stats['saved']} err={stats['errors']}",
                flush=True,
            )

    (out_dir / "extract_index.json").write_text(
        json.dumps({"records": index_records, "stats": stats}, indent=1), encoding="utf-8"
    )
    stats["elapsed_sec"] = round(time.time() - t0, 1)
    stats["out_dir"] = str(out_dir)
    return stats
