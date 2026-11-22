"""sync use case — the CI entry point.

One command that keeps a local mirror current:
  1. fetch the latest XAPK from APKPure (stable URL, no auth) unless --xapk is given
  2. extract + decrypt + index (the proven Phase 1/2 pipeline)
  3. diff against the previous run's state (new/changed/removed files)

This is deliberately CDN-independent: Devsisters ships the full install-time
asset pack inside the XAPK on every game update, so re-fetching the XAPK
always yields the current content snapshot.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import time
import urllib.request
from pathlib import Path

APKPURE_LATEST = "https://d.apkpure.com/b/XAPK/com.devsisters.ck?version=latest"
STATE_FILE = "state.json"


def fetch_latest_xapk(dest: Path, force: bool = False) -> tuple[Path, bool]:
    """Download the latest CRK XAPK from APKPure. Returns (path, downloaded_now)."""
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() and dest.stat().st_size > 100_000_000 and not force:
        print(f"[sync] reusing cached {dest} ({dest.stat().st_size/1e9:.2f} GB)")
        return dest, False
    print(f"[sync] downloading latest XAPK from APKPure (~1.4 GB) ...", flush=True)
    tmp = dest.with_suffix(".part")
    t0 = time.time()
    import cloudscraper

    resp = None
    for attempt in range(8):
        scraper = cloudscraper.create_scraper()
        try:
            resp = scraper.get(APKPURE_LATEST, stream=True, timeout=60)
            if resp.status_code == 200 and resp.headers.get("Content-Type", "").startswith("application"):
                break
            print(f"[sync]   attempt {attempt+1}: HTTP {resp.status_code}, retrying with fresh session ...", flush=True)
            resp.close()
            resp = None
        except Exception as e:
            print(f"[sync]   attempt {attempt+1}: {type(e).__name__}: {str(e)[:60]}", flush=True)
        time.sleep(min(2 ** attempt, 30))
    if resp is None:
        raise RuntimeError("APKPure download failed after retries (Cloudflare)")
    with resp as r:
        r.raise_for_status()
        total = int(r.headers.get("Content-Length", 0)) or None
        done = 0
        with open(tmp, "wb") as f:
            last_report = 0
            for chunk in r.iter_content(chunk_size=1 << 20):
                if not chunk:
                    break
                f.write(chunk)
                done += len(chunk)
                if total and done - last_report >= (200 << 20):
                    last_report = done
                    print(f"[sync]   {done/1e9:.2f}/{total/1e9:.2f} GB {time.time()-t0:.0f}s", flush=True)
    shutil.move(tmp, dest)
    print(f"[sync] downloaded {dest.stat().st_size/1e9:.2f} GB in {time.time()-t0:.0f}s")
    return dest, True


def _manifest_fingerprint(xapk_path: Path, work_dir: Path) -> dict:
    """Extract just metadata.zeson -> {hash: size} map (cheap fingerprint)."""
    from ..infrastructure import xapk

    pack, _ = xapk.unpack_xapk(xapk_path, work_dir)
    _enc, records = xapk.load_manifest(pack)
    return {r["hash"]: r.get("size") for r in records}, records


def run_sync(
    out_dir: Path,
    xapk_path: Path | None = None,
    work_dir: Path | None = None,
    types: tuple[str, ...] = ("text",),
    force_download: bool = False,
    keep_xapk: bool = False,
) -> dict:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    work_dir = Path(work_dir) if work_dir else out_dir / "_work"
    state_path = out_dir / STATE_FILE
    prev: dict = {}
    if state_path.exists():
        try:
            prev = json.loads(state_path.read_text())
        except Exception:
            prev = {}

    # 1. obtain the XAPK
    if xapk_path:
        xapk_p = Path(xapk_path)
        downloaded = False
    else:
        xapk_p, downloaded = fetch_latest_xapk(out_dir / "latest.xapk", force=force_download)

    # 2. fingerprint the manifest BEFORE the heavy extract (cheap update detection)
    new_fp, _records = _manifest_fingerprint(xapk_p, work_dir)
    old_fp = prev.get("manifest", {})
    added = sorted(set(new_fp) - set(old_fp))
    removed = sorted(set(old_fp) - set(new_fp))
    changed = sorted(k for k in set(new_fp) & set(old_fp) if new_fp[k] != old_fp.get(k))
    if old_fp and not (added or removed or changed):
        print(f"[sync] manifest unchanged vs previous run ({len(new_fp)} files) — nothing to do")
    else:
        if old_fp:
            print(f"[sync] manifest diff: +{len(added)} new, ~{len(changed)} changed, -{len(removed)} removed")
        else:
            print(f"[sync] first run: {len(new_fp)} files")

    # 3. extract + index (reuse run_extract, then build_index)
    from .extract import run_extract
    from .indexer import build_index

    stats = run_extract(
        xapk_p,
        out_dir=out_dir / "Extracted",
        work_dir=work_dir,
        types=types,
        save_dec=False,
    )
    result = build_index(out_dir / "Extracted", xapk_path=xapk_p, work_dir=work_dir)
    print(
        f"[sync] index: bundles={len(result['bundles'])} cookies={len(result['cookies'])} "
        f"strings={len(result['localization'].get('strings', {}))}"
    )

    # 4. persist state
    state = {
        "last_sync": time.strftime("%Y-%m-%d %H:%M:%S"),
        "manifest": new_fp,
        "added_last": added,
        "changed_last": changed,
        "removed_last": removed,
        "extract_stats": {k: v for k, v in stats.items() if not isinstance(v, list)},
    }
    state_path.write_text(json.dumps(state, indent=1))
    if not keep_xapk and downloaded:
        # CI disks are small: drop the 1.4GB XAPK after extraction
        try:
            xapk_p.unlink()
            print("[sync] removed downloaded XAPK to save disk")
        except OSError:
            pass
    return {"added": added, "changed": changed, "removed": removed, "stats": stats}
