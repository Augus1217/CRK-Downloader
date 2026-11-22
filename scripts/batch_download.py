#!/usr/bin/env python3
"""Batch download + extract historical CRK versions via ipatool.

從最舊到最新逐版處理（version ID 整數排序 = 時間順序）：

  新格式（有 metadata.zeson）：
    讀 manifest → 跟「累積已見 hash 集合」比對 → 只提取這版獨有的資產
    → archive/v<id>/（bundles/ zip/ fmod/）+ archive/manifests/v<id>.json
  舊格式（2021 年代，無 manifest，無加密）：
    UnityPy 直接解 Texture2D → PNG；FMOD .bank 原樣保存
    用「名稱+尺寸」去重，之後的版本只補新檔

去重種子 = seeds/current_hashes.json（現在這版的全部 hash），
所以「現在還存在的內容」不會被重複封存，只有歷史上被移除/替換的內容會進 archive。

狀態記在 download_state.json，重跑自動接續。處理完刪 IPA 省磁碟（KEEP_IPA=1 保留）。
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from ck_downloader.application.ipa import BUNDLE_ID, run_ipa  # noqa: E402
from ck_downloader.infrastructure.crypto import decrypt_legacy, parse_zip  # noqa: E402

IPATOOL = os.environ.get("IPATOOL", "ipatool")
OUT_DIR = Path(os.environ.get("OUT_DIR", REPO / "versions"))
ARCHIVE = Path(os.environ.get("ARCHIVE_DIR", REPO / "archive"))
STATE_FILE = Path(os.environ.get("STATE_FILE", REPO / "download_state.json"))
SEED_FILE = Path(os.environ.get("SEED_FILE", REPO / "seeds" / "current_hashes.json"))
KEYCHAIN_PASS = os.environ.get("IPATOOL_KEYCHAIN_PASS", "")
KEEP_IPA = os.environ.get("KEEP_IPA", "") == "1"
# 舊格式解 Unity 用的暫存目錄（.resS 外部參照需要實體檔案）
WORK_ROOT = Path(os.environ.get("WORK_DIR", "/tmp"))


# ---------------------------------------------------------------- state

def load_state() -> dict:
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text())
    return {"done": {}, "old_names": [], "seen_keys": []}


def save_state(state: dict) -> None:
    # 序列化時把工作中的 set 轉成 list，但保留在 state 裡給後續迴圈用
    out = {k: v for k, v in state.items() if k not in ("_seen_names", "_seen_keys")}
    if "_seen_names" in state:
        out["old_names"] = sorted(state["_seen_names"])
    if "_seen_keys" in state:
        out["seen_keys"] = sorted(state["_seen_keys"])
    STATE_FILE.write_text(json.dumps(out, ensure_ascii=False))


def seen_names_of(state: dict) -> set[str]:
    if "_seen_names" not in state:
        state["_seen_names"] = set(state.get("old_names", []))
    return state["_seen_names"]


def seen_keys_of(state: dict) -> set[str]:
    if "_seen_keys" not in state:
        state["_seen_keys"] = set(state.get("seen_keys", []))
    return state["_seen_keys"]


# ---------------------------------------------------------------- ipatool

def _ipatool_cmd(*args: str) -> list[str]:
    """ipatool 指令前綴；有 passphrase 用參數帶（CI 無互動提示）。"""
    cmd = [IPATOOL, *args]
    if KEYCHAIN_PASS:
        cmd += ["--keychain-passphrase", KEYCHAIN_PASS]
    return cmd


def load_versions() -> list[str]:
    r = subprocess.run(_ipatool_cmd("list-versions", "--bundle-identifier", BUNDLE_ID),
                       capture_output=True, text=True, timeout=120)
    vids = sorted(set(re.findall(r"\d{8,12}", r.stdout)), key=int)
    if not vids:
        detail = f"STDOUT: {(r.stdout or '')[-200:]} STDERR: {(r.stderr or '')[-400:]}"
        raise RuntimeError(f"ipatool list-versions failed (rc={r.returncode}): {detail}")
    return vids


def download(vid: str, out: Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    cmd = _ipatool_cmd("download", "--bundle-identifier", BUNDLE_ID,
                       "--external-version-id", vid, "--output", str(out),
                       "--non-interactive")
    print(f"[{vid}] downloading via ipatool ...", flush=True)
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
    if r.returncode != 0 or not out.exists():
        detail = f"STDOUT: {(r.stdout or '')[-200:]} STDERR: {(r.stderr or '')[-400:]}"
        raise RuntimeError(f"ipatool download failed (rc={r.returncode}): {detail}")


# ---------------------------------------------------------------- manifests

def parse_manifest(ipa: Path) -> list[dict] | None:
    """metadata.zeson → records；舊格式沒有這個檔 → None。
    內層 JSON 解不開（ era-3 過渡期：ZipCrypto 換密碼）也回 None → 走舊格式分支，
    至少保住 data.unity3d / Raw/font 這些明文資產。"""
    zf = zipfile.ZipFile(ipa)
    members = [i for i in zf.infolist() if i.filename.endswith(("metadata.zeson", "metadata.zson"))]
    if not members:
        return None
    enc = zf.read(members[0])
    container = enc if enc[:4] == b"PK\x03\x04" else decrypt_legacy(enc, "metadata")
    try:
        inner = parse_zip(container)[0].data
    except Exception as e:
        print(f"[manifest] metadata 容器解析失敗，fallback 舊格式: {e!r}", flush=True)
        return None
    try:
        return json.loads(inner)
    except (json.JSONDecodeError, ValueError) as e:
        print(f"[manifest] metadata 內容非 JSON（歷史版換過密碼），fallback 舊格式: {e!r}", flush=True)
        return None


# ---------------------------------------------------------------- helpers

def split_oversized(out_dir: Path, limit: int = 90 * 1024 * 1024) -> list[str]:
    """GitHub 擋 >100MB 的檔案 → 超過就切成 .part000/.part001/...

    還原方式：cat 檔名.part* > 檔名
    """
    split = []
    for f in list(out_dir.rglob("*")):
        if not (f.is_file() and f.stat().st_size > limit and ".part" not in f.name):
            continue
        data = f.read_bytes()
        for n, off in enumerate(range(0, len(data), limit)):
            f.with_name(f"{f.name}.part{n:03d}").write_bytes(data[off:off + limit])
        f.unlink()
        split.append(f.name)
    return split


# ---------------------------------------------------------------- new format

def process_new_format(vid: str, ipa: Path, records: list[dict],
                       seen_hashes: set[str], seen_keys: set[str]) -> dict:
    """雙重去重：hash（現行種子）+ key 名稱（歷史版 bundle 每版重打包，
    hash 幾乎全變；用 manifest 的 key 邏輯名稱擋住「內容仍存在」的 bundle，
    只封存整個歷史中真正出現過一次的 key）。"""
    hashes = {r["hash"] for r in records if r.get("hash")}
    keys = {r["key"] for r in records if r.get("key")}
    new_records = [r for r in records
                   if r.get("hash") and r.get("key")
                   and r["hash"] not in seen_hashes
                   and r["key"] not in seen_keys]
    new = sorted({r["hash"] for r in new_records})

    mdir = ARCHIVE / "manifests"
    mdir.mkdir(parents=True, exist_ok=True)
    (mdir / f"v{vid}.json").write_text(json.dumps(records, ensure_ascii=False))

    info: dict = {"records": len(records), "new": len(new_records)}
    if not new:
        info["extracted"] = 0
    else:
        stats = run_ipa(ipa, ARCHIVE / f"v{vid}", only_hashes=set(new), save_other=False)
        info["extracted"] = stats.get("saved", 0)
        info["errors"] = stats.get("errors", 0)
    seen_hashes |= hashes
    seen_keys |= keys
    return info


# ---------------------------------------------------------------- old format

def process_old_format(vid: str, ipa: Path, seen: set[str]) -> dict:
    import UnityPy

    out = ARCHIVE / f"v{vid}"
    tex_dir = out / "tex"
    bank_dir = out / "bank"
    tex_dir.mkdir(parents=True, exist_ok=True)
    bank_dir.mkdir(parents=True, exist_ok=True)
    info = {"textures": 0, "banks": 0, "skipped": 0}

    zf = zipfile.ZipFile(ipa)

    # 1) FMOD banks：舊版未加密，原樣保存
    for i in zf.infolist():
        if not i.filename.endswith(".bank") or i.file_size < 1000:
            continue
        name = i.filename.rsplit("/", 1)[-1]
        key = f"bank:{name}:{i.file_size}"
        if key in seen:
            info["skipped"] += 1
            continue
        (bank_dir / name).write_bytes(zf.read(i))
        seen.add(key)
        info["banks"] += 1

    # 2) Unity 序列化檔：解到 WORK_ROOT 讓 .resS 外部參照可解析，逐檔用 UnityPy 解
    work = WORK_ROOT / f"old_ck_{vid}"
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    for i in zf.infolist():
        fn = i.filename.rsplit("/", 1)[-1]
        if "/Data/" not in i.filename:
            continue
        if fn.endswith(".assets") or fn.endswith(".resS") or fn == "globalgamemanagers" \
                or fn == "data.unity3d" or fn == "font":
            (work / fn).write_bytes(zf.read(i))

    for assets_path in sorted(work.glob("*.assets")) + sorted(work.glob("data.unity3d")) + sorted(work.glob("font")):
        try:
            env = UnityPy.load(str(assets_path))
        except Exception:
            continue
        for obj in env.objects:
            if obj.type.name != "Texture2D":
                continue
            try:
                d = obj.read()
                nm = d.m_Name or ""
                w, h = int(d.m_Width), int(d.m_Height)
                if w < 32 or not nm.strip():
                    continue
                key = f"tex:{nm}:{w}x{h}"
                if key in seen:
                    info["skipped"] += 1
                    continue
                img = d.image
                if img is None or img.width == 0:
                    continue
                safe = re.sub(r"[^A-Za-z0-9._-]", "_", nm)[:120]
                tpng = tex_dir / f"{safe}.png"
                img.save(tpng)
                try:
                    from PIL import Image
                    with Image.open(tpng) as chk:
                        chk.verify()
                except Exception:
                    tpng.unlink(missing_ok=True)  # crunch 壓縮等 UnityPy 解不動的
                    continue
                seen.add(key)
                info["textures"] += 1
            except Exception:
                continue
        # TextAsset（rules/table 等）只保存 data.unity3d 裡的（.assets 的多半在 manifest 體系）
        if assets_path.name == "data.unity3d":
            ta_dir = out / "textasset"
            ta_dir.mkdir(parents=True, exist_ok=True)
            for obj in env.objects:
                if obj.type.name != "TextAsset":
                    continue
                try:
                    d = obj.read()
                    nm = (d.m_Name or "").strip() or f"textasset_{d.path_id}"
                    if f"txt:{nm}:{len(d.m_Script)}" in seen:
                        continue  # 同名內容
                    key = f"txt:{nm}:{len(d.m_Script)}"
                    if key in seen:
                        continue
                    (ta_dir / (re.sub(r"[^A-Za-z0-9._-]", "_", nm)[:100] + ".raw")).write_bytes(
                        d.m_Script.encode("utf-8", "surrogateescape") if isinstance(d.m_Script, str) else bytes(d.m_Script)
                    )
                    seen.add(key)
                    info["textassets"] = info.get("textassets", 0) + 1
                except Exception:
                    continue
            # 字型（Raw/font：跨版穩定，只落一次）
            for obj in env.objects:
                if obj.type.name != "Font":
                    continue
                try:
                    d = obj.read()
                    fd = d.m_FontData
                    nm = (d.m_Name or "").strip() or f"font_{obj.path_id}"
                    if not fd or len(fd) < 1024:
                        continue
                    key = f"font:{nm}:{len(fd)}"
                    if key in seen:
                        continue
                    fdir = out / "font"
                    fdir.mkdir(parents=True, exist_ok=True)
                    (fdir / (re.sub(r"[^A-Za-z0-9._-]", "_", nm)[:80] + ".ttf")).write_bytes(bytes(fd))
                    seen.add(key)
                    info["fonts"] = info.get("fonts", 0) + 1
                except Exception:
                    continue

    shutil.rmtree(work, ignore_errors=True)
    return info


# ---------------------------------------------------------------- main

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--batch-size", type=int, default=3)
    ap.add_argument("--versions-file", default=None,
                    help="JSON list of version IDs（預設用 ipatool list-versions 現查）")
    ap.add_argument("--only", nargs="*", default=None,
                    help="只處理這些 version ID（測試用）")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    if args.only:
        vids = sorted(args.only, key=int)
    elif args.versions_file:
        vids = sorted(json.loads(Path(args.versions_file).read_text()), key=int)
    else:
        vids = load_versions()

    state = load_state()
    seen_names = seen_names_of(state)
    seen_keys = seen_keys_of(state)
    seen_hashes: set[str] = set()
    if SEED_FILE.exists():
        seen_hashes = set(json.loads(SEED_FILE.read_text()))
    KEYS_SEED = REPO / "seeds" / "current_keys.json"
    if KEYS_SEED.exists():
        seen_keys |= set(json.loads(KEYS_SEED.read_text()))
    print(f"seed hashes (current version): {len(seen_hashes)} | seed keys: {len(seen_keys)}")

    done = state["done"]
    pending = [v for v in vids if v not in done]
    batch = pending[:args.batch_size]
    print(f"total {len(vids)} | done {len(done)} | pending {len(pending)} "
          f"| this batch: {len(batch)} -> {batch[:5]}{'...' if len(batch) > 5 else ''}")
    if args.dry_run:
        return

    for vid in batch:
        ipa = OUT_DIR / f"crk-{vid}.ipa"
        try:
            if not (ipa.exists() and ipa.stat().st_size > 1_000_000):
                download(vid, ipa)
            print(f"[{vid}] IPA {ipa.stat().st_size / 1e6:.0f} MB", flush=True)

            records = parse_manifest(ipa)
            if records is None:
                info = process_old_format(vid, ipa, seen_names)
                fmt = "old"
            else:
                info = process_new_format(vid, ipa, records, seen_hashes, seen_keys)
                fmt = "new"
            state["done"][vid] = {"format": fmt, **info}
            oversize = split_oversized(ARCHIVE / f"v{vid}")
            if oversize:
                state["done"][vid]["split"] = oversize
            print(f"[{vid}] {fmt}-format: {info}"
                  + (f" | split: {oversize}" if oversize else ""), flush=True)
        except Exception as e:
            msg = repr(e)[:300]
            if "ipatool download failed" in msg:
                # 暫時性下載錯誤（CDN artwork 拒絕等）：不標 done，下一批重試
                retries = state.setdefault("retries", {})
                n = retries.get(vid, 0) + 1
                retries[vid] = n
                state["done"][vid] = {"error": msg}
                if n >= 3:
                    print(f"[{vid}] download failed {n}x, giving up", flush=True)
                else:
                    state["done"].pop(vid, None)
                    print(f"[{vid}] download failed (attempt {n}/3, will retry)", flush=True)
                print(f"[{vid}] FAILED: {e!r}", flush=True)
            else:
                state["done"][vid] = {"error": msg}
                print(f"[{vid}] FAILED: {e!r}", flush=True)
        finally:
            save_state(state)
            if not KEEP_IPA and ipa.exists():
                ipa.unlink()
                print(f"[{vid}] IPA deleted", flush=True)

    remaining = len([v for v in vids if v not in state["done"]])
    print(f"batch complete | {remaining} versions remaining")


if __name__ == "__main__":
    main()
