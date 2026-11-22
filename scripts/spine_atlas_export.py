#!/usr/bin/env python3
"""把 CRK 的（其實是文字格式的）*.atlas.bin 合併成官方 Spine Skeleton Viewer
吃得下的 *.atlas（一個 skeleton 一份、內含它 skin 家族的所有分頁）。

用法：
    python3 spine_atlas_export.py <目錄> [更多目錄...]
    python3 spine_atlas_export.py --all <bundles根目錄>   # 遞迴處理含 *.skel.bin 的子目錄

規則：
- 每個 *.skel.bin 的字根 X：同目錄中檔名 == "X.atlas.bin" 或以 "X" 為前綴的
  *.atlas.bin（Xs01、Xs02、族系 skin 頁…）→ 依序串接為 "X.atlas"
  （官方 viewer 載入 X.skel.bin 時依「同基底檔名 .atlas」自動尋找）
- CRK 的 .atlas.bin 本身已是 Spine 3.8 文字格式 → 直接拼接，不需轉碼
- PNG 應已在同目錄（viewer 依 atlas 內宣告的頁面檔名解析）
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

PAGE_RE = re.compile(r"^([\w./\\ ,:()\-'!]+\.png)$")


def pages_of(text: str) -> list[str]:
    out = []
    for line in text.splitlines():
        s = line.strip()
        if s.endswith(".png") and PAGE_RE.match(s) and line == line.lstrip():
            out.append(s)
    return out


def merge_for_skel(dirp: Path, skel: Path):
    base = skel.name[: -len(".skel.bin")]
    bins = [b for b in sorted(dirp.glob("*.atlas.bin")) if b.is_file()]
    own = [b for b in bins
           if b.name == f"{base}.atlas.bin"
           or (b.name.startswith(base) and re.match(re.escape(base) + r"(s\d+|r\d+|_c\d+)(_\w+)?\.atlas\.bin$", b.name))]
    # 退化：沒有族系頁就只抓同名那張
    if not own:
        same = dirp / f"{base}.atlas.bin"
        if same.is_file():
            own = [same]
    if not own:
        return None
    pages: list[str] = []
    parts: list[str] = []
    for b in own:
        t = b.read_text(errors="replace").replace("\r\n", "\n").replace("\r", "\n")
        t = t.lstrip("\n").rstrip("\n")  # 拿掉開頭空行（前導空行會卡某些 spine 解析器）
        parts.append(t)
        pages.extend(pages_of(t))
    out = dirp / f"{base}.atlas"
    out.write_text("\n\n".join(parts) + "\n")   # 頁間一個空行、檔尾一個換行
    return out, pages


def process_dir(dirp: Path) -> list[str]:
    logs = []
    for skel in sorted(dirp.glob("*.skel.bin")):
        r = merge_for_skel(dirp, skel)
        if r is None:
            logs.append(f"[skip] {dirp.name}/{skel.name}: 沒有對應的 atlas.bin")
            continue
        out, pages = r
        missing = [p for p in pages if not (dirp / Path(p).name).exists()]
        extra = f"  ⚠ 缺圖: {missing}" if missing else ""
        logs.append(f"[ok] {dirp.name}/{out.name}  分頁 {pages}{extra}")
    return logs


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("dirs", nargs="+")
    ap.add_argument("--all", action="store_true",
                    help="把每個 dir 當根目錄，遞迴處理底下所有含 *.skel.bin 的資料夾")
    a = ap.parse_args()

    targets: list[Path] = []
    for d in map(Path, a.dirs):
        if not d.is_dir():
            print(f"not a dir: {d}", file=sys.stderr)
            continue
        if a.all:
            targets.extend(sorted({p.parent for p in d.rglob("*.skel.bin")}))
        else:
            targets.append(d)
    for t in targets:
        for line in process_dir(t):
            print(line)


if __name__ == "__main__":
    main()
