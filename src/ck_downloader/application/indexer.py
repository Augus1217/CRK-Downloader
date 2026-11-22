"""Index/search use case — full build:

  1. bundle catalog   : assetbundle_index.json  (1726 Infos: labels/deps/files)
  2. asset linker     : assetlinker_index.json  (GUID -> asset name)
  3. localization     : all .zeml string tables (multi-language)
  4. asset names      : UnityFS object names per bundle (UnityPy, name-only fast pass)
  5. cookies          : parsed cookie IDs + display names

Everything is re-derivable from the XAPK; index files are extracted on demand.
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path

from ..infrastructure import xapk
from ..infrastructure.containers import extract_unityfs
from ..infrastructure.crypto import decrypt_legacy, gpart_of, parse_zip
from ..infrastructure.zeml import parse_string_table, split_zeml_name

INDEX_GPARTS = ("assetbundle_index", "assetlinker_index")
COOKIE_RE = re.compile(r"cookie(\d{3,4})(s\d{2})?$", re.IGNORECASE)


def _ensure_index_files(pack: Path, extract_dir: Path) -> None:
    extract_dir.mkdir(parents=True, exist_ok=True)
    if (extract_dir / "assetbundle_index.json").exists() and (extract_dir / "assetlinker_index.json").exists():
        return
    for r in xapk.load_manifest(pack)[1]:
        gpart = gpart_of(r["key"])
        if gpart in INDEX_GPARTS:
            enc = xapk.read_resource(pack, r["hash"])
            for e in parse_zip(decrypt_legacy(enc, gpart)):
                (extract_dir / f"{gpart}.json").write_bytes(e.data)


def _collect_localization(pack: Path, records: list[dict]) -> dict:
    """Parse all .zeml string tables -> {key: {lang: value}}."""
    tables: dict[str, dict[str, str]] = {}
    meta: dict[str, dict] = {}
    for r in records:
        if not r["key"].endswith(".zeml"):
            continue
        gpart = gpart_of(r["key"])
        lang, category, _sid = split_zeml_name(gpart)
        try:
            enc = xapk.read_resource(pack, r["hash"])
            entries = parse_zip(decrypt_legacy(enc, gpart))
            if not entries:
                continue
            table = parse_string_table(entries[0].data)
        except Exception:
            continue
        tables.setdefault(gpart, {}).update(table)
        meta[gpart] = {"lang": lang, "category": category, "strings": len(table)}
    # invert: string key -> {lang: value} (using category+lang disambiguation)
    inverted: dict[str, dict[str, str]] = {}
    for gpart, table in tables.items():
        lang = meta[gpart]["lang"]
        for k, v in table.items():
            inverted.setdefault(k, {})[lang or gpart] = v
    return {"files": meta, "strings": inverted}


def _collect_asset_names(pack: Path, records: list[dict], progress=100) -> dict:
    """UnityPy name-only pass: {gpart: {object_type: [names]}}."""
    out: dict[str, dict] = {}
    ufs = [r for r in records if not r["key"].endswith((".zeml", ".bank", ".zson"))]
    t0 = time.time()
    for i, r in enumerate(ufs):
        gpart = gpart_of(r["key"])
        try:
            enc = xapk.read_resource(pack, r["hash"])
            # names-only: reuse extract_unityfs with an impossible search term = stats only,
            # too slow; do a light pass here instead
            import UnityPy

            env = UnityPy.load(dec := decrypt_legacy(enc, gpart))
            names: dict[str, list[str]] = {}
            for _p, bundle in getattr(env, "files", {}).items():
                for f in getattr(bundle, "files", {}).values():
                    if type(f).__name__ != "SerializedFile":
                        continue
                    for obj in f.objects.values():
                        try:
                            if obj.type.name in ("Texture2D", "Sprite", "TextAsset", "AudioClip", "Mesh"):
                                data = obj.read()
                                nm = getattr(data, "m_Name", "") or ""
                                if nm:
                                    names.setdefault(obj.type.name, []).append(nm)
                        except Exception:
                            pass
            if names:
                out[gpart] = {k: sorted(set(v)) for k, v in names.items()}
        except Exception:
            continue
        if progress and (i + 1) % progress == 0:
            print(f"  names-pass [{i+1}/{len(ufs)}] {time.time()-t0:.0f}s", flush=True)
    return out


def _cookie_index(bundles: dict, localization: dict) -> dict:
    """cookieNNNN -> {display names by lang (if found), bundles, labels}."""
    cookies: dict[str, dict] = {}
    for name, meta in bundles.items():
        m = COOKIE_RE.search(name)
        if not m:
            continue
        cid = "cookie" + m.group(1)
        c = cookies.setdefault(cid, {"id": cid, "bundles": [], "labels": set(), "names": {}})
        c["bundles"].append(name)
        c["labels"].update(meta.get("labels", []))
    # display names: localization keys mentioning the cookie id
    for key, langs in localization.get("strings", {}).items():
        kl = key.lower()
        m = re.search(r"cookie(\d{3,4})", kl)
        if not m:
            continue
        cid = "cookie" + m.group(1)
        if cid in cookies:
            for lang, val in langs.items():
                cookies[cid]["names"].setdefault(lang, val)
    for c in cookies.values():
        c["labels"] = sorted(c["labels"])
        c["bundles"].sort()
    return dict(sorted(cookies.items()))


def build_index(
    extract_dir: Path,
    xapk_path: Path | None = None,
    work_dir: Path | None = None,
    with_names: bool = True,
    with_localization: bool = True,
) -> dict:
    extract_dir = Path(extract_dir)
    extract_dir.mkdir(parents=True, exist_ok=True)
    result: dict = {"bundles": {}, "labels": {}, "linker": {}, "localization": {}, "assets": {}, "cookies": {}}

    pack = None
    records = []
    if xapk_path:
        from ..infrastructure.xapk import open_xapk

        contents = open_xapk(xapk_path, work_dir or extract_dir / "_work")
        pack, records = contents.asset_pack, contents.records

    _ensure_index_files(pack, extract_dir) if pack else None
    ab = extract_dir / "assetbundle_index.json"
    if ab.exists():
        for it in json.loads(ab.read_text(encoding="utf-8")).get("Infos", []):
            result["bundles"][it.get("name", "")] = {
                "files": it.get("files", []),
                "dependencies": it.get("dependencies", []),
                "localization_files": it.get("localization_files", []),
                "labels": it.get("labels", []),
            }
            for lab in it.get("labels", []) or []:
                result["labels"].setdefault(lab, []).append(it.get("name", ""))
    lk = extract_dir / "assetlinker_index.json"
    if lk.exists():
        result["linker"] = json.loads(lk.read_text(encoding="utf-8")).get("Index", {})

    if with_localization and pack:
        print("parsing localization (.zeml) ...", flush=True)
        result["localization"] = _collect_localization(pack, records)
    elif not with_localization:
        lp = extract_dir / "localization.json"
        if lp.exists():
            result["localization"] = json.loads(lp.read_text(encoding="utf-8"))

    if with_names and pack:
        print("collecting asset names (UnityPy name-only pass) ...", flush=True)
        result["assets"] = _collect_asset_names(pack, records)

    result["cookies"] = _cookie_index(result["bundles"], result["localization"])

    slim = {k: result[k] for k in ("bundles", "labels", "linker", "cookies")}
    (extract_dir / "index" / "asset_index.json").parent.mkdir(parents=True, exist_ok=True)
    (extract_dir / "index" / "asset_index.json").write_text(
        json.dumps(slim, indent=1, ensure_ascii=False), encoding="utf-8"
    )
    if result["localization"]:
        (extract_dir / "localization.json").write_text(
            json.dumps(result["localization"], indent=1, ensure_ascii=False), encoding="utf-8"
        )
    if result["assets"]:
        (extract_dir / "asset_names.json").write_text(
            json.dumps(result["assets"], indent=1, ensure_ascii=False), encoding="utf-8"
        )
    return result


def search(index_dir: Path, terms: list[str], limit: int = 40, with_localization: bool = True) -> dict:
    index_dir = Path(index_dir)
    idx = json.loads((index_dir / "asset_index.json").read_text(encoding="utf-8"))
    low = [t.lower() for t in terms]
    hits: dict = {"cookies": [], "bundles": [], "linker": [], "strings": [], "counts": {}}

    for cid, c in idx.get("cookies", {}).items():
        hay = cid + " " + " ".join(c.get("bundles", [])).lower() + " " + " ".join(
            str(v) for v in c.get("names", {}).values()
        ).lower()
        if any(t in hay for t in low):
            hits["cookies"].append(c)
    for name, meta in idx.get("bundles", {}).items():
        hay = name.lower() + " " + " ".join(meta.get("labels", [])).lower()
        if any(t in hay for t in low):
            hits["bundles"].append({"name": name, "labels": meta["labels"], "files": len(meta["files"])})
    for guid, name in idx.get("linker", {}).items():
        if any(t in name.lower() for t in low):
            hits["linker"].append({"guid": guid, "name": name})

    if with_localization:
        loc_path = index_dir.parent / "localization.json"
        if not loc_path.exists():
            loc_path = Path("Extracted") / "localization.json"
        if loc_path.exists():
            loc = json.loads(loc_path.read_text(encoding="utf-8"))
            for key, langs in loc.get("strings", {}).items():
                if any(t in key.lower() or any(t in str(v).lower() for v in langs.values()) for t in low):
                    hits["strings"].append({"key": key, "values": langs})
                    if len(hits["strings"]) >= limit:
                        break

    for k in ("cookies", "bundles", "linker", "strings"):
        hits[k] = hits[k][:limit]
        hits["counts"][k] = len(hits[k])
    return hits
