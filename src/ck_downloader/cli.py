"""ck-downloader CLI."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path


def _add_common(p: argparse.ArgumentParser):
    p.add_argument("--xapk", "-x", required=True, help="path to CookieRun Kingdom .xapk (or extracted dir)")
    p.add_argument("--out", "-o", default="Extracted", help="output directory")
    p.add_argument("--work", "-w", default=None, help="working dir for extracted inner APKs (default: <out>/_work)")
    p.add_argument("--threads", "-t", type=int, default=4, help="reserved (Phase 3)")
    p.add_argument("--search", "-s", nargs="*", default=None, help="keyword filter (any-match)")
    p.add_argument("--limit", "-l", type=int, default=None, help="process only first N records")
    p.add_argument("--save-dec", action="store_true", help="also save decrypted raw payloads")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="ck-downloader",
        description="CookieRun: Kingdom asset downloader/extractor (offline XAPK mode; DevPlay download in Phase 3)",
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    pe = sub.add_parser("extract", help="decrypt + extract all assets from an XAPK")
    _add_common(pe)
    pe.add_argument(
        "--type", "-rt", nargs="*", default=["texture", "sprite", "text"],
        choices=["texture", "sprite", "text", "audio", "mesh"],
        help="Unity asset types to extract (default: texture sprite text)",
    )
    pe.add_argument("--save-raw", action="store_true", help="save decrypted container payloads")

    pi = sub.add_parser("index", help="build asset/cookie/localization index (needs --xapk for full build)")
    _add_common(pi)
    pi.add_argument("--extract-dir", "-ed", default="Extracted")
    pi.add_argument("--no-names", action="store_true", help="skip the UnityPy name pass (faster)")
    pi.add_argument("--no-localization", action="store_true", help="skip the .zeml localization pass")

    ps = sub.add_parser("search", help="search the built index")
    ps.add_argument("terms", nargs="+")
    ps.add_argument("--index-dir", "-i", default="Extracted/index")
    ps.add_argument("--limit", "-l", type=int, default=40)
    ps.add_argument("--no-strings", action="store_true", help="skip localization hits")

    pd = sub.add_parser("download", help="download updated assets from CDN (Phase 3 — not implemented)")
    pd.add_argument("--region", "-r", default="gl")

    psn = sub.add_parser("sync", help="CI entry point: fetch latest XAPK from APKPure + extract + index + diff")
    psn.add_argument("--out", "-o", default="CKMirror", help="mirror root directory")
    psn.add_argument("--xapk", "-x", default=None, help="use a local XAPK instead of fetching from APKPure")
    psn.add_argument("--work", "-w", default=None)
    psn.add_argument("--type", "-rt", nargs="*", default=["text"], choices=["texture", "sprite", "text", "audio", "mesh"],
                     help="Unity asset types (default: text — small; add texture/sprite locally)")
    psn.add_argument("--force-download", action="store_true", help="re-download even if cached")
    psn.add_argument("--keep-xapk", action="store_true", help="keep the fetched XAPK")

    ping = sub.add_parser("ingest", help="ingest an adb-pulled device cache (no root needed)")
    ping.add_argument("--pulled-dir", "-pd", required=True, help="dir from `adb pull /sdcard/Android/data/com.devsisters.ck`")
    ping.add_argument("--out", "-o", default="Extracted")
    ping.add_argument("--type", "-rt", nargs="*", default=["texture", "sprite", "text"],
                      choices=["texture", "sprite", "text", "audio", "mesh"])
    ping.add_argument("--search", "-s", nargs="*", default=None)
    ping.add_argument("--limit", "-l", type=int, default=None)

    pip = sub.add_parser("ipa", help="extract from an iOS App Store IPA (~3.9 GB, full asset set)")
    pip.add_argument("--ipa-file", "-if", required=True, help="path to the downloaded .ipa")
    pip.add_argument("--out", "-o", default="Extracted")
    pip.add_argument("--type", "-rt", nargs="*", default=["texture", "sprite", "text"],
                     choices=["texture", "sprite", "text", "audio", "mesh"])
    pip.add_argument("--search", "-s", nargs="*", default=None)
    pip.add_argument("--limit", "-l", type=int, default=None)
    pip.add_argument("--save-dec", action="store_true")
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.cmd == "extract":
        from .application.extract import run_extract

        stats = run_extract(
            Path(args.xapk),
            out_dir=Path(args.out),
            work_dir=Path(args.work) if args.work else None,
            types=tuple(args.type),
            search=args.search,
            limit=args.limit,
            save_dec=args.save_dec,
        )
        print("\n==== RESULT ====")
        for k, v in stats.items():
            print(f"{k}: {v}")
        return 0

    if args.cmd == "index":
        from .application.indexer import build_index

        result = build_index(
            Path(args.extract_dir),
            xapk_path=Path(args.xapk),
            work_dir=Path(args.work) if args.work else None,
            with_names=not args.no_names,
            with_localization=not args.no_localization,
        )
        print(
            f"bundles: {len(result['bundles'])}  labels: {len(result['labels'])}  "
            f"linker: {len(result['linker'])}  cookies: {len(result['cookies'])}  "
            f"loc-files: {len(result['localization'].get('files', {}))}  "
            f"loc-strings: {len(result['localization'].get('strings', {}))}  "
            f"asset-bundles-with-names: {len(result['assets'])}"
        )
        return 0

    if args.cmd == "search":
        from .application.indexer import search
        import json

        hits = search(Path(args.index_dir), args.terms, args.limit, with_localization=not args.no_strings)
        print(json.dumps(hits, indent=1, ensure_ascii=False))
        return 0

    if args.cmd == "download":
        print("download (DevPlay online mode) is Phase 3 — not implemented yet.", file=sys.stderr)
        return 2

    if args.cmd == "sync":
        from .application.sync import run_sync

        result = run_sync(
            Path(args.out),
            xapk_path=Path(args.xapk) if args.xapk else None,
            work_dir=Path(args.work) if args.work else None,
            types=tuple(args.type),
            force_download=args.force_download,
            keep_xapk=args.keep_xapk,
        )
        print("\n==== SYNC RESULT ====")
        print(f"added:   {len(result['added'])} {result['added'][:5] if result['added'] else ''}")
        print(f"changed: {len(result['changed'])}")
        print(f"removed: {len(result['removed'])}")
        return 0

    if args.cmd == "ingest":
        from .application.ingest import run_ingest

        stats = run_ingest(
            Path(args.pulled_dir),
            Path(args.out),
            types=tuple(args.type),
            search=args.search,
            limit=args.limit,
        )
        print("\n==== INGEST RESULT ====")
        for k, v in stats.items():
            print(f"{k}: {v}")
        return 0

    if args.cmd == "ipa":
        from .application.ipa import run_ipa

        stats = run_ipa(
            Path(args.ipa_file),
            Path(args.out),
            types=tuple(args.type),
            search=args.search,
            limit=args.limit,
            save_dec=args.save_dec,
        )
        print("\n==== IPA EXTRACT RESULT ====")
        for k, v in stats.items():
            print(f"{k}: {v}")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
