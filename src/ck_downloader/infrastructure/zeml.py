"""Localization (.zeml) binary string-table parser.

.zeml = ZIP(strings.xml) where strings.xml is NOT XML but a custom table:
    [version u32 LE][count u32 LE]
    then count x [klen ULEB128][key utf8][vlen ULEB128][value utf8]
File naming: <lang>_<category>_<id>.zeml  (e.g. de_cookietalk_1073961114)
"""
from __future__ import annotations

import struct


def _uleb128(data: bytes, p: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        b = data[p]
        p += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, p
        shift += 7
        if shift > 28:
            raise ValueError("uleb128 too long")


def parse_string_table(data: bytes) -> dict[str, str]:
    if len(data) < 8:
        return {}
    version, count = struct.unpack("<II", data[:8])
    if version != 1 or count > 1000000:
        return {}
    out: dict[str, str] = {}
    p = 8
    n = len(data)
    try:
        for _ in range(count):
            if p + 2 > n:
                break
            klen, p = _uleb128(data, p)
            key = data[p : p + klen]
            p += klen
            vlen, p = _uleb128(data, p)
            val = data[p : p + vlen]
            p += vlen
            out[key.decode("utf-8", "replace")] = val.decode("utf-8", "replace")
    except IndexError:
        pass
    return out


def split_zeml_name(gpart: str) -> tuple[str, str, str]:
    """de_cookietalk_1073961114 -> (lang='de', category='cookietalk', id='1073961114')
    zh-Hant_cookietalk_x    -> (lang='zh-Hant', ...)
    """
    parts = gpart.split("_", 2)
    if len(parts) >= 3 and (len(parts[0]) == 2 or parts[0] in ("zh-Hant", "zh-Hans", "pt-BR", "es-419")):
        return parts[0], parts[1], parts[2]
    if len(parts) == 2:
        return parts[0], parts[1], ""
    return "", gpart, ""
