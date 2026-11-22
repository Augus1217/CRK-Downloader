"""DevPlay CDN download chain (fully reversed 2026-11-22, all steps verified 200).

Chain:
  1. ResourceKey  = GET {srv}/resourceKey.json            (bare JSON string)
  2. metadata.zip = GET {srv}/index/{SHA1upper(RK+BuildKey)}/metadata.zip
                    ZipCrypto password = SHA1upper(RK + ZIP_PW_SALT)
  3. bundle_pass  = v2 decrypt (secret=BuildKey, name='bundle_pass')
                    -> {"current": ..., "previous": ...}
  4. download URL = (srv + '/' + key).Replace('/files', '/files/' + SHA1upper(RK+BK))
  5. decrypt      = v2 (secrets=[current, previous, buildKey, '']) or legacy

{srv} = https://static.devscdn.com/ck/resource/{resource_hash}
"""
from __future__ import annotations

import hashlib
import io
import json
import urllib.request
import zipfile

from .crypto import ZIP_PASSWORD, MK_DEFAULT, EPOCH_SALT, decrypt_v2, decrypt_legacy, sniff_container, gpart_of

SRV_TPL = "https://static.devscdn.com/ck/resource/{rh}"
ZIP_PW_SALT = "1u05t4Obdu+YxKapFTxDZA=="
BUILDKEY_165 = "bda24e6c-a05c-4687-b82e-39d886b5d3fa"   # 1.6.5 / 7.11 family (per-VERSION)


def http_get(url: str, timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "UnityWebRequest/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def sha1u(b: bytes) -> str:
    return hashlib.sha1(b).hexdigest().upper()


def resource_key(resource_hash: str) -> str:
    srv = SRV_TPL.format(rh=resource_hash)
    return json.loads(http_get(f"{srv}/resourceKey.json").decode())


def fetch_metadata(resource_hash: str, build_key: str = BUILDKEY_165):
    """Return (srv, prefix, resource_key, files)."""
    srv = SRV_TPL.format(rh=resource_hash)
    rk = resource_key(resource_hash)
    prefix = sha1u((rk + build_key).encode())
    zbytes = http_get(f"{srv}/index/{prefix}/metadata.zip")
    pw = sha1u((rk + ZIP_PW_SALT).encode())
    zz = zipfile.ZipFile(io.BytesIO(zbytes))
    meta = json.loads(zz.read(zz.namelist()[0], pwd=pw.encode()))
    return srv, "/" + prefix, rk, meta["files"]


def bundle_pass(srv: str, prefix: str, files: list, build_key: str = BUILDKEY_165,
                mk: bytes = MK_DEFAULT, salt: bytes = EPOCH_SALT):
    """Fetch + decrypt bundle_pass.zson -> (current, previous)."""
    bp = next(e for e in files if e["key"].endswith("/bundle_pass.zson"))
    data = http_get((srv + "/" + bp["key"]).replace("/files", "/files" + prefix, 1))
    pt = decrypt_v2(data, build_key, "bundle_pass", mk, salt)
    d = json.loads(pt)
    return d["current"], d.get("previous", "")


def download_entry(srv: str, prefix: str, entry: dict) -> bytes:
    url = (srv + "/" + entry["key"]).replace("/files", "/files" + prefix, 1)
    return http_get(url)


def decrypt_resource(data: bytes, key: str, secrets: list,
                     mk: bytes = MK_DEFAULT, salt: bytes = EPOCH_SALT):
    """Try plaintext -> v2(each secret) -> legacy. Return (bytes, kind) or (None, None)."""
    stem = gpart_of(key)
    kind = sniff_container(data)
    if kind is not None:
        return data, kind
    for sec in secrets:
        cand = decrypt_v2(data, sec, stem, mk, salt)
        kind = sniff_container(cand)
        if kind:
            return cand, kind
    cand = decrypt_legacy(data, stem)
    kind = sniff_container(cand)
    if kind:
        return cand, kind
    return None, None


def extract_zeson(pt: bytes) -> dict:
    """zeson/zson zip -> {name: inner_bytes} (auto ZipCrypto)."""
    zz = zipfile.ZipFile(io.BytesIO(pt))
    out = {}
    for nm in zz.namelist():
        info = zz.getinfo(nm)
        inner = zz.read(nm, pwd=ZIP_PASSWORD) if info.flag_bits & 1 else zz.read(nm)
        out[nm] = inner
    return out
