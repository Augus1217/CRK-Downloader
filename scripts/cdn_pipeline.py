#!/usr/bin/env python3
"""CRK CDN 完整自動管線（獨立腳本版；同樣邏輯也已整合進套件 ck_downloader.infrastructure.cdn）.

用法:
  python3 cdn_pipeline.py <resource_hash> [--out OUTDIR] [--buildKey BK] [--list FILE] [--only SUB] [--dry]

resource_hash 例: Ui8B1i7Wu3oJl2ro (7.11) / MVVauiRBMCNE0lJd (7.9)
BuildKey 預設 1.6.5/7.11 = bda24e6c-a05c-4687-b82e-39d886b5d3fa（per-VERSION，
可由 scripts/extract_buildkey 從新 APK 的 global-metadata.dat 推導）。

從 resource_hash → resourceKey.json → metadata.zip → 全量清單 → CDN 下載 → 全解密。

用法:
  python3 crk_pipeline.py <resource_hash> [--out OUTDIR] [--buildKey BK] [--dry]

resource_hash 例: Ui8B1i7Wu3oJl2ro (7.11) / MVVauiRBMCNE0lJd (7.9)
BuildKey 預設 7.11 = bda24e6c-a05c-4687-b82e-39d886b5d3fa（per-VERSION，新版要從新 APK 的
BuildState blob 重推，方法見記憶 crk-cdn-endpoint-hunt）。
"""
import hashlib, hmac, json, os, struct, sys, zipfile, io, urllib.request, argparse

SRV_TPL = 'https://static.devscdn.com/ck/resource/{rh}'
BUILDKEY_711 = 'bda24e6c-a05c-4687-b82e-39d886b5d3fa'
ZIP_PW_SALT = '1u05t4Obdu+YxKapFTxDZA=='
LEGACY_SALT = 'qjtjtqjrjd!'
ZIP_PW_INNER = '6yC&Gq#HgmbQ6JQ6CktijiJK9?SjM!K8!zrd$trDc4'  # zeson 內層 ZipCrypto

# MK/S：7.11 metadata 的 PID 常數（A^B 與 EpochSalt）——跨版同名同值，但新版應重新抽取
MK_DEFAULT = bytes.fromhex('73a345be1285412550fdffe182247cc4d95478f6fb6aa47556cc9c0ae5f32d58')
S_DEFAULT = bytes.fromhex('96289932d7d420186eef6f25362e40ca')

def http_get(url, timeout=60):
    req = urllib.request.Request(url, headers={'User-Agent': 'UnityWebRequest/1.0'})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()

# ---------- EncryptStream v2 (ChaCha20 + HKDF) ----------
def hkdf(ikm, salt, info, L=44):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, t, i = b'', b'', 1
    while len(out) < L:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t; i += 1
    return out[:L]

def _rotl(v, n): return ((v << n) | (v >> (32 - n))) & 0xffffffff
def _qr(x, a, b, c, d):
    x[a]=(x[a]+x[b])&0xffffffff; x[d]^=x[a]; x[d]=_rotl(x[d],16)
    x[c]=(x[c]+x[d])&0xffffffff; x[b]^=x[c]; x[b]=_rotl(x[b],12)
    x[a]=(x[a]+x[b])&0xffffffff; x[d]^=x[a]; x[d]=_rotl(x[d],8)
    x[c]=(x[c]+x[d])&0xffffffff; x[b]^=x[c]; x[b]=_rotl(x[b],7)

def cc20_ks(key, nonce, ctr, nbytes):
    base=[0x61707865,0x3320646e,0x79622d32,0x6b206574]+list(struct.unpack('<8I',key))
    nz=list(struct.unpack('<3I',nonce))
    out=b''
    block=0
    while len(out) < nbytes:
        st = base + [ (ctr+block)&0xffffffff ] + nz
        w=st[:]
        for _ in range(10):
            _qr(w,0,4,8,12); _qr(w,1,5,9,13); _qr(w,2,6,10,14); _qr(w,3,7,11,15)
            _qr(w,0,5,10,15); _qr(w,1,6,11,12); _qr(w,2,7,8,13); _qr(w,3,4,9,14)
        out += struct.pack('<16I', *[(x+y)&0xffffffff for x,y in zip(w,st)])
        block += 1
    return out[:nbytes]

def encv2_info(sec, name):
    pre = b'EncryptStream/v2'
    return (pre + f'/{sec}/Data/{name}'.encode()) if sec else (pre + f'/Data/{name}'.encode())

def dec_v2(data, sec, name, mk=MK_DEFAULT, s=S_DEFAULT):
    """EncryptStream v2 (2026-11-22 完整逆向):
    - continuous [0, 16384)（.bank=524288）＝ChaCha20(dataKey) 全段
    - 之後每 16384 頁一個 64B sparse 視窗：off = u32le(ChaCha20(schedKey, counter=page)[0:4]) % 16321，
      視窗內容用 dataKey 在絕對位置 counter 解密
    - dataKey   = HKDF(MK, S, 'EncryptStream/v2/{sec}/Data/{name}', 44)[:32+12]
    - schedKey  = HKDF(MK, S, 'EncryptStream/v2/{sec}/Schedule/{name}', 44)
    """
    dkm = hkdf(mk, s, (b'EncryptStream/v2' + (f'/{sec}'.encode() if sec else b'') + b'/Data/' + name.encode()), 44)
    skm = hkdf(mk, s, (b'EncryptStream/v2' + (f'/{sec}'.encode() if sec else b'') + b'/Schedule/' + name.encode()), 44)
    dkey, dnonce = dkm[:32], dkm[32:44]
    skey, snonce = skm[:32], skm[32:44]
    out = bytearray(data)
    N = len(out)
    cont = 524288 if name.endswith('.bank') else 16384
    cont = min(cont, N)
    if cont:
        ks = cc20_ks(dkey, dnonce, 0, cont)
        for i in range(cont):
            out[i] ^= ks[i]
    # sparse beyond continuous
    first_page = (cont + 16383) // 16384
    last_page = (N - 1) // 16384 if N > cont else 0
    for p in range(first_page, last_page + 1):
        r = struct.unpack_from('<I', cc20_ks(skey, snonce, p, 64), 0)[0]
        off = r % 16321
        ws = p * 16384 + off
        if ws >= N:
            continue
        ln = min(64, N - ws)
        blk = cc20_ks(dkey, dnonce, ws // 64, ((ws % 64) + ln + 63) // 64 * 64)
        blk = blk[ws % 64: ws % 64 + ln]
        for j in range(ln):
            out[ws + j] ^= blk[j]
    return bytes(out)

# ---------- EncryptStream legacy (SHA512 pad + sparse ROR) ----------
def _ror(b, n):
    n &= 7
    return ((b >> (8-n)) | (b << n)) & 0xFF if n else b

def dec_legacy(d, name):
    b = name.rsplit('/',1)[-1]
    name = b.rsplit('.',1)[0] if '.' in b else b
    K = hashlib.sha512((name + LEGACY_SALT).encode('utf8')).digest()
    pt = bytearray(d)
    n = min(len(pt), 0x4000)
    for p in range(n): pt[p] ^= K[p % 64]
    k = 0
    while True:
        p = 16400 + 1025*k
        if p >= len(pt): break
        pt[p] = _ror(pt[p] ^ K[(16+k) % 64], k % 8)
        k += 1
    return bytes(pt)

# ---------- helpers ----------
def sha1u(b): return hashlib.sha1(b).hexdigest().upper()

def sniff(pt):
    if pt[:8] == b'UnityFS\x00' or pt[:7] == b'UnityFS': return 'unityfs'
    if pt[:4] == b'PK\x03\x04': return 'zip'
    if pt[:4] in (b'RIFF', b'FSB5', b'OggS'): return pt[:4].decode().lower()
    if pt[:2] in (b'{"', b'[{'):
        try:
            json.loads(pt); return 'json'
        except Exception: return None
    return None

def download_entry(srv, prefix, entry, outdir):
    key = entry['key']
    # GetDownloadUrl = (srv + '/' + key).Replace('/files', '/files/' + prefix)
    # prefix 本身含前導 '/'：'/'+SHA1upper(RK+BK)
    url = (srv + '/' + key).replace('/files', '/files' + prefix, 1)
    data = http_get(url)
    return data, url

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('resource_hash')
    ap.add_argument('--out', default='cdndownload')
    ap.add_argument('--buildKey', default=BUILDKEY_711)
    ap.add_argument('--mk', default=None, help='64-hex MK (A^B)；預設 7.11 值')
    ap.add_argument('--s', default=None, help='32-hex EpochSalt')
    ap.add_argument('--only', default=None, help='只處理 key 含此子字串的條目')
    ap.add_argument('--list', default=None, help='JSON 檔：只處理此清單內的條目（{key,hash,size}）')
    ap.add_argument('--dry', action='store_true')
    args = ap.parse_args()

    mk = bytes.fromhex(args.mk) if args.mk else MK_DEFAULT
    s = bytes.fromhex(args.s) if args.s else S_DEFAULT
    srv = SRV_TPL.format(rh=args.resource_hash)
    os.makedirs(args.out, exist_ok=True)
    raw_out = os.path.join(args.out, 'raw'); os.makedirs(raw_out, exist_ok=True)
    dec_out = os.path.join(args.out, 'dec'); os.makedirs(dec_out, exist_ok=True)

    # 1) ResourceKey
    rk = json.loads(http_get(f'{srv}/resourceKey.json').decode())
    print(f'[1] ResourceKey = {rk}')

    # 2) metadata.zip
    prefix = '/' + sha1u((rk + args.buildKey).encode())
    meta_url = f'{srv}/index{prefix}/metadata.zip'
    print(f'[2] metadata.zip: {meta_url}')
    zbytes = http_get(meta_url)
    pw = sha1u((rk + ZIP_PW_SALT).encode())
    zz = zipfile.ZipFile(io.BytesIO(zbytes))
    meta = json.loads(zz.read(zz.namelist()[0], pwd=pw.encode()))
    files_all = meta['files']
    if args.list:
        allow = {e['key'] for e in json.load(open(args.list))}
        files = [e for e in files_all if e['key'] in allow]
        print(f'    --list filter: {len(files)} entries')
    else:
        files = files_all

    # 3) bundle_pass → current secret（bundle_pass 本身用 buildKey 當 secret）
    bp = next(e for e in files_all if e['key'].endswith('/bundle_pass.zson'))
    bp_data, _ = download_entry(srv, prefix, bp, raw_out)
    bp_pt = dec_v2(bp_data, args.buildKey, 'bundle_pass', mk, s)
    cur = json.loads(bp_pt)['current']
    prev = json.loads(bp_pt).get('previous', '')
    print(f'[3] bundle_pass current={cur!r} previous={prev!r}')
    open(os.path.join(args.out, 'bundle_pass.json'), 'w').write(json.dumps({'current': cur, 'previous': prev}))

    # 4) download + decrypt all
    secrets = [cur, prev, args.buildKey, '']
    stats = {'ok': 0, 'fail': 0}
    for i, e in enumerate(files):
        key = e['key']
        if args.only and args.only not in key:
            continue
        try:
            data, url = download_entry(srv, prefix, e, raw_out)
        except Exception as ex:
            print(f'  DL FAIL {key}: {ex}'); stats['fail'] += 1; continue
        # integrity: sha1(cipher) == hash
        if sha1u(data) != e['hash']:
            print(f'  HASH MISMATCH {key}')
        base = key.rsplit('/', 1)[-1]
        stem = base.rsplit('.', 1)[0] if '.' in base else base
        # 先試原始資料（部分 CDN 檔案不加密，如 *_video）
        pt = None
        kind = sniff(data)
        if kind is not None:
            pt = data
            print(f'  (plaintext) {key}')
        else:
            for sec in secrets:
                try:
                    cand = dec_v2(data, sec, stem, mk, s)
                except Exception:
                    continue
                kind = sniff(cand)
                if kind:
                    pt = cand; break
        if pt is None:
            cand = dec_legacy(data, stem)
            kind = sniff(cand)
            if kind: pt = cand
        if pt is None:
            open(os.path.join(raw_out, key.replace('/', '_')), 'wb').write(data)
            print(f'  DEC FAIL {key} (raw saved)'); stats['fail'] += 1
            continue
        # zeson zip → 解出內層 json
        if kind == 'zip' and (base.endswith('.zeson') or base.endswith('.zson')):
            try:
                z2 = zipfile.ZipFile(io.BytesIO(pt))
                for nm2 in z2.namelist():
                    info2 = z2.getinfo(nm2)
                    inner = z2.read(nm2, pwd=ZIP_PW_INNER.encode()) if info2.flag_bits & 1 else z2.read(nm2)
                    open(os.path.join(dec_out, nm2), 'wb').write(inner)
            except Exception as ex:
                print(f'  inner zip fail {key}: {ex}')
        else:
            open(os.path.join(dec_out, stem + ('.bundle' if kind in ('unityfs','riff','fsb5','ogg') else '')), 'wb').write(pt)
        stats['ok'] += 1
        if i % 200 == 0:
            print(f'  ...{i}/{len(files)} ok={stats["ok"]} fail={stats["fail"]}')
    print(f'[4] done: ok={stats["ok"]} fail={stats["fail"]}')

if __name__ == '__main__':
    main()
