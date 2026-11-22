# ck-downloader — CookieRun: Kingdom Asset Downloader/Extractor

CookieRun: Kingdom 的資產下載/提取工具（靈感與架構取自
[Blue-Archive-Asset-Downloader](https://github.com/ZM-Kimu/Blue-Archive-Asset-Downloader)）。

## 現況

| 階段 | 狀態 |
|---|---|
| **Phase 1 — extract**（純離線：XAPK → 解密 → 提取） | ✅ 可用 |
| **Phase 2 — index / search**（資產/cookie 索引） | ✅ 可用 |
| **Phase 3 — download**（DevPlay CDN 線上更新） | 🚧 未實作（需 DevPlay 登入流程） |

## 運作原理

CRK 的所有資產以 `EncryptStream`（自製串流加密）打包在 XAPK 內：

```
XAPK
└─ UnityDataAssetPack.apk
   ├─ assets/metadata.zeson              # 下載清單（雙層：Legacy 加密 ZIP + ZipCrypto 內層）
   └─ assets/android/<SHA1>.resource     # 2552 個加密資產（1.2 GB）
```

解密（`EncryptScheme.Legacy`，從 libil2cpp.so 逆向並經 CRC 數學驗證）：

```
key = SHA512(gpart + "qjtjtqjrjd!")          # gpart = 清單 key 的 basename 去副檔名
[0, 16384):       dec = enc ^ key[x % 64]
[16384, 16400):   gap（明文）
x ≡ 0 (mod 1025), x ≥ 16400:
                  dec = ROTL8(enc ^ key[x % 64], x % 8)     # ★稀疏點 = 位元組旋轉
其他:             明文
```

資產容器三類：`ZIP`（ZipCrypto，密碼已破）／`UnityFS` v8（UnityPy 解析）／`FMOD bank`。
`metadata.zeson` 清單中每筆 `{key, hash, size}`，本地檔名 = `hash`（SHA1）、`key` basename = gpart。
每個 bundle 的加密方式標記於 `assetbundle_index.json` 的 labels（`EncLegacy` / `EncNew` / `NotEncrypt`）。

## 安裝

```shell
pip install -e .
# 或
uv sync
```

需要 Python 3.10+。UnityPy 與 Pillow 會自動安裝。

## 使用

```shell
# 從 XAPK 提取全部（texture + sprite + text；1.2GB → 數 GB，約 1-3 小時）
ck-downloader extract --xapk CookieRun_+Kingdom_7.9.102_APKPure.xapk

# 只提取特定資源
ck-downloader extract -x game.xapk -rt sprite --search cookie0661 gacha

# 建立索引（資產 + cookie + labels + 依賴圖）
ck-downloader index --extract-dir Extracted

# 搜尋
ck-downloader search cookie0661 gacha --index-dir Extracted/index
```

### extract 參數

| 參數 | 說明 | 預設 |
|---|---|---|
| `--xapk` / `-x` | XAPK 路徑（必填） | |
| `--out` / `-o` | 輸出目錄 | `Extracted` |
| `--type` / `-rt` | Unity 資產類型：`texture sprite text audio mesh` | `texture sprite text` |
| `--search` / `-s` | 關鍵字過濾（任一符合） | 無 |
| `--limit` / `-l` | 只處理前 N 筆（測試用） | 無 |
| `--save-dec` | 另存解密後原始容器 | 關 |
| `--work` / `-w` | 內部 APK 解包工作目錄 | `<out>/_work` |

### 輸出結構

```
Extracted/
├── assetbundle_index.json    # 1726 bundle Infos（labels/dependencies/files）
├── assetlinker_index.json    # GUID → 資產名（1049 筆）
├── bundles/<gpart>/CAB-*/    # PNG 貼圖、Spine .skel/.atlas、TextAsset
├── zeml/                     # 各語系 strings.xml
├── fmod/                     # FMOD 音效 bank
├── _other/                   # 未解檔案（4 個，ChaCha20 scheme、伺服器金鑰）
└── extract_index.json        # 全部記錄 + 統計
```

## 已知限制

- 2,552 檔中 2,548 個已驗證解出（ZIP 全數 CRC32 命中、UnityFS 全數 UnityPy 解析）。
  剩 4 檔（`gacha_portrait_cookie0602s02/0661/0668`、`bundle_pass.zson`）為
  `EncNew`（ChaCha20 scheme），金鑰含伺服器下發的 secret，離線不可得。
- 線上更新下載（Phase 3）需 DevPlay 登入流程，尚未實作。

## 授權與用途

僅供教育研究與個人備份用途。遊戲資產版權歸 Devsisters 所有。

## 自動化同步（CI）

Devsisters **每次遊戲更新都會把完整 install-time asset pack 打進 XAPK**，而 APKPure 的
`?version=latest` 永遠指向最新版 → **免認證、免模擬器、跨版本失效免疫**。

```shell
# 一條指令完成：抓最新 XAPK → 解密 → 提取 → 索引 → 與上次 diff
ck-downloader sync --out CKMirror --type text

# 手動指定本地 XAPK
ck-downloader sync --out CKMirror -x /path/to/CookieRun_x.y.z_APKPure.xapk
```

GitHub Actions：見 `.github/workflows/sync.yml`（每日自動執行，index 有變更自動 commit）。

**更新偵測**：`sync` 對 `metadata.zeson` 的 2552 筆 {hash, size} 做指紋比對，
輸出 `+new / ~changed / -removed`，寫入 `state.json`。實測：7.9.102 → 最新版比對 = 0 差異（同版本）。

### CI 資源估算

| 模式 | 下載 | 提取時間 | 磁碟 |
|---|---|---|---|
| `--type text`（CI 預設） | 1.4 GB | ~2 分 | <1 GB |
| `--type texture sprite text`（本機） | 1.4 GB | ~17 分 | ~4 GB |

## 裝置快取 ingest（4GB CDN 內容的無破解方案）

CDN-only 的 ~2.8GB（Spine 動畫、語音、影片、大量美術——`NotIncludeAndroidBuild` 908 bundle）
**遊戲自己會下載到手機快取**。任何一台有裝 CRK 的 Android 手機（不需要 root）：

```shell
# 手機開 USB 偵錯 → 接電腦
adb pull /sdcard/Android/data/com.devsisters.ck ./pulled
ck-downloader ingest --pulled-dir ./pulled --out Extracted
```

- 快取裡的 `EncLegacy` 檔案會用 Legacy 公式自動解密
- `EncNew`（38 檔，ChaCha20 + 伺服器 secret）保留原樣並在報告中標記
- 遊戲會自動更新快取 → 之後重跑 `adb pull` + `ingest` 即為最新

## iOS IPA 路線（★ 最大覆蓋：單檔完整資產集）

iOS 沒有 Play 資產包 1-2GB 上限——App Store 上的 CRK = **3.9GB 單一 IPA = 完整資產集**
（含 Android 排除的 908 個 bundle 與 CDN-only 內容）。FairPlay 只加密執行檔，資料檔為明文。

```shell
# 一次性：建立 Apple ID（免費）→ 安裝 ipatool → 登入（2FA 一次）→ 免費「購買」
ipatool auth login --email you@example.com
ipatool purchase --bundle-identifier com.devsisters.ck

# 每次同步（可 CI）：
ipatool download --bundle-identifier com.devsisters.ck --output crk.ipa --non-interactive
ck-downloader ipa --ipa-file crk.ipa --out Extracted
```

iOS 版與 Android 用同一套 C# 加密 → 同一個 Legacy 公式直接解。

## 歷史版本批量封存（GitHub Actions）

App Store 保留 CRK 上架以來的**全部 205 個版本**（2021 → 現在）。
每個版本 = 當時遊戲內容的完整快照；收集多個版本 = 收回所有被替換掉的
banner、活動、限時角色與舊版語音。

```shell
# 任意歷史版本都能下載（version id 用 ipatool list-versions 查）
ipatool download --bundle-identifier com.devsisters.ck \
  --external-version-id 835650207 --output crk-835650207.ipa
```

### 四個時代格式（205 版全史解剖）

| 時期 | 版本範圍特徵 | 提取方式 |
|---|---|---|
| era-1 舊格式（2021 初） | `ck.app`、無 manifest、無加密 | UnityPy 直接解紋理 + FMOD bank 原樣保存 |
| era-2 zson 空殼（~2023 H1） | `Raw/metadata.zson`（無 Legacy 外層，內層密碼未破解）；bundle 以 SHA1 content-hash 定址 | manifest 解不開 → fallback；**`Data/data.unity3d`（50MB）與 `Raw/font` 是明文 UnityFS** → 紋理/TextAsset/字型全可解 |
| era-3 zeson 過渡 | `Raw/metadata.zeson`（Legacy 外層舊 salt ✓）+ 內層 ZipCrypto **換過密碼** | manifest 解不開 → fallback 同上（data.unity3d / font 也是明文） |
| era-4+ 新格式（現行管線） | Legacy + 已破解 ZipCrypto 密碼 | 與現行版同一套解密管線；以 **manifest key 名稱**做歷史去重（hash 每版重打包會全變） |

去重三層：`seeds/current_hashes.json`（現行版 hash）＋ `seeds/current_keys.json`
（現行版 key 名稱）＋ state 累積的 `seen_keys` 池 → 每個歷史新格式版只提取
「該時代獨有 key」的 bundle（實測每版 ~0~60 個，秒級裁決）；manifest 全量也封存為
`archive/manifests/v<id>.json`。下載類暫時錯誤（CDN artwork）自動重試最多 3 次。

```shell
# 任意歷史版本都能下載（version id 用 ipatool list-versions 查）
ipatool download --bundle-identifier com.devsisters.ck \
  --external-version-id 835650207 --output crk-835650207.ipa
```

腳本 `scripts/batch_download.py` 會自動判斷格式，並且**只提取該版本獨有的內容**
（跟「累積已見 hash/名稱集合」比對），不會重複封存。

### GitHub Actions 認證（檔案後端，無需鑰匙圈服務）

CI 上沒有 GNOME keyring 服務。ipatool 的鑰匙圈後端會依序嘗試
macOS Keychain → Secret Service → **FileBackend**；FileBackend = 純檔案
（JWE 加密），存放在 state 目錄 `~/.ipatool/`：

- `account` — Apple 帳號憑證（由 scripts/ 產生的 JWE，加密金鑰 = IPATOOL_KEYCHAIN_PASS）
- `kbsync-v1` — 下載用的 kbsync 憑證快取
- `cookies` — Apple session cookies

secrets：`IPATOOL_ACCOUNT`、`IPATOOL_KBSYNC`、`IPATOOL_COOKIES`（都是檔案的 base64）
與 `IPATOOL_KEYCHAIN_PASS`（JWE 解鎖密碼，給 `--keychain-passphrase` 用）。
（本機匯出时用同款 Go 函式庫 byteness/keyring v1.9.0 轉檔，與 ipatool 讀取格式 100% 相容。）

每次執行 = 下載 N 個版本（`workflow_dispatch` 的 `batch_size`）→ 提取該版獨有資產 →
commit 進 `archive/`。`download_state.json` 記錄進度，中斷可接續（error 也會記，可手動
刪條目讓某版重試）。

### 檔案說明

- `archive/v<id>/bundles|zip|fmod/` — 新格式版本的獨有資產
- `archive/v<id>/tex/`、`archive/v<id>/bank/` — 2021 舊格式版本的紋理與音效
- `archive/manifests/v<id>.json` — 每版完整 manifest（供日後分析）
- `download_state.json` — 處理進度
- `seeds/current_hashes.json` — 現行版全部 hash（去重種子）
- 超過 90MB 的檔案會切成 `.part000/.part001/...`（GitHub 單檔上限 100MB），
  還原方式：`cat 檔名.part* > 檔名`

> 注意：/tmp 常見是 RAM 磁碟（tmpfs），舊格式解 Unity 需 ~1.6GB 暫存；
> 本機跑請設 `WORK_DIR` 指到實體磁碟，例如 `WORK_DIR=~/ck-work`。


## CDN 下載（Phase 3，2026-11-22 全鏈打通 ✅）

不需要 DevPlay 登入、不需要模擬器——資源金鑰由 CDN 自己發布：

```python
from ck_downloader.infrastructure.cdn import (
    fetch_metadata, bundle_pass, download_entry, decrypt_resource, extract_zeson,
)
from ck_downloader.infrastructure.buildkey import extract_buildkey

# 1) BuildKey 可從新 APK 的 global-metadata.dat 自動推導（per-VERSION 常數）
bk = extract_buildkey(open("global-metadata.dat", "rb").read())

# 2) 全量清單（8,000+ 條）
srv, prefix, rk, files = fetch_metadata("Ui8B1i7Wu3oJl2ro", bk)
#    prefix = "/" + SHA1upper(RK + BuildKey)；zip 密碼 = SHA1upper(RK + PasswordSalt)

# 3) current secret（EncNew/v2 用）
current, previous = bundle_pass(srv, prefix, files, bk)

# 4) 下載＋解密任一條目
data = download_entry(srv, prefix, files[0])
pt, kind = decrypt_resource(data, files[0]["key"], [current, previous, bk, ""])
```

或用獨立腳本（全量下載＋解密，支援 `--list`／`--only` 過濾）：`scripts/cdn_pipeline.py`。

### 鏈條摘要（全部實測 200）

| 步驟 | 公式 |
|---|---|
| ResourceKey | `GET {srv}/resourceKey.json`（CDN 自發布，e.g. `patch-data-dc6cec-23bd7b-39c076`） |
| metadata.zip | `{srv}/index/{SHA1upper(RK+BuildKey)}/metadata.zip` |
| zip 密碼 | `SHA1upper(RK + "1u05t4Obdu+YxKapFTxDZA==")` |
| 下載 URL | `(srv + "/" + key).Replace("/files", "/files/" + prefix)` |
| bundle_pass | v2 解密，secret=**BuildKey**、name=`bundle_pass` |

### EncryptStream v2（ChaCha20 scheme）完整規格

- `dataKey = HKDF(MK, EpochSalt, "EncryptStream/v2/{secret}/Data/{gpart}", 44)`
- `schedKey = 同上但 /Schedule/`
- 連續區 `[0, 16384)`（`.bank`=512KB）＝data ChaCha20 全段
- 之後每 16384 頁一個 **64B 視窗**：`off = u32le(schedChacha(counter=page)[0:4]) % 16321`，
  視窗用 dataKey 在絕對位置解密；**頁外其餘 bytes＝明文**
- MK/EpochSalt 為跨版本常數（已寫死在 `crypto.py`）
