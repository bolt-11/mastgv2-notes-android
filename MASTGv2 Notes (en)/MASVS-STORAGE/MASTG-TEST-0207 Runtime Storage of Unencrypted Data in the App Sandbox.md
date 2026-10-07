# MASTG-TEST-0207 Runtime Storage of Unencrypted Data in the App Sandbox

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0207 |
| **Platform** | Android |
| **MASVS Category** | MASVS-STORAGE (MASVS-STORAGE-1: The app securely stores sensitive data) |
| **Weakness** | **MASWE-0001** — *Sensitive Data Stored Unencrypted in Private Storage* |
| **Test Type** | Dynamic, Filesystem |
| **Profile** | **L2 only** (not L1) |
| **Prerequisites** | `identify-sensitive-data` |
| **Knowledge** | MASTG-KNOW-0041 (Internal Storage) |
| **Best Practice** | MASTG-BEST-0050 (Store Data Encrypted in App Sandbox Directory) |
| **Related Techniques** | MASTG-TECH-0005 (Installing Apps), MASTG-TECH-0008 (Accessing App Data Directories) |
| **Related Demo** | MASTG-DEMO-0010 (File System Snapshots from Internal Storage) |
| **Sibling Tests** | MASTG-TEST-0287 (SharedPreferences — dynamic/hooks), MASTG-TEST-0304 (SQLite), MASTG-TEST-0305 (DataStore), MASTG-TEST-0306 (Room) — all MASWE-0001 |
| **Conceptual Counterpart** | MASTG-TEST-0200 (*Files Written to External Storage* — MASWE-0002) |
| **Related CWE** | CWE-312 (Cleartext Storage of Sensitive Information), CWE-311 (Missing Encryption of Sensitive Data), CWE-922 (Insecure Storage of Sensitive Information), CWE-200 (Exposure of Sensitive Information) |

---

## 1. Explanation

### 1.1 Testing Objective

The goal of this test is to **retrieve the files written to internal storage (the app sandbox) and then inspect their contents**, regardless of which API was used to write them.

Direct quote from the MASTG overview:

> *"The goal of this test is to retrieve the files written to the **internal storage** and inspect them **regardless of the APIs used to write them**. It uses a simple approach based on file retrieval from the device storage before and after the app is exercised to identify the files created during the app's execution and to check if they contain sensitive data."*

The methodology is **identical to MASTG-TEST-0200**, differing only in the target directory:

| | MASTG-TEST-0200 | MASTG-TEST-0207 *(this document)* |
|---|---|---|
| **Target** | External storage (`/sdcard/...`) | **Internal storage / app sandbox** (`/data/data/<pkg>/`) |
| **Weakness** | MASWE-0002 (*outside* private storage) | **MASWE-0001** (*inside* private storage) |
| **Profile** | L1, L2 | **L2 only** |
| **Root required?** | No | **Yes** (or a debuggable app) |
| Methodology | Before/after snapshot + diff | Before/after snapshot + diff |

Together, both tests cover the application's **entire local storage surface**.

### 1.2 The Key Question: If the Sandbox Already Protects the Data, Why Does This FAIL?

This is the most natural, and most important, question to answer before testing, because MASTG-KNOW-0041 itself states:

> *"Files saved to internal storage are **containerized by default and cannot be accessed by other apps** on the device. When the user uninstalls your app, these files are removed."*

So why is storing plaintext data there still flagged as a failure? Because the sandbox protects against **only one** class of attacker: other, non-compromised apps on the device. There are many other paths in:

| Access path | Condition | Notes |
|---|---|---|
| **Rooted device** | Root/exploit/custom ROM | The Linux UID sandbox no longer matters. A root user can always read `/data/data/*` |
| **Malware with privilege escalation** | Kernel/vendor exploit | Same as above |
| **Debuggable app** | `android:debuggable="true"` | `adb shell run-as <pkg>` grants full access to the sandbox **without root** |
| **`adb backup`** | `allowBackup="true"` | Extraction of sandbox data without root. Restricted on modern Android, but still relevant for older devices/target SDKs. Connects to MASTG-TEST-0216 |
| **Cloud/vendor backup** | Auto Backup, vendor backup (Samsung/Xiaomi) | Sandbox data synced off the device |
| **Chained vulnerabilities** | Path traversal, exported ContentProvider, arbitrary file read, `WebView` `file://`, deep link | A "minor" vulnerability turns into credential theft because the underlying data is plaintext |
| **Physical forensics / stolen device** | Physical access | FBE protects data *Before First Unlock*. Once a device has been unlocked (AFU), the key resides in memory and data can be extracted with commercial forensic tooling |
| **Shared device / work profile** | MDM, dual profiles | A device administrator may have broader access |
| **Bugs in the app itself** | Faulty logic | E.g., a sandbox file is copied to external storage or attached to a bug report |

The principle: **the sandbox is an access control, not confidentiality of data at rest.** Encryption is the next defense-in-depth layer that keeps data safe once the first layer falls.

**This is also why the profile is `L2`, not L1.** MASVS-L2 targets applications with higher security requirements (financial, health, government) whose threat model **includes** attackers with physical access or rooted devices. For L1 apps, plaintext data in the sandbox may be considered an accepted risk; for L2, it is not.

> Note the contrast: MASTG-TEST-0287 (SharedPreferences) is profiled for **both L1 and L2**, while TEST-0207 is **L2 only**. This means MASTG considers plaintext `SharedPreferences` a problem even at the baseline level (because it's so commonly used for tokens and easy to find), while a thorough sweep of the entire sandbox is an advanced-level activity.

### 1.3 Anatomy of the App Sandbox — What to Inspect

Per MASTG-TECH-0008, the internal data directory is located at `/data/data/<package-name>` or `/data/user/0/<package-name>` (both equivalent; `/data/user/0/` is the multi-user-aware form).

**Standard structure and its testing implications:**

| Directory | Function | What to look for |
|---|---|---|
| **`shared_prefs/`** | XML files from the `SharedPreferences` API | **Highest-priority target.** Often holds tokens, login flags, user IDs, settings. Plaintext XML — very easy to read |
| **`databases/`** | SQLite files created by the app at runtime | User data, cached API responses, chat history. **Don't forget the `-wal`, `-shm`, `-journal` files** (see §1.4) |
| **`files/`** | Regular files created by the app | Anything — tokens, documents, keys, encoded cache |
| **`cache/`** | Cached data; **WebView cache is here too** | Cached HTTP responses (may contain PII-bearing API bodies), images, thumbnails |
| **`code_cache/`** | Code cache; cleared by the system on app/platform upgrade | Optimized code |
| **`lib/`** | Native libraries (`.so`) per architecture (`armeabi-v7a`, `arm64-v8a`, `x86`, `x86_64`, etc.) | Usually not a target, but may contain sensitive strings |
| **`no_backup/`** | Files excluded from backup | Still needs content inspection |
| **`app_webview/`** | WebView data: `Cookies`, `Local Storage`, `Session Storage`, `IndexedDB` | **Frequently overlooked.** Session cookies and tokens from an SPA running inside a WebView |
| **`app_textures/`, `app_flutter/`, `app_*`** | Framework-specific directories | Flutter (`app_flutter/`), React Native, etc. |

MASTG-TECH-0008 gives an important warning:

> *"However, the app might store more data not only inside these folders but also in the **parent folder** (`/data/data/[package-name]`)."*

So don't just check the known subdirectories — **sweep the entire directory recursively**. This is the strength of the diffing approach: it is both API-agnostic **and** directory-agnostic.

### 1.4 The Classic Internal Storage Blind Spot: WAL, Journal, and Residual Data

This is the aspect that often makes this test uncover things that neither static analysis nor hooking would find:

**SQLite Write-Ahead Log (WAL) and journal files.** If the app uses SQLite (directly, via Room, or via a third-party library), write operations pass through additional files:

| File | Content |
|---|---|
| `<db>.db-wal` | Write-ahead log — contains **data pages that have not yet been checkpointed**, including rows already "deleted" from the app's perspective |
| `<db>.db-shm` | Shared memory index for the WAL |
| `<db>.db-journal` | Rollback journal (legacy journal mode) |

Consequence: **sensitive data can persist in `-wal` even after it has been deleted from the main table**, and even when the app claims to "clear data on logout." Always pull and inspect these files, not just the `.db` itself.

**Other residue worth checking:**
- **Temporary files** written then deleted — may not show up in a diff, but sometimes survive due to crashes
- **Self-made backup files** (`*.bak`, `*.old`, `*.tmp`)
- **WebView cache** that holds API response bodies
- **Crash dumps / ANR traces** the app writes to the sandbox

### 1.5 A New Evaluation Element: Encoding Is Not Encryption

This test's evaluation criteria contain an instruction **absent from MASTG-TEST-0200** that constitutes one of its most important additions:

> *"When evaluating the data, attempt to identify and decode data that has been encoded using methods such as **base64 encoding, hexadecimal representation, URL encoding, escape sequences, wide characters** and common data obfuscation methods such as **xoring**. Also consider identifying and decompressing compressed files such as **tar or zip**. **These methods obscure but do not protect sensitive data.**"*

That last sentence is the heart of this test's evaluation. Patterns commonly found in real apps:

| What was found | Is this encryption? | Verdict |
|---|---|---|
| `c2VjcjN0UGEkJFcwcmQK` (Base64) | ❌ Encoding | **FAIL** |
| `7365637233745061242457307264` (hex) | ❌ Representation | **FAIL** |
| `secr3tPa%24%24W0rd` (URL-encoded) | ❌ Encoding | **FAIL** |
| `sec...` (escape sequence) | ❌ Encoding | **FAIL** |
| UTF-16LE / wide char (`s\0e\0c\0...`) | ❌ Representation | **FAIL** |
| XOR with a static/hardcoded key | ❌ Obfuscation | **FAIL** |
| ROT13 / simple substitution | ❌ Obfuscation | **FAIL** |
| ZIP/GZIP/TAR (even with a weak ZIP password) | ❌ Compression | **FAIL** |
| AES-256-GCM with a key from the Android KeyStore | ✅ Authenticated encryption | PASS |

For this reason, the inspection flow must include **layered normalization** — not a plain `grep`. The implementation is in §3.4.

---

## 2. Tools Used for Testing

### 2.1 Core Tools (Required)

| Tool | MASTG ID | Function in This Test |
|---|---|---|
| **adb** | MASTG-TOOL-0004 | APK installation, file enumeration (`find`), file retrieval (`pull`), `run-as`. The primary tool |
| **Android device / emulator (rooted)** | MASTG-TOOL-0003 | **Root is required** to read `/data/data/<pkg>/` — unless the app is debuggable. An AVD emulator with a *Google APIs* image (not Google Play) is easily rooted via `adb root` |
| **Objection** | MASTG-TOOL-0038 | Used by MASTG-TECH-0008: `env` to list all app directory paths, `ls`/`cd` for exploration, `filesystem download <file>` / `--folder` to pull data. **Works without the app being debuggable** |
| **`sqlite3` / DB Browser for SQLite** | — | Opens discovered databases, including inspection of the WAL |
| **`file`, `strings`, `xxd`, `hexdump`** | — | File type identification and string extraction |

### 2.2 Supporting Tools

| Tool | Function |
|---|---|
| **`ent` / entropy analysis** | Distinguishes genuinely encrypted files (≈7.9+ bits/byte) from those merely encoded/obfuscated. **Crucial** for this test |
| **`base64`, `xxd -r -p`, `python3`** | Layered decoding per the MASTG evaluation instructions |
| **`binwalk`** | Detection & extraction of compressed/embedded files inside a blob |
| **`xortool`** | Recovers XOR keys — proves that "encryption" found is merely XOR |
| **`jq`, `protoc --decode_raw`** | Reading JSON and Protobuf payloads (Proto DataStore uses Protobuf) |
| **`grep` / `ripgrep`, TruffleHog, gitleaks** | Secret pattern scanning on pulled results |
| **jadx** | MASTG-TOOL-0018 — confirms code locations and verifies encryption claims (cipher mode, key origin) |
| **Frida** | MASTG-TOOL-0001 — for MASTG-TEST-0287 (hooking `SharedPreferences`) and for catching temporary files that are written then deleted |
| **Android Studio Device File Explorer** | Visual browsing (View → Tool Windows → Device File Explorer). On a non-rooted device it only works if the app is debuggable, and it is "confined" within the app's sandbox |
| **`adb backup` / `abe` (Android Backup Extractor)** | Alternative extraction path without root. Restricted on modern Android — see §2.3 |

### 2.3 Environment Prerequisites

**This is the biggest practical distinction from MASTG-TEST-0200: you need access into the sandbox.** There are three paths:

```bash
# Path A — ROOT (most reliable, recommended)
adb root
adb shell "find /data/data/com.example.target -type f"
adb pull /data/data/com.example.target ./sandbox_dump

# On an emulator, `adb root` usually succeeds immediately.
# On a rooted device with Magisk:
adb shell "su -c 'find /data/data/com.example.target -type f'"
# For pull, first copy to a location readable by adb:
adb shell "su -c 'tar czf /data/local/tmp/sandbox.tgz -C /data/data com.example.target'"
adb pull /data/local/tmp/sandbox.tgz

# Path B — run-as (no root, BUT the app must be debuggable)
adb shell run-as com.example.target ls -laR /data/data/com.example.target
adb shell run-as com.example.target tar czf - . > sandbox.tgz   # from inside the sandbox
# If the app is not debuggable -> "run-as: package not debuggable"
# Workaround: repackage the APK with android:debuggable="true" (apktool + apksigner)

# Path C — Objection (no root, NO NEED for the app to be debuggable)
objection -g com.example.target explore
#   env                                  -> list all directory paths
#   cd /data/user/0/com.example.target
#   ls
#   filesystem download shared_prefs ./sp --folder
```

> **Note on `adb backup`:** this used to be a popular rootless extraction path, but on modern Android it is heavily restricted — app data is no longer included by default unless the app marks itself as debuggable. Don't make this your primary path; use it as a supplement, and treat its success as a **finding in its own right** (connects to MASTG-TEST-0216 on data exclusion from backups).

**Other prerequisites:**

- **Satisfy the `identify-sensitive-data` prerequisite first.** You need to know what data is considered sensitive for this app before you can judge the contents of the files.
- **A clean device/emulator** (fresh wipe or snapshot) so the diff isn't polluted by leftovers from a previous session.
- **A unique canary value** for every input — the same key technique used in TEST-0200/0203. Examples: `MASTG_CANARY_PWD_7f3a`, `mastg.canary.7f3a@example.com`, `MASTG_TOKEN_A1B2C3`.
- **Test the relevant build.** Test a **release** build whenever possible; note if only a debug build is available (and remember debug builds are generally debuggable, so Path B is available).
- **Allow enough exercise time.** Some data is only written on logout, on cache flush, or when the app enters the background.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0005** (*Installing Apps*) to install the app.
2. Use **MASTG-TECH-0008** (*Accessing App Data Directories*) to take a **first copy** of the app's private data directory as a reference for offline analysis.
3. **Run and use the app**, exercising various workflows while entering sensitive data wherever possible. **Noting down the data you enter will help identify it later** using a search tool.
4. Use MASTG-TECH-0008 to take a **second copy** of the app's private data directory, then **diff it against the first copy** to identify all files created or modified during the test session.

> Note the difference in emphasis from TEST-0200: here MASTG explicitly recommends taking **full copies** (not just a file listing) for **offline analysis**, and states the diff should cover files **created OR MODIFIED**. This matters because files like `shared_prefs/*.xml` and `databases/*.db` typically already exist from the start and only **change in content** — so a "new files only" approach would miss them.

### 3.2 Practical Implementation — Timestamp Marker Method (MASTG-DEMO-0010)

**Step 0 — Preparation**

```bash
adb devices
adb install -g ./target-app.apk
PKG=com.example.target

# Verify access to the sandbox & map its directories (MASTG-TECH-0008)
adb root
adb shell "ls -la /data/user/0/$PKG/"
# or via objection:
#   objection -g $PKG explore  -> env
```

**Step 1 — Create a time marker (`run_before.sh`)**

```bash
#!/bin/bash

# SUMMARY: This script creates a dummy file to mark a timestamp that we can use later
# on to identify files created while the app was being exercised

adb shell "touch /data/local/tmp/test_start"
```

**Step 2 — Exercise the app**

Run through as many flows as possible with a canary value in every input:

- Registration, login, "remember me", logout, **re-login** (logout often triggers writes/deletions)
- Failed login, account lockout, password reset, OTP, 2FA/biometric setup
- Complete the profile: name, national ID, address, phone, date of birth, document/photo upload
- Add a payment method, make a transaction, download an invoice/e-statement
- Chat/messages, drafts, search history
- **Offline mode** (turn off networking) → triggers local caching; then back online
- Open **WebView**-based features (SSO login, terms & conditions, help pages) → populates `app_webview/`
- Repeated background/foreground, screen rotation, force-stop, reopen
- Leave idle for a few minutes (periodic cache flush)
- Enable every toggle in Settings, including debug options if present
- Trigger an error/crash if possible

**Step 3 — Diff and pull files (`run_after.sh`)**

```bash
#!/bin/bash

# SUMMARY: List all files created after the creation date of a file created in run_before

adb shell "find /data/user/0/org.owasp.mastestapp/ -type f -newer /data/local/tmp/test_start" > output.txt
adb shell "rm /data/local/tmp/test_start"
mkdir -p new_files
while read -r line; do
  adb pull "$line" ./new_files/
done < output.txt
```

> This demo script pulls all files into a single flat directory (`./new_files/`). For real apps with many identically-named files (e.g. multiple `index` files), these will overwrite each other. A version that preserves the directory structure is given in §3.4.

**Step 4 — Inspect file contents**

```bash
file ./new_files/*
grep -riE "MASTG_CANARY_PWD_7f3a|password|token|api[_-]?key" ./new_files/
```

### 3.3 Full Snapshot Method (More Faithful to the Official MASTG Steps)

The official MASTG steps call for **full copies** of the directory, taken twice, then diffed. This method follows that more closely and captures **modified files**, not just new ones — important for `shared_prefs` and `databases`.

```bash
PKG=com.example.target
D=/data/user/0/$PKG

# ---- SNAPSHOT 1 (before exercising the app) ----
adb shell "su -c 'tar czf /data/local/tmp/before.tgz -C /data/user/0 $PKG'"
adb pull /data/local/tmp/before.tgz ./
mkdir -p before && tar xzf before.tgz -C before

# (no-root alternative, app debuggable)
# adb shell "run-as $PKG tar czf - -C $D ." > before.tgz

# ---- EXERCISE THE APP ----

# ---- SNAPSHOT 2 (after exercising the app) ----
adb shell "su -c 'tar czf /data/local/tmp/after.tgz -C /data/user/0 $PKG'"
adb pull /data/local/tmp/after.tgz ./
mkdir -p after && tar xzf after.tgz -C after

# ---- DIFF: files that are NEW OR CHANGED ----
diff -rq before after
# Only in after/...            -> new file
# Files ... and ... differ     -> MODIFIED file (often missed by the -newer method)

# Content diff for text files (shared_prefs, json, xml)
diff -ru before/$PKG/shared_prefs after/$PKG/shared_prefs
```

Hash-based comparison for a clean list:

```bash
( cd before && find . -type f -exec sha256sum {} \; | sort ) > before.sha
( cd after  && find . -type f -exec sha256sum {} \; | sort ) > after.sha
comm -13 before.sha after.sha        # new or changed
```

### 3.4 Deep Inspection — Encoding Normalization (Mandatory per the Evaluation Criteria)

This implements the MASTG evaluation instruction from §1.5.

```bash
# ============ 1. Map the type of every file ============
find ./after -type f -exec file {} \;

# ============ 2. Search for canaries & secret patterns (case-insensitive, including binary) ============
grep -raiE "MASTG_CANARY_PWD_7f3a|mastg\.canary|MASTG_TOKEN_A1B2C3" ./after/
grep -raiE "password|passwd|pwd|token|bearer|authorization|api[_-]?key|secret|credential|session|jwt|eyJ[A-Za-z0-9_-]{10,}|BEGIN (RSA|EC|OPENSSH)? ?PRIVATE KEY" ./after/

# ============ 3. shared_prefs — highest-priority target ============
for f in ./after/*/shared_prefs/*.xml; do echo "--- $f"; cat "$f"; done

# ============ 4. SQLite databases — DON'T FORGET WAL/journal ============
for db in $(find ./after -name "*.db" -o -name "*.sqlite" -o -name "*.db3"); do
  echo "=== $db"
  sqlite3 "$db" ".tables"
  sqlite3 "$db" ".dump" | grep -iE "MASTG_CANARY|password|token|email"
done
# WAL & journal: may hold data already "deleted" from the table
for w in $(find ./after -name "*-wal" -o -name "*-journal" -o -name "*-shm"); do
  echo "=== $w"; strings -n 4 "$w" | grep -iE "MASTG_CANARY|password|token"
done

# ============ 5. WebView — frequently overlooked ============
find ./after -path "*app_webview*" -type f
sqlite3 ./after/*/app_webview/Default/Cookies ".dump" 2>/dev/null | head -40
find ./after -path "*Local Storage*" -o -path "*Session Storage*" | head

# ============ 6. ENCODING NORMALIZATION (explicit MASTG instruction) ============
cat > decode_scan.py <<'PY'
import base64, binascii, codecs, gzip, io, os, re, sys, urllib.parse, zlib, zipfile, tarfile

CANARIES = [b"MASTG_CANARY_PWD_7f3a", b"MASTG_TOKEN_A1B2C3", b"mastg.canary"]
PATTERNS = [rb"password", rb"passwd", rb"token", rb"api[_-]?key", rb"secret",
            rb"BEGIN (RSA |EC )?PRIVATE KEY", rb"eyJ[A-Za-z0-9_-]{10,}"]

def hits(data: bytes):
    out = []
    low = data.lower()
    for c in CANARIES:
        if c.lower() in low: out.append(("canary", c.decode()))
    for p in PATTERNS:
        if re.search(p, low): out.append(("pattern", p.decode(errors="ignore")))
    return out

def layers(data: bytes, depth=0):
    """Yield normalized variants of the data (recursive, depth-limited)."""
    if depth > 3 or not data:
        return
    yield ("raw", data)

    # Base64
    for m in re.findall(rb"[A-Za-z0-9+/=]{16,}", data):
        try:
            d = base64.b64decode(m + b"==", validate=False)
            if d and d != data:
                yield ("base64", d)
                yield from layers(d, depth + 1)
        except Exception: pass

    # Hexadecimal
    for m in re.findall(rb"(?:[0-9a-fA-F]{2}){8,}", data):
        try:
            d = binascii.unhexlify(m)
            if d: yield ("hex", d); yield from layers(d, depth + 1)
        except Exception: pass

    # URL encoding
    try:
        d = urllib.parse.unquote_to_bytes(data.decode("latin-1"))
        if d != data: yield ("urldecode", d)
    except Exception: pass

    # Escape sequences (\uXXXX, \xXX)
    try:
        d = codecs.decode(data.decode("latin-1"), "unicode_escape").encode("latin-1")
        if d != data: yield ("unicode_escape", d)
    except Exception: pass

    # Wide characters (UTF-16LE / BE)
    for enc in ("utf-16-le", "utf-16-be"):
        try:
            d = data.decode(enc).encode("utf-8")
            if d != data: yield (f"widechar:{enc}", d)
        except Exception: pass

    # Compression
    for name, fn in (("gzip", gzip.decompress), ("zlib", zlib.decompress)):
        try:
            d = fn(data)
            if d: yield (name, d); yield from layers(d, depth + 1)
        except Exception: pass

    # ZIP / TAR
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
        for n in z.namelist()[:50]:
            d = z.read(n)
            yield (f"zip:{n}", d); yield from layers(d, depth + 1)
    except Exception: pass
    try:
        t = tarfile.open(fileobj=io.BytesIO(data))
        for m in t.getmembers()[:50]:
            if m.isfile():
                d = t.extractfile(m).read()
                yield (f"tar:{m.name}", d); yield from layers(d, depth + 1)
    except Exception: pass

    # Single-byte XOR (most common obfuscation)
    for key in range(1, 256):
        d = bytes(b ^ key for b in data[:4096])
        if hits(d):
            yield (f"xor:0x{key:02x}", d)

for root, _, files in os.walk(sys.argv[1] if len(sys.argv) > 1 else "."):
    for fn in files:
        path = os.path.join(root, fn)
        try:
            raw = open(path, "rb").read()
        except Exception:
            continue
        for how, variant in layers(raw):
            h = hits(variant)
            if h and how != "raw":
                print(f"[!] {path}  via {how}  -> {h}")
            elif h:
                print(f"[!] {path}  PLAINTEXT      -> {h}")
PY
python3 decode_scan.py ./after

# ============ 7. Test whether a file is ACTUALLY ENCRYPTED (vs. merely encoded) ============
for f in $(find ./after -type f -size +64c); do
  E=$(ent "$f" 2>/dev/null | awk '/Entropy/ {print $3}')
  echo "$E  $f"
done | sort -rn | head -20
# Entropy ~7.9+ bits/byte  => consistent with encryption
# Entropy < 6.0            => plaintext / encoding / weak obfuscation

# ============ 8. If an "encrypted" file is found, verify in code (jadx) ============
jadx -d ./decompiled ./target-app.apk
grep -rnE "EncryptedFile|EncryptedSharedPreferences|MasterKey|CipherOutputStream|AndroidKeyStore|SQLCipher|Tink|AeadSerializer" ./decompiled/sources/
# Reject findings where: AES/ECB, DES/RC4, or a hardcoded key is used
grep -rnE "AES/ECB|\"DES\"|RC4|SecretKeySpec\(\"" ./decompiled/sources/
```

**A `run_after.sh` script that preserves directory structure** (an improvement over the demo script):

```bash
#!/bin/bash
PKG=${1:-org.owasp.mastestapp}
adb shell "find /data/user/0/$PKG/ -type f -newer /data/local/tmp/test_start" > output.txt
adb shell "rm /data/local/tmp/test_start"
mkdir -p new_files
while read -r remote; do
  [ -z "$remote" ] && continue
  rel="${remote#/data/user/0/$PKG/}"          # relative path
  mkdir -p "./new_files/$(dirname "$rel")"     # preserve structure
  adb pull "$remote" "./new_files/$rel" >/dev/null 2>&1 \
    || adb shell "su -c 'cat $remote'" > "./new_files/$rel"
done < output.txt
find ./new_files -type f | sed 's|^|  |'
```

### 3.5 Alternative Testing Methods (Multi-Tool)

The main obstacle for this test is **access into the sandbox** (§2.3). The alternative methods below offer different ways in, plus ways to capture data that never appears in a snapshot.

#### Method B — Objection *(no root, no app debuggable requirement)*

This is the best path when root isn't available — Objection works through Frida, so it needs neither `run-as` nor `adb root`.

```bash
objection -g com.example.target explore

# Inside the objection shell:
env                                                        # map the entire sandbox path layout
cd /data/user/0/com.example.target
ls

# Pull key directories
filesystem download shared_prefs ./sp --folder             # priority target #1
filesystem download databases    ./db --folder
filesystem download files        ./files --folder
filesystem download app_webview  ./webview --folder        # often overlooked

# Convenient shortcut: read all SharedPreferences directly
android hooking list classes | grep -i preference
android heap search instances android.app.SharedPreferencesImpl
```

Objection also has ready-made commands for SQLite:

```bash
sqlite connect /data/user/0/com.example.target/databases/app.db
.tables
SELECT * FROM users LIMIT 5;
```

#### Method C — Frida: Hooking Storage APIs *(captures data BEFORE it is written)*

Its decisive advantage: it observes the **plaintext value** going into storage APIs, even when the resulting file is encrypted or immediately deleted.

```javascript
// sandbox_writes.js
function bt(max = 10) {
    const E = Java.use("java.lang.Exception");
    const st = E.$new().getStackTrace();
    return Array.from({length: Math.min(max, st.length)}, (_, i) => "    " + st[i]).join("\n");
}

Java.perform(() => {
    // --- SharedPreferences: highest-priority target (see also MASTG-TEST-0287) ---
    const Ed = Java.use("android.content.SharedPreferences$Editor");
    ['putString', 'putInt', 'putLong', 'putBoolean', 'putFloat'].forEach(m => {
        try {
            Ed[m].overloads.forEach(ov => {
                ov.implementation = function (k, v) {
                    console.log(`\n[SP] ${m}("${k}", "${v}")`);
                    console.log(bt());
                    return ov.call(this, k, v);
                };
            });
        } catch (e) {}
    });

    // --- SQLite: values inserted into the database ---
    const DB = Java.use("android.database.sqlite.SQLiteDatabase");
    DB.insert.overload('java.lang.String', 'java.lang.String', 'android.content.ContentValues')
      .implementation = function (t, n, v) {
        console.log(`\n[SQL] insert into ${t}: ${v}`);
        console.log(bt());
        return this.insert(t, n, v);
    };
    DB.execSQL.overloads.forEach(ov => {
        ov.implementation = function (...a) {
            console.log(`\n[SQL] execSQL: ${a[0]}`);
            return ov.apply(this, a);
        };
    });

    // --- Internal storage file I/O ---
    const INT = ['/data/data/', '/data/user/'];
    const addr = Process.getModuleByName('libc.so').findExportByName('openat');
    if (addr) Interceptor.attach(addr, {
        onEnter(args) {
            const p = args[1].readCString();
            if (p && INT.some(e => p.indexOf(e) === 0)) {
                console.log(`\n[open] ${p}`);
                Java.perform(() => console.log(bt()));
            }
        }
    });

    // --- Peek at content being written ---
    const FOS = Java.use("java.io.FileOutputStream");
    FOS.write.overload('[B', 'int', 'int').implementation = function (b, off, len) {
        try {
            const prev = Java.use("java.lang.String").$new(b, off, Math.min(len, 200));
            console.log(`[write] ${len}B  preview: ${prev}`);
        } catch (e) {}
        return this.write(b, off, len);
    };
});
```

```bash
frida -U -f com.example.target -l sandbox_writes.js -o sandbox.log
grep -i "MASTG_CANARY" sandbox.log        # canary found even if the file is encrypted
```

> **This is also what distinguishes a "plaintext data on disk" finding from an "encrypted data on disk" finding.** If the canary appears in the `putString` hook but **does not** appear in the pulled file, that's evidence that the encryption is working. If it appears in both, it's plaintext.

#### Method D — `adb backup` / `bmgr` *(rootless sandbox extraction)*

An alternative way into the sandbox that needs neither root nor Frida.

```bash
# Option 1: bmgr local transport (works on non-debuggable apps)
adb shell bmgr enable true
adb shell bmgr transport com.android.localtransport/.LocalTransport
adb shell bmgr backupnow com.example.target
adb root && adb pull /data/data/com.android.localtransport/files/1/_full/com.example.target app.ab
tar xvf app.ab       # -> apps/<pkg>/{f,db,sp,r}/

# Option 2: adb backup (requires android:debuggable="true")
adb backup -apk -nosystem com.example.target
java -jar abe.jar unpack backup.ab backup.tar && tar xvf backup.tar
```

The resulting structure maps directly to sandbox directories: `f/` = `filesDir`, `db/` = `databases`, `sp/` = `shared_prefs`, `r/` = root. See MASTG-TEST-0216 for details.

> Note: files **excluded from backup** will not appear here — so this method can **miss** sensitive data. Use it as a supplement, not a replacement.

#### Method E — fsmon / strace *(monitoring without touching the app)*

```bash
# fsmon — monitors all filesystem activity in the sandbox
adb push fsmon-arm64 /data/local/tmp/fsmon && adb shell "chmod 755 /data/local/tmp/fsmon"
adb shell "su -c '/data/local/tmp/fsmon /data/data/com.example.target'" | tee fsmon.log

# strace — syscall-level, resistant to anti-Frida
PID=$(adb shell pidof -s com.example.target)
adb shell "su -c 'strace -f -e trace=openat,write,unlink,rename -p $PID'" 2>&1 \
  | grep "/data/data/com.example.target" | tee strace.log
```

Advantage: catches writes from **native code** and **separate processes** (`:remote` services) that Java hooks miss.

#### Method F — MobSF Dynamic Analyzer *(automated + SQLite dump)*

```bash
docker run -it --rm -p 8000:8000 -p 1337:1337 \
  opensecurity/mobile-security-framework-mobsf:latest
```

Upload the APK → **Start Dynamic Analysis**. The relevant report sections:

| Section | Content |
|---|---|
| **Dumped Files / Files Analysis** | The entire sandbox contents along with the files, ready to download |
| **SQLite Database** | Automatic table dumps from every `.db` discovered |
| **Shared Preferences** | Parsed `shared_prefs` XML content |
| **Logcat** | Connects to MASTG-TEST-0203 |

Advantage: one session produces a complete sandbox inventory without writing a script. Limitation: the automated exercise is shallow (cannot log in), so it's a **supplement** for an initial pass.

#### Method G — SQLite-specific inspection: WAL, journal, and freelist pages

This is the blind spot described in §1.4 and is not caught by any other method unless checked explicitly.

```bash
D=./after/com.example.target/databases

# 1. Make sure the WAL/journal were also pulled — "deleted" data can survive here
ls -la $D/*.db $D/*-wal $D/*-shm $D/*-journal 2>/dev/null

# 2. Raw strings in the WAL — reveals rows already deleted from the table
for w in $D/*-wal $D/*-journal; do
  [ -f "$w" ] && { echo "--- $w"; strings -n 4 "$w" | grep -iE "MASTG_CANARY|password|token|@.*\."; }
done

# 3. Freelist pages in the .db itself (residual data not yet VACUUM'd)
sqlite3 $D/app.db "PRAGMA freelist_count;"
strings -n 6 $D/app.db | grep -iE "MASTG_CANARY|password|token"

# 4. Full dump including the not-yet-checkpointed WAL
sqlite3 $D/app.db ".recover" > recovered.sql
grep -iE "MASTG_CANARY|password|token" recovered.sql

# 5. Dedicated tools for carving deleted SQLite records
#    undark / sqlite-deleted-records-parser
undark --file $D/app.db --freespace | grep -i "MASTG_CANARY"
```

> `.recover` (SQLite 3.29+) is far more powerful than `.dump` because it reconstructs data from corrupted/deleted pages. This is what often reveals post-logout data thought to have been erased.

#### Method H — Inspecting WebView storage *(the most frequently overlooked directory)*

```bash
W=./after/com.example.target/app_webview

# Session cookies — often contain tokens
sqlite3 "$W/Default/Cookies" "SELECT host_key, name, value, is_secure, is_httponly FROM cookies;"

# Local Storage & Session Storage (LevelDB)
find "$W" -path "*Local Storage*" -o -path "*Session Storage*"
strings -n 6 "$W/Default/Local Storage/leveldb/"*.log 2>/dev/null | grep -iE "token|MASTG_CANARY"

# IndexedDB
find "$W" -path "*IndexedDB*" -type f | head
```

#### Method I — Forensic tooling *(timeline & residual data)*

```bash
# ALEAPP — structured Android artifact parsing + timeline
python3 aleapp.py -t fs -i ./sandbox_dump -o ./aleapp_out

# Timeline with Sleuth Kit
fls -r -m / ./image.dd > bodyfile && mactime -b bodyfile -d > timeline.csv

# Bulk extractor — carving PII/credentials from binary blobs
bulk_extractor -o ./bulk_out -R ./sandbox_dump
grep -iE "MASTG_CANARY|password" ./bulk_out/*.txt
```

Useful for answering "**when** was this file written relative to logout?" and for carving data out of binary files that `strings` cannot read.

---

### 3.6 Method Comparison: When to Use Which

| Method | Tool | Root required? | App debuggable required? | Sees data before encryption? | Captures temp files? | When to use |
|---|---|---|---|---|---|---|
| **A** | `adb root` + `find`/`tar` (MASTG) | **Yes** | No | ❌ | ❌ | Official baseline — most complete when root is available |
| **A'** | `run-as` | No | **Yes** | ❌ | ❌ | Rootless alternative for debug builds |
| **B** | Objection | No | No | Partial | Partial | **Best rootless option** — also has `sqlite connect` |
| **C** | Frida hooking storage APIs | Yes/gadget | No | ✅ **(key advantage)** | ✅ | **Distinguishes plaintext vs. encrypted**; catches temp files |
| **D** | `bmgr` / `adb backup` + `abe` | Partial | Partial | ❌ | ❌ | Rootless; **but misses files excluded from backup** |
| **E** | fsmon / strace | Yes | No | ❌ | ✅ | Native code & `:remote` processes; resistant to anti-Frida |
| **F** | MobSF Dynamic | No | No | ❌ | ❌ | Broad initial pass + automatic SQLite/SharedPrefs dump |
| **G** | sqlite3 `.recover` / undark | — | — | — | — | **WAL/journal & deleted data** — blind spot §1.4 |
| **H** | sqlite3 on `app_webview` | — | — | — | — | **WebView cookies & Local Storage** — most commonly missed |
| **I** | ALEAPP / Sleuth Kit / bulk_extractor | Yes | — | ❌ | ❌ | Timeline, carving, post-logout analysis |

**Minimum recommended combination:** **A (full snapshot) → G (WAL/journal) → H (WebView)**.
A gives the basic inventory, G and H close the two blind spots that most often cause real findings to be missed. Add **C (Frida)** to distinguish plaintext data from truly encrypted data — this turns suspicion into proof. Use **B (Objection)** when root is unavailable.

---

### 3.7 Evaluation Criteria: Positive and Negative Cases

**Official MASTG rules:**

> **Observation:** *"The output should contain a list of files that were created in the app's private storage during execution."*
>
> **Evaluation:** *"The test case **fails** if you find **any sensitive data (keys, passwords, or any data inputted into the app)** in the extracted files."*
>
> *"When evaluating the data, attempt to identify and decode data that has been encoded using methods such as base64 encoding, hexadecimal representation, URL encoding, escape sequences, wide characters and common data obfuscation methods such as xoring. Also consider identifying and decompressing compressed files such as tar or zip. **These methods obscure but do not protect sensitive data.**"*

Note that the criteria are **stricter than MASTG-TEST-0200**. TEST-0200 requires the file to be *"not encrypted **and** leak sensitive data"*. Here: **"any sensitive data ... in the extracted files"** → FAIL. The phrase *"or any data inputted into the app"* also broadens the scope to all user input, not just credentials.

---

#### ❌ FAIL / ISSUE — The check is declared FAILED when:

| No | Condition | Example evidence |
|---|---|---|
| F1 | A file in the sandbox is found containing **plaintext credentials** | `/data/user/0/<pkg>/files/secret.txt` contains `secr3tPa$$W0rd` |
| F2 | **`shared_prefs/*.xml`** holds a plaintext token, password, or auth flag | `<string name="auth_token">eyJhbGciOi...</string>` — the most common target |
| F3 | An **unencrypted SQLite database** holds user data | `sqlite3 app.db ".dump"` shows the `users` table with `password`/`email` columns |
| F4 | Sensitive data is found in **`-wal` / `-journal`** even after being "deleted" from the table | `strings app.db-wal \| grep MASTG_CANARY` → a hit |
| F5 | The **canary value** you entered is found anywhere in the sandbox | `grep -r MASTG_CANARY_PWD_7f3a ./after/` → a hit |
| F6 | Sensitive data is merely **Base64-encoded** | `echo 'c2VjcjN0...' \| base64 -d` → plaintext. **Encoding is not encryption** |
| F7 | Sensitive data is **hex / URL-encoded / escape-sequenced / wide-char encoded** | Detected by `decode_scan.py` |
| F8 | Sensitive data is **XOR'd** with a static key | `xortool` recovers the key; or `decode_scan.py` finds a hit on an `xor:` variant |
| F9 | Sensitive data is inside a **compressed archive** (zip/tar/gzip) without real encryption | Detected after decompression |
| F10 | Encryption exists, but the **key is hardcoded** in the APK or also stored in the sandbox | jadx: `SecretKeySpec("hardcodedkey".getBytes(), "AES")`; or `key.bin` in the same directory |
| F11 | Encryption exists, but the **algorithm/mode is weak** | `AES/ECB`, DES/3DES/RC4, CBC without a MAC |
| F12 | **WebView cache** holds a PII-bearing API response body, or `Cookies` holds a session token | `app_webview/Default/Cookies` |
| F13 | **Log / crash dump** with sensitive data was written to the sandbox | `files/logs/debug.log` contains `Authorization: Bearer ...` |
| F14 | Sensitive data **still exists after logout** | Repeat the snapshot post-logout — token still in `shared_prefs` |
| F15 | Sensitive data can be extracted via **`adb backup`** (without root) | Raises severity; connects to MASTG-TEST-0216 |
| F16 | The app is **debuggable** in the release build, so `run-as` grants sandbox access without root | Combined finding: sandbox exposure + plaintext data |
| F17 | Use of `MODE_WORLD_READABLE` / `MODE_WORLD_WRITEABLE` | Deprecated & risky; nullifies sandbox protection |

**Example output indicating FAIL** (official MASTG-DEMO-0010 result):

Sample code (`MastgTest.kt`):

```kotlin
private fun mastgTestWriteIntFile() {
    val internalStorageDir = context.filesDir
    val fileName = File(internalStorageDir, "secret.txt")
    val fileContent = "secr3tPa\$\$W0rd\n"

    try {
        FileOutputStream(fileName).use { output ->
            output.write(fileContent.toByteArray())
            Log.d("WriteInternalStorage", "File written to internal storage successfully.")
        }
    } catch (e: IOException) {
        Log.e("WriteInternalStorage", "Error writing file to internal storage", e)
    }
}
```

`output.txt`:

```
/data/user/0/org.owasp.mastestapp/files/secret.txt
```

`./new_files/secret.txt`:

```
secr3tPa$$W0rd
```

MASTG adds a location note:

> *"The file was created in `/data/user/0/org.owasp.mastestapp/files/` which is equivalent to `/data/data/org.owasp.mastestapp/files/`."*

MASTG evaluation: *"This test **fails** because the file is not encrypted and contains sensitive data (a password). You can further confirm this by reverse engineering the app and inspecting the code."*

**Three observations from this demo:**

1. **The code is identical to MASTG-DEMO-0001** except for one line: `context.filesDir` (internal) instead of `context.getExternalFilesDir(null)` (external). This confirms that simply moving data to internal storage **alone** does not resolve MASWE-0001 — the data is still plaintext, only relocated from MASWE-0002 to MASWE-0001.
2. **`run_after.sh` uses `find /data/user/0/<pkg>/`**, which on a non-rooted device will fail with *permission denied*. This demo runs on an emulator (and MASTestApp is debuggable). For real apps, you need root, `run-as`, or Objection — see §2.3.
3. **Only one file is detected** in this demo. On a real app, the diff will produce dozens to hundreds of files (WebView cache, databases, shared_prefs), making triage and encoding normalization (§3.4) essential.

---

#### ✅ PASS — The check is declared PASSED when:

| No | Condition | Example evidence |
|---|---|---|
| P1 | **No sensitive data** is found in any sandbox file, even after layered encoding normalization | `decode_scan.py` produces no hits; canary is not found |
| P2 | New/modified files exist, but **their content is not sensitive** | Public asset caches, UI configuration, feature flags, non-sensitive logs |
| P3 | Sensitive data exists, but is **properly encrypted** — AEAD (AES-256-GCM / ChaCha20-Poly1305) with a key from the **Android KeyStore** | `file` → `data`; entropy ≈7.99; canary not found in any encoding variant; jadx shows `EncryptedFile`/`EncryptedSharedPreferences`/Tink with `MasterKey` |
| P4 | Sensitive `SharedPreferences` use **`EncryptedSharedPreferences`** or an equivalent mechanism | The XML holds an encrypted key and value, not plaintext |
| P5 | The database uses **SQLCipher** or equivalent encryption; `.db`, `-wal`, and `-journal` are all unreadable | `sqlite3 app.db ".tables"` → *file is not a database* |
| P6 | Session tokens are **stored in memory only**, never touching disk | The sandbox diff contains no token at all |
| P7 | Sensitive data is **correctly erased on logout** | A post-logout snapshot is clean |
| P8 | Keys never leave secure hardware | jadx: `KeyGenParameterSpec` + `"AndroidKeyStore"`, ideally with `setUserAuthenticationRequired` / StrongBox |

**Example output indicating PASS:**

```bash
$ diff -rq before after
Files before/com.example.app/shared_prefs/secure_prefs.xml and after/com.example.app/shared_prefs/secure_prefs.xml differ

$ cat after/com.example.app/shared_prefs/secure_prefs.xml
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="AY6FZ9k1pQ...">AaX2m9QvT7...==</string>
</map>
# -> BOTH key AND value are encrypted (EncryptedSharedPreferences pattern)

$ python3 decode_scan.py ./after
# (no hits)

$ grep -rai "MASTG_CANARY_PWD_7f3a" ./after/
# (no results)

$ ent after/com.example.app/files/vault.bin | grep Entropy
Entropy = 7.998211 bits per byte.

$ sqlite3 after/com.example.app/databases/app.db ".tables"
Error: file is not a database        # -> SQLCipher
```

Confirmed via jadx:

```kotlin
val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build()

val prefs = EncryptedSharedPreferences.create(
    context,
    "secure_prefs",
    masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
)
```

---

#### ⚠️ Important Notes on Evaluation

1. **This test's criteria are stricter than TEST-0200's.** Here, simply *"any sensitive data ... in the extracted files"* → FAIL. There is no "and not encrypted" clause as in TEST-0200 (although in practice, correctly implemented encryption means the data is no longer "found"). The phrase *"or any data inputted into the app"* also broadens the scope to all user input.

2. **Encoding normalization is mandatory — this is an explicit MASTG instruction.** A plain `grep` search will miss Base64, hex, URL encoding, escape sequences, wide chars, XOR, and compressed archives. Remember the key MASTG sentence: *"These methods obscure but do not protect sensitive data."* Use `decode_scan.py` (§3.4) or an equivalent.

3. **The `find -newer` method misses files MODIFIED without an mtime change, and more importantly: misses context.** The official MASTG steps call for **two full copies then a diff** precisely because `shared_prefs/*.xml` and `databases/*.db` usually already exist before the session starts and only change in content. Use the method in §3.3 for complete results; the timestamp method (§3.2) as a quick version.

4. **Don't forget the WAL/journal files.** Sensitive data can survive in `<db>-wal` even after it's deleted from the main table. This is a blind spot that neither static analysis nor hooking will catch.

5. **Don't forget `app_webview/`.** Session cookies and Local Storage from WebView often contain tokens, and this directory is routinely overlooked because it isn't part of the "standard" structure people memorize.

6. **Also check the parent directory.** MASTG-TECH-0008 warns that apps may store data directly in `/data/data/<pkg>/`, not just in known subdirectories.

7. **Watch out for false passes from fake encryption.** Always test with `strings`, layered decoding, and **entropy analysis**. Entropy below 6.0 bits/byte on a file claimed to be encrypted is a red flag. Then verify in code: cipher mode (reject ECB) and **key origin** (reject hardcoded).

8. **Empty output ≠ automatic PASS.** Causes of false passes:
   - The triggering flow was never exercised (data is often written on logout, background, or cache flush)
   - **Sandbox access failed** (no root, app not debuggable) so the snapshot is incomplete — this is **Inconclusive, not PASS**
   - A temporary file was written then immediately deleted → doesn't appear in the diff. Supplement with **MASTG-TEST-0287** (hooking `SharedPreferences`) and file I/O hooking
   - Data is written by a **separate process** (`:remote` service) in a different directory
   - The snapshot was taken before the app flushed data to disk → force-stop the app before the second snapshot so buffers are written

9. **Re-test after logout.** This is a high-value check not explicitly mentioned in the MASTG steps: take a third snapshot after logout. A lingering token means the session wasn't truly terminated (connects to MASWE-0024, *Sensitive Data Accessible After Session Termination*).

10. **Severity is modulated by several factors:**

    | Factor | Severity |
    |---|---|
    | Plaintext private key / cryptographic key in the sandbox | **Critical** |
    | Password, long-lived session token, plaintext refresh token | **High** |
    | Plaintext financial/health data | **High** |
    | Plaintext PII (national ID, address, phone) | **Medium–High** (+ privacy dimension) |
    | Data can be extracted **without root** (`adb backup` succeeds, or the app is debuggable in release) | **Significantly raised** — the attacker model is much broader |
    | "Encryption" turns out to be mere encoding/XOR | **Raised** — creates false confidence |
    | Hardcoded key in the APK | **Raised** |
    | Sensitive data survives after logout | Raised |
    | Data is only in `-wal` (residue from already-deleted data) | Medium — still a finding |
    | **L1**-profile app whose threat model doesn't include root/physical access | Lowered — may be reported as *informational*; remember this test itself is L2-profile |
    | Non-sensitive data | **Not a finding** |

11. **Document complete evidence per finding:** absolute file path, file type (`file`), content (partially redacted but sufficient to prove the finding), **the decode method used to reveal it** (e.g., "Base64 → gzip → plaintext"), entropy value, the access path used (root / `run-as` / Objection), whether it can be extracted without root, post-logout status, reproduction steps with a canary value, and code confirmation from jadx. Also note limitations (e.g., unable to access the sandbox on a given host, `:remote` process not checked).

---

## 4. Recommendations

### 4.1 Core Principles (in priority order)

**Priority 1 — Don't store what doesn't need to be stored.** The strongest remediation is eliminating the data itself.

- **Session tokens should ideally live in memory only.** Use short-lived access tokens held in a variable (not disk), with a refresh token protected by the KeyStore.
- Don't cache API responses that carry PII; if caching is necessary, store only non-sensitive fields.
- **Delete sensitive data on logout** — including `shared_prefs`, databases, WebView cache, and run `VACUUM` on SQLite so WAL residue disappears.
- Don't write verbose logs or crash dumps containing PII to the sandbox (see MASTG-TEST-0203).

**Priority 2 — Use the Android KeyStore for all cryptographic material.** Keys never leave secure hardware, so they cannot be extracted from the filesystem.

```kotlin
val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
keyGen.init(
    KeyGenParameterSpec.Builder(
        "vault_key",
        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
    )
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setRandomizedEncryptionRequired(true)
        .setUserAuthenticationRequired(true)        // for the most sensitive data
        .setIsStrongBoxBacked(true)                 // if the hardware supports it
        .build()
)
keyGen.generateKey()
```

**Priority 3 — Encrypt sensitive data that genuinely must be persisted (MASTG-BEST-0050).**

MASTG-BEST-0050 states: *"Store sensitive data in `SharedPreferences` only after encrypting it. Standard `SharedPreferences` stores values in XML files inside the app's private data directory, so values such as credentials, authentication tokens, private keys, or personally identifiable information (PII) should not be stored in cleartext."*

Requirements for an acceptable mechanism per BEST-0050: *"use authenticated encryption, protect encryption keys with the Android Keystore or another appropriate key management system, and avoid custom cryptography."*

| Data type | Mechanism |
|---|---|
| Key-value preferences | `EncryptedSharedPreferences` — **or** manual AES-GCM encryption with a KeyStore key (see deprecation note below) |
| Files | `EncryptedFile` (Jetpack Security) or `CipherOutputStream` with AES-256-GCM + a KeyStore key |
| SQLite / Room database | **SQLCipher** (`net.zetetic:sqlcipher-android`), with a passphrase from the KeyStore |
| DataStore | **`androidx.datastore:datastore-tink`** + `AeadSerializer` |
| Keys & secrets | **Android KeyStore** (never write to a file at all) |

> **⚠️ Important deprecation note from MASTG-BEST-0050:**
>
> *"`EncryptedSharedPreferences` is part of the Jetpack Security Crypto library. All APIs in that library were **deprecated** in version `1.1.0`, and Android states that there will be **no subsequent releases**. It may still be a practical mitigation for existing apps that must keep using `SharedPreferences`, but it should not be treated as a long term storage strategy. Monitor Android's cryptography and DataStore guidance, and plan a migration to a supported encryption approach when available."*
>
> So: `EncryptedSharedPreferences` **remains a valid mitigation** and still makes this test PASS, but it is not a long-term strategy. For new apps, plan directly for a supported approach.

**For DataStore** — BEST-0050 gives clear direction: Android recommends `DataStore` as the modern replacement for `SharedPreferences`, **but `DataStore` does not encrypt data by default**. When migrating sensitive data to `DataStore`, use an encryption layer. AndroidX introduced the **`androidx.datastore:datastore-tink`** artifact in version `1.3.0-alpha07`, which provides encryption via the **Tink** library and **`AeadSerializer`** — a wrapper around the DataStore serializer that performs authenticated encryption/decryption.

```kotlin
// Example of the modern approach: DataStore + Tink AeadSerializer
// (see the DataStore 1.3.0-alpha07 release notes for a full example)
val dataStore = DataStoreFactory.create(
    serializer = AeadSerializer(
        delegate = MySettingsSerializer,
        aead = aeadFromAndroidKeystore      // key managed by the Android KeyStore
    ),
    produceFile = { context.dataStoreFile("settings.pb") }
)
```

```kotlin
// Example of SQLCipher for Room
val passphrase: ByteArray = getPassphraseFromKeyStore()   // NOT hardcoded
val factory = SupportOpenHelperFactory(passphrase)
val db = Room.databaseBuilder(context, AppDatabase::class.java, "app.db")
    .openHelperFactory(factory)
    .build()
```

**Cryptographic requirements considered adequate:**
- **AES-256-GCM** or ChaCha20-Poly1305 (authenticated encryption). Reject ECB, DES/3DES/RC4, CBC without a MAC.
- A random IV/nonce per operation, never reused.
- Keys **generated and stored in the Android KeyStore** — not hardcoded, not derived from static values (IMEI, package name, timestamp — see MASTG-TEST-0205), not written to the sandbox.
- If the key is derived from a user password: a strong KDF (Argon2id / scrypt / high-iteration PBKDF2) with a random salt from `SecureRandom`.
- **Never use custom-built cryptography** (BEST-0050: *"avoid custom cryptography"*).

**Priority 4 — Never use encoding/obfuscation as a substitute for encryption.** This is a direct consequence of the MASTG evaluation criteria. Base64, hex, URL encoding, XOR, and ROT13 **provide no protection whatsoever** — they only add one trivial step for an attacker while giving the development team a false sense of security.

**Priority 5 — Limit sandbox data extraction paths.**

```xml
<application
    android:allowBackup="false"
    android:debuggable="false"            <!-- make sure it is NOT true in release -->
    android:dataExtractionRules="@xml/data_extraction_rules"
    android:fullBackupContent="@xml/backup_rules">
```

- **`android:debuggable="false"`** in the release build — if `true`, `run-as` grants full sandbox access **without root**. Verify on the release APK, not just in `build.gradle`.
- **Exclude sensitive data from backup** via `dataExtractionRules` (Android 12+) / `fullBackupContent`, or `allowBackup="false"` (see MASTG-TEST-0216).
- Use the **`no_backup/`** directory (`context.noBackupFilesDir`) for files that must never be backed up.
- Don't use `MODE_WORLD_READABLE` / `MODE_WORLD_WRITEABLE` (deprecated since API 17, throws a `SecurityException` since API 24). To share data with other apps, use a **ContentProvider** or **FileProvider** — per the Android Security Guidelines cited by MASTG-KNOW-0041.

**Priority 6 — Properly clean up residual data.**

```kotlin
// On logout: delete all sensitive storage
context.getSharedPreferences("auth", MODE_PRIVATE).edit().clear().commit()
context.deleteDatabase("app.db")
File(context.filesDir, "cache_token.bin").delete()
WebStorage.getInstance().deleteAllData()
CookieManager.getInstance().removeAllCookies(null)
context.cacheDir.deleteRecursively()

// SQLite: VACUUM so WAL/freelist residue is truly gone
db.query("PRAGMA wal_checkpoint(TRUNCATE)")
db.query("VACUUM")
```

Also consider `PRAGMA secure_delete = ON` for databases holding sensitive data.

**Priority 7 — Additional defense-in-depth measures.**
- **Biometric/credential gating** for the most sensitive keys (`setUserAuthenticationRequired(true)`), so data cannot be decrypted even if the file is extracted.
- **StrongBox** where the hardware supports it.
- Consider MASVS-RESILIENCE controls (root detection, integrity checks) as an additional layer — **not a substitute for encryption**.
- Audit **third-party libraries**: analytics SDKs, crash reporters, image loaders, and WebView often write cache to the sandbox without the developer's knowledge. This test frequently finds files from SDKs, not from the app's own code.
- **Integrate into CI/CD**: run the snapshot+diff+decode script on an emulator in the pipeline alongside UI tests, and fail the build if a canary value appears in the sandbox.

### 4.2 Remediation Checklist

- [ ] All files from the sandbox diff have been reviewed, including after **layered encoding normalization** (Base64/hex/URL/escape/wide char/XOR/compression)
- [ ] No plaintext credentials, tokens, keys, or PII in `files/`, `cache/`, `code_cache/`, `no_backup/`, or the parent directory
- [ ] `shared_prefs/*.xml` contains no plaintext sensitive data
- [ ] SQLite/Room databases are encrypted (SQLCipher or equivalent); **`.db`, `-wal`, `-shm`, `-journal` are all unreadable**
- [ ] `DataStore` holding sensitive data uses an encryption layer (`datastore-tink` + `AeadSerializer`)
- [ ] `app_webview/` (Cookies, Local Storage, Session Storage) contains no persistent tokens/PII
- [ ] No encoding/obfuscation (Base64/hex/XOR/ROT13) is used as a substitute for encryption
- [ ] Encryption uses AEAD (AES-256-GCM / ChaCha20-Poly1305); no ECB/DES/RC4/CBC-without-MAC
- [ ] Keys are generated & stored in the **Android KeyStore**; not hardcoded, not derived from static values, not written to the sandbox
- [ ] No custom-built cryptography
- [ ] Session tokens are memory-only where possible; refresh tokens are protected by the KeyStore
- [ ] Sensitive data is **deleted on logout**, including WebView storage & cookies; `VACUUM`/`wal_checkpoint` is run on SQLite
- [ ] Verbose logs & crash dumps with PII are not written to the sandbox
- [ ] `android:debuggable="false"` verified on the **release APK**
- [ ] Sensitive data is excluded from backup (`dataExtractionRules`/`fullBackupContent`/`allowBackup="false"`); `no_backup/` is used where relevant
- [ ] No `MODE_WORLD_READABLE` / `MODE_WORLD_WRITEABLE`; data sharing uses a ContentProvider/FileProvider
- [ ] `setUserAuthenticationRequired(true)` and StrongBox are considered for the most sensitive data
- [ ] Third-party libraries are audited for writes to the sandbox
- [ ] Separate processes (`:remote` service) and framework-specific directories (`app_flutter/`, etc.) are also checked
- [ ] This test is integrated into CI/CD with canary value checks
- [ ] **Re-verification:** re-run MASTG-TEST-0207 (full snapshot + decode scan) → no sensitive data found
- [ ] **Post-logout verification:** a third snapshot after logout → clean
- [ ] **Cross-verification:** run MASTG-TEST-0287 (`SharedPreferences` hooking), MASTG-TEST-0200 (external storage), and MASTG-TEST-0216 (backup)

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0207: Runtime Storage of Unencrypted Data in the App Sandbox](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0207/)
- [MASTG-TEST-0287: Runtime Storage of Unencrypted Data via the SharedPreferences API](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0287/)
- [MASTG-TEST-0200: Files Written to External Storage](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0200/)
- [MASTG-TEST-0216: Data Exclusion from Backups](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0216/)
- [MASTG-TEST-0001: Testing Local Storage for Sensitive Data](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0001/)
- [MASWE-0001: Sensitive Data Stored Unencrypted in Private Storage](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0001/)
- [MASWE-0024: Sensitive Data Accessible After Session Termination](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0024/)
- [MASTG-DEMO-0010: File System Snapshots from Internal Storage](https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0010/MASTG-DEMO-0010/)
- [MASTG-DEMO-0059: Using SharedPreferences to Write Sensitive Data Unencrypted to the App Sandbox](https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0059/MASTG-DEMO-0059/)
- [MASTG-DEMO-0060: App Writing Sensitive Data to Sandbox using EncryptedSharedPreferences](https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0060/MASTG-DEMO-0060/)
- [MASTG-KNOW-0041: Internal Storage](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0041/)
- [MASTG-BEST-0050: Store Data Encrypted in App Sandbox Directory](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0050/)
- [MASTG-TECH-0008: Accessing App Data Directories](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0008/)
- [MASTG-TECH-0005: Installing Apps](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0005/)
- [MASTG-TECH-0002: Host-Device Data Transfer](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0002/)
- [MASTG-TOOL-0004: adb](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0004/)
- [MASTG-TOOL-0038: Objection](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0038/)
- [MASTG — Testing Data Storage chapter](https://mas.owasp.org/MASTG/0x05d-Testing-Data-Storage/)
- [MASVS-STORAGE: Storage](https://mas.owasp.org/MASVS/05-MASVS-STORAGE/)
- [OWASP Mobile Top 10 2024 — M9: Insecure Data Storage](https://owasp.org/www-project-mobile-top-10/2023-risks/m9-insecure-data-storage)

### 5.2 Official Android / Google Documentation

- [Data and file storage overview](https://developer.android.com/training/data-storage)
- [Access app-specific files (internal storage)](https://developer.android.com/training/data-storage/app-specific)
- [Security tips — Internal storage](https://developer.android.com/privacy-and-security/security-tips#internal-storage)
- [Security tips — Content providers](https://developer.android.com/privacy-and-security/security-tips#content-providers)
- [App security best practices — Store data in internal storage based on use case](https://developer.android.com/privacy-and-security/security-best-practices#internal-storage)
- [Cryptography best practices](https://developer.android.com/privacy-and-security/cryptography)
- [Jetpack Security Crypto deprecation notice](https://developer.android.com/privacy-and-security/cryptography#security-crypto-jetpack-deprecated)
- [`EncryptedSharedPreferences` — API reference](https://developer.android.com/reference/androidx/security/crypto/EncryptedSharedPreferences)
- [`EncryptedFile` — API reference](https://developer.android.com/reference/androidx/security/crypto/EncryptedFile)
- [`MasterKey` — API reference](https://developer.android.com/reference/androidx/security/crypto/MasterKey)
- [DataStore — Jetpack library](https://developer.android.com/topic/libraries/architecture/datastore)
- [DataStore release notes — `datastore-tink` 1.3.0-alpha07](https://developer.android.com/jetpack/androidx/releases/datastore#1.3.0-alpha07)
- [`AeadSerializer` — API reference](https://developer.android.com/reference/kotlin/androidx/datastore/tink/AeadSerializer)
- [Android Keystore system](https://developer.android.com/privacy-and-security/keystore)
- [`KeyGenParameterSpec` — API reference](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec)
- [`Context.getFilesDir()` / `getNoBackupFilesDir()`](https://developer.android.com/reference/android/content/Context#getNoBackupFilesDir())
- [SharedPreferences APIs](https://developer.android.com/training/data-storage/shared-preferences)
- [Room persistence library](https://developer.android.com/training/data-storage/room)
- [Back up user data with Auto Backup](https://developer.android.com/identity/data/autobackup)
- [File-Based Encryption (AOSP)](https://source.android.com/docs/security/features/encryption/file-based)
- [Application sandbox (AOSP)](https://source.android.com/docs/security/app-sandbox)
- [FileProvider](https://developer.android.com/reference/androidx/core/content/FileProvider)
- [Google Tink — cryptographic library](https://developers.google.com/tink)
- [SQLCipher for Android (Zetetic)](https://www.zetetic.net/sqlcipher/sqlcipher-for-android/)
- [SQLite — Write-Ahead Logging](https://www.sqlite.org/wal.html)
- [SQLite — `PRAGMA secure_delete`](https://www.sqlite.org/pragma.html#pragma_secure_delete)

### 5.3 Standards, Taxonomies, and Other Guidelines

- [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
- [CWE-311: Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html)
- [CWE-922: Insecure Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/922.html)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [CWE-732: Incorrect Permission Assignment for Critical Resource](https://cwe.mitre.org/data/definitions/732.html)
- [SEI CERT Android — DRD10: Do not release apps that are debuggable](https://wiki.sei.cmu.edu/confluence/display/android/DRD10-J.+Do+not+release+apps+that+are+debuggable)
- [NIST SP 800-163 Rev.1 — Vetting the Security of Mobile Applications](https://csrc.nist.gov/publications/detail/sp/800-163/rev-1/final)
- [NIST SP 800-124 Rev.2 — Guidelines for Managing the Security of Mobile Devices](https://csrc.nist.gov/publications/detail/sp/800-124/rev-2/final)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [CodeQL — Cleartext storage of sensitive information in the Android filesystem](https://codeql.github.com/codeql-query-help/java/java-android-cleartext-storage-filesystem/)
- [MITRE ATT&CK Mobile — T1409: Stored Application Data](https://attack.mitre.org/techniques/T1409/)
- [MITRE ATT&CK Mobile — T1533: Data from Local System](https://attack.mitre.org/techniques/T1533/)

### 5.4 Security Research & Technical Articles

- [Security Café — Mobile Pentesting 101: The Death of ADB Backup: Modern Data Extraction](https://securitycafe.ro/2026/02/02/mobile-pentesting-101-the-death-of-adb-backup-modern-data-extraction-in-2026/)
- [Pen Test Partners — How to subvert Android backups to export sandboxed app files](https://www.pentestpartners.com/security-blog/how-to-subvert-android-backups-to-export-sandboxed-app-files/)
- [ProAndroidDev — How to Extract Sandbox data of an Android App?](https://proandroiddev.com/how-to-extract-sandbox-data-of-an-android-app-d9d80c535a19)
- [Oxygen Forensics — Sandboxing in Android: implications for extraction of data via ADB](https://www.oxygenforensics.com/resources/android-sandboxing/)
- [Hack The Dome — Data Storage Security & Local Forensics in Android](https://hackthedome.com/module-15-data-storage-security-local-forensics-in-android/)
- [Check Point Research — Man-in-the-Disk (for contrast with external storage)](https://research.checkpoint.com/2018/androids-man-in-the-disk/)
- [HackTricks — Android Applications Pentesting](https://book.hacktricks.wiki/en/mobile-pentesting/android-app-pentesting/index.html)

### 5.5 Tool Documentation

- [adb — Android Debug Bridge](https://developer.android.com/tools/adb)
- [Objection — runtime mobile exploration](https://github.com/sensepost/objection)
- [Frida — Documentation Home](https://frida.re/docs/home/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [apktool — Reverse engineering Android APK files](https://apktool.org/)
- [Android Backup Extractor (abe)](https://github.com/nelenkov/android-backup-extractor)
- [sqlite3 CLI](https://www.sqlite.org/cli.html)
- [DB Browser for SQLite](https://sqlitebrowser.org/)
- [ent — Pseudorandom number sequence test (entropy)](https://www.fourmilab.ch/random/)
- [binwalk — firmware analysis tool](https://github.com/ReFirmLabs/binwalk)
- [xortool — XOR cipher analysis](https://github.com/hellman/xortool)
- [TruffleHog — secret scanning](https://github.com/trufflesecurity/trufflehog)

---

*This document was compiled based on the OWASP MASTG (latest release as of September 2026), official Android Developers documentation, CWE/NIST/SEI CERT standards, and third-party security and forensic research.*
