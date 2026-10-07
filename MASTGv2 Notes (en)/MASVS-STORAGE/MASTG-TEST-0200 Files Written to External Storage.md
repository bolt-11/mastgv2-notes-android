# MASTG-TEST-0200 Files Written to External Storage

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0200 |
| **Platform** | Android |
| **MASVS Category** | MASVS-STORAGE (MASVS-STORAGE-1: The app securely stores sensitive data) |
| **Weakness** | MASWE-0002 — *Sensitive Data Stored Unencrypted Outside of Private Storage* |
| **Test Type** | Dynamic, Filesystem, Manual |
| **Profile** | L1, L2 |
| **Related CWE** | CWE-312 (Cleartext Storage of Sensitive Information), CWE-921 (Storage of Sensitive Data in a Mechanism without Access Control), CWE-200 (Exposure of Sensitive Information) |

---

## 1. Explanation

### 1.1 Testing Objective

The objective of this test is to **retrieve every file the app writes to external storage and inspect its contents**, regardless of which API was used to write that file.

The approach is deliberately "API-agnostic": the tester does not care whether the app uses `getExternalFilesDir()`, `Environment.getExternalStorageDirectory()`, `MediaStore`, the Storage Access Framework, `DownloadManager`, or even native code (JNI/NDK). What is done is **comparing a snapshot of the external storage filesystem before and after the app is run/exercised**, then taking the difference (new/modified files) and examining their contents.

> This differs from its sibling tests:
> - **MASTG-TEST-0200** (this test) → a **dynamic, filesystem-diffing-based** approach. Answers: *"What files actually appear on external storage?"*
> - **MASTG-TEST-0201** — *Runtime Use of External Storage APIs* → a **dynamic, hooking/API-tracing-based** approach (Frida). Answers: *"What storage APIs are called at runtime?"*
> - **MASTG-TEST-0202** — *References to APIs and Permissions for Accessing External Storage* → a **static** approach (reverse engineering + scanning permission & API references). Answers: *"What APIs and permissions are referenced inside the binary/manifest?"*
>
> Best practice: run all three as a single sequence. TEST-0202 gives a map of areas to test, TEST-0201 proves which APIs are actively called, and TEST-0200 proves the real impact on disk.

### 1.2 Why External Storage Is Dangerous

External storage on Android is **shared** storage — it may be removable media (SD card) or emulated (an internal partition mounted as `/sdcard`). Its security characteristics:

| Aspect | Internal Storage (`/data/data/<pkg>/`) | External Storage (`/sdcard/...`) |
|---|---|---|
| Linux UID sandbox | Yes, fully protected | No / weak (FUSE + emulated permissions) |
| Readable by other apps | No (except root) | Yes, depending on API level & permission |
| Modifiable by user via USB/MTP | No | Yes |
| Lost on uninstall | Yes | Depends on location (app-specific: yes; shared/MediaStore: **no**) |
| Readable after reinstalling another app | No | Yes (for shared locations) |

Concrete risks:

1. **Data reading by other applications (information disclosure).** On applications targeting Android 9 (API 28) and below — or that opt out of scoped storage via `android:requestLegacyExternalStorage="true"` — a malicious app with `READ_EXTERNAL_STORAGE` can read another app's *app-specific directory*.
2. **Data manipulation (integrity violation) → "Man-in-the-Disk".** Check Point research (DEF CON 2018) showed that a malicious app with external storage access could monitor and **overwrite** data transferred by other apps to external storage. The consequences: installing apps without consent, DoS, crashes, and even **code injection within the privileged context of the target app**. Affected apps at the time included Google Translate, Yandex Translate, Google Voice Typing, Google Text-to-Speech, and Xiaomi Browser — about half of the Google Play apps studied did not comply with Android guidelines.
3. **Data persistence post-uninstall.** Files written via `MediaStore` to `Downloads/`, `Pictures/`, etc. are **not deleted** when the app is uninstalled, so credentials can remain on the device forever.
4. **Exfiltration via cloud backup / MTP / adb backup.** Files on `/sdcard` are generally synced to third-party backup services as well, and are easy to pull via USB without root.
5. **Access on a rooted device or via physical forensics.** Emulated external storage is also FBE-encrypted, but once a device is unlocked/rooted, plaintext files are immediately readable.

### 1.3 Technical Foundation: Scoped Storage & the Permission Matrix

Understanding scoped storage is essential for correctly assessing the severity of findings.

**Scoped Storage** (Android 10 / API 29 and above): an app only has access to (a) its own app-specific directory on external storage, and (b) media files it created itself (`owner_package_name` attribution in MediaStore). Apps can no longer access the app-specific directory belonging to other apps.

- Apps targeting API ≤ 29 could **temporarily opt out** using `android:requestLegacyExternalStorage="true"`.
- Once an app targets **Android 11 (API 30)**, the system **ignores** that attribute — scoped storage is forced active.

**External storage permission matrix:**

| Permission | Behavior per API level |
|---|---|
| `READ_EXTERNAL_STORAGE` | < API 19: not enforced, every app can read all of external storage. API 19+: not needed for its own app-specific dir. API 29+: cannot read other apps' app-specific dirs (scoped storage). **API 33+: has no effect at all.** |
| `WRITE_EXTERNAL_STORAGE` | API 19+: not needed for its own app-specific dir. API 29+: cannot write to another app's app-specific dir. **API 30+: deprecated & has no effect** (equivalent only to READ), unless `requestLegacyExternalStorage` / `preserveLegacyExternalStorage` is used. |
| `MANAGE_EXTERNAL_STORAGE` | Only for target API 30+. Grants "All files access" — **bypasses scoped storage**. Its use is restricted by Google Play policy and requires justification. The presence of this permission is itself a red flag. |
| `READ_MEDIA_IMAGES` / `READ_MEDIA_VIDEO` / `READ_MEDIA_AUDIO` | Required from API 33 onward to access MediaStore collections owned by other apps, replacing `READ_EXTERNAL_STORAGE`. |

**Locations to check during testing:**

| Path | Calling API | Characteristics |
|---|---|---|
| `/sdcard/Android/data/<package>/files/` | `getExternalFilesDir()` | App-specific external. Protected by scoped storage (API 29+), **not** protected before that. Lost on uninstall. |
| `/sdcard/Android/data/<package>/cache/` | `getExternalCacheDir()` | Same as above. |
| `/sdcard/Download/`, `/sdcard/Documents/`, `/sdcard/DCIM/`, `/sdcard/Pictures/`, `/sdcard/Music/` | `MediaStore`, `getExternalStoragePublicDirectory()` | **Shared storage.** Accessible to other apps with the appropriate media permission. **Persists after uninstall.** |
| `/sdcard/<custom_dir>/` | `Environment.getExternalStorageDirectory()` + `File()` | Shared, most risky. Common in legacy apps. |
| `/mnt/media_rw/<uuid>/`, `/storage/<uuid>/` | Secondary/removable storage | Physical SD card — can be removed and read on another device. |

### 1.4 Types of Data Considered Sensitive

When inspecting files found in the diff, items considered findings include:

- Credentials: passwords, PINs, API keys, client secrets, access/refresh tokens, session IDs, JWTs
- Cryptographic material: private keys, keystores, certificates + passwords, seed phrases/mnemonics
- PII: national ID numbers, phone numbers, addresses, email, date of birth, biometric data
- Financial/health data: card numbers, account numbers, transaction history, medical records
- App operational data: unencrypted SQLite/Realm databases, shared_prefs copied out, API response cache containing user data, verbose debug logs, crash dumps
- Configuration/code files reloaded by the app (DEX, SO, JS bundle, template) → **code injection** risk, not just disclosure

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | MASTG ID | Function in This Test |
|---|---|---|
| **adb** (Android Debug Bridge) | MASTG-TOOL-0004 | APK installation, file enumeration (`adb shell find`), file pulling (`adb pull`), MediaStore queries, permission management. The main tool for this test. |
| **Android device / emulator** | MASTG-TOOL-0003 (AVD) | Test target. Recommended to have several API levels available (28, 30, 33+) to assess scoped storage behavior differences. |
| **Objection** | MASTG-TOOL-0038 | Exploring the filesystem and downloading files from the app sandbox without needing the app to be debuggable (`filesystem download <file>`, `... --folder`). |
| **Frida** | MASTG-TOOL-0001 | Complementary (for MASTG-TEST-0201): tracing external storage API calls at runtime, ensuring no write is missed. |

### 2.2 Supporting Tools

| Tool | Function |
|---|---|
| **Android Studio Device File Explorer** | Visual filesystem browsing (View → Tool Windows → Device File Explorer). Limited to the app sandbox if the device is non-rooted and the app is debuggable. |
| **MASTestApp / MASTG demo app** | Reference app for validating methodology & tooling before applying it to the target app. |
| **`file`, `strings`, `xxd`, `hexdump`, `binwalk`, `jq`** | File-type identification and string extraction from pulled files. Crucial for assessing whether a file is encrypted or plaintext. |
| **`sqlite3` / DB Browser for SQLite** | Opening SQLite databases found on external storage. |
| **`ent` / entropy analysis** | Distinguishing an encrypted file (high entropy ~7.9 bit/byte) from plaintext/obfuscated data (low entropy). Prevents a false pass caused by data merely Base64/XOR-encoded. |
| **grep with sensitive patterns / TruffleHog / gitleaks** | Automated scanning of pulled files for secret patterns (API keys, tokens, private keys). |
| **jadx / apktool** (MASTG-TOOL-0018 / 0011) | Reverse engineering to confirm the file-writing code location and verify encryption claims. |
| **semgrep** (with MASTG rules) | Supporting static analysis (more relevant for MASTG-TEST-0202). |

### 2.3 Environment Prerequisites

- A device/emulator with USB debugging enabled. **Root is not required** for this test since `/sdcard` can generally be read via `adb shell`.
- The app installed via `adb install` (if needed with `-g` to auto-grant runtime permissions so all flows can be exercised).
- Recommended to test on **at least two API levels**: one below 29 (to prove legacy exposure to other apps) and one at 33+ (for current behavior).
- A clean device state (fresh wipe / emulator snapshot) so the diff isn't contaminated by leftover files from previous tests.
- A test account with sensitive data that is **recognizable and unique** (e.g., password `MASTG_Pa55w0rd_UNIQ`, email `tester+mastg@example.com`) so it's easy to grep in the diff results. This is a key technique: use a *canary value*.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0005** (*Installing Apps*) to install the application.
2. Use **MASTG-TECH-0002** (*Host-Device Data Transfer*) to get the current list of files on external storage (snapshot **before**).
3. **Exercise the app extensively** — trigger as many flows as possible and enter sensitive data wherever possible.
4. Use MASTG-TECH-0002 again to get the list of files on external storage (snapshot **after**).
5. Compute the **difference** between the two lists.

### 3.2 Practical Implementation — Timestamp Marker Method (recommended by MASTG-DEMO-0001)

This method is more accurate and concise than comparing two large listings, because it uses a single timestamp marker file.

**Step 0 — Preparation**

```bash
# Verify the device is connected
adb devices

# Install the target app (auto-grant all runtime permissions)
adb install -g ./target-app.apk

# Note the package name
adb shell pm list packages | grep -i <app_name>

# (Optional) Check the storage configuration in the manifest first
# targetSdkVersion, requestLegacyExternalStorage, storage permission
```

**Step 1 — Create a timestamp marker (`run_before.sh`)**

```bash
#!/bin/bash
# SUMMARY: Creates a dummy file as a timestamp marker,
# to identify files created while the app is exercised
adb shell "touch /data/local/tmp/test_start"
```

**Step 2 — Exercise the app**

Open the app and perform as many flows as possible, consciously and systematically:

- Register, log in, log out, log in again, "remember me"
- Reset password, verify OTP, set up 2FA/biometrics
- Complete the profile (name, national ID, address, phone, upload ID card/photo)
- Add a payment method, make a transaction, download invoice/statement
- Upload and download files/attachments, export data, share/print
- Camera, gallery, document scanner, voice note features
- Chat/messages, search history, drafts
- Offline mode (turn off network → trigger local caching), then back online
- Repeated background/foreground, screen rotation, force-stop, reopen
- Trigger an error/crash if possible (to trigger a crash dump to disk)
- Enable all options in Settings, including "debug"/"developer" options if present

> Use a unique **canary value** in every input so it's easy to find via `grep` later.

**Step 3 — Compute the diff and pull the files (`run_after.sh`)**

```bash
#!/bin/bash
# SUMMARY: List all files created after the timestamp marker from run_before

adb shell "find /sdcard/ -type f -newer /data/local/tmp/test_start" > output.txt
adb shell "rm /data/local/tmp/test_start"
mkdir -p new_files
while read -r line; do
  adb pull "$line" ./new_files/
done < output.txt
```

**Step 4 — Inspect file contents**

```bash
# Identify the type of each file
file ./new_files/*

# Search for the canary value and sensitive patterns
grep -riE "MASTG_Pa55w0rd_UNIQ|password|passwd|secret|token|api[_-]?key|bearer|authorization|BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY|[0-9]{16}" ./new_files/

# View strings in a binary file
strings -n 6 ./new_files/<file> | less

# Test whether the file is genuinely encrypted (entropy close to 8.0 = likely encrypted)
ent ./new_files/<file>

# Open a database if present
sqlite3 ./new_files/<db_file> ".tables" ".dump"
```

### 3.3 Alternative Implementation — Two-Snapshot Method

Useful when `find -newer` is unavailable, or when you want to detect files that were **modified** (not just created), along with their hashes.

```bash
# --- BEFORE ---
adb shell "find /sdcard/ -type f -exec md5sum {} \;" | sort > before.txt

# --- Exercise the app ---

# --- AFTER ---
adb shell "find /sdcard/ -type f -exec md5sum {} \;" | sort > after.txt

# Difference: new files as well as files whose content changed
diff before.txt after.txt | grep '^>' | sed 's/^> //'

# Only new filenames
comm -13 <(awk '{$1="";print}' before.txt | sort) <(awk '{$1="";print}' after.txt | sort)
```

### 3.4 Recommended Additional Checks

```bash
# 1. Specifically enumerate the app-specific external directory
adb shell "ls -laR /sdcard/Android/data/<package>/"
adb shell "ls -laR /sdcard/Android/media/<package>/"

# 2. Query MediaStore — MediaStore files may not appear clearly in find
adb shell content query --uri content://media/external_primary/file \
  --projection _display_name:relative_path:owner_package_name:mime_type
adb shell content query --uri content://media/external_primary/downloads
adb shell content query --uri content://media/external_primary/images/media

# 3. Check the app's scoped storage configuration
adb shell dumpsys package <package> | grep -iE "targetSdk|versionName"
# or from the apktool manifest result:
#   grep -E "requestLegacyExternalStorage|preserveLegacyExternalStorage|targetSdkVersion" AndroidManifest.xml

# 4. Check the storage permissions granted
adb shell dumpsys package <package> | grep -iE "EXTERNAL_STORAGE|READ_MEDIA"

# 5. EXPLOITABILITY TEST: read the target file from another app's context
#    (simulate a malicious app — successful read = confirms cross-app exposure)
adb shell run-as <other_test_app_package> cat /sdcard/Android/data/<target_package>/files/secret.txt

# 6. Verify post-uninstall persistence
adb uninstall <package>
adb shell "ls -la /sdcard/Download/ /sdcard/Documents/"   # MediaStore files should still exist → a finding
```

### 3.5 Alternative Testing Methods (Multi-Tool)

The `adb` + `find` diffing method (§3.2/§3.3) has one structural weakness: it only sees the **final state**, so it misses files that are written and immediately deleted. The alternative methods below close that gap and offer a path that doesn't require root.

#### Method B — Objection *(no root, interactive exploration)*

Objection works via Frida, so it **doesn't require the app to be debuggable or require root** — a real advantage over `adb shell find` in the sandbox.

```bash
objection -g com.example.target explore

# Inside the objection shell:
env                                                    # map all app storage paths
cd /sdcard/Android/data/com.example.target/files
ls
filesystem download secret.txt                         # pull a single file
filesystem download . ./dump --folder                  # pull an entire directory
filesystem ls /sdcard/Download

# Monitor file writes in real time (while exercising the app)
android hooking watch class_method java.io.FileOutputStream.$init --dump-args --dump-backtrace
```

Additional advantage: `env` immediately gives a complete list of `externalCacheDirectory`, `filesDirectory`, `obbDir` — saving time mapping out paths.

#### Method C — Frida: hooking file I/O *(catching temporary files that get deleted)*

This closes the biggest gap of the diffing method. A file that's written and then deleted **won't appear** in the snapshot, but still manages to expose data to other apps.

```javascript
// catch_temp_writes.js — logs ALL writes, including ones later deleted
const EXT = ['/sdcard', '/storage/emulated', '/storage/self/primary', '/mnt/sdcard'];
function isExt(p) { return p && EXT.some(e => p.indexOf(e) === 0); }

function bt(max = 10) {
    const E = Java.use("java.lang.Exception");
    const st = E.$new().getStackTrace();
    return Array.from({length: Math.min(max, st.length)}, (_, i) => "    " + st[i]).join("\n");
}

['open', 'openat', 'creat', 'unlink', 'rename'].forEach(fn => {
    const a = Process.getModuleByName('libc.so').findExportByName(fn);
    if (!a) return;
    Interceptor.attach(a, {
        onEnter(args) {
            const p = (fn === 'openat' ? args[1] : args[0]).readCString();
            if (isExt(p)) {
                console.log(`\n[${fn}] ${p}`);
                Java.perform(() => console.log(bt()));
            }
        }
    });
});

// Peek at the CONTENT being written — detect plaintext without needing to pull the file
Java.perform(() => {
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
frida -U -f com.example.target -l catch_temp_writes.js -o writes.log
# Search for the canary value directly in the log, without needing the file to still exist on disk
grep -i "MASTG_CANARY" writes.log
```

> The `unlink` hook matters: if you see a pair of `open(...O_CREAT)` → `write` → `unlink` on the same path, that's a **temporary file** that escapes the diffing method. See also MASTG-TEST-0201 for a more complete hooking approach.

#### Method D — fsmon *(real-time filesystem monitoring, without app instrumentation)*

An alternative that doesn't touch the app at all — monitoring at the kernel/inotify level.

```bash
# fsmon (NowSecure) — FileSystem monitor for Android
adb push fsmon-arm64 /data/local/tmp/fsmon
adb shell "chmod 755 /data/local/tmp/fsmon"
adb shell "su -c '/data/local/tmp/fsmon /sdcard'" | tee fsmon.log

# Filter events only from the target app's process
adb shell "su -c '/data/local/tmp/fsmon -P com.example.target /sdcard'"

# Built-in alternative: inotifywait (if available in the ROM/BusyBox)
adb shell "su -c 'inotifywait -m -r -e create,modify,delete,moved_to /sdcard'"
```

Advantage: catches **all** filesystem activity including from native code and separate processes, without risk of detection by anti-instrumentation.

#### Method E — strace *(independent comparison when the app has anti-Frida)*

```bash
PID=$(adb shell pidof -s com.example.target)
adb shell "su -c 'strace -f -e trace=openat,write,unlink -p $PID'" 2>&1 \
  | grep -E "/sdcard|/storage/emulated" | tee strace.log
```

Useful when the app detects Frida and changes its behavior — strace operates at the syscall level and is far harder to detect.

#### Method F — MediaStore query *(catching files not visible to `find`)*

Files written via `MediaStore` are managed by a content provider and can escape ordinary path enumeration.

```bash
# All MediaStore entries along with their owners — the owner_package_name column is key
adb shell content query --uri content://media/external_primary/file \
  --projection _id:_display_name:relative_path:owner_package_name:mime_type:_data

# Per collection
adb shell content query --uri content://media/external_primary/downloads \
  --projection _display_name:relative_path:owner_package_name
adb shell content query --uri content://media/external_primary/images/media \
  --projection _display_name:relative_path:owner_package_name

# Filter only the target app's entries
adb shell content query --uri content://media/external_primary/file \
  --projection _display_name:relative_path:owner_package_name \
  | grep "com.example.target"
```

#### Method G — Full hash-based snapshot *(detecting MODIFIED files)*

The `find -newer` method misses files that already existed before and only had their content changed.

```bash
# --- BEFORE ---
adb shell "find /sdcard/ -type f -exec md5sum {} \;" 2>/dev/null | sort > before.txt

# --- exercise the app ---

# --- AFTER ---
adb shell "find /sdcard/ -type f -exec md5sum {} \;" 2>/dev/null | sort > after.txt

# New files AS WELL AS those whose content changed
comm -13 before.txt after.txt

# Pull all of them while preserving the directory structure
comm -13 before.txt after.txt | awk '{$1=""; sub(/^ /,""); print}' | while read -r p; do
  mkdir -p "./diff_files/$(dirname "${p#/sdcard/}")"
  adb pull "$p" "./diff_files/${p#/sdcard/}" >/dev/null 2>&1
done
```

#### Method H — MobSF Dynamic Analyzer *(automated, quote-ready report)*

```bash
docker run -it --rm -p 8000:8000 -p 1337:1337 \
  opensecurity/mobile-security-framework-mobsf:latest
```

Workflow: upload the APK → **Start Dynamic Analysis** → MobSF runs the app in a managed emulator, automatically exercises activities, then produces a **Files Analysis** / **Dumped Files** section containing the files the app created along with their contents. Advantage: it simultaneously captures logcat, network traffic, and SQLite dumps in a single session — useful for a broad initial pass.

Limitation: its automated exercise is shallow (cannot log in), so this is a **complement**, not a replacement for manual exercising.

#### Method I — Android Studio Device File Explorer *(visual, no CLI)*

**View → Tool Windows → Device File Explorer**. Navigate to `/sdcard/Android/data/<pkg>/`, right-click → Save As. The timestamp column helps identify newly created files. Suitable for quick verification or when demonstrating findings to a developer.

#### Method J — Forensic tooling *(deep analysis & timeline)*

```bash
# Pull all of external storage for offline analysis
adb pull /sdcard ./sdcard_dump

# ALEAPP — Android Logs Events And Protobuf Parser (structured artifacts + timeline)
python3 aleapp.py -t fs -i ./sdcard_dump -o ./aleapp_out

# Autopsy / Sleuth Kit — timeline analysis & keyword search across files
fls -r -m / ./image.dd > bodyfile
mactime -b bodyfile -d > timeline.csv
```

Useful when you need to **reconstruct the timeline** of file writes, or examine residual data in files that have already been deleted.

---

### 3.6 Method Comparison: When to Use Which

| Method | Tool | Needs root? | Catches temp files? | Catches modified files? | Catches MediaStore? | When to use |
|---|---|---|---|---|---|---|
| **A** | `adb` + `find -newer` (MASTG) | No (for `/sdcard`) | ❌ | ❌ | Partially | Official baseline — fast & simple |
| **B** | Objection | No | Partially (via watch) | Manual | Partially | **No root & no app debuggable needed**; `env` maps paths |
| **C** | Frida hook file I/O | Yes/gadget | ✅ **(main advantage)** | ✅ | ✅ (via ContentResolver) | Closes the biggest gap of the diffing method |
| **D** | fsmon / inotifywait | Yes | ✅ | ✅ | ✅ | **Without touching the app** — resistant to anti-instrumentation |
| **E** | strace | Yes | ✅ | ✅ | ✅ | Independent comparison when anti-Frida is present |
| **F** | `content query` | No | ❌ | ❌ | ✅ **(specialized)** | MediaStore files that escape `find` |
| **G** | Hash snapshot (md5sum) | No | ❌ | ✅ **(main advantage)** | Partially | Old files whose content changed |
| **H** | MobSF Dynamic | No | ❌ | ❌ | Partially | Broad initial pass + quote-ready report |
| **I** | Device File Explorer | No | ❌ | Manual | Partially | Visual verification / developer demo |
| **J** | ALEAPP / Autopsy | Yes | ❌ | ✅ | ✅ | Timeline reconstruction, deep forensic analysis |

**Minimum recommended combination:** **A (find -newer) → G (hash snapshot) → C or D**.
A is fast for an initial picture, G catches files that were modified, and C/D catch temporary files that disappear before the snapshot. Always add **F** — MediaStore files are the riskiest category (persist post-uninstall) and are most often missed. Use **B** when root is unavailable.

---

### 3.7 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> *"The test case **fails** if the files found above are not encrypted and leak sensitive data."*
>
> **Further Validation Required** — inspect the content of every reported file to determine whether its data is sensitive:
> - Determine whether the file contains sensitive information (e.g., personal data, credentials, or tokens).
> - Determine whether the data is stored without encryption.

Both conditions must hold (**AND**): the file is sensitive **AND** not encrypted → FAIL.

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition | Example evidence |
|---|---|---|
| F1 | A new file is found on external storage containing **sensitive data in plaintext** | `/sdcard/Android/data/org.owasp.mastestapp/files/secret.txt` contains `secr3tPa$$W0rd` |
| F2 | A sensitive file is written to **shared storage** via MediaStore/public directory | `/sdcard/Download/secretFile75.txt` contains `MAS_API_KEY=8767086b9f6f976g-a8df76` |
| F3 | An unencrypted database (SQLite/Realm) containing user data is found on external storage | `/sdcard/MyApp/app.db` → `sqlite3 ... .dump` shows a `users` table with a `password` column |
| F4 | The "encryption" found turns out to be only **encoding/obfuscation** (Base64, hex, ROT13, XOR with a hardcoded key) | `echo '<content>' \| base64 -d` directly produces plaintext; low entropy (< 6.0 bit/byte) |
| F5 | Encrypted, but **the key is also stored** on external storage or hardcoded in the APK | `key.pem` / `keystore.jks` + password found in the same directory, or the key found via `strings classes.dex` |
| F6 | A log / crash dump / API response cache containing sensitive data is written to external storage | `/sdcard/MyApp/logs/debug.log` contains `Authorization: Bearer eyJ...` |
| F7 | The file **remains present and readable after the app is uninstalled** and still contains sensitive data | A file in `/sdcard/Download/` still contains a token after `adb uninstall` |
| F8 | Sensitive data is successfully **read from another app's context** (exploitability test succeeds) | `run-as <other_app> cat <path>` returns plaintext content |
| F9 | The app loads **executable code/configuration** from external storage without an integrity check | A DEX/SO/JS bundle at `/sdcard/...` can be overwritten, and the app still loads it → Man-in-the-Disk / code injection |
| F10 | The app opts out of scoped storage (`requestLegacyExternalStorage="true"` with target ≤ API 29) **and** writes sensitive data to external storage | Manifest + findings F1/F2 |

**Example output indicating FAIL** (results from MASTG-DEMO-0001):

```
# output.txt
/sdcard/Android/data/org.owasp.mastestapp/files/secret.txt
/sdcard/Download/secretFile75.txt
```

```
# ./new_files/secret.txt
secr3tPa$$W0rd

# ./new_files/secretFile75.txt
MAS_API_KEY=8767086b9f6f976g-a8df76
```

MASTG evaluation: *"This test **fails** because the files are not encrypted and contain sensitive data (a password and an API key)."*

The responsible code (demo sample):

```kotlin
// Writing via the external storage API — plaintext
fun mastgTestApi() {
    val externalStorageDir = context.getExternalFilesDir(null)
    val fileName = File(externalStorageDir, "secret.txt")
    val fileContent = "secr3tPa\$\$W0rd\n"
    FileOutputStream(fileName).use { output ->
        output.write(fileContent.toByteArray())
    }
}

// Writing via MediaStore to Downloads — plaintext & persists post-uninstall
fun mastgTestMediaStore() {
    val resolver = context.contentResolver
    val contentValues = ContentValues().apply {
        put(MediaStore.MediaColumns.DISPLAY_NAME, "secretFile75.txt")
        put(MediaStore.MediaColumns.MIME_TYPE, "text/plain")
        put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
    }
    val textUri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, contentValues)
    textUri?.let {
        resolver.openOutputStream(it)?.use { os ->
            os.write("MAS_API_KEY=8767086b9f6f976g-a8df76\n".toByteArray())
        }
    }
}
```

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition | Example evidence |
|---|---|---|
| P1 | **No new files at all** appear on external storage during extensive exercising of the app | `output.txt` is empty; `wc -l output.txt` → `0` |
| P2 | There are new files, but **their content is not sensitive** — purely non-personal data | Public image assets, icons, fonts, `.nomedia` files, map tiles, thumbnail cache of public content |
| P3 | There is a sensitive file, but it is **correctly encrypted** using a strong algorithm, and **the key is stored in the Android KeyStore** (not on external storage / hardcoded) | `file` → `data`; `strings` shows no canary value; entropy ≈ 7.9+ bit/byte; code shows `EncryptedFile` / AES-GCM with a key from the KeyStore |
| P4 | The file created is the result of an **explicit user action** (e.g., the user taps "Export PDF" / "Save photo"), is data genuinely intended to be shared, and contains no credentials/tokens | An invoice PDF resulting from the user clicking the Download button — note: this should still be documented as an informational risk |
| P5 | All sensitive data is found only on **internal storage** (`/data/data/<pkg>/`), no trace on `/sdcard` | `find /sdcard -newer ...` is clean; data exists only on internal storage |
| P6 | The exploitability test **fails** — another app cannot read the file, and any existing files are not sensitive | `run-as <other_app> cat <path>` → `Permission denied` + no plaintext findings |

**Example output indicating PASS:**

```bash
$ cat output.txt
$ wc -l output.txt
0 output.txt
# → No file was written to external storage
```

or:

```bash
$ cat output.txt
/sdcard/Android/data/com.example.app/files/vault.bin

$ file ./new_files/vault.bin
./new_files/vault.bin: data

$ grep -riE "MASTG_Pa55w0rd_UNIQ|password|token|api_key" ./new_files/
# (no results)

$ strings -n 6 ./new_files/vault.bin | head
# only random bytes, no meaningful strings

$ ent ./new_files/vault.bin
Entropy = 7.998432 bits per byte.
# → consistent with encrypted data
```

Confirmed via reverse engineering that the encryption uses `EncryptedFile` with a MasterKey from the Android KeyStore:

```kotlin
val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build()

val encryptedFile = EncryptedFile.Builder(
    context,
    File(context.getExternalFilesDir(null), "vault.bin"),
    masterKey,
    EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
).build()
```

---

#### ⚠️ Important Notes on Scoring

1. **Don't stop at listing files — content inspection is mandatory.** MASTG explicitly flags this test as requiring *Further Validation*. A filename that looks harmless (`cache.dat`, `tmp_001`) often contains a token.
2. **Don't conclude PASS just because `output.txt` is empty in one session.** The file may only be written on a flow that hasn't been exercised yet. Correlate with **MASTG-TEST-0201** (Frida API tracing) and **MASTG-TEST-0202** (static analysis) — if static analysis shows a reference to `getExternalFilesDir` but the diff is empty, that means the triggering flow hasn't been touched yet.
3. **Beware of a false pass caused by fake encryption.** Always test with `strings`, `base64 -d`, and entropy analysis.
4. **Severity is modulated by API level and location**, but **does not eliminate a finding**:
   - Sensitive plaintext data in **shared storage** (Download/Documents/DCIM) → highest severity (readable by other apps + persists post-uninstall).
   - Sensitive plaintext data in an **app-specific external dir** on a target API ≥ 30 → lower severity (protected by scoped storage from other apps), but **still FAIL** because it remains readable by the user via MTP/USB, by a rooted device, by third-party backup, and by malware with `MANAGE_EXTERNAL_STORAGE`.
   - The presence of `requestLegacyExternalStorage="true"` or `MANAGE_EXTERNAL_STORAGE` → raises severity.
5. **Document evidence thoroughly** for every finding: file path, content (redacted if needed), device API level, app target SDK, granted permissions, reproduction steps, and the cross-app read test result.

---

## 4. Recommendations

### 4.1 Main Principles (in priority order)

**Priority 1 — Do not store sensitive data on external storage.** This is the only remediation that eliminates the root of the problem. Android Security Guidelines and SEI CERT Android (DRD00) both affirm this. Move it to internal storage protected by the Linux UID sandbox.

```kotlin
// ❌ WRONG — external storage
val file = File(context.getExternalFilesDir(null), "secret.txt")
file.writeText(password)

// ✅ CORRECT — internal storage (private, deleted on uninstall)
context.openFileOutput("secret.txt", Context.MODE_PRIVATE).use { it.write(data) }
// or
val file = File(context.filesDir, "secret.txt")
```

Never use `MODE_WORLD_READABLE` / `MODE_WORLD_WRITEABLE` (already deprecated since API 17 and throws a `SecurityException` since API 24).

**Priority 2 — Use the storage mechanism appropriate for the data type.**

| Data type | Correct mechanism |
|---|---|
| Cryptographic keys, crypto material | **Android KeyStore** (with `setUserAuthenticationRequired`, StrongBox where available). The key never leaves secure hardware. |
| Passwords, tokens, API keys | Avoid storing if it can be avoided. If necessary: encrypt with a key from the KeyStore, store in internal storage. |
| Sensitive key-value preferences | Internal storage + encryption (`EncryptedSharedPreferences` / its successor; note that Jetpack Security `androidx.security:security-crypto` is now deprecated — consider implementing AES-GCM yourself with a KeyStore key, or Google Tink). |
| Structured data | Room + **SQLCipher** / encrypted SQLite, on internal storage. |
| Large app-owned files | Internal storage; if size forces the use of external, encryption is mandatory (Priority 3). |
| Files genuinely intended to be shared | MediaStore / Storage Access Framework, **only for non-sensitive data**, and ideally following an explicit user action. |
| Sharing a file to another app | **FileProvider** with a `content://` URI and temporary grant permission — not placing the file on `/sdcard`. |

**Priority 3 — If external storage is truly unavoidable: encrypt with a key from the KeyStore.**

```kotlin
// Encrypting a file on external storage, key in the Android KeyStore
val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build()

val targetFile = File(context.getExternalFilesDir(null), "data.enc")
val encryptedFile = EncryptedFile.Builder(
    context,
    targetFile,
    masterKey,
    EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
).build()

encryptedFile.openFileOutput().use { it.write(sensitiveBytes) }
```

Requirements to be considered adequate:
- A modern algorithm with authenticated encryption: **AES-256-GCM** or ChaCha20-Poly1305. No ECB, no DES/3DES/RC4, no CBC without a MAC.
- A random IV/nonce per operation, never reused.
- The key **generated and stored in the Android KeyStore** — not hardcoded in the code, not derived from a static value (IMEI, package name, constant string), not placed on external storage.
- If the key is derived from a user password: a strong KDF (high-iteration PBKDF2 / **Argon2id** / scrypt) with a random salt.

**Priority 4 — Enable and maintain scoped storage.**

```xml
<!-- AndroidManifest.xml -->
<application
    android:requestLegacyExternalStorage="false"
    ... >
```

- Target **Android 11 (API 30) and above** — scoped storage is forced active by the OS.
- **Remove** `android:requestLegacyExternalStorage="true"` and `preserveLegacyExternalStorage`.
- Avoid `MANAGE_EXTERNAL_STORAGE` unless truly required (file manager, antivirus, backup app) — its use is restricted by Google Play policy.
- Declare storage permissions minimally; use the granular `READ_MEDIA_IMAGES`/`VIDEO`/`AUDIO` (API 33+), or better, the **Photo Picker** which needs no permission at all.

**Priority 5 — Validate the input and integrity of all data read from external storage.** This is a mitigation specifically against Man-in-the-Disk. Treat every file from external storage as **untrusted input**.

- **Never** load executable code (DEX, SO, APK, JS bundle, script) from external storage.
- Strict validation: check size, MIME type, magic bytes, schema/structure, value bounds. Don't deserialize Java/Kotlin objects from a file on external storage.
- Prevent path traversal and symlink attacks: canonicalize the path (`File.canonicalPath`) and ensure it remains within the allowed directory.
- Verify integrity with a SHA-256 hash **stored on internal storage** (not next to the file), or better with an HMAC/signature:

```kotlin
object FileIntegrityChecker {
    @Throws(IOException::class, NoSuchAlgorithmException::class)
    fun getIntegrityHash(filePath: String?): String {
        val md = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(8192)
        var bytesRead: Int
        BufferedInputStream(FileInputStream(filePath)).use { fis ->
            while (fis.read(buffer).also { bytesRead = it } != -1) {
                md.update(buffer, 0, bytesRead)
            }
        }
        return md.digest().joinToString("") { "%02x".format(it) }
    }

    fun verifyIntegrity(filePath: String?, expectedHash: String): Boolean =
        getIntegrityHash(filePath) == expectedHash
}
```

> Note: a SHA-256 hash alone only detects corruption/tampering by an attacker who doesn't know the hash value. For genuine protection against an active attacker, use **HMAC-SHA256** with a key from the KeyStore, or authenticated encryption (AES-GCM) which also guarantees integrity.

### 4.2 Additional Practice Improvements

- **Data minimization:** don't store what doesn't need to be stored. Session tokens should ideally live only in memory; use short-lived refresh tokens.
- **Delete temporary files & cache** immediately after use; don't leave temporary files on `/sdcard`. Use `File.deleteOnExit()` or explicitly delete in a `finally` block.
- **Turn off verbose logging in release builds** (`BuildConfig.DEBUG`), and ensure the crash handler doesn't write dumps containing PII/credentials to external storage.
- **Audit third-party SDKs/libraries.** Analytics, crash reporters, map SDKs, and image loaders often write cache to external storage without the developer's knowledge. This test frequently finds files from an SDK, not from the app's own code.
- **Exclude from backup:** use `android:allowBackup="false"` or `dataExtractionRules` / `fullBackupContent` to exclude sensitive files (see MASWE-0006).
- **Integrate into CI/CD:** make this check part of the regression test suite — run a diff script on an emulator in the pipeline and fail the build if an unexpected new file appears on `/sdcard`.
- **Explicit threat model:** document every intentional write to external storage along with its justification, so reviewers can distinguish a design decision from an unintentional leak.

### 4.3 Remediation Checklist

- [ ] No sensitive data (credentials, tokens, PII, financial data) is written to external storage
- [ ] Sensitive data is stored in internal storage (`context.filesDir`, `openFileOutput(..., MODE_PRIVATE)`)
- [ ] No use of `MODE_WORLD_READABLE` / `MODE_WORLD_WRITEABLE`
- [ ] If external storage is still used: data is encrypted with AES-256-GCM, key in the Android KeyStore
- [ ] No key/secret is hardcoded in code or stored alongside data on external storage
- [ ] `targetSdkVersion` ≥ 30 and `requestLegacyExternalStorage` is not set to `true`
- [ ] `MANAGE_EXTERNAL_STORAGE` is not declared (unless with strong justification and Play approval)
- [ ] Minimal storage permissions; use Photo Picker / SAF / granular `READ_MEDIA_*`
- [ ] All data read from external storage is validated and integrity-verified (HMAC/AEAD)
- [ ] No executable code is loaded from external storage
- [ ] Temporary/cache files on external storage are cleaned up after use
- [ ] Verbose logging and crash dumps to external storage are disabled in release builds
- [ ] Third-party libraries are audited for writes to external storage
- [ ] Sensitive files are excluded from backup
- [ ] Re-verification: repeat MASTG-TEST-0200 after remediation → `output.txt` is clean or all files are proven encrypted

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0200: Files Written to External Storage](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0200/)
- [MASTG-TEST-0201: Runtime Use of External Storage APIs](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0201/)
- [MASTG-TEST-0202: References to APIs and Permissions for Accessing External Storage](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0202/)
- [MASTG-TEST-0001: Testing Local Storage for Sensitive Data](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0001/)
- [MASWE-0002: Sensitive Data Stored Unencrypted Outside of Private Storage](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0002/)
- [MASTG-DEMO-0001: File System Snapshots from External Storage](https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0001/MASTG-DEMO-0001/)
- [MASTG-DEMO-0002: External Storage APIs Tracing with Frida](https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0002/MASTG-DEMO-0002/)
- [MASTG-DEMO-0003: App Writing to External Storage without Scoped Storage Restrictions](https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0003/MASTG-DEMO-0003/)
- [MASTG-DEMO-0004: App Writing to External Storage with Scoped Storage Restrictions](https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0004/MASTG-DEMO-0004/)
- [MASTG-DEMO-0005: App Writing to External Storage via the MediaStore API](https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0005/MASTG-DEMO-0005/)
- [MASTG-KNOW-0042: External Storage](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0042/)
- [MASTG-TECH-0002: Host-Device Data Transfer](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0002/)
- [MASTG-TECH-0005: Installing Apps](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0005/)
- [MASVS-STORAGE: Storage](https://mas.owasp.org/MASVS/05-MASVS-STORAGE/)
- [OWASP MASTG Repository (GitHub)](https://github.com/OWASP/mastg)
- [OWASP Mobile Top 10 2024 — M9: Insecure Data Storage](https://owasp.org/www-project-mobile-top-10/2023-risks/m9-insecure-data-storage)

### 5.2 Official Android / Google Documentation

- [Sensitive Data Stored in External Storage — Android Security Risks](https://developer.android.com/privacy-and-security/risks/sensitive-data-external-storage)
- [Data and file storage overview](https://developer.android.com/training/data-storage)
- [Access app-specific files](https://developer.android.com/training/data-storage/app-specific)
- [Scoped storage](https://developer.android.com/training/data-storage#scoped-storage)
- [Storage use cases and best practices](https://developer.android.com/training/data-storage/use-cases)
- [Access media files from shared storage (MediaStore)](https://developer.android.com/training/data-storage/shared/media)
- [Access documents and other files (Storage Access Framework)](https://developer.android.com/training/data-storage/shared/documents-files)
- [Manage all files on a storage device (MANAGE_EXTERNAL_STORAGE)](https://developer.android.com/training/data-storage/manage-all-files)
- [App security best practices — Store data safely](https://developer.android.com/privacy-and-security/security-best-practices#external-storage)
- [Security tips — Using external storage](https://developer.android.com/privacy-and-security/security-tips#external-storage)
- [Android Keystore system](https://developer.android.com/privacy-and-security/keystore)
- [Cryptography best practices](https://developer.android.com/privacy-and-security/cryptography)
- [FileProvider](https://developer.android.com/reference/androidx/core/content/FileProvider)
- [Photo picker](https://developer.android.com/training/data-storage/shared/photopicker)
- [adb — Copy files to/from a device](https://developer.android.com/studio/command-line/adb#copyfiles)
- [Device File Explorer (Android Studio)](https://developer.android.com/studio/debug/device-file-explorer)
- [File-Based Encryption (AOSP)](https://source.android.com/docs/security/features/encryption/file-based)
- [Google Play — Use of the All files access permission](https://support.google.com/googleplay/android-developer/answer/10467955)

### 5.3 Standards, Taxonomies, and Other Guidelines

- [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
- [CWE-921: Storage of Sensitive Data in a Mechanism without Access Control](https://cwe.mitre.org/data/definitions/921.html)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [SEI CERT Android — DRD00: Do not store sensitive information on external storage (SD card) unless encrypted first](https://wiki.sei.cmu.edu/confluence/display/android/DRD00.+Do+not+store+sensitive+information+on+external+storage+%28SD+card%29+unless+encrypted+first)
- [NIST SP 800-163 Rev.1 — Vetting the Security of Mobile Applications](https://csrc.nist.gov/publications/detail/sp/800-163/rev-1/final)
- [NIST SP 800-124 Rev.2 — Guidelines for Managing the Security of Mobile Devices](https://csrc.nist.gov/publications/detail/sp/800-124/rev-2/final)
- [SonarQube Rule java:S5324 — Accessing Android external storage is security-sensitive](https://rules.sonarsource.com/java/RSPEC-5324/)
- [CodeQL — Cleartext storage of sensitive information in the Android filesystem](https://codeql.github.com/codeql-query-help/java/java-android-cleartext-storage-filesystem/)
- [MITRE ATT&CK Mobile — T1533: Data from Local System](https://attack.mitre.org/techniques/T1533/)
- [MITRE ATT&CK Mobile — T1409: Stored Application Data](https://attack.mitre.org/techniques/T1409/)

### 5.4 Security Research & Technical Articles

- [Check Point Research — Man-in-the-Disk: Android Apps Exposed via External Storage](https://research.checkpoint.com/2018/androids-man-in-the-disk/)
- [Check Point Blog — Man-in-the-Disk: A New Attack Surface for Android Apps](https://blog.checkpoint.com/security/man-in-the-disk-a-new-attack-surface-for-android-apps/)
- [Threatpost — DEF CON 2018: 'Man in the Disk' Attack Surface Affects All Android Phones](https://threatpost.com/def-con-2018-man-in-the-disk-attack-surface-affects-all-android-phones/134993/)
- [The Hacker News — New Man-in-the-Disk attack leaves millions of Android phones vulnerable](https://thehackernews.com/2018/08/man-in-the-disk-android-hack.html)
- [NDSS 2025 — ScopeVerif: Analyzing the Security of Android's Scoped Storage via Differential Analysis](https://www.ndss-symposium.org/wp-content/uploads/2025-340-paper.pdf)
- [PolyScope: Multi-Policy Access Control Analysis to Triage Android Scoped Storage (arXiv)](https://arxiv.org/pdf/2302.13506)
- [Security Smells in Android (arXiv)](https://arxiv.org/pdf/2006.01181)
- [HackTricks — Android Applications Basics & Local Storage](https://book.hacktricks.wiki/en/mobile-pentesting/android-app-pentesting/index.html)
- [Google Tink — Cryptographic library](https://developers.google.com/tink)

### 5.5 Tool Documentation

- [Frida — Dynamic instrumentation toolkit](https://frida.re/docs/home/)
- [Objection — Runtime mobile exploration](https://github.com/sensepost/objection)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [apktool — Reverse engineering Android APK files](https://apktool.org/)
- [Semgrep — Static analysis](https://semgrep.dev/docs/)
- [sqlite3 CLI](https://www.sqlite.org/cli.html)
- [ent — Pseudorandom number sequence test (entropy)](https://www.fourmilab.ch/random/)

---

*This document was prepared based on OWASP MASTG (latest release as of September 2026), official Android Developers documentation, CWE/SEI CERT/NIST standards, and third-party security research.*
