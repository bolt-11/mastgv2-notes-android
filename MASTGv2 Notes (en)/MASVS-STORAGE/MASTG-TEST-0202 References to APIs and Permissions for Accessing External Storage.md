# MASTG-TEST-0202 References to APIs and Permissions for Accessing External Storage

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0202 |
| **Platform** | Android |
| **MASVS Category** | MASVS-STORAGE (MASVS-STORAGE-1: The app securely stores sensitive data) |
| **Weakness** | MASWE-0002 — *Sensitive Data Stored Unencrypted Outside of Private Storage* |
| **Test Type** | **Static**, Code, Manual |
| **Profile** | L1, L2 |
| **Knowledge** | MASTG-KNOW-0042 (External Storage) |
| **Highlighted APIs** | `Environment#getExternalStoragePublicDirectory`, `Environment#getExternalStorageDirectory`, `Environment#getExternalFilesDir`, `Environment#getExternalCacheDir`, `MediaStore`, `WRITE_EXTERNAL_STORAGE`, `MANAGE_EXTERNAL_STORAGE` |
| **Related Techniques** | MASTG-TECH-0013 (Reverse Engineering Android Apps), MASTG-TECH-0014 (Static Analysis on Android), MASTG-TECH-0117 (Obtaining Information from the AndroidManifest), MASTG-TECH-0126 (Obtaining App Permissions), MASTG-TECH-0023 (Reviewing Decompiled Java Code) |
| **Related Demo** | MASTG-DEMO-0003, MASTG-DEMO-0004, MASTG-DEMO-0005 |
| **Related CWEs** | CWE-312 (Cleartext Storage of Sensitive Information), CWE-921 (Storage of Sensitive Data in a Mechanism without Access Control), CWE-200 (Exposure of Sensitive Information), CWE-250 (Execution with Unnecessary Privileges — for `MANAGE_EXTERNAL_STORAGE`) |

---

## 1. Explanation

### 1.1 Testing Objective

This test uses **static analysis** to look for the use of APIs that allow the application to write to a location shared with other apps — namely the External Storage API or the `MediaStore` API — **along with the related storage permissions declared in the AndroidManifest**.

Direct quote from the MASTG overview:

> *"This test uses static analysis to look for uses of APIs allowing an app to write to locations that are shared with other apps such as the External Storage APIs or the `MediaStore` API as well as the relevant Android manifest storage-related permissions."*
>
> *"Some APIs used to write to shared storage include `getExternalStoragePublicDirectory`, `getExternalStorageDirectory`, `getExternalFilesDir`, or `MediaStore`. Permissions include `WRITE_EXTERNAL_STORAGE`, and `MANAGE_EXTERNAL_STORAGE`."*

So this test has **two targets that must be correlated**:

1. **The code side** — where (file + line number) the app calls an external/shared storage API.
2. **The manifest side** — what storage permission is declared, and whether there is a scoped-storage opt-out flag.

Both must be examined together. A permission without a matching API call could be a leftover; an API call without a permission is in fact normal for scoped storage APIs (see §1.4).

### 1.2 Official MASTG Note: This Test's Limitations

MASTG itself explicitly provides a warning (in a `!!! note` block) about the limits of this test's capabilities:

> *"This static test is great for identifying **all code locations** where the app is writing data to shared storage. However, it **does not provide the actual data being written**, and in some cases, **the actual path in the device storage** where the data is being written. Therefore, it is recommended to **combine this test with others that take a dynamic approach**, as this will provide a more complete view of the data being written to shared storage."*

Three practical consequences of this note:

- **This test cannot stand alone to decide a FAIL.** It finds *locations*, not *content*. The sensitive/non-sensitive decision must come from manual code review (MASTG-TECH-0023) or from dynamic testing.
- **The actual path sometimes cannot be determined statically.** Example: `getExternalFilesDir(null)` → the path depends on the package name and runtime; `MediaStore` → the path depends on `relative_path` in `ContentValues`, which can be dynamic.
- **It must be combined** with MASTG-TEST-0200 (filesystem diff) and MASTG-TEST-0201 (hooking).

### 1.3 This Test's Position Within the MASVS-STORAGE Series

| Test | Approach | Answers | Strength | Weakness |
|---|---|---|---|---|
| **MASTG-TEST-0200** | Dynamic — *filesystem diffing* | "What files **actually appear** on disk?" | Real evidence, fully API-agnostic, no root needed | Doesn't know who wrote it & which line of code |
| **MASTG-TEST-0201** | Dynamic — *method hooking* | "**Which API** is called, by **which code**?" | Precise attribution + backtrace, catches native code & temp files | Needs Frida/root, only exercised flows, can be blocked by anti-instrumentation |
| **MASTG-TEST-0202** *(this document)* | **Static** — reverse engineering + pattern matching | "What API & permission is **referenced** across the entire code base?" | **Comprehensive coverage** of existing code without running the app; fast & automated; CI-friendly; not blocked by anti-instrumentation | Many false positives (dead code, unused library); doesn't know data content; blind to dynamic/native/obfuscated code |

**This test's unique value:** it is the only one that provides **complete coverage**. A dynamic test only sees the flows you ran; a static test sees **all** code paths present in the APK, including features only active for premium accounts, feature-flagged features, or error flows that are hard to trigger. That's why this test is best used **first** — as a map to direct dynamic testing.

**Recommended workflow:**

```
TEST-0202 (static)  ──►  list of code locations + permissions  ──►  map of risk areas
        │
        ├──►  TEST-0201 (hooking)  ──►  confirm which APIs are active + backtrace
        │
        └──►  TEST-0200 (diffing)  ──►  real file evidence + data content
                                              │
                                              ▼
                                    PASS / FAIL decision
```

Conversely, this relationship also applies to closing blind spots: if TEST-0202 finds a reference to `getExternalFilesDir` but TEST-0201 never recorded the call, that means **the triggering flow has not been exercised** — the status is inconclusive, not PASS.

### 1.4 Technical Foundation: The APIs and Permissions Being Searched For

It is important to understand that these APIs **do not carry an equal level of risk**. MASTG itself separates them into two distinct Semgrep rules with different messages.

**Group A — APIs to "public" shared storage (highest risk):**

| API | Path | Permission | Note |
|---|---|---|---|
| `Environment.getExternalStorageDirectory()` | `/storage/emulated/0` (shared storage root) | Requires `MANAGE_EXTERNAL_STORAGE` ("All files access") on API 30+ | **Deprecated (API 29)**. A strong indicator of legacy code |
| `Environment.getExternalStoragePublicDirectory(type)` | `/sdcard/Download/`, `/sdcard/Documents/`, `/sdcard/DCIM/` | Same as above | **Deprecated (API 29)**. Persists post-uninstall |
| `Environment.getDownloadCacheDirectory()` | System download cache | — | Also scanned by the MASTG rule |
| `Intent.ACTION_CREATE_DOCUMENT` | User-determined via SAF | Not needed | Scanned by MASTG because it writes outside the sandbox; lower risk since it involves user interaction |

The MASTG rule message for this group: *"[MASVS-STORAGE] Make sure to encrypt files at these locations if necessary"*.

**Group B — APIs to scoped external storage (medium risk):**

| API | Path | Permission |
|---|---|---|
| `Context.getExternalFilesDir()` / `getExternalFilesDirs()` | `/sdcard/Android/data/<pkg>/files/` | **No permission needed** (API 19+) |
| `Context.getExternalCacheDir()` / `getExternalCacheDirs()` | `/sdcard/Android/data/<pkg>/cache/` | **No permission needed** |
| `Context.getExternalMediaDirs()` | `/sdcard/Android/media/<pkg>/` | **No permission needed**; visible in MediaStore |

The MASTG rule message for this group: *"[MASVS-STORAGE] These locations might be accessible to other apps on Android 10 and below given relevant permissions"*.

> **A key point that's often misunderstood:** Group B APIs **require no permission at all**. So the absence of `WRITE_EXTERNAL_STORAGE` in the manifest **does not at all mean the app is safe**. This matters for interpreting the evaluation criteria (see §3.6).

**Group C — MediaStore (high risk, persistent):**

| API | Note |
|---|---|
| `MediaStore.Downloads` / `Images` / `Video` / `Audio` / `Files` `.EXTERNAL_CONTENT_URI` | Writes to `/sdcard/Download/`, `/sdcard/Pictures/`, etc. |
| `ContentResolver.insert()` + `openOutputStream()` | The actual write point |
| `MediaStore.MediaColumns.RELATIVE_PATH` / `DISPLAY_NAME` | Determines the final path |

No permission needed for self-created files (API 29+), **not removed when the app is uninstalled**, and accessible by other apps with the appropriate media permission.

**Manifest permissions and flags scanned:**

| Manifest Item | Meaning & Risk |
|---|---|
| `WRITE_EXTERNAL_STORAGE` | Write to shared storage. **Deprecated & has no effect on API 30+** (equivalent only to READ). Its presence in a modern app = leftover or an indication of a low target SDK |
| `MANAGE_EXTERNAL_STORAGE` | **"All files access"** — fully bypasses scoped storage. Restricted by Google Play policy. **The strongest red flag** |
| `ACCESS_ALL_EXTERNAL_STORAGE` | A system permission (signature-level), not for ordinary apps. Its presence is highly suspicious |
| `android:requestLegacyExternalStorage="true"` | **Opts out of scoped storage.** Only has an effect when target ≤ API 29; ignored by the system when target ≥ API 30 |
| `android:preserveLegacyExternalStorage="true"` | Preserves legacy access when upgrading the app's target API to 30 |
| `android:requestRawExternalStorageAccess="true"` | Bypasses the FUSE abstraction for raw I/O access (API 30+) |

The last three flags all **raise severity** because they widen cross-app exposure.

### 1.5 Risks Indicated by This Test

The root risk is the same as MASTG-TEST-0200 and 0201 (MASWE-0002) — see those documents for details. In summary:

1. **Cross-app information disclosure** — plaintext files on shared storage read by other apps (especially targeting API ≤ 29 or with `requestLegacyExternalStorage="true"`).
2. **Man-in-the-Disk** (Check Point, DEF CON 2018) — an attacker overwrites data on external storage; potentially leading to DoS, crashes, or even **code injection within the privileged context of the target app**.
3. **Post-uninstall persistence** — MediaStore files in `Download/`, `Documents/` are not deleted when the app is uninstalled.
4. **Over-privilege** — `MANAGE_EXTERNAL_STORAGE` grants access to the entire device's storage; if the app is compromised, the impact extends to other apps' data (CWE-250).

**Risks this test is particularly effective at finding** (and that are hard for a dynamic test to find):
- **High-risk deprecated APIs in rarely-executed code paths** — for example, `getExternalStorageDirectory()` in a legacy export/backup module that is only active under certain conditions.
- **Leftover permissions** — `WRITE_EXTERNAL_STORAGE` / `MANAGE_EXTERNAL_STORAGE` still declared even though the corresponding feature has been removed, widening the attack surface for no benefit.
- **Forgotten scoped-storage opt-out flags** in the manifest.
- **References from third-party libraries** that are not visible during normal dynamic testing.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | MASTG ID | Function in This Test |
|---|---|---|
| **jadx** | MASTG-TOOL-0018 | **DEX → Java decompilation** (MASTG-TECH-0013/0017). Also extracts the full manifest, including the `<uses-sdk>` element, via `jadx --no-src`. Required for MASTG-TECH-0023 (reviewing finding locations) |
| **semgrep** | MASTG-TOOL-0110 | **Pattern matching** on decompiled code and on the manifest. The primary tool for automating this test; MASTG provides ready-to-use rules |
| **apktool** | MASTG-TOOL-0011 | Decode the binary manifest → XML (`apktool d -s -f`). Note: `minSdkVersion`/`targetSdkVersion` is moved into `apktool.yml`, not in the decoded manifest |
| **aapt2** | MASTG-TOOL-0124 | Quick extraction of metadata & permissions: `aapt2 d badging`, `aapt d permissions`. The output is **not** XML |
| **grep** | — | The simplest yet effective static analysis (MASTG-TECH-0014), e.g., `grep 'android:minSdkVersion' AndroidManifest.xml` |
| **adb** | MASTG-TOOL-0004 | `adb shell dumpsys package <pkg> \| grep permission` — views the permission **along with its grant status** at runtime (MASTG-TECH-0126) |

### 2.2 Alternative and Supporting Tools

| Tool | Function |
|---|---|
| **mobsfscan** | A mobile-specific SAST tool based on semgrep + libsast, supports Java/Kotlin/Swift/Obj-C and XML manifests. Lightweight and suitable for CI pipelines |
| **MobSF** (Mobile Security Framework) | Comprehensive static analysis of an APK: dangerous permissions, insecure data storage, hardcoded secrets, exported components. Good for a broad first pass |
| **semgrep-rules-android-security** (IMQ Minded Security) | A third-party collection of Android-security-specific semgrep rules — complements the official MASTG rules |
| **CodeQL** | Data-flow (taint) analysis — more powerful than semgrep for tracing *whether sensitive data actually reaches* a storage API. The `java/android-cleartext-storage-filesystem` query is available |
| **SonarQube** | Rule `java:S5324` — *Accessing Android external storage is security-sensitive* |
| **jadx-gui** | Interactive navigation, symbol renaming when analyzing obfuscated code (MASTG-TECH-0023) |
| **APKiD / apkid** | Packer/obfuscator detection — important for assessing the reliability of static analysis results |
| **dex2jar + JD-GUI / CFR / Procyon** | Alternative decompilers when jadx fails on certain code |
| **Ghidra / radare2** | Native code (`.so`) analysis — closes DEX analysis blind spots; search for `/sdcard`, `/storage/emulated` strings, and `open`/`fopen` calls |
| **TruffleHog / gitleaks** | Hardcoded secret scanning on decompiled code — supports the "is the data sensitive" evaluation step |
| **apksigner / bundletool** | Handle AAB and split APKs so all modules (including dynamic features) are included in the analysis |

### 2.3 Environment Prerequisites

- **No device and no root needed.** This is a major advantage of this test over TEST-0200/0201 — just the APK file is enough. This makes it the easiest to automate in CI/CD.
- **The target APK file.** If the app is an **AAB / split APK**, make sure **all** splits and dynamic feature modules are included in the analysis (`adb shell pm path <pkg>` then pull all of them), otherwise a module will be missed.
- **semgrep installed** (`pip install semgrep`) and **the MASTG rules** available (clone `github.com/OWASP/mastg`, `rules/` directory).
- **Watch for obfuscation.** If the app is protected by aggressive ProGuard/R8, a packer, or string encryption, pattern-matching results may be incomplete. Run APKiD first and **document this limitation** in the report. Important note: Android framework API names (`getExternalFilesDir`, `MediaStore`) are **not obfuscated** by ProGuard/R8 since they are system APIs — so this test remains effective on obfuscated apps; what gets obfuscated is the app's own class/method names, which complicates the code review stage (MASTG-TECH-0023), not the detection stage.
- **Native code analysis is separate.** The semgrep rules only work on Java/Kotlin. Writes from a `.so` must be found with `strings`/Ghidra.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0013** (*Reverse Engineering Android Apps*) to reverse engineer the application.
2. Use **MASTG-TECH-0014** (*Static Analysis on Android*) to search for relevant APIs.
3. Use **MASTG-TECH-0117** (*Obtaining Information from the AndroidManifest*) to obtain `AndroidManifest.xml`.
4. Use **MASTG-TECH-0126** (*Obtaining App Permissions*) to obtain the relevant permissions.

For evaluation, use **MASTG-TECH-0023** (*Reviewing Decompiled Java Code*) on every reported code location.

### 3.2 Practical Implementation

**Step 1 — Decompile the Application (MASTG-TECH-0013)**

```bash
# Decompile DEX to Java with jadx
jadx -d ./decompiled ./target-app.apk

# If the app is a split APK / AAB, get all parts first
adb shell pm path com.example.target
# package:/data/app/.../base.apk
# package:/data/app/.../split_config.arm64_v8a.apk
# ... then adb pull all of them and decompile each

# Check whether the app is protected by a packer/obfuscator
apkid ./target-app.apk
```

**Step 2 — Manifest Extraction (MASTG-TECH-0117)**

Three options, each with different characteristics:

```bash
# Option A: jadx — the MOST COMPLETE manifest, including the <uses-sdk> element
jadx --no-src -d out_dir ./target-app.apk
# -> out_dir/resources/AndroidManifest.xml

# Option B: apktool — fast with -s (skip baksmali)
apktool d -s -f -o output_dir ./target-app.apk
# -> output_dir/AndroidManifest.xml
# NOTE: <uses-sdk> is NOT here; its value is moved to apktool.yml:
cat output_dir/apktool.yml | grep -A2 sdkInfo
#   sdkInfo:
#     minSdkVersion: 29
#     targetSdkVersion: 35

# Option C: aapt2 — fastest for specific values. Output is NOT XML
aapt2 d badging ./target-app.apk
# package: name='org.owasp.mastestapp' versionCode='1' ... compileSdkVersion='35'
# sdkVersion:'29'
# targetSdkVersion:'35'
# uses-permission: name='android.permission.INTERNET'
```

> The choice of tool here has real consequences: if you use apktool and then search for `targetSdkVersion` in the manifest, you won't find it and could draw the wrong conclusion. Use jadx or aapt2 for SDK attributes.

**Step 3 — Permission Extraction (MASTG-TECH-0126)**

```bash
# Option A: from the decoded manifest
grep -E "uses-permission" out_dir/resources/AndroidManifest.xml

# Option B: aapt
aapt d permissions ./target-app.apk
# package: org.owasp.mastestapp
# uses-permission: name='android.permission.INTERNET'
# uses-permission: name='android.permission.CAMERA'
# uses-permission: name='android.permission.WRITE_EXTERNAL_STORAGE'
# uses-permission: name='android.permission.READ_EXTERNAL_STORAGE'

# Option C: adb — ADVANTAGE: shows the runtime GRANT status
adb shell dumpsys package com.example.target | grep -A30 permission
#     runtime permissions:
#       android.permission.WRITE_EXTERNAL_STORAGE: granted=false, flags=[ RESTRICTION_INSTALLER_EXEMPT]
```

> Option C provides information that cannot be obtained from pure static analysis: a permission that is **declared but never granted** has a lower real-world impact. This is useful for calibrating severity — though the declaration itself is still worth reporting as over-privilege.

**Step 4 — Pattern Matching with semgrep (MASTG-TECH-0014)**

The official MASTG rule for APIs — `mastg-android-data-unencrypted-shared-storage-no-user-interaction-apis.yml`:

```yaml
rules:
  - id: mastg-android-data-unencrypted-shared-storage-no-user-interaction-external-api-public
    severity: WARNING
    languages:
      - java
    metadata:
      summary: This rule looks for methods that returns locations to "external storage" which is shared with other apps
    message: "[MASVS-STORAGE] Make sure to encrypt files at these locations if necessary"
    pattern-either:
      - pattern: $X.getExternalStorageDirectory(...)
      - pattern: $X.getExternalStoragePublicDirectory(...)
      - pattern: $X.getDownloadCacheDirectory(...)
      - pattern: Intent.ACTION_CREATE_DOCUMENT

  - id: mastg-android-data-unencrypted-shared-storage-no-user-interaction-external-api-scoped
    severity: WARNING
    languages:
      - java
    metadata:
      summary: This rule looks for methods that returns locations to "scoped external storage"
    message: "[MASVS-STORAGE] These locations might be accessible to other apps on Android 10 and below given relevant permissions"
    pattern-either:
      - pattern: $X.getExternalFilesDir(...)
      - pattern: $X.getExternalFilesDirs(...)
      - pattern: $X.getExternalCacheDir(...)
      - pattern: $X.getExternalCacheDirs(...)
      - pattern: $X.getExternalMediaDirs(...)

  - id: mastg-android-data-unencrypted-shared-storage-no-user-interaction-mediastore
    severity: WARNING
    languages:
      - java
    metadata:
      summary: This rule scans for uses of MediaStore API that writes data to the external storage. This data can be accessed by other apps.
    message: "[MASVS-STORAGE] Make sure to want this data to be shared with other apps"
    pattern-either:
      - pattern: import android.provider.MediaStore
      - pattern: $X.MediaStore
```

The official MASTG rule for the manifest — `mastg-android-data-unencrypted-shared-storage-no-user-interaction-manifest.yml`:

```yaml
rules:
  - id: mastg-android-data-unencrypted-shared-storage-no-user-interaction-manifest
    severity: WARNING
    languages:
      - generic
    metadata:
      summary: This rule scans for permissions that allows your app to write to external storage or shared storage
    message: "[MASVS-STORAGE] Make sure to encrypt files in external storage if necessary"
    pattern-either:
      - pattern: WRITE_EXTERNAL_STORAGE
      - pattern: MANAGE_EXTERNAL_STORAGE
      - pattern: ACCESS_ALL_EXTERNAL_STORAGE
      - pattern: requestLegacyExternalStorage="true"
      - pattern: preserveLegacyExternalStorage="true"
      - pattern: android:requestRawExternalStorageAccess="true"
```

Running it (`run.sh` from MASTG-DEMO-0003):

```bash
NO_COLOR=true semgrep \
  -c ../../../../rules/mastg-android-data-unencrypted-shared-storage-no-user-interaction-apis.yml \
  ./MastgTest_reversed.java > output.txt

NO_COLOR=true semgrep \
  -c ../../../../rules/mastg-android-data-unencrypted-shared-storage-no-user-interaction-manifest.yml \
  ./AndroidManifest_reversed.xml > output2.txt
```

For a real-world app, run it on the entire decompiled directory:

```bash
# Scan the entire decompiled code
NO_COLOR=true semgrep \
  -c ./mastg/rules/mastg-android-data-unencrypted-shared-storage-no-user-interaction-apis.yml \
  ./decompiled/sources/ --json -o findings-apis.json

# Scan the manifest
NO_COLOR=true semgrep \
  -c ./mastg/rules/mastg-android-data-unencrypted-shared-storage-no-user-interaction-manifest.yml \
  ./out_dir/resources/AndroidManifest.xml -o findings-manifest.txt
```

**Step 5 — Supplementary Checks with grep (and Closing Blind Spots)**

The MASTG rules don't cover the entire surface. Supplement them with:

```bash
# Additional storage APIs not in the MASTG rules
grep -rnE "getExternalStorageState|getExternalStorageDirectory|getStorageDirectory|DIRECTORY_(DOWNLOADS|DOCUMENTS|PICTURES|DCIM|MUSIC|MOVIES)" ./decompiled/sources/

# The actual MediaStore/SAF write point (more meaningful than just the MediaStore import)
grep -rnE "ContentResolver|\.insert\(|openOutputStream|openFileDescriptor|createWriteRequest" ./decompiled/sources/

# DownloadManager — writes directly to shared storage
grep -rnE "DownloadManager|setDestinationInExternalPublicDir|setDestinationInExternalFilesDir" ./decompiled/sources/

# Hardcoded external storage path strings
grep -rnE "\"/sdcard|/storage/emulated|/mnt/sdcard|/storage/self/primary" ./decompiled/sources/

# HIGH DANGER: loading code from an external path (an indication of Man-in-the-Disk)
grep -rnE "DexClassLoader|PathClassLoader|System\.load\(|loadLibrary\(|InMemoryDexClassLoader" ./decompiled/sources/

# Indications of encryption on the write path (for assessing a possible PASS)
grep -rnE "EncryptedFile|CipherOutputStream|MasterKey|AndroidKeyStore|SQLCipher|Tink" ./decompiled/sources/

# Crypto weaknesses that invalidate the "already encrypted" claim
grep -rnE "AES/ECB|DES|RC4|SecretKeySpec\(\"|Base64\.encode" ./decompiled/sources/

# Scoped storage configuration & SDK attributes
grep -nE "requestLegacyExternalStorage|preserveLegacyExternalStorage|requestRawExternalStorageAccess|targetSdkVersion|minSdkVersion" \
  ./out_dir/resources/AndroidManifest.xml

# Native code — the semgrep rules don't reach this
for so in $(find ./decompiled -name "*.so"); do
  echo "--- $so"; strings "$so" | grep -E "/sdcard|/storage/emulated|getExternal"
done
```

**Step 6 — Review Every Found Location (MASTG-TECH-0023)** — **mandatory, not optional**

For every line reported by semgrep, open its location in jadx and answer three questions:

1. **Is this code path actually executed?** (not dead code / an unused library)
2. **What data is written there?** Trace the variable that goes into `write()` — does it come from user input, an API response, or a credential?
3. **Is there any encryption on this path?** Look for an `EncryptedFile` / `CipherOutputStream` frame; if present, check the cipher mode (reject ECB) and **the key's origin** (reject hardcoded).

```bash
# After semgrep reports, e.g., MastgTest.java:27, open its context
sed -n '15,45p' ./decompiled/sources/org/owasp/mastestapp/MastgTest.java

# Trace the variable being written to determine data sensitivity
grep -rn "fileContent\|getBytes\|\.write(" ./decompiled/sources/org/owasp/mastestapp/MastgTest.java
```

### 3.3 Alternative Testing Methods (Multi-Tool)

The MASTG semgrep rule has many gaps (see §3.5 note 4). Below are alternative paths that can be used standalone or for cross-verification.

#### Method B — apktool + grep/ripgrep *(most portable, no dependency)*

The main advantage: **catches any variable/constant name** and works on class-level field initializers — the two biggest gaps in the MASTG rule.

```bash
apktool d -f -o ./decoded ./target-app.apk
jadx -d ./decompiled ./target-app.apk
D=./decompiled/sources

# --- 1. "Public" shared storage API (Group A) ---
rg -n --no-heading "getExternalStorageDirectory|getExternalStoragePublicDirectory|getDownloadCacheDirectory" $D

# --- 2. Scoped external storage API (Group B) ---
rg -n --no-heading "getExternalFilesDirs?|getExternalCacheDirs?|getExternalMediaDirs" $D

# --- 3. MediaStore — search for the WRITE POINT, not just the import ---
rg -n --no-heading "ContentResolver|\.insert\(|openOutputStream|openFileDescriptor|createWriteRequest" $D
rg -n --no-heading "MediaStore\.(Downloads|Images|Video|Audio|Files)" $D

# --- 4. DownloadManager (not in the MASTG rule) ---
rg -n --no-heading "setDestinationInExternalPublicDir|setDestinationInExternalFilesDir|DownloadManager" $D

# --- 5. Hardcoded paths (not in the MASTG rule) ---
rg -n --no-heading '"/sdcard|/storage/emulated|/mnt/sdcard|/storage/self/primary' $D

# --- 6. Manifest permissions & flags — CATCH EVERYTHING, not just the default names ---
rg -o 'android:name="android\.permission\.[A-Z_]*(STORAGE|MEDIA)[A-Z_]*"' ./decoded/AndroidManifest.xml
rg -o 'android:(requestLegacyExternalStorage|preserveLegacyExternalStorage|requestRawExternalStorageAccess)="[^"]*"' ./decoded/AndroidManifest.xml

# --- 7. HIGH DANGER: loading code from external storage (Man-in-the-Disk) ---
rg -n --no-heading "DexClassLoader|PathClassLoader|InMemoryDexClassLoader|System\.load\(|loadLibrary\(" $D

# --- 8. Indicators of encryption on the write path (for assessing a PASS) ---
rg -n --no-heading "EncryptedFile|CipherOutputStream|MasterKey|AndroidKeyStore|SQLCipher|Tink" $D
```

#### Method C — aapt2 *(fastest for permissions, no decompilation)*

```bash
# Permissions + SDK attributes in a single command
aapt2 d badging ./target-app.apk | grep -E "uses-permission|sdkVersion|targetSdkVersion"

# Manifest tree — shows attributes not visible in badging
aapt2 d xmltree --file AndroidManifest.xml ./target-app.apk \
  | grep -iE "STORAGE|MEDIA|LegacyExternal|RawExternal"

# Batch-scan many APKs
for a in ./apks/*.apk; do
  echo "=== $a"
  aapt2 d badging "$a" 2>/dev/null | grep -E "MANAGE_EXTERNAL_STORAGE|WRITE_EXTERNAL_STORAGE"
done
```

> Remember the MASTG-TECH-0150 note: aapt2 outputs a **custom decoded format**, not XML — its attribute names differ.

#### Method D — MobSF *(GUI, report-ready)*

```bash
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
# Upload the APK via http://localhost:8000
```

What to look for in the report:

| MobSF Report Section | Relevant Finding |
|---|---|
| **Manifest Analysis** | `WRITE_EXTERNAL_STORAGE` / `MANAGE_EXTERNAL_STORAGE` flagged as *dangerous permission*; `requestLegacyExternalStorage` |
| **Code Analysis** | The *"App can read/write to external storage"* pattern |
| **Permissions** | List of permissions with severity classification |
| **Files** | List of bundled assets |

Advantage: severity and risk descriptions can be directly quoted into a report; it also simultaneously checks `debuggable`, `allowBackup`, and exported components in a single pass.

#### Method E — mobsfscan *(lightweight CLI for CI/CD)*

```bash
pip install mobsfscan
mobsfscan --json -o mobsfscan.json ./decompiled/sources/ ./decoded/
jq '.results | to_entries[] | select(.key | test("storage|external|permission"))' mobsfscan.json

# As a CI gate (non-zero exit code if there are findings)
mobsfscan --exit-warning ./decompiled/sources/
```

#### Method F — CodeQL *(taint analysis — answers "does sensitive data ACTUALLY flow to a storage API?")*

This is an advantage semgrep lacks: semgrep only does intra-file pattern matching, while CodeQL traces data flow across functions.

```bash
# Create a database from Java/Kotlin source (if available)
codeql database create ./cqldb --language=java --command="./gradlew assembleDebug"

# Relevant built-in query
codeql database analyze ./cqldb \
  codeql/java-queries:Security/CWE/CWE-312/CleartextStorageAndroidFilesystem.ql \
  --format=sarif-latest --output=results.sarif

# Read the results
jq '.runs[].results[] | {rule: .ruleId, msg: .message.text, loc: .locations[0].physicalLocation.artifactLocation.uri}' results.sarif
```

A custom query to map the flow to external storage:

```ql
/**
 * @name Sensitive data flows to external storage
 * @kind path-problem
 */
import java
import semmle.code.java.dataflow.TaintTracking

class ExternalStorageSink extends DataFlow::Node {
  ExternalStorageSink() {
    exists(MethodAccess ma |
      ma.getMethod().hasName(["getExternalFilesDir", "getExternalStorageDirectory",
                              "getExternalStoragePublicDirectory", "getExternalCacheDir"]) and
      this.asExpr() = ma
    )
  }
}
```

#### Method G — drozer *(audit from the device side)*

```bash
drozer console connect
dz> run app.package.info -a com.example.target        # permissions requested & granted
dz> run app.package.attacksurface com.example.target
dz> run scanner.misc.readablefiles --privileged /sdcard
dz> run scanner.misc.writablefiles --privileged /sdcard
```

#### Method H — `adb dumpsys` *(runtime grant status — information that CANNOT be obtained from static analysis)*

```bash
PKG=com.example.target

# Permissions with their grant status — severity calibration
adb shell dumpsys package $PKG | grep -A40 "requested permissions"
adb shell dumpsys package $PKG | grep -E "granted=(true|false)"

# The actual targetSdk as seen by the system
adb shell dumpsys package $PKG | grep -E "targetSdk|versionName"

# Check whether the app has All-files access (MANAGE_EXTERNAL_STORAGE)
adb shell appops get $PKG MANAGE_EXTERNAL_STORAGE
adb shell appops get $PKG LEGACY_STORAGE
```

> `appops get ... LEGACY_STORAGE` is very useful: it shows whether the system **actually** grants legacy access (scoped storage turned off) to this app — something not always readable from the manifest alone.

#### Method I — APKHunt & Other Scanners *(additional automated pass)*

```bash
# APKHunt — OWASP MASVS static analyzer
go install github.com/Cyber-Buddy/APKHunt@latest
APKHunt -p ./target-app.apk -l

# Semgrep registry rules (beyond the MASTG rule)
semgrep --config "p/mobsfscan" ./decompiled/sources/
semgrep --config "p/java" ./decompiled/sources/

# A third-party Android-specific rule set
git clone https://github.com/mindedsecurity/semgrep-rules-android-security
semgrep -c ./semgrep-rules-android-security/rules/ ./decompiled/sources/
```

#### Method J — jadx-gui *(manual, for obfuscated code)*

When the app is protected by a heavy obfuscator and pattern matching fails:

1. Open the APK in jadx-gui
2. **Search** (`Ctrl+Shift+F`) → look for `getExternalFilesDir`, `MediaStore`, `/sdcard` — framework API names are **not obfuscated**, so this remains effective
3. Right-click a method → **Find Usage** to trace callers
4. Rename identified symbols (press `N`) per MASTG-TECH-0023

#### Method K — Native Code Analysis *(the blind spot of all Java rules)*

```bash
unzip -o ./target-app.apk -d ./apk_x >/dev/null
for so in $(find ./apk_x -name "*.so"); do
  echo "--- $so"
  strings "$so" | grep -aE "/sdcard|/storage/emulated|getExternal|MediaStore" | head
done

# Deeper analysis if there is a hit
ghidra_headless ./project ./apk_x/lib/arm64-v8a/libnative.so   # or open in Ghidra GUI
```

---

### 3.4 Method Comparison: When to Use Which

| Method | Tool | Needs device? | Catches non-default names? | Taint analysis? | When to use |
|---|---|---|---|---|---|
| **A** | semgrep (MASTG) | No | ❌ | ❌ | Official baseline & CI gate |
| **B** | apktool + ripgrep | No | ✅ | ❌ | **Mandatory cross-verification** — most accurate for static |
| **C** | aapt2 | No | ✅ (permissions) | ❌ | Rapid triage of many APKs |
| **D** | MobSF | No | ✅ | ❌ | Report-ready output + broad audit at once |
| **E** | mobsfscan | No | ✅ | ❌ | Lightweight CI/CD gate |
| **F** | CodeQL | No | ✅ | ✅ | **Proves sensitive data flow** → reduces false positives |
| **G** | drozer | Yes | ✅ | ❌ | Part of a broader drozer session |
| **H** | `adb dumpsys` / `appops` | Yes | — | ❌ | **Severity calibration** — actual grant status & LEGACY_STORAGE |
| **I** | APKHunt / semgrep registry | No | ✅ | ❌ | Additional automated pass, broader rule coverage |
| **J** | jadx-gui manual | No | ✅ | Manual | Heavily obfuscated code |
| **K** | `strings` / Ghidra | No | ✅ | ❌ | Native code (`.so`) |

**Minimum recommended combination:** **B (apktool+ripgrep) → A (semgrep) → H (dumpsys)**.
B gives the most complete static coverage without naming gaps, A gives a MASTG-aligned baseline, H calibrates severity with actual grant status. Add **F (CodeQL)** if source code is available — it is the only one that can prove data flow. Add **K** if the APK bundles a `.so`.

---

### 3.5 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Observation:** *"The output should contain a list of APIs and storage-related permissions used to write to shared storage and their code locations."*
>
> **Evaluation:** *"The test case fails if **all of the following** apply:*
> - *the app has the proper permissions declared in the Android manifest (e.g. `WRITE_EXTERNAL_STORAGE`, `MANAGE_EXTERNAL_STORAGE`, etc.)*
> - *the app uses APIs that write to shared storage (e.g. `getExternalStoragePublicDirectory`, `getExternalStorageDirectory`, `getExternalFilesDir`, `getExternalCacheDir`, `MediaStore`, etc.)*
> - *the data being written to shared storage is sensitive and not encrypted."*
>
> **Further Validation Required** — inspect every reported code location using MASTG-TECH-0023 to determine whether the data is sensitive:
> - Determine whether the data written to shared storage contains sensitive information (e.g., personal data, credentials, or tokens).
> - Determine whether the data is stored without encryption.

#### ⚠️ A Critical Note on the First Condition

The official criteria state that all three conditions must be met (**"all of the following"**), including *"the app has the proper permissions declared in the Android manifest."* **This condition must not be applied literally**, because it contradicts MASTG's own demos:

- **MASTG-DEMO-0004** uses `getExternalFilesDir()` — an API that **requires no permission at all** (API 19+). Its manifest declares no storage permission. Yet MASTG still states: *"the test **fails** because the file written by this instance contains sensitive data, specifically a password."*
- **MASTG-DEMO-0005** uses MediaStore to write to `Downloads` — also **without a permission** for self-created files (API 29+). MASTG also states a **fail**.

So in practice, **the permission condition is contextual, not an absolute prerequisite**. The correct interpretation:

> **FAIL if: the app writes to shared/external storage using a relevant API, AND the data written is sensitive and unencrypted.**
>
> A permission declaration (`WRITE_EXTERNAL_STORAGE`, `MANAGE_EXTERNAL_STORAGE`, legacy flags) serves as a **finding reinforcer and severity multiplier** — not as a prerequisite that must exist. The absence of a permission does not turn a finding into a PASS, because scoped storage APIs and MediaStore genuinely don't need one.

The only genuinely mandatory **AND** is the last two conditions: **a write to shared storage occurs** AND **the data is sensitive and unencrypted**.

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition | Example evidence |
|---|---|---|
| F1 | Semgrep finds a call to a **public shared storage** API (Group A), and code review proves the data written is **sensitive & plaintext** | `27┆ File externalStorageDir = Environment.getExternalStorageDirectory();` + review shows a password being written |
| F2 | Semgrep finds a call to a **scoped external storage** API (Group B) with sensitive plaintext data | `25┆ File externalStorageDir = this.context.getExternalFilesDir(null);` + `"secr3tPa$$W0rd\n".getBytes(...)` |
| F3 | Semgrep finds use of **MediaStore** to write sensitive data to shared storage | `35┆ Uri textUri = resolver.insert(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, contentValues);` + `"MAS_API_KEY=8767086b9f6f976g-a8df76\n"` |
| F4 | The manifest declares **`MANAGE_EXTERNAL_STORAGE`** ("All files access") and the app writes sensitive data to shared storage | `2┆ <uses-permission android:name="android.permission.MANAGE_EXTERNAL_STORAGE"/>` + finding F1 |
| F5 | The manifest contains a **scoped-storage opt-out flag** (`requestLegacyExternalStorage="true"` / `preserveLegacyExternalStorage="true"` / `requestRawExternalStorageAccess="true"`) along with a sensitive data write | Manifest rule result + finding F1/F2/F3 → **severity raised** |
| F6 | A **high-risk deprecated API** (`getExternalStorageDirectory`, `getExternalStoragePublicDirectory`) is found in an app with a modern `targetSdkVersion` | Indicates legacy code not yet migrated; assess the data it writes |
| F7 | A **hardcoded external storage path** is found followed by a sensitive data write operation | `grep` → `"/sdcard/MyApp/credentials.json"` |
| F8 | The "encryption" found on the write path is merely **encoding/obfuscation** or weak crypto | `Base64.encode(...)` before `write()`; or `SecretKeySpec(key, "AES/ECB/PKCS7Padding")` |
| F9 | Encryption is found, but **the key is hardcoded** or derived from a static value | `new SecretKeySpec("hardcodedkey123".getBytes(), "AES")` in jadx |
| F10 | Loading of **executable code** from an external storage path without an integrity check is found | `DexClassLoader` / `System.load()` with a `/sdcard` path argument → **Man-in-the-Disk / code injection**, critical severity |
| F11 | `DownloadManager.setDestinationInExternalPublicDir()` is used to download sensitive data | Sensitive data lands on shared storage and persists post-uninstall |
| F12 | Native code (`.so`) contains an external storage path string along with a write operation | `strings lib.so` → `/storage/emulated/0/...` — a blind spot for the semgrep rules |

**Example output indicating FAIL — MASTG-DEMO-0003** (`getExternalStorageDirectory` + `MANAGE_EXTERNAL_STORAGE`):

`output.txt` (code scan result):
```
┌────────────────┐
│ 1 Code Finding │
└────────────────┘

    MastgTest_reversed.java
    ❯❱ rules.mastg-android-data-unencrypted-shared-storage-no-user-interaction-external-api-public
          [MASVS-STORAGE] Make sure to encrypt files at these locations if necessary

           27┆ File externalStorageDir = Environment.getExternalStorageDirectory();
```

`output2.txt` (manifest scan result):
```
┌────────────────┐
│ 1 Code Finding │
└────────────────┘

    AndroidManifest_reversed.xml
    ❯❱ rules.mastg-android-data-unencrypted-shared-storage-no-user-interaction-manifest
          [MASVS-STORAGE] Make sure to encrypt files in external storage if necessary

            2┆ <uses-permission android:name="android.permission.MANAGE_EXTERNAL_STORAGE"/>
```

The source code and its decompiled result:

```kotlin
// MastgTest.kt — original source
val externalStorageDir = Environment.getExternalStorageDirectory()
val fileName = File(externalStorageDir, "secret.txt")
val fileContent = "Secret not using scoped storage"
FileOutputStream(fileName).use { output ->
    output.write(fileContent.toByteArray())
}
```

```java
// MastgTest_reversed.java — what semgrep sees (line 27)
public final String mastgTest() {
    File externalStorageDir = Environment.getExternalStorageDirectory();
    File fileName = new File(externalStorageDir, "secret.txt");
    try {
        FileOutputStream fileOutputStream = new FileOutputStream(fileName);
        byte[] bytes = "Secret not using scoped storage".getBytes(Charsets.UTF_8);
        output.write(bytes);
        ...
```

```xml
<!-- AndroidManifest.xml -->
<uses-permission android:name="android.permission.MANAGE_EXTERNAL_STORAGE" />
```

MASTG's evaluation: *"After reviewing the decompiled code at the location specified in the output (file and line number) we can conclude that the test **fails** because the file written by this instance contains sensitive data, specifically a password."*

This is the **most severe** of the three demos: a deprecated API to the shared storage root **plus** `MANAGE_EXTERNAL_STORAGE`, which fully bypasses scoped storage.

---

**Example output indicating FAIL — MASTG-DEMO-0004** (`getExternalFilesDir`, scoped storage active, **with no permission at all**):

```
┌────────────────┐
│ 1 Code Finding │
└────────────────┘

    MastgTest_reversed.java
    ❯❱ rules.mastg-android-data-unencrypted-shared-storage-no-user-interaction-external-api-scoped
          [MASVS-STORAGE] These locations might be accessible to other apps on Android 10 and below given
          relevant permissions

           25┆ File externalStorageDir = this.context.getExternalFilesDir(null);
```

```java
// MastgTest_reversed.java
File externalStorageDir = this.context.getExternalFilesDir(null);      // <-- line 25
File fileName = new File(externalStorageDir, "secret.txt");
FileOutputStream fileOutputStream = new FileOutputStream(fileName);
byte[] bytes = "secr3tPa$$W0rd\n".getBytes(Charsets.UTF_8);            // <-- plaintext password
output.write(bytes);
```

MASTG's evaluation: *"the test **fails** because the file written by this instance contains sensitive data, specifically a password."*

**This is the demo most important to understand.** This app:
- Targets Android 12 (API 31) → **scoped storage is active**
- Uses `getExternalFilesDir()` → path `/storage/emulated/0/Android/data/org.owasp.mastestapp/files`
- **Declares no storage permission at all** (none needed)

Still a **FAIL**. This is direct proof that scoped storage and the absence of a permission **do not** make storing plaintext sensitive data on external storage acceptable — the file remains readable by the user via MTP/USB, on a rooted device, by third-party backup services, and by apps with `MANAGE_EXTERNAL_STORAGE`. This also confirms that the "permission declared" condition in the official evaluation criteria must not be read as an absolute prerequisite.

---

**Example output indicating FAIL — MASTG-DEMO-0005** (MediaStore API):

```
┌─────────────────┐
│ 2 Code Findings │
└─────────────────┘

    MastgTest_reversed.java
    ❯❱ rules.mastg-android-data-unencrypted-shared-storage-no-user-interaction-mediastore
          [MASVS-STORAGE] Make sure to want this data to be shared with other apps

            8┆ import android.provider.MediaStore;
            ⋮┆----------------------------------------
           35┆ Uri textUri = resolver.insert(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, contentValues);
```

MASTG explains: *"The first location is the import statement for the `MediaStore` API and the second location is where the `MediaStore` API is used to write to shared storage."*

```java
// MastgTest_reversed.java
ContentResolver resolver = this.context.getContentResolver();
ContentValues contentValues = new ContentValues();
contentValues.put("_display_name", "secretFile.txt");
contentValues.put("mime_type", "text/plain");
contentValues.put("relative_path", Environment.DIRECTORY_DOCUMENTS);
Uri textUri = resolver.insert(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, contentValues);  // <-- line 35
if (textUri != null) {
    OutputStream outputStream = resolver.openOutputStream(textUri);
    byte[] bytes = "MAS_API_KEY=8767086b9f6f976g-a8df76\n".getBytes(Charsets.UTF_8);        // <-- plaintext API key
    it.write(bytes);
```

MASTG's evaluation: *"the test **fails** because the file written by this instance contains sensitive data, specifically a API key."*

Two technical notes on this demo worth keeping in mind when replicating it:

1. **The first finding (line 8) is merely an `import` statement** — not proof of a write. The MASTG MediaStore rule is deliberately broad (`pattern: import android.provider.MediaStore`), making it prone to false positives: an app that only **reads** the photo gallery would also trigger it. This is a concrete example of why the manual review step (MASTG-TECH-0023) is mandatory, not optional.
2. **There is a small discrepancy between the `.kt` and `.java` artifacts in this demo.** The Kotlin source uses `MediaStore.Downloads.EXTERNAL_CONTENT_URI` + `DIRECTORY_DOWNLOADS`, while the decompiled Java (which semgrep scans) uses `MediaStore.Images.Media.EXTERNAL_CONTENT_URI` + `DIRECTORY_DOCUMENTS` — indicating the two artifacts came from different builds. This doesn't affect the test's conclusion, but don't be confused if you compare the two.

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition | Example evidence |
|---|---|---|
| P1 | **Semgrep finds no findings at all** in either the code or the manifest | `0 Code Findings` on both scans; no storage `uses-permission`; no legacy flag |
| P2 | There is an external storage API finding, but code review (MASTG-TECH-0023) proves the data written is **not sensitive** | `getExternalCacheDir()` used for caching a public image thumbnail / map tile / `.nomedia` file |
| P3 | There is an external storage API finding with sensitive data, but review proves the data is **correctly encrypted** — AES-256-GCM with a key from the Android KeyStore | The write path passes through `EncryptedFile.openFileOutput()` with `MasterKey.KeyScheme.AES256_GCM`; no hardcoded key |
| P4 | A finding is merely **dead code / a library that is never executed** | The finding's location is in a class that is never referenced; confirmed with a call-graph in jadx **and** with MASTG-TEST-0201 (never appears in the runtime trace) |
| P5 | A finding is an `Intent.ACTION_CREATE_DOCUMENT` / SAF where **the user explicitly chooses the location**, and the exported data contains no credentials/tokens | An "Export report" feature triggered by the user; the resulting file contains no secret. *(Still noted as informational.)* |
| P6 | All sensitive data is proven to be written to **internal storage** | Only `context.getFilesDir()` / `openFileOutput(..., MODE_PRIVATE)` appears; no external API |
| P7 | The manifest is **clean**: no `WRITE_EXTERNAL_STORAGE` / `MANAGE_EXTERNAL_STORAGE` / `ACCESS_ALL_EXTERNAL_STORAGE`, no scoped-storage opt-out flag, and `targetSdkVersion` ≥ 30 | The manifest rule → `0 Code Findings`; `aapt2 d badging` → `targetSdkVersion:'35'` |

**Example output indicating PASS:**

```bash
$ NO_COLOR=true semgrep -c mastg-...-apis.yml ./decompiled/sources/
┌──────────────────┐
│ 0 Code Findings  │
└──────────────────┘

$ NO_COLOR=true semgrep -c mastg-...-manifest.yml ./out_dir/resources/AndroidManifest.xml
┌──────────────────┐
│ 0 Code Findings  │
└──────────────────┘

$ aapt d permissions ./target-app.apk
package: com.example.secureapp
uses-permission: name='android.permission.INTERNET'
# -> no storage permission at all
```

or — there is a finding, but review proves correct encryption:

```
    SecureVault.java
    ❯❱ rules.mastg-android-data-unencrypted-shared-storage-no-user-interaction-external-api-scoped
           41┆ File dir = this.context.getExternalFilesDir(null);
```

Review in jadx at that location:

```java
// SecureVault.java:41-52 — sensitive data, but encrypted with a key from the KeyStore
File dir = this.context.getExternalFilesDir(null);
MasterKey masterKey = new MasterKey.Builder(this.context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build();
EncryptedFile encryptedFile = new EncryptedFile.Builder(
        this.context,
        new File(dir, "vault.bin"),
        masterKey,
        EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
).build();
OutputStream out = encryptedFile.openFileOutput();
out.write(sensitiveBytes);
```

Reinforced by a negative verification:

```bash
# No hardcoded key or weak crypto
$ grep -rnE "SecretKeySpec\(\"|AES/ECB|\"DES\"|RC4" ./decompiled/sources/
# (no result)
```

---

#### ⚠️ Important Notes on Assessment

1. **A semgrep finding alone is NOT a vulnerability.** This is the most common mistake made with this test. The MASTG rule is *indicative* — its very message reads *"Make sure to encrypt files at these locations **if necessary**"*, i.e., a warning to be reviewed, not a vulnerability statement. Reporting raw semgrep output as a vulnerability list is incorrect practice. The **Further Validation Required** step (MASTG-TECH-0023) is mandatory.

2. **The MediaStore rule is highly prone to false positives.** The patterns `import android.provider.MediaStore` and `$X.MediaStore` will trigger even on an app that only **reads** the gallery, or that doesn't functionally use that import at all. Always confirm against the actual write point: `ContentResolver.insert()` + `openOutputStream()`.

3. **The manifest rule uses `languages: generic`** with a plain string pattern. The consequence: it will match the string `WRITE_EXTERNAL_STORAGE` **anywhere** — including inside a comment, another attribute's value, or even in a non-manifest file. Verify that the match is genuinely inside a `<uses-permission>` element.

4. **Empty output ≠ automatic PASS.** Causes of a false pass on a static test:
   - **Heavy obfuscation/packing** — the code is encrypted or loaded at runtime, so it's invisible to semgrep.
   - **Native code** — writes from a `.so` are not reached by the Java rules.
   - **Reflection** — `Class.forName("android.os.Environment").getMethod("getExternalStorageDirectory")` doesn't match the pattern.
   - **Split APK / dynamic feature module** not included in the analysis.
   - **Code loaded at runtime** via `DexClassLoader` from a network source.

   **Mitigation:** run APKiD to detect protections, analyze all split APKs, grep strings in `.so` files, search for reflection patterns, and **always correlate** with MASTG-TEST-0200 (filesystem diff — fully API-agnostic). If TEST-0200 finds a new file while TEST-0202 is clean, static analysis has a blind spot.

5. **The "permission declared" condition is not an absolute prerequisite** — see the discussion in §3.3. Scoped storage and MediaStore APIs do not require a permission, yet MASTG-DEMO-0004 and 0005 are both still declared FAIL.

6. **A permission without a matching API call is still worth reporting** as a separate finding (over-privilege, CWE-250), though with lower severity. A leftover `WRITE_EXTERNAL_STORAGE` widens the attack surface for no benefit; a leftover `MANAGE_EXTERNAL_STORAGE` even risks Google Play review rejection.

7. **Distinguish the origin of a finding.** Check whether the finding's location is in the app's own package or in a third-party library package (`com.google.*`, `com.facebook.*`, `io.*`). A finding in a library is still the app developer's responsibility, but the remediation differs (update/configure/replace vendor, not edit code).

8. **Severity is modulated by a combination of factors:**

   | Factor | Effect on Severity |
   |---|---|
   | Plaintext sensitive data on public shared storage (`Download/`, `Documents/`, MediaStore) | **Highest** — readable by other apps + persists post-uninstall |
   | `MANAGE_EXTERNAL_STORAGE` declared | Raised — fully bypasses scoped storage |
   | `requestLegacyExternalStorage="true"` with target ≤ API 29 | Raised — active cross-app exposure |
   | `targetSdkVersion` ≤ 29 | Raised — scoped storage not enforced |
   | Plaintext sensitive data in an app-specific external directory, target ≥ API 30 | Medium — still FAIL, but protected from other apps |
   | Loading code from external storage | **Critical** — regardless of data sensitivity |
   | Permission declared but never granted (`dumpsys` → `granted=false`) | Slightly lowered — lower real impact, but the declaration is still reported |

9. **Document complete evidence per finding:** the triggered rule ID, file path + line number, the decompiled code snippet, the MASTG-TECH-0023 review result (data type + presence/absence of encryption), the permission status from the manifest and from `dumpsys`, `targetSdkVersion`/`minSdkVersion`, and correlation with TEST-0200/0201 results. Also note applicable limitations (obfuscation, unanalyzed native code) so the report's reader understands the confidence boundaries of the result.

---

## 4. Recommendations

The root cause is the same as MASTG-TEST-0200 and 0201 (MASWE-0002). This test's advantage for remediation: it gives a **complete list of all code locations** that need fixing — not just the ones that happen to execute during dynamic testing. Treat semgrep output as a remediation *worklist*.

### 4.1 Core Principles (in priority order)

**Priority 1 — Remove external storage API calls for sensitive data.**

```kotlin
// ❌ WRONG — detected by the "external-api-public" rule (DEMO-0003)
val dir = Environment.getExternalStorageDirectory()
FileOutputStream(File(dir, "secret.txt")).use { it.write(password.toByteArray()) }

// ❌ WRONG — detected by the "external-api-scoped" rule (DEMO-0004)
val dir = context.getExternalFilesDir(null)
FileOutputStream(File(dir, "secret.txt")).use { it.write(password.toByteArray()) }

// ❌ WRONG — detected by the "mediastore" rule (DEMO-0005)
val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, contentValues)
resolver.openOutputStream(uri!!)?.use { it.write(apiKey.toByteArray()) }

// ✅ CORRECT — internal storage, detected by no rule at all
context.openFileOutput("secret.txt", Context.MODE_PRIVATE).use { it.write(data) }
// or
File(context.filesDir, "secret.txt").writeBytes(data)
```

Never use `MODE_WORLD_READABLE` / `MODE_WORLD_WRITEABLE` (deprecated since API 17, throws a `SecurityException` since API 24).

**Priority 2 — Clean risky permissions and flags from the manifest.**

```xml
<!-- ❌ REMOVE all of this if not truly needed -->
<uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" />
<uses-permission android:name="android.permission.MANAGE_EXTERNAL_STORAGE" />
<application
    android:requestLegacyExternalStorage="true"
    android:preserveLegacyExternalStorage="true"
    android:requestRawExternalStorageAccess="true">

<!-- ✅ CORRECT — modern target, scoped storage forced active, granular permission -->
<uses-permission android:name="android.permission.READ_MEDIA_IMAGES" />
<application android:requestLegacyExternalStorage="false">
```

- Target **Android 11 (API 30) and above** — scoped storage is forced active by the OS and `requestLegacyExternalStorage` is ignored.
- `WRITE_EXTERNAL_STORAGE` already **has no effect** on API 30+ — if it's still present, it's almost always a leftover that should be removed.
- Avoid `MANAGE_EXTERNAL_STORAGE` unless truly required (file manager, antivirus, backup app) — restricted by Google Play policy and requires justification during review.
- If you only need to pick a photo: use the **Photo Picker** (no permission at all), not `READ_MEDIA_IMAGES`.

**Priority 3 — Replace detected deprecated APIs.**

| API Detected | Correct Replacement |
|---|---|
| `Environment.getExternalStorageDirectory()` | `context.filesDir` (sensitive data) or `context.getExternalFilesDir()` (large non-sensitive files) |
| `Environment.getExternalStoragePublicDirectory()` | MediaStore API / Storage Access Framework — **only for non-sensitive data** |
| `WRITE_EXTERNAL_STORAGE` + direct `File` API | MediaStore (media) / SAF (documents) / internal storage (sensitive) |
| Putting a file in `/sdcard` so it can be shared with another app | **FileProvider** + `content://` URI with a temporary permission grant |
| `DownloadManager.setDestinationInExternalPublicDir()` for sensitive data | Download to `context.filesDir` via the app's own HTTP client |

**Priority 4 — Use the correct storage mechanism per data type.**

| Data Type | Correct Mechanism |
|---|---|
| Cryptographic keys | **Android KeyStore** (`setUserAuthenticationRequired`, StrongBox if available) |
| Password, token, API key | Avoid storage where possible (a session token can stay in memory). If needed: encrypt with a KeyStore key in internal storage |
| Sensitive key-value preferences | Internal storage + encryption. Note: Jetpack Security `androidx.security:security-crypto` is now **deprecated** — consider your own AES-GCM with a KeyStore key, or **Google Tink** |
| Structured data | Room + **SQLCipher**, in internal storage |
| Large app-owned files | Internal storage; if size forces external, encryption is mandatory (Priority 5) |
| Files genuinely meant to be shared | MediaStore / SAF — **non-sensitive data only**, ideally following an explicit user action |

**Priority 5 — If external storage is unavoidable: encrypt with a key from the KeyStore.**

```kotlin
val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build()

val encryptedFile = EncryptedFile.Builder(
    context,
    File(context.getExternalFilesDir(null), "data.enc"),
    masterKey,
    EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
).build()

encryptedFile.openFileOutput().use { it.write(sensitiveBytes) }
```

Requirements to be considered adequate:
- **AES-256-GCM** or ChaCha20-Poly1305 (authenticated encryption). Reject ECB, DES/3DES/RC4, CBC without a MAC.
- Random IV/nonce per operation, never repeated.
- The key is **generated & stored in the Android KeyStore** — not hardcoded, not derived from a static value (IMEI, package name, constant), not written to external storage.
- If the key is derived from a user password: a strong KDF (high-iteration PBKDF2 / **Argon2id** / scrypt) with a random salt.

> **Important consequence:** after this remediation, the semgrep finding **will still appear** (the call to `getExternalFilesDir` still exists). What changes is the result of the MASTG-TECH-0023 review: the data is proven encrypted → PASS (P3). So don't judge remediation success purely by the number of semgrep findings dropping to zero.

**Priority 6 — Validate input & integrity for data READ from external storage** (Man-in-the-Disk mitigation; closes finding F10).

- **Never** load executable code (DEX, SO, APK, JS bundle, script) from external storage. If grep finds `DexClassLoader` / `System.load()` with an `/sdcard` path, remove it entirely.
- Strict validation: size, MIME type, magic bytes, schema structure, value bounds. Do not deserialize Java/Kotlin objects from an external storage file.
- Prevent path traversal & symlink attacks: canonicalize the path (`File.canonicalPath`), ensure it stays within the permitted directory.
- Verify integrity with a **keyed HMAC-SHA256** from the KeyStore or AEAD (AES-GCM) — not a bare hash stored next to the file.

### 4.2 Additional Practice Improvements

- **Integrate this test into CI/CD.** This is the biggest advantage of a static test: no device or root required. Run semgrep with the MASTG rule (or mobsfscan) on every PR, and fail the build if a new finding appears outside an allowlist. This prevents regressions — including ones introduced via a library update.

```bash
# Example CI gate
semgrep --config ./mastg/rules/ --error --json -o findings.json ./app/src/
# --error makes the exit code non-zero if there are findings
```

- **Create an explicit allowlist** for intentional, already-encrypted external storage calls, with a justification comment in the code. This makes subsequent reviews fast and distinguishes a design decision from an unintentional leak.
- **Audit third-party libraries.** Run semgrep on the decompiled library code too, not just the app's own code.
- **Data minimization.** Don't store what doesn't need to be stored; use short-lived refresh tokens.
- **Direct caching to internal storage** (`context.cacheDir`) instead of `getExternalCacheDir()`.
- **Disable verbose logging in release builds** (`BuildConfig.DEBUG`); ensure the crash handler doesn't write a dump to external storage.
- **Exclude sensitive files from backup** (`android:allowBackup="false"` or `dataExtractionRules`/`fullBackupContent`) — see MASWE-0006.
- **Supplement with taint analysis.** Semgrep does intra-file pattern matching. To prove whether sensitive data **actually flows** to a storage API, use **CodeQL** (query `java/android-cleartext-storage-filesystem`), which can perform cross-function taint analysis.

### 4.3 Remediation Checklist

- [ ] Every code location from the semgrep output has been reviewed with MASTG-TECH-0023 and classified (sensitive/not, encrypted/not)
- [ ] No sensitive data (credentials, tokens, PII, financial data) is written to external/shared storage
- [ ] `Environment.getExternalStorageDirectory()` and `getExternalStoragePublicDirectory()` (deprecated) have been removed from the code
- [ ] Writes via MediaStore are only for non-sensitive data
- [ ] Sensitive data is stored in internal storage (`context.filesDir`, `openFileOutput(..., MODE_PRIVATE)`)
- [ ] No use of `MODE_WORLD_READABLE` / `MODE_WORLD_WRITEABLE`
- [ ] If external storage is still used: data is encrypted with AES-256-GCM using a key from the Android KeyStore
- [ ] No hardcoded key/secret (`SecretKeySpec("...")`) and no weak crypto (ECB/DES/RC4)
- [ ] `WRITE_EXTERNAL_STORAGE` is removed from the manifest (has no effect on API 30+)
- [ ] `MANAGE_EXTERNAL_STORAGE` and `ACCESS_ALL_EXTERNAL_STORAGE` are not declared (unless with strong justification + Play approval)
- [ ] `requestLegacyExternalStorage`, `preserveLegacyExternalStorage`, `requestRawExternalStorageAccess` are not set to `true`
- [ ] `targetSdkVersion` ≥ 30 (ideally following the latest Play requirement)
- [ ] Minimal storage permissions; use Photo Picker / SAF / granular `READ_MEDIA_*`
- [ ] No executable code (DEX/SO/APK/JS) is loaded from external storage
- [ ] Data read from external storage is validated and integrity-verified (HMAC/AEAD with a KeyStore key)
- [ ] Cache is directed to `context.cacheDir`, not `getExternalCacheDir()`
- [ ] Verbose logging & crash dumps to external storage are disabled in release builds
- [ ] Third-party libraries have been audited (semgrep also run on library code)
- [ ] Native code (`.so`) has been checked for external storage path strings
- [ ] All split APKs / dynamic feature modules are included in the analysis
- [ ] The semgrep scan is integrated into CI/CD as a gate, with a documented allowlist
- [ ] **Re-verify:** rerun MASTG-TEST-0202 → zero findings, or all remaining findings proven encrypted/non-sensitive
- [ ] **Cross-verify:** run MASTG-TEST-0200 (filesystem diff) and MASTG-TEST-0201 (hooking) to close static-analysis blind spots

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0202: References to APIs and Permissions for Accessing External Storage](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0202/)
- [MASTG-TEST-0200: Files Written to External Storage](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0200/)
- [MASTG-TEST-0201: Runtime Use of APIs to Access External Storage](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0201/)
- [MASTG-TEST-0001: Testing Local Storage for Sensitive Data](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0001/)
- [MASWE-0002: Sensitive Data Stored Unencrypted Outside of Private Storage](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0002/)
- [MASTG-DEMO-0003: App Writing to External Storage without Scoped Storage Restrictions](https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0003/MASTG-DEMO-0003/)
- [MASTG-DEMO-0004: App Writing to External Storage with Scoped Storage Restrictions](https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0004/MASTG-DEMO-0004/)
- [MASTG-DEMO-0005: App Writing to External Storage via the MediaStore API](https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0005/MASTG-DEMO-0005/)
- [MASTG-DEMO-0001: File System Snapshots from External Storage](https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0001/MASTG-DEMO-0001/)
- [MASTG-DEMO-0002: External Storage APIs Tracing with Frida](https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0002/MASTG-DEMO-0002/)
- [MASTG-KNOW-0042: External Storage](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0042/)
- [MASTG-TECH-0013: Reverse Engineering Android Apps](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/)
- [MASTG-TECH-0014: Static Analysis on Android](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/)
- [MASTG-TECH-0017: Decompiling Java Code](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0017/)
- [MASTG-TECH-0023: Reviewing Decompiled Java Code](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/)
- [MASTG-TECH-0117: Obtaining Information from the AndroidManifest](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0117/)
- [MASTG-TECH-0126: Obtaining App Permissions](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0126/)
- [MASTG-TOOL-0110: semgrep](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/)
- [MASTG-TOOL-0018: jadx](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/)
- [MASTG-TOOL-0011: apktool](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0011/)
- [MASTG-TOOL-0124: aapt2](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0124/)
- [MASTG Rules — the `rules/` directory in the OWASP/mastg repo](https://github.com/OWASP/mastg/tree/master/rules)
- [MASVS-STORAGE: Storage](https://mas.owasp.org/MASVS/05-MASVS-STORAGE/)
- [OWASP Mobile Top 10 2024 — M9: Insecure Data Storage](https://owasp.org/www-project-mobile-top-10/2023-risks/m9-insecure-data-storage)

### 5.2 Static Analysis Tools (Outside MASTG)

- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [Semgrep — Pattern syntax reference](https://semgrep.dev/docs/writing-rules/pattern-syntax/)
- [Semgrep — Rule syntax (`pattern-either`, metavariables)](https://semgrep.dev/docs/writing-rules/rule-syntax/)
- [mobsfscan — static analysis for Android/iOS based on semgrep + libsast](https://github.com/MobSF/mobsfscan)
- [mobsfscan — semgrep rules for Android](https://github.com/MobSF/mobsfscan/tree/main/mobsfscan/rules/semgrep/android)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
- [IMQ Minded Security — Semgrep Rules for Android Application Security](https://blog.mindedsecurity.com/2023/10/semgrep-rules-for-android-application.html)
- [IMQ Intuity — Semgrep Rules for Android Application Security](https://www.intuity.it/2023/10/23/semgrep-rules-for-android-application-security-2/)
- [mindedsecurity/semgrep-rules-android-security](https://github.com/mindedsecurity/semgrep-rules-android-security)
- [CodeQL — Cleartext storage of sensitive information in the Android filesystem](https://codeql.github.com/codeql-query-help/java/java-android-cleartext-storage-filesystem/)
- [CodeQL — Java/Kotlin query help](https://codeql.github.com/codeql-query-help/java/)
- [SonarQube Rule java:S5324 — Accessing Android external storage is security-sensitive](https://rules.sonarsource.com/java/RSPEC-5324/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [apktool — Reverse engineering Android APK files](https://apktool.org/)
- [aapt2 — Android Asset Packaging Tool](https://developer.android.com/tools/aapt2)
- [APKiD — Android Application Identifier (packer/obfuscator detection)](https://github.com/rednaga/APKiD)
- [bundletool — working with the Android App Bundle](https://developer.android.com/tools/bundletool)
- [Ghidra — software reverse engineering framework (`.so` analysis)](https://ghidra-sre.org/)
- [TruffleHog — secret scanning](https://github.com/trufflesecurity/trufflehog)

### 5.3 Official Android / Google Documentation

- [Sensitive Data Stored in External Storage — Android Security Risks](https://developer.android.com/privacy-and-security/risks/sensitive-data-external-storage)
- [Data and file storage overview](https://developer.android.com/training/data-storage)
- [Access app-specific files](https://developer.android.com/training/data-storage/app-specific)
- [Scoped storage](https://developer.android.com/training/data-storage#scoped-storage)
- [Storage use cases and best practices](https://developer.android.com/training/data-storage/use-cases)
- [Access media files from shared storage (MediaStore)](https://developer.android.com/training/data-storage/shared/media)
- [Access documents and other files (Storage Access Framework)](https://developer.android.com/training/data-storage/shared/documents-files)
- [Manage all files on a storage device (`MANAGE_EXTERNAL_STORAGE`)](https://developer.android.com/training/data-storage/manage-all-files)
- [All files access (Android 11 privacy)](https://developer.android.com/preview/privacy/storage#all-files-access)
- [`<uses-permission>` element](https://developer.android.com/guide/topics/manifest/uses-permission-element)
- [`Environment` — API reference](https://developer.android.com/reference/android/os/Environment)
- [`Context.getExternalFilesDir()` — API reference](https://developer.android.com/reference/android/content/Context#getExternalFilesDir(java.lang.String))
- [`MediaStore` — API reference](https://developer.android.com/reference/android/provider/MediaStore)
- [`R.attr.requestLegacyExternalStorage`](https://developer.android.com/reference/android/R.attr#requestLegacyExternalStorage)
- [`R.attr.preserveLegacyExternalStorage`](https://developer.android.com/reference/android/R.attr#preserveLegacyExternalStorage)
- [`EncryptedFile` (Jetpack Security)](https://developer.android.com/reference/androidx/security/crypto/EncryptedFile)
- [Android Keystore system](https://developer.android.com/privacy-and-security/keystore)
- [Cryptography best practices](https://developer.android.com/privacy-and-security/cryptography)
- [App security best practices — Store data safely](https://developer.android.com/privacy-and-security/security-best-practices#external-storage)
- [Security tips — Using external storage](https://developer.android.com/privacy-and-security/security-tips#external-storage)
- [FileProvider](https://developer.android.com/reference/androidx/core/content/FileProvider)
- [Photo picker](https://developer.android.com/training/data-storage/shared/photopicker)
- [Google Play — Use of the All files access permission](https://support.google.com/googleplay/android-developer/answer/10467955)
- [Google Tink — cryptographic library](https://developers.google.com/tink)

### 5.4 Standards, Taxonomy, and Other Guidelines

- [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
- [CWE-921: Storage of Sensitive Data in a Mechanism without Access Control](https://cwe.mitre.org/data/definitions/921.html)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [CWE-250: Execution with Unnecessary Privileges](https://cwe.mitre.org/data/definitions/250.html)
- [CWE-732: Incorrect Permission Assignment for Critical Resource](https://cwe.mitre.org/data/definitions/732.html)
- [SEI CERT Android — DRD00: Do not store sensitive information on external storage (SD card) unless encrypted first](https://wiki.sei.cmu.edu/confluence/display/android/DRD00.+Do+not+store+sensitive+information+on+external+storage+%28SD+card%29+unless+encrypted+first)
- [NIST SP 800-163 Rev.1 — Vetting the Security of Mobile Applications](https://csrc.nist.gov/publications/detail/sp/800-163/rev-1/final)
- [NIST SP 800-124 Rev.2 — Guidelines for Managing the Security of Mobile Devices](https://csrc.nist.gov/publications/detail/sp/800-124/rev-2/final)
- [MITRE ATT&CK Mobile — T1533: Data from Local System](https://attack.mitre.org/techniques/T1533/)
- [MITRE ATT&CK Mobile — T1409: Stored Application Data](https://attack.mitre.org/techniques/T1409/)

### 5.5 Security Research & Technical Articles

- [Check Point Research — Man-in-the-Disk: Android Apps Exposed via External Storage](https://research.checkpoint.com/2018/androids-man-in-the-disk/)
- [Check Point Blog — Man-in-the-Disk: A New Attack Surface for Android Apps](https://blog.checkpoint.com/security/man-in-the-disk-a-new-attack-surface-for-android-apps/)
- [Threatpost — DEF CON 2018: 'Man in the Disk' Attack Surface Affects All Android Phones](https://threatpost.com/def-con-2018-man-in-the-disk-attack-surface-affects-all-android-phones/134993/)
- [The Hacker News — New Man-in-the-Disk attack leaves millions of Android phones vulnerable](https://thehackernews.com/2018/08/man-in-the-disk-android-hack.html)
- [NDSS 2025 — ScopeVerif: Analyzing the Security of Android's Scoped Storage via Differential Analysis](https://www.ndss-symposium.org/wp-content/uploads/2025-340-paper.pdf)
- [PolyScope: Multi-Policy Access Control Analysis to Triage Android Scoped Storage (arXiv)](https://arxiv.org/pdf/2302.13506)
- [Security Smells in Android (arXiv)](https://arxiv.org/pdf/2006.01181)
- [HackTricks — Android Applications Pentesting](https://book.hacktricks.wiki/en/mobile-pentesting/android-app-pentesting/index.html)

---

*This document was prepared based on OWASP MASTG (current release as of September 2026), official Semgrep and Android Developers documentation, CWE/SEI CERT/NIST standards, and third-party security research.*
