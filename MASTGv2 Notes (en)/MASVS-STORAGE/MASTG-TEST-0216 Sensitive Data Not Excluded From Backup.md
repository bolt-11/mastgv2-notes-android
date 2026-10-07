# MASTG-TEST-0216 Sensitive Data Not Excluded From Backup

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0216 |
| **Platform** | Android |
| **MASVS Category** | MASVS-STORAGE (MASVS-STORAGE-2: The app prevents leakage of unnecessary sensitive data) |
| **Weakness** | **MASWE-0006** — *Sensitive Data Not Excluded From Backup* |
| **Test Type** | **Dynamic**, Filesystem |
| **Profile** | L1, L2, **P** (Privacy) |
| **Knowledge** | MASTG-KNOW-0050 (Backups) |
| **Best Practice** | MASTG-BEST-0004 (Exclude Sensitive Data from Backups) |
| **Related Techniques** | MASTG-TECH-0005 (Installing Apps), MASTG-TECH-0128 (Performing a Backup and Restore of App Data), MASTG-TECH-0127 (Inspecting an App's Backup Data) |
| **Related Demos** | MASTG-DEMO-0020 (via Backup Manager `bmgr`), MASTG-DEMO-0035 (via `adb backup`) |
| **Static Counterpart** | **MASTG-TEST-0262** (References to Backup Configurations Not Excluding Sensitive Data) — demo: MASTG-DEMO-0034 |
| **Related CWE** | CWE-530 (Exposure of Backup File to an Unauthorized Control Sphere), CWE-200 (Exposure of Sensitive Information), CWE-312 (Cleartext Storage of Sensitive Information), CWE-359 (Exposure of Private Personal Information), CWE-16 (Configuration) |

---

## 1. Explanation

### 1.1 Testing Objective

Direct quote from the MASTG overview:

> *"This test verifies whether apps correctly instruct the system to **exclude sensitive files from backups** by **performing a backup and restore of the app data and checking which files are restored**."*
>
> *"Android provides a way to start the backup daemon to back up and restore app files, which you can use to verify **which files are actually restored** from the backup."*

The key phrase distinguishing this test from its static counterpart: **"actually restored"**. This test doesn't read configuration — it **empirically proves** which files actually go out and come back through the backup mechanism. A configuration can look correct on paper but fail in practice (a path typo, a wrong domain, a rule that doesn't cover a subdirectory, a forgotten `device-transfer` block).

### 1.2 Why Backup Is an Attack Surface

MASTG-KNOW-0050 explains that the Android ecosystem supports many backup options, and **each one is an exfiltration path**:

| Backup path | Where the data goes | Notes |
|---|---|---|
| **`adb backup`** (USB) | To the tester's/attacker's computer | Restricted since Android 12; requires `android:debuggable="true"` |
| **Google "Back Up My Data"** | Google's servers | Automatic, requires no special user interaction |
| **Auto Backup for Apps** (API 23+) | User's Google Drive, max. **25 MB** per app | **Enabled by default** — this is the main source of the problem |
| **Key/Value Backup** (Backup API) | Android Backup Service cloud | Requires a `BackupAgent`/`BackupAgentHelper` |
| **Device-to-device transfer** | The user's new device | Often forgotten — a **separate** rule set from cloud backup |
| **OEM backup** (e.g., HTC Backup, Samsung/Xiaomi Cloud) | Vendor servers | Outside Google's control, policies vary |

MASTG-KNOW-0050 emphasizes:

> *"Apps must carefully ensure that **sensitive user data doesn't end within these backups** as this may allow an attacker to extract it."*

**The single most important point to understand:** the `allowBackup` attribute **defaults to `true`** when not declared. So an app that never thought about backups at all **automatically** allows its entire sandbox to be backed up.

> *"When this attribute is unavailable, the `allowBackup` setting is **enabled by default**, and backup must be **manually deactivated**."*

Concrete attack scenarios:

| Scenario | How it happens |
|---|---|
| **Brief physical access** | An unlocked device + USB debugging enabled → `adb backup` pulls sandbox data with no root, within seconds |
| **Data ends up in the cloud** | Auto Backup syncs a token/credential to the user's Google Drive; a compromised Google account = a compromised app |
| **Old device sold/handed over** | A D2D transfer or cloud backup carries sensitive data to a new device — or leaves it behind in the cloud |
| **Work/shared device** | An admin or other user triggers a restore to a device they control |
| **Attacker with the victim's Google account** | App restored to the attacker's device → sensitive data comes back without needing the app's own credentials |
| **APK injection via backup archive** | Research shows a `BackupAgent` can inject an additional APK into the backup archive without user consent |

### 1.3 Two Generations of Backup Configuration — Both Must Be Present

This is the most common source of error. Android has **two different attributes** for two version ranges, and both need to be declared if the app's `minSdkVersion` spans both:

| Attribute | Applies to | Rule file | Root element |
|---|---|---|---|
| `android:fullBackupContent` | **Android 11 (API 30) and below** | `backup_rules.xml` | `<full-backup-content>` |
| `android:dataExtractionRules` | **Android 12 (API 31) and above** | `data_extraction_rules.xml` | `<data-extraction-rules>` |

And within `data_extraction_rules.xml`, there are **two separate sections**, each of which must be configured independently:

```xml
<data-extraction-rules>
    <cloud-backup>    <!-- backup to Google Drive -->
        <exclude domain="..." path="..." />
    </cloud-backup>
    <device-transfer> <!-- device-to-device transfer -->
        <exclude domain="..." path="..." />
    </device-transfer>
</data-extraction-rules>
```

**MASTG-BEST-0004 explicitly emphasizes:** *"Make sure to use **both** the `cloud-backup` and `device-transfer` parameters."* Excluding a file only from `cloud-backup` still leaves it able to leak via D2D transfer — and vice versa.

**Available `domain` values** for `<include>`/`<exclude>`:

| `domain` | Refers to |
|---|---|
| `file` | `getFilesDir()` — `/data/data/<pkg>/files/` |
| `database` | `getDatabasePath()` — `/data/data/<pkg>/databases/` |
| `sharedpref` | `getSharedPreferences()` — `/data/data/<pkg>/shared_prefs/` |
| `root` | The app data's root directory |
| `external` | `getExternalFilesDir()` |
| `device_file`, `device_database`, `device_sharedpref`, `device_root` | *Device-protected storage* (Direct Boot) variants |

> A common mistake: excluding `domain="file"` but forgetting `domain="sharedpref"` and `domain="database"` — even though tokens are usually in `shared_prefs/` instead.

**End-to-end encryption.** For highly sensitive data, there's a mechanism to ensure backup only occurs when the device supports client-side encryption (Android 9+ with lock screen enabled):

```xml
<!-- Android 11 and below -->
<full-backup-content requireFlags="clientSideEncryption"> ... </full-backup-content>

<!-- Android 12 and above -->
<cloud-backup disableIfNoEncryptionCapabilities="true"> ... </cloud-backup>
```

This is an **additional mitigation, not a replacement for `<exclude>`** — the data still goes into the backup, just encrypted with a key Google doesn't know.

### 1.4 This Test's Position vs. MASTG-TEST-0262 (Static)

MASTG states this relationship explicitly: *"See MASTG-TEST-0262 for a static analysis counterpart."*

| | MASTG-TEST-0216 *(this document)* | MASTG-TEST-0262 |
|---|---|---|
| **Approach** | Dynamic — real backup & restore | Static — reads the manifest + rule files |
| **Answers** | "What files are **actually** restored?" | "What does the configuration **look like**?" |
| **Strength** | **Empirical proof**; catches path typos, wrong domains, missed subdirectories, files created at runtime | Fast, no device needed, CI-friendly, sees the entire configuration |
| **Weakness** | Needs a device + root (for bmgr local transport); only covers files created during the exercise | **Cannot determine whether the rules cover ALL sensitive files** — a fundamental limitation |
| **FAIL criterion** | *"if any of the files are considered sensitive"* | A combination of 4 configuration conditions |

**TEST-0262's fundamental limitation**, which makes TEST-0216 necessary: static analysis can see that `backup_rules.xml` exists and contains `<exclude>`, but **cannot know what files the app will actually create at runtime**, so it cannot ensure all of them are covered. TEST-0262's own evaluation criteria say *"don't exclude **all** sensitive files"* — that judgment of "all" can only be proven dynamically.

**Recommended workflow:**

```
TEST-0262 (static)  ──►  allowBackup? attribute present? rule file content?
        │                        (fast, full configuration coverage)
        ▼
TEST-0216 (dynamic) ──►  real backup + restore → list of restored files
        │                        (empirical proof, catches rule gaps)
        ▼
   Compare against the sensitive data inventory (from MASTG-TEST-0207)
        ▼
   PASS / FAIL decision
```

And it ties strongly to **MASTG-TEST-0207**: the sandbox file inventory from that test is the list you need to check against for backup exclusion.

---

## 2. Tools Used for Testing

### 2.1 Core Tools (Required)

| Tool | MASTG ID | Function |
|---|---|---|
| **adb** | MASTG-TOOL-0004 | `bmgr`, `adb backup`, `adb pull`, file enumeration. The primary tool |
| **`bmgr`** (Backup Manager) | — | The Android backup daemon, via `adb shell bmgr`. **The recommended method** since it isn't subject to the Android 12 restrictions |
| **Android device / emulator (rooted)** | MASTG-TOOL-0003 | Root is required to pull `.ab` files from `/data/data/com.android.localtransport/` and to `find` in the sandbox |
| **`tar`** | — | Opens `.ab` archives (TAR with a special header) |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **Android Backup Extractor (`abe`)** | Recommended by MASTG-TECH-0128. Opens `.ab` files, including ones **password-encrypted** — `adb backup` produces a format that plain `tar` can't always open |
| **semgrep** (MASTG-TOOL-0110) | For MASTG-TEST-0262 — scans manifest backup attributes |
| **apktool** (MASTG-TOOL-0011) | Extracts `AndroidManifest.xml` **and** `res/xml/backup_rules.xml` / `data_extraction_rules.xml` |
| **aapt2** (MASTG-TOOL-0124) | Quick manifest attribute queries without extraction |
| **jadx** (MASTG-TOOL-0018) | Full manifest + searches for a `BackupAgent` implementation |
| **MobSF** | Flags `allowBackup` automatically in its report; useful for a first pass |
| **mobsfscan** | A lightweight CLI for CI |
| **drozer** | `app.package.backup` / `scanner.misc.*` modules for backup attribute auditing |
| **`sqlite3`, `strings`, `file`, `ent`** | Inspecting the content of restored files |
| **Frida** (MASTG-TOOL-0001) | Hook `BackupAgent.onBackup()` / `onFullBackup()` to see what the app sends to backup (key-value path) |
| **Google Drive UI / Settings** | Manual verification of the size & existence of a cloud backup |

### 2.3 Environment Prerequisites

- **Root** for the `bmgr` method (pulling `.ab` from `/data/data/com.android.localtransport/files/`). An AVD emulator with a *Google APIs* image is most practical (`adb root` succeeds immediately).
- **For `adb backup`:** this only works if `android:allowBackup="true"` **and** — since Android 12 (targetSdk 31+) — `android:debuggable="true"`. On a properly configured release app, `debuggable=false`, so **`adb backup` will not return app data**. This isn't a testing failure; use `bmgr` instead.
- **A clean device/emulator** (fresh wipe or snapshot) so there's no backup residue from a previous session.
- **A unique canary value** for every input — makes it easier to identify in restored files (`MASTG_CANARY_PWD_7f3a`, etc.).
- **Build a sensitive data inventory first.** Ideally, run MASTG-TEST-0207 first so you have a list of sandbox files along with their content for comparison.
- **DO NOT open the app after reinstalling/restoring.** This is an explicit MASTG instruction (step 4: *"Uninstall and reinstall the app but **don't open it anymore**"*). Opening the app recreates files, polluting the diff result so you can no longer distinguish restored files from newly created ones.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0005** to install the app.
2. **Run and use the app** through various workflows while entering sensitive data wherever possible.
3. Use **MASTG-TECH-0128** to perform a backup and restore of app data.
4. **Uninstall and reinstall the app, but don't open it again.**
5. Restore data from the backup and get the list of files that are restored.

---

### 3.2 Method A — Backup Manager (`bmgr`) + Local Transport *(official, MASTG-DEMO-0020)*

This is the most reliable method because it is **not subject to the Android 12 restrictions on `adb backup`** and works on non-debuggable apps.

**Official MASTG backup script** (`utils/mastg-android-backup-bmgr.sh`):

```bash
#!/bin/bash
package_name="$1"

# Script from https://developer.android.com/identity/data/testingbackup
# Initialize and create a backup
adb shell bmgr enable true
adb shell bmgr transport com.android.localtransport/.LocalTransport | grep -q "Selected transport" \
    || (echo "Error: error selecting local transport"; exit 1)
adb shell settings put secure backup_local_transport_parameters 'is_encrypted=true'
adb shell bmgr backupnow "$package_name" | grep -F "Package $package_name with result: Success" \
    || (echo "Backup failed"; exit 1)

# Uninstall and reinstall the app to clear the data and trigger a restore
apk_path_list=$(adb shell pm path "$package_name")
OIFS=$IFS; IFS=$'\n'
apk_number=0
for apk_line in $apk_path_list; do
    (( ++apk_number ))
    apk_path=${apk_line:8:1000}
    adb pull "$apk_path" "myapk${apk_number}.apk"
done
IFS=$OIFS
adb shell pm uninstall --user 0 "$package_name"
apks=$(seq -f 'myapk%.f.apk' 1 $apk_number)
adb install-multiple -t --user 0 $apks

# Clean up
adb shell bmgr transport com.google.android.gms/.backup.BackupTransportService
rm $apks
echo "Done"
```

What this script does, step by step:

| Command | Function |
|---|---|
| `bmgr enable true` | Enables the Backup Manager |
| `bmgr transport com.android.localtransport/.LocalTransport` | Switches backup from the Google cloud to the **local transport** — so the `.ab` is stored on-device and can be inspected |
| `settings put secure backup_local_transport_parameters 'is_encrypted=true'` | Marks the local transport as encrypted — important so that `requireFlags="clientSideEncryption"` / `disableIfNoEncryptionCapabilities` rules don't block the backup |
| `bmgr backupnow <pkg>` | Triggers an immediate backup |
| `pm path` + `adb pull` | Saves the APK (including split APKs) before uninstalling |
| `pm uninstall --user 0` | Removes the app **and its data** |
| `install-multiple -t --user 0` | Reinstall → **the automatic restore happens here** |
| `bmgr transport com.google.android.gms/...` | Restores the transport to the cloud (housekeeping) |

**Test script (`run.sh` from MASTG-DEMO-0020):**

```bash
#!/bin/bash
package_name="org.owasp.mastestapp"

adb root
adb shell "find /data/user/0/$package_name/files -type f" > output_before.txt

../../../../utils/mastg-android-backup-bmgr.sh $package_name

adb shell "find /data/user/0/$package_name/files -type f" > output_after.txt

mkdir -p restored_files
while read -r line; do
  adb pull "$line" ./restored_files/
done < output_after.txt
```

**Extracting the `.ab` archive directly** (MASTG-TECH-0128), if you want to see the backup's content itself rather than the restore result:

```bash
adb root
adb pull /data/data/com.android.localtransport/files/1/_full/org.owasp.mastestapp \
         org.owasp.mastestapp.ab
tar xvf org.owasp.mastestapp.ab
```

> **An important note about the demo's `run.sh`:** the script only checks `.../files` (`filesDir`). For real-world testing, **expand to cover the entire sandbox** — especially `shared_prefs/` and `databases/`, which are most likely to hold tokens. An extended version is provided in §3.9.

---

### 3.3 Method B — `adb backup` *(official, MASTG-DEMO-0035)*

**Official MASTG backup script** (`utils/mastg-android-backup-adb.sh`):

```bash
#!/bin/bash
package_name="$1"

adb backup -apk -nosystem $package_name
tail -c +25 backup.ab | python3 -c "import zlib,sys;sys.stdout.buffer.write(zlib.decompress(sys.stdin.buffer.read()))" > backup.tar
tar xvf backup.tar

echo "Done, extracted as apps/ to current directory"
```

Note the `tail -c +25` — this skips the **24-byte `.ab` header** before the zlib stream begins. The `.ab` format is a text header + a zlib payload containing a TAR.

**Test script (`run.sh` from MASTG-DEMO-0035):**

```bash
#!/bin/bash
package_name="org.owasp.mastestapp"

../../../../utils/mastg-android-backup-adb.sh $package_name

ls -l1 apps/org.owasp.mastestapp/f > output.txt

# Cleanup
rm backup.ab backup.tar
find apps/org.owasp.mastestapp/ -mindepth 1 -maxdepth 1 ! -name 'f*' -exec rm -rf {} +
```

**Backup archive structure** (MASTG-TECH-0127) — important for mapping files to their original location:

| Path within the archive | Origin on the device |
|---|---|
| `apps/<pkg>/a/` | The app's `.apk` file itself |
| `apps/<pkg>/obb/` | Related `.obb` containers |
| `apps/<pkg>/f/` | The `getFilesDir()` subtree |
| `apps/<pkg>/db/` | The parent `getDatabasePath()` subtree |
| `apps/<pkg>/sp/` | The parent `getSharedPrefsFile()` subtree |
| `apps/<pkg>/r/` | Files relative to the app's root file tree |
| `apps/<pkg>/c/` | The `getCacheDir()` directory — **not stored** |

> **This method's limitation — and MASTG gives an explicit warning:** *"`adb backup` is **restricted since Android 12** and requires `android:debuggable=true` in the AndroidManifest.xml."*
>
> On a correctly configured release app (`debuggable=false`), `adb backup` **will not return app data** — the archive will be empty. That is **not a PASS**; it means this method cannot be used. Use Method A (`bmgr`) instead.
>
> MASTG also notes: *"The behavior might differ between an emulator and a physical device."*

---

### 3.4 Method C — Android Backup Extractor (`abe`) for Encrypted Archives

MASTG-TECH-0128 recommends this tool, and it solves a real problem: `adb backup` can produce a **password-encrypted** `.ab` (if the user sets a backup password), which can't be opened with `tail` + `zlib` as shown in §3.3.

```bash
# Download abe (Android Backup Extractor)
#   https://github.com/nelenkov/android-backup-extractor

# Backup without a password
java -jar abe.jar unpack backup.ab backup.tar
tar xvf backup.tar

# Backup WITH a password
java -jar abe.jar unpack backup.ab backup.tar "MyBackupPassword"
tar xvf backup.tar

# The reverse — repack (useful for testing restore integrity, see §3.8)
java -jar abe.jar pack backup.tar modified.ab "MyBackupPassword"
adb restore modified.ab

# Archive info without extracting
java -jar abe.jar info backup.ab
```

When to use this: when `tar xvf` fails with a format error, or when you need to **modify and then restore** an archive (testing whether the app validates restored data — see §3.8).

---

### 3.5 Method D — Static with semgrep *(MASTG-TEST-0262 / MASTG-DEMO-0034)*

This is the official static counterpart. Fast, device-free, CI-friendly.

**Official MASTG rule** (`rules/mastg-android-backup-manifest.yml`):

```yaml
rules:
  - id: mastg-android-backup-manifest-allow-backup
    severity: WARNING
    languages:
      - xml
    metadata:
      summary: This rule inspects the AndroidManifest.xml for allowBackup.
      references:
        - https://developer.android.com/guide/topics/data/autobackup
    message: "[MASVS-STORAGE-2] allowBackup detected as $ARG."
    patterns:
      - pattern: 'android:allowBackup="$ARG"'

  - id: mastg-android-backup-manifest-backup-rules
    severity: WARNING
    languages:
      - xml
    metadata:
      summary: This rule inspects the AndroidManifest.xml for backup rules.
      references:
        - https://developer.android.com/guide/topics/data/autobackup
    message: "[MASVS-STORAGE-2] Backup rules detected."
    pattern-either:
      - pattern: 'android:fullBackupContent="@xml/backup_rules"'
      - pattern: 'android:dataExtractionRules="@xml/data_extraction_rules"'
```

Running it:

```bash
apktool d -f -o ./decoded ./target-app.apk

NO_COLOR=true semgrep -c ./mastg/rules/mastg-android-backup-manifest.yml \
  ./decoded/AndroidManifest.xml > output.txt

# Then read the rule file itself — semgrep does NOT do this
cat ./decoded/res/xml/backup_rules.xml
cat ./decoded/res/xml/data_extraction_rules.xml
```

> ⚠️ **A serious gap in this rule:** the pattern matches the **literal filename** `@xml/backup_rules` and `@xml/data_extraction_rules`. If a developer names the file differently — which is extremely common — the rule will **report "no backup rules"** even when rules actually exist.
>
> Ironically, **Android's own official documentation examples** use `@xml/backup_rules_extraction` and `@xml/backup_rules_full`, which **would not match** this MASTG rule. So this rule has significant potential for **false positives** (reporting rules as absent when they aren't).
>
> An extended rule that closes this gap is in §3.9.

---

### 3.6 Method E — Alternative Static Analysis: apktool + grep, aapt2, MobSF, drozer

Several paths that don't depend on semgrep, useful when you don't have the MASTG rule or want cross-verification.

**E1 — apktool + grep (most portable, no extra dependencies):**

```bash
apktool d -f -o ./decoded ./target-app.apk

# 1. Backup attributes in the manifest (catch ANY filename, not just the default ones)
grep -oE 'android:(allowBackup|fullBackupContent|dataExtractionRules|backupAgent|restoreAnyVersion|fullBackupOnly|backupInForeground)="[^"]*"' \
  ./decoded/AndroidManifest.xml

# Example output:
#   android:allowBackup="true"
#   android:dataExtractionRules="@xml/data_extraction_rules"
#   android:fullBackupContent="@xml/backup_rules"

# 2. CHECK: is allowBackup declared at all? If not -> defaults to TRUE (a finding!)
grep -q 'android:allowBackup' ./decoded/AndroidManifest.xml \
  && echo "allowBackup is declared" \
  || echo "[!] allowBackup is NOT declared -> defaults to TRUE"

# 3. Dynamically resolve the rule filename, then display its content
for attr in fullBackupContent dataExtractionRules; do
  ref=$(grep -oE "android:$attr=\"@xml/[^\"]+\"" ./decoded/AndroidManifest.xml \
        | sed -E 's/.*@xml\/([^"]+)".*/\1/')
  if [ -n "$ref" ]; then
    echo "=== $attr -> res/xml/$ref.xml ==="
    cat "./decoded/res/xml/$ref.xml"
  else
    echo "[!] $attr is not declared"
  fi
done

# 4. Check whether device-transfer is also excluded (often forgotten)
grep -c "device-transfer" ./decoded/res/xml/*.xml

# 5. Check which domains are excluded — sharedpref & database are often missed
grep -oE 'domain="[^"]*"' ./decoded/res/xml/data_extraction_rules.xml | sort -u

# 6. Check for a custom BackupAgent (key-value path)
grep -n "android:backupAgent" ./decoded/AndroidManifest.xml
grep -rn "extends BackupAgent\|extends BackupAgentHelper\|onBackup\|onFullBackup" \
  ./decompiled/sources/ 2>/dev/null
```

**E2 — aapt2 (fastest, no decompilation needed):**

```bash
aapt2 d badging ./target-app.apk | grep -iE "allowBackup|application-debuggable"
aapt2 d xmltree --file AndroidManifest.xml ./target-app.apk | grep -iE "allowBackup|BackupContent|dataExtraction|backupAgent"
```

> Remember MASTG-TECH-0150's note: aapt2 outputs a **custom decoded format**, not standard XML — attribute names differ (e.g., `application-debuggable`, not `android:debuggable`).

**E3 — MobSF (GUI + ready-made report):**

```bash
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
# Upload the APK via http://localhost:8000
```

Look in the report for the **Manifest Analysis** section → the finding `[android:allowBackup=true]` titled *"Application Data can be Backed up"*. Its advantage: it gives a ready-to-quote risk explanation and severity; it also checks `debuggable` at the same time.

**E4 — mobsfscan (CLI, CI-friendly):**

```bash
pip install mobsfscan
mobsfscan --json -o mobsfscan.json ./decoded/
jq '.results | to_entries[] | select(.key | test("backup"))' mobsfscan.json
```

**E5 — drozer (device-side audit):**

```bash
drozer console connect
dz> run app.package.info -a com.example.target      # shows application flags
dz> run scanner.misc.readablefiles --privileged      # complementary
```

**E6 — One-liner, no tools required (quick initial triage):**

```bash
unzip -p ./target-app.apk AndroidManifest.xml | strings | grep -iE "allowBackup|backupAgent|dataExtraction"
```

This works because the binary manifest still stores attribute names as strings — useful for a fast check, though it won't give you the value.

---

### 3.7 Method F — Verifying the Cloud and Device-Transfer Paths

Methods A–C verify the local backup mechanism. But the `cloud-backup` and `device-transfer` rules are **separate sections**, and misconfiguration there won't be visible to the local transport.

```bash
# 1. Force the backup to the CLOUD transport (not local) to test the real path
adb shell bmgr transport com.google.android.gms/.backup.BackupTransportService
adb shell bmgr backupnow com.example.target

# 2. Check backup status & queue
adb shell bmgr list transports
adb shell dumpsys backup | head -60
adb shell dumpsys backup | grep -iE "Ancestral|Current|Pending|allowBackup"

# 3. Verify cloud backup size (Auto Backup is capped at 25 MB)
#    Settings > Google > Backup > App data  — or:
adb shell dumpsys backup | grep -iE "size|quota"

# 4. Test device-transfer: run a backup with the D2D transport if available
adb shell bmgr list transports        # look for a transfer-type transport
```

**Verifying `device-transfer` practically** is hard to automate because it requires two devices. A realistic alternative: **strictly audit the configuration** (§3.6 E1, step 4) and ensure every `<exclude>` in `<cloud-backup>` is also present in `<device-transfer>` — a mismatch between the two is almost always a bug, not a design decision.

---

### 3.8 Method G — Advanced Testing: Restored Data Integrity

This is outside MASTG-TEST-0216's formal scope, but it's a natural security question arising from the same mechanism: **does the app validate restored data?** Backup data can be modified by an attacker before it's restored.

```bash
# 1. Backup
adb backup -apk -nosystem com.example.target        # or via bmgr

# 2. Extract, MODIFY, repack
java -jar abe.jar unpack backup.ab backup.tar
tar xvf backup.tar
#    -> change a value in apps/<pkg>/sp/auth_prefs.xml, e.g. is_premium=false -> true
#    -> or change user_id to a different user
tar cvf modified.tar apps/
java -jar abe.jar pack modified.tar modified.ab

# 3. Restore the modified data
adb shell pm uninstall --user 0 com.example.target
adb install ./target-app.apk
adb restore modified.ab

# 4. Open the app and check: was the modification accepted?
```

If the app accepts the modified value (e.g., premium status, quota, user ID), this is a finding in its own right: restored data is being treated as trusted input. This also relates to the `android:restoreAnyVersion="true"` attribute, which allows restore from **any** version of the app — including older, more vulnerable ones.

> Only perform this within the scope of an authorized engagement.

---

### 3.9 Extended Scripts and Extended Rules

**An extended `run.sh` script covering the WHOLE sandbox** (not just `files/`):

```bash
#!/bin/bash
PKG=${1:-com.example.target}
D=/data/user/0/$PKG

adb root >/dev/null

echo "[*] Snapshot BEFORE backup (whole sandbox)..."
adb shell "find $D -type f" | sort > output_before.txt
wc -l output_before.txt

echo "[*] Backup + uninstall + reinstall (automatic restore)..."
./mastg-android-backup-bmgr.sh "$PKG" || exit 1

# Give the restore time to finish; DO NOT open the app
sleep 5

echo "[*] Snapshot AFTER restore..."
adb shell "find $D -type f" | sort > output_after.txt
wc -l output_after.txt

echo "[*] Files that WERE RESTORED (present in after):"
mkdir -p restored_files
while read -r remote; do
  [ -z "$remote" ] && continue
  rel="${remote#$D/}"
  mkdir -p "./restored_files/$(dirname "$rel")"     # preserve directory structure
  adb pull "$remote" "./restored_files/$rel" >/dev/null 2>&1 \
    || adb shell "su -c 'cat $remote'" > "./restored_files/$rel"
done < output_after.txt

echo "[*] Files that were SUCCESSFULLY EXCLUDED (present before, missing after):"
comm -23 output_before.txt output_after.txt

echo "[*] Search for the canary value in restored files:"
grep -raiE "MASTG_CANARY_PWD_7f3a|password|token|bearer|api[_-]?key|secret" ./restored_files/ || echo "  (clean)"

echo "[*] Inspect restored shared_prefs & databases:"
for f in ./restored_files/shared_prefs/*.xml; do [ -f "$f" ] && echo "--- $f" && cat "$f"; done
for db in $(find ./restored_files -name "*.db"); do echo "--- $db"; sqlite3 "$db" ".tables"; done
```

**An extended semgrep rule** — closing the literal-filename gap from §3.5:

```yaml
rules:
  # 1. allowBackup=true (without assuming a rule filename)
  - id: custom-backup-allowbackup-true
    severity: WARNING
    languages: [xml, generic]
    message: "[MASVS-STORAGE-2] android:allowBackup=\"true\" — app data can be backed up"
    pattern-regex: 'android:allowBackup\s*=\s*"true"'

  # 2. Backup rule attribute with ANY filename
  - id: custom-backup-rules-any-name
    severity: INFO
    languages: [xml, generic]
    message: "[MASVS-STORAGE-2] Backup rule attribute found — verify the CONTENT of the rule file"
    pattern-either:
      - pattern-regex: 'android:fullBackupContent\s*=\s*"@xml/[^"]+"'
      - pattern-regex: 'android:dataExtractionRules\s*=\s*"@xml/[^"]+"'

  # 3. Other risky backup attributes
  - id: custom-backup-risky-attributes
    severity: WARNING
    languages: [xml, generic]
    message: "[MASVS-STORAGE-2] Risky backup attribute (restoreAnyVersion / custom backupAgent)"
    pattern-either:
      - pattern-regex: 'android:restoreAnyVersion\s*=\s*"true"'
      - pattern-regex: 'android:backupAgent\s*=\s*"[^"]+"'

  # 4. data_extraction_rules.xml that ONLY has cloud-backup (device-transfer forgotten)
  - id: custom-backup-missing-device-transfer
    severity: ERROR
    languages: [generic]
    paths:
      include: ["*data_extraction_rules*.xml", "*extraction*.xml"]
    message: "[MASVS-STORAGE-2] <cloud-backup> is present but <device-transfer> is not — data leaks via D2D transfer"
    patterns:
      - pattern-regex: '<cloud-backup'
      - pattern-not-regex: '<device-transfer'

  # 5. A backup rule that includes everything without any exclude
  - id: custom-backup-include-all-no-exclude
    severity: ERROR
    languages: [generic]
    paths:
      include: ["*backup_rules*.xml", "*data_extraction_rules*.xml", "*extraction*.xml"]
    message: "[MASVS-STORAGE-2] <include> covers everything without any <exclude>"
    patterns:
      - pattern-regex: '<include[^>]+path\s*=\s*"\."'
      - pattern-not-regex: '<exclude'
```

Run it against both the manifest **and** the rule files:

```bash
NO_COLOR=true semgrep -c ./custom-backup-rules.yml ./decoded/AndroidManifest.xml ./decoded/res/xml/
```

---

### 3.10 Method Comparison: When to Use Which

| Method | Root required? | Works on non-debuggable apps? | Subject to Android 12 restrictions? | Strength | When to use |
|---|---|---|---|---|---|
| **A — `bmgr` local transport** | Yes (for pulling `.ab`/`find`) | ✅ Yes | ❌ No | **Most reliable & representative**; tests the real Auto Backup path | **Default for this test** |
| **B — `adb backup`** | No | ❌ No (requires `debuggable=true`) | ✅ Yes | Fast, rootless, archive easy to inspect | Debug/legacy apps, or target SDK < 31 |
| **C — `abe`** | No | — | — | Opens **encrypted** `.ab` files; can repack | When `tar` fails, or for restore integrity testing |
| **D — semgrep (TEST-0262)** | No | ✅ Yes | ❌ No | Fast, CI-friendly, no device | First pass & CI gate |
| **E1 — apktool + grep** | No | ✅ Yes | ❌ No | Portable, catches **any** rule filename | Cross-verifying semgrep; most accurate for static analysis |
| **E2 — aapt2** | No | ✅ Yes | ❌ No | Fastest, no decompilation | Quick triage of many APKs |
| **E3 — MobSF** | No | ✅ Yes | ❌ No | Ready-to-quote report + severity | Report documentation, broad audits |
| **E4 — mobsfscan** | No | ✅ Yes | ❌ No | Lightweight for pipelines | CI/CD gate |
| **E5 — drozer** | No | ✅ Yes | ❌ No | Device-side audit | Part of a broader drozer session |
| **F — cloud/D2D** | Partial | ✅ Yes | ❌ No | Tests the real `cloud-backup` & `device-transfer` paths | L2/high-privacy apps |
| **G — restore integrity** | No | ❌ No (requires `adb restore`) | ✅ Yes | Finds weaknesses in restored data validation | Advanced testing, outside formal scope |

**Practical recommendation:** run **E1 (apktool+grep) → A (bmgr)** as the minimum combination. E1 provides a full configuration picture without the filename gap, A provides empirical proof. Add D for CI, F for apps with high privacy requirements.

---

### 3.11 Evaluation Criteria: Positive and Negative Cases

**Official MASTG rules (TEST-0216):**

> **Observation:** *"The output should contain a list of files that are restored from the backup."*
>
> **Evaluation:** *"The test case **fails if any of the files are considered sensitive**."*

The criteria are very straightforward — no additional clauses. **Any sensitive file is restored → FAIL.**

**For comparison, MASTG-TEST-0262's (static) criteria** list a combination of conditions:

> *The test case fails if the app allows sensitive data to be backed up. Specifically, if the following conditions are met:*
> - *`android:allowBackup="true"` in the `AndroidManifest.xml`*
> - *`android:fullBackupContent="@xml/backup_rules"` isn't declared (for Android 11 or lower)*
> - *`android:dataExtractionRules="@xml/data_extraction_rules"` isn't declared (for Android 12 and higher)*
> - *`backup_rules.xml` or `data_extraction_rules.xml` aren't present or **don't exclude all sensitive files**.*

---

#### ❌ FAIL / ISSUE — The check is declared FAILED when:

| No | Condition | Example evidence |
|---|---|---|
| F1 | A file containing **credentials/tokens** is restored from the backup | `restored_files/secret.txt` contains `secr3tPa$$W0rd` |
| F2 | **`shared_prefs/*.xml`** is restored and contains a plaintext auth token/flag | `<string name="auth_token">eyJ...</string>` in `restored_files/shared_prefs/` |
| F3 | A **database** is restored and contains user data | `restored_files/databases/app.db` → `users` table |
| F4 | The **canary value** you entered is found in a restored file | `grep -r MASTG_CANARY_PWD_7f3a ./restored_files/` → a hit |
| F5 | `allowBackup` is **not declared** in the manifest (defaults to `true`) and sensitive data exists in the sandbox | `grep android:allowBackup` → no result |
| F6 | `android:allowBackup="true"` without **any rule attribute** | A manifest with neither `fullBackupContent` nor `dataExtractionRules` |
| F7 | A rule file exists but **doesn't exclude all** sensitive files | MASTG demo: `backup_excluded_secret.txt` is excluded, but `secret.txt` is not |
| F8 | `<exclude>` only exists in **`cloud-backup`**, not in **`device-transfer`** (or vice versa) | A violation of MASTG-BEST-0004 → leaks via D2D transfer |
| F9 | Only `dataExtractionRules` exists, while `minSdkVersion` ≤ 30 | Devices on Android 11 or below are unprotected |
| F10 | Only `fullBackupContent` exists, while `targetSdkVersion` ≥ 31 | Devices on Android 12 or above use a rule set that's ignored |
| F11 | **A domain is missed** — excluding `domain="file"` but not `sharedpref`/`database` | Tokens in `shared_prefs/` still get backed up |
| F12 | **Wrong/typo'd `<exclude>` path** so the rule has no effect | Proven dynamically: the file is still restored despite an exclude rule |
| F13 | `android:debuggable="true"` in a release build, allowing `adb backup` to pull data without root | Combined finding: backup exposure + plaintext data |
| F14 | `android:restoreAnyVersion="true"` | Allows restore from any app version, including vulnerable ones |
| F15 | A custom `BackupAgent` includes sensitive data | Review `onBackup()`/`onFullBackup()` |
| F16 | Data is backed up **without** `requireFlags="clientSideEncryption"` / `disableIfNoEncryptionCapabilities="true"` for an app handling highly sensitive data | Sensitive data can be stored in the cloud without E2E encryption |
| F17 | **A referenced rule file does not exist** in the APK | `android:fullBackupContent="@xml/backup_rules"` but `res/xml/backup_rules.xml` is not found |

**Example output indicating FAIL — MASTG-DEMO-0020 (`bmgr`):**

Sample code (`MastgTest.kt`) — creates **two** files with the same content, one excluded and one not:

```kotlin
val internalStorageDir = context.filesDir
val fileName = File(internalStorageDir, "secret.txt")
val fileNameOfBackupExcludedFile = File(internalStorageDir, "backup_excluded_secret.txt")
val fileContent = "secr3tPa\$\$W0rd\n"

FileOutputStream(fileName).use { it.write(fileContent.toByteArray()) }
FileOutputStream(fileNameOfBackupExcludedFile).use { it.write(fileContent.toByteArray()) }
```

`AndroidManifest.xml`:

```xml
<application
    android:allowBackup="true"
    android:dataExtractionRules="@xml/data_extraction_rules"
    android:fullBackupContent="@xml/backup_rules"
    ... >
```

`backup_rules.xml` (Android 11 and below):

```xml
<?xml version="1.0" encoding="utf-8"?>
<full-backup-content>
    <include domain="file" path="." requireFlags="clientSideEncryption" />
    <exclude domain="file" path="backup_excluded_secret.txt" />
</full-backup-content>
```

`data_extraction_rules.xml` (Android 12 and above) — note the demo **correctly** excludes it in both sections:

```xml
<?xml version="1.0" encoding="utf-8"?>
<data-extraction-rules>
    <cloud-backup disableIfNoEncryptionCapabilities="true">
        <exclude domain="file" path="backup_excluded_secret.txt" />
    </cloud-backup>

    <device-transfer disableIfNoEncryptionCapabilities="true">
        <exclude domain="file" path="backup_excluded_secret.txt" />
    </device-transfer>
</data-extraction-rules>
```

**`output_before.txt`** (before backup):

```
/data/user/0/org.owasp.mastestapp/files/secret.txt
/data/user/0/org.owasp.mastestapp/files/backup_excluded_secret.txt
/data/user/0/org.owasp.mastestapp/files/profileInstalled
```

**`output_after.txt`** (after restore) — **this is the proof**:

```
/data/user/0/org.owasp.mastestapp/files/profileInstalled
/data/user/0/org.owasp.mastestapp/files/secret.txt
```

**`restored_files/secret.txt`**:

```
secr3tPa$$W0rd
```

MASTG evaluation: *"The test **fails** because `secret.txt` is restored from the backup and it contains sensitive data. Note that `output_after.txt` does **not** contain the `backup_excluded_secret.txt` file, which is expected as it was marked as `exclude` in the `backup_rules.xml` file."*

**Example output indicating FAIL — MASTG-DEMO-0035 (`adb backup`):**

`output.txt` (content of `apps/org.owasp.mastestapp/f`):

```
profileInstalled
secret.txt
```

`apps/org.owasp.mastestapp/f/secret.txt`:

```
secr3tPa$$W0rd
```

MASTG evaluation: *"The test **fails** because `secret.txt` is part of the backup and it contains sensitive data. Note that `backup_excluded_secret.txt` file is not part of the backup, which is expected."*

**Example output from MASTG-TEST-0262 (static, DEMO-0034):**

```
┌─────────────────┐
│ 3 Code Findings │
└─────────────────┘

    ../MASTG-DEMO-0020/AndroidManifest.xml
    ❯❱ rules.mastg-android-backup-manifest-allow-backup
          [MASVS-STORAGE-2] allowBackup detected as true.

            6┆ android:allowBackup="true"

    ❯❱ rules.mastg-android-backup-manifest-backup-rules
          [MASVS-STORAGE-2] Backup rules detected.

            7┆ android:dataExtractionRules="@xml/data_extraction_rules"
            ⋮┆----------------------------------------
            8┆ android:fullBackupContent="@xml/backup_rules"
```

MASTG-DEMO-0034 evaluation: *"The test **fails** because the sensitive file `secret.txt` ends up in the backup. This is due to: `android:allowBackup="true"`; the `android:fullBackupContent` attribute is present; the `backup_rules.xml` file is present in the APK and **does not exclude all sensitive files**."*

**Four important observations from these demos:**

1. **The backup configuration is technically "correct" — and still FAILS.** The app declares **both** attributes (`fullBackupContent` and `dataExtractionRules`), excludes in **both** sections (`cloud-backup` and `device-transfer`), **and** uses `requireFlags="clientSideEncryption"` / `disableIfNoEncryptionCapabilities="true"`. What's wrong isn't the mechanism, but the **coverage**: only one of the two sensitive files is excluded. This shows that this test evaluates **completeness**, not merely the presence of configuration.

2. **This is proof of why static testing alone isn't enough.** The semgrep output on DEMO-0034 reports something that sounds "reassuring": *allowBackup detected as true* and *Backup rules detected*. From that output alone, a tester could conclude the app properly manages backups. Only dynamic testing shows that `secret.txt` is actually restored.

3. **The demo shows both a positive and negative control in a single session.** `backup_excluded_secret.txt` **disappears** from `output_after.txt` — proving the `<exclude>` mechanism works and the test itself is valid. This is a good pattern to replicate: include one file known to be excluded as a sanity check. If both files disappear, the backup may have failed entirely, rather than the rules working.

4. **`profileInstalled` is noise, not a finding.** This file is created by `androidx.profileinstaller` (a baseline profile), not app data. Filter out files like this to keep the report focused.

---

#### ✅ PASS — The check is declared PASSED when:

| No | Condition | Example evidence |
|---|---|---|
| P1 | **No files** are restored from the backup | `output_after.txt` is empty (aside from system-created files like `profileInstalled`) |
| P2 | Files are restored, but **none are sensitive** | Only UI preferences (theme, language), public asset caches, onboarding flags |
| P3 | `android:allowBackup="false"` — backup is fully disabled | `grep android:allowBackup` → `"false"`; `bmgr backupnow` → no data |
| P4 | All sensitive files are **excluded** and proven to be missing after restore | `comm -23 output_before.txt output_after.txt` contains all sensitive files |
| P5 | The canary value is **not found** in any restored file | `grep -r MASTG_CANARY_PWD_7f3a ./restored_files/` → empty |
| P6 | Sensitive files are restored but **encrypted with a key from the Android KeyStore** | The key cannot be backed up (the KeyStore doesn't include it in a backup) → the data cannot be decrypted on another device |
| P7 | Both attributes are declared appropriate to the `minSdk`–`targetSdk` range, and `<exclude>` is present in **both** sections (`cloud-backup` + `device-transfer`) | A complete configuration |
| P8 | All relevant domains are covered (`file`, `sharedpref`, `database`, `external`, and `device_*` variants if using Direct Boot) | `grep -oE 'domain="[^"]*"'` shows them all |
| P9 | `android:debuggable="false"` is verified on the release APK | `aapt2 d badging` does not show `application-debuggable` |

**Example output indicating PASS:**

```bash
$ ./run_extended.sh com.example.secureapp
[*] Snapshot BEFORE backup (whole sandbox)...
      23 output_before.txt
[*] Backup + uninstall + reinstall (automatic restore)...
Backup Manager now enabled
Package com.example.secureapp with result: Success
[*] Snapshot AFTER restore...
       1 output_after.txt
[*] Files that WERE RESTORED (present in after):
[*] Files that were SUCCESSFULLY EXCLUDED (present before, missing after):
/data/user/0/com.example.secureapp/shared_prefs/auth_prefs.xml
/data/user/0/com.example.secureapp/databases/app.db
/data/user/0/com.example.secureapp/files/session.bin
...
[*] Search for the canary value in restored files:
  (clean)
```

A correct configuration:

```xml
<!-- AndroidManifest.xml — declare BOTH -->
<application
    android:allowBackup="true"
    android:fullBackupContent="@xml/backup_rules"
    android:dataExtractionRules="@xml/data_extraction_rules"
    android:debuggable="false"
    ... >
```

```xml
<!-- res/xml/data_extraction_rules.xml (Android 12+) -->
<?xml version="1.0" encoding="utf-8"?>
<data-extraction-rules>
    <cloud-backup disableIfNoEncryptionCapabilities="true">
        <include domain="root" path="." />
        <exclude domain="sharedpref" path="auth_prefs.xml" />
        <exclude domain="database"   path="app.db" />
        <exclude domain="database"   path="app.db-wal" />
        <exclude domain="database"   path="app.db-journal" />
        <exclude domain="file"       path="session.bin" />
        <exclude domain="file"       path="vault/" />
        <exclude domain="external"   path="cache/" />
    </cloud-backup>

    <device-transfer disableIfNoEncryptionCapabilities="true">
        <!-- Mirror ALL excludes above -->
        <include domain="root" path="." />
        <exclude domain="sharedpref" path="auth_prefs.xml" />
        <exclude domain="database"   path="app.db" />
        <exclude domain="database"   path="app.db-wal" />
        <exclude domain="database"   path="app.db-journal" />
        <exclude domain="file"       path="session.bin" />
        <exclude domain="file"       path="vault/" />
        <exclude domain="external"   path="cache/" />
    </device-transfer>
</data-extraction-rules>
```

```xml
<!-- res/xml/backup_rules.xml (Android 11 and below) — mirror the same rules -->
<?xml version="1.0" encoding="utf-8"?>
<full-backup-content requireFlags="clientSideEncryption">
    <include domain="root" path="." />
    <exclude domain="sharedpref" path="auth_prefs.xml" />
    <exclude domain="database"   path="app.db" />
    <exclude domain="database"   path="app.db-wal" />
    <exclude domain="database"   path="app.db-journal" />
    <exclude domain="file"       path="session.bin" />
    <exclude domain="file"       path="vault/" />
</full-backup-content>
```

---

#### ⚠️ Important Notes on Evaluation

1. **Don't open the app after reinstalling.** This is an explicit MASTG instruction. Opening the app recreates files (new tokens, new databases), so you can no longer distinguish restored files from newly created ones — and might incorrectly report a FAIL.

2. **An `adb backup` returning an empty archive ≠ PASS.** Since Android 12, `adb backup` excludes app data unless `android:debuggable="true"`. On a properly configured release app, this will always be empty. The status is **Inconclusive for that method** — use `bmgr` (Method A) instead. Conversely: if `adb backup` **succeeds** in pulling data from a release APK, it means the app is debuggable → an additional finding (F13).

3. **Include a positive control.** As in the demo, make sure at least one file you know is excluded is indeed missing after restore. If all files are missing, the backup may have failed entirely (wrong transport, `bmgr` not enabled, quota exceeded) — not because the rules are working. Check the `bmgr backupnow` output for `result: Success`.

4. **Filter out system-created files.** `profileInstalled`, `oat/`, `code_cache/` and similar are not app data. Focus on `files/`, `shared_prefs/`, `databases/`, and `app_webview/`.

5. **Check the ENTIRE sandbox, not just `files/`.** The demo script limits itself to `filesDir` for simplicity, but **tokens are most often in `shared_prefs/`** and user data in `databases/`. Use the script in §3.9.

6. **Don't forget the SQLite WAL/journal.** `app.db` being excluded while `app.db-wal` isn't will still leak data via backup. The `<exclude>` rule must cover all three.

7. **Verify attribute coverage matches the app's SDK range.** This is a mistake that often slips through:
   - `minSdkVersion ≤ 30` → `fullBackupContent` is **mandatory**
   - `targetSdkVersion ≥ 31` → `dataExtractionRules` is **mandatory**
   - An app spanning `minSdk 24`–`targetSdk 34` → **needs both**

8. **Encryption with a KeyStore key is a strong mitigation here.** Android KeyStore keys **are not backed up** (they cannot be exported from secure hardware). So an encrypted file that gets included in the backup still cannot be decrypted on another device. This is a legitimate PASS path (P6) — but verify the key truly comes from the KeyStore, not hardcoded (MASTG-TEST-0212).

9. **Gap in the MASTG semgrep rule.** The rule matches the literal filenames `@xml/backup_rules` / `@xml/data_extraction_rules`. Other names — including **examples from Android's own documentation** (`@xml/backup_rules_extraction`) — will be missed and reported as "no rules present." Use Method E1 (apktool+grep) or the extended rule in §3.9 for verification.

10. **Severity is modulated by several factors:**

    | Factor | Severity |
    |---|---|
    | Credentials/token/private key restored | **Critical** — enables account takeover from another device |
    | Financial/health data restored | **Critical** |
    | PII restored | **High** (+ privacy dimension, profile `P`) |
    | `allowBackup` not declared at all + sensitive data present | **High** — an oversight, not a decision |
    | Data can be pulled **without root** (`adb backup` succeeds / app debuggable) | **Significantly raised** |
    | `<exclude>` only in `cloud-backup`, not `device-transfer` | **High** — the D2D path is often used by users |
    | Attribute mismatch with SDK range (F9/F10) | **High** — part of the user base is unprotected |
    | No `requireFlags`/`disableIfNoEncryptionCapabilities` for highly sensitive data | Medium |
    | Sensitive data backed up but **encrypted with a KeyStore key** | Low / informational |
    | Only non-sensitive UI preferences restored | **Not a finding** |

11. **Document complete evidence:** the file list before & after restore, the content of restored sensitive files (partially redacted), **the files successfully excluded** (as a positive control), the backup method used (bmgr/adb/cloud), the verbatim content of `AndroidManifest.xml` and **both** rule files, `minSdkVersion`/`targetSdkVersion`, `debuggable` status, the `bmgr backupnow` result (`result: Success`), and reproduction steps with a canary value. Also note limitations (e.g., `device-transfer` not verified because only one device was available).

---

## 4. Recommendations

### 4.1 Core Principles (in priority order)

**Priority 1 — Don't store unneeded sensitive data.** The strongest remediation: if the data isn't in the sandbox, it can't be backed up. Session tokens should ideally be memory-only. This also resolves MASTG-TEST-0207.

**Priority 2 — Exclude sensitive data from backup (MASTG-BEST-0004).**

MASTG-BEST-0004 states:

> *"For the sensitive files found, instruct the system to exclude them from the backup:*
> - *If you are using Auto Backup, mark them with the `exclude` tag in `backup_rules.xml` (for Android 11 or lower using `android:fullBackupContent`) or `data_extraction_rules.xml` (for Android 12 and higher using `android:dataExtractionRules`), depending on the target API. **Make sure to use both the `cloud-backup` and `device-transfer` parameters.***
> - *If you are using the key-value approach, set up your `BackupAgent` accordingly."*

Correct configuration checklist:
- Declare **both** attributes if the SDK range spans both
- Mirror **every** `<exclude>` in both `<cloud-backup>` **and** `<device-transfer>`
- Cover **all relevant domains**: `file`, `sharedpref`, `database`, `external`, plus `device_*` variants if using Direct Boot
- Include **SQLite derived files**: `-wal`, `-shm`, `-journal`
- Use directory patterns (`path="vault/"`) instead of listing individual files so new files are automatically covered

**Priority 3 — Disable backup entirely if the app doesn't need it.**

```xml
<application android:allowBackup="false" ... >
```

This is the safest and simplest option. The trade-off: the user loses the convenience of restore. For financial/health apps that need to sync data from the server after login anyway, this is usually the right choice.

> Note: **don't rely on the absence of the attribute**. If `allowBackup` is not declared, its value is **`true`**. It must be explicitly declared `false`.

**Priority 4 — Use `no_backup/` for files that must not be backed up.** Android provides a dedicated directory that is **automatically excluded** from backup — no XML rule needed:

```kotlin
// ✅ Automatically excluded from backup, no configuration needed
val f = File(context.noBackupFilesDir, "session.bin")
f.writeBytes(sessionData)
```

This is a more mistake-resistant approach than relying on `<exclude>`, which can be typo'd or missed when new files are added.

**Priority 5 — Encrypt data with a key from the Android KeyStore.** This is the strongest mitigation because it's fail-safe: KeyStore keys **are not backed up** and cannot be exported from secure hardware. So even if an encrypted file ends up in the backup, it **cannot be decrypted** on another device.

```kotlin
val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build()
// data is encrypted; the key stays in the KeyStore and isn't backed up
```

Combine with Priority 2 as a defense-in-depth measure — don't rely on either alone.

**Priority 6 — Require end-to-end encryption for highly sensitive data.**

```xml
<!-- Android 12+ : backup only occurs if the device supports E2E encryption -->
<cloud-backup disableIfNoEncryptionCapabilities="true"> ... </cloud-backup>

<!-- Android 11 and below -->
<full-backup-content requireFlags="clientSideEncryption"> ... </full-backup-content>
```

Android's documentation explains that on Android 9+ with lock screen enabled, backup data is encrypted with a key **unknown to Google**. The attributes above ensure the backup doesn't occur unless that guarantee is available.

**Priority 7 — Properly configure a `BackupAgent` if using key-value backup.** If the app uses `BackupAgent`/`BackupAgentHelper`, `<exclude>` XML rules don't apply — the control is in code:

```kotlin
class MyBackupAgent : BackupAgent() {
    override fun onBackup(oldState: ParcelFileDescriptor?, data: BackupDataOutput,
                          newState: ParcelFileDescriptor) {
        // Write ONLY non-sensitive data; do not include tokens/credentials
    }
    override fun onRestore(data: BackupDataInput, appVersionCode: Int,
                           newState: ParcelFileDescriptor) {
        // VALIDATE restored data — treat it as untrusted input
    }
}
```

**Priority 8 — Validate restored data.** Related to Method G (§3.8): backup data can be modified by an attacker. Don't trust restored values for security decisions (premium status, quota, user role) — revalidate with the server. And avoid `android:restoreAnyVersion="true"`, which allows restore from old app versions.

**Priority 9 — Ensure `debuggable=false` in the release build.** If `true`, `adb backup` can pull the entire sandbox without root — nullifying all the Android 12 restrictions. Verify on the **release APK**, not just in `build.gradle`.

**Priority 10 — Enforce continuously.**
- Add static checks (the extended semgrep rule in §3.9 or mobsfscan) to CI/CD
- **Run this dynamic test as a regression test** after every change to local storage — a new file isn't automatically covered by an existing `<exclude>`
- Establish a policy: any new file that stores sensitive data must be placed in `noBackupFilesDir` **or** added to both rule files in the same PR
- Android's documentation emphasizes: *"**Test Regularly** — Verify backup behavior hasn't changed unexpectedly."*

### 4.2 Remediation Checklist

- [ ] A complete sandbox file inventory (from MASTG-TEST-0207) is available as a checklist
- [ ] Every sensitive file is proven to **not be restored** after a real backup+restore
- [ ] `android:allowBackup` is **explicitly** declared (not relying on the default `true`)
- [ ] If backup is not needed: `android:allowBackup="false"`
- [ ] If backup is needed: **both** attributes are declared appropriate to the `minSdk`–`targetSdk` range
- [ ] Both `backup_rules.xml` **and** `data_extraction_rules.xml` exist in the APK and match their manifest references
- [ ] Every `<exclude>` is mirrored in both **`cloud-backup`** and **`device-transfer`**
- [ ] All relevant domains are covered: `file`, `sharedpref`, `database`, `external`, and `device_*` variants if using Direct Boot
- [ ] SQLite derived files (`-wal`, `-shm`, `-journal`) are also excluded
- [ ] Directory patterns are used (`path="vault/"`) so new files are automatically covered
- [ ] Sensitive files are placed in **`context.noBackupFilesDir`** where possible
- [ ] Sensitive data that must persist is **encrypted with a key from the Android KeyStore**
- [ ] `disableIfNoEncryptionCapabilities="true"` / `requireFlags="clientSideEncryption"` is applied for highly sensitive data
- [ ] A custom `BackupAgent` (if present) does not include sensitive data, and `onRestore()` validates input
- [ ] `android:restoreAnyVersion="true"` is not used
- [ ] Restored data is not trusted for security decisions; it is revalidated with the server
- [ ] `android:debuggable="false"` is verified on the **release APK**
- [ ] Session tokens are memory-only; deleted on logout
- [ ] Static backup checks are integrated into CI/CD
- [ ] A **dynamic regression test** is run after every change to local storage
- [ ] PR policy: new storage files must go into `noBackupFilesDir` or both rule files
- [ ] **Re-verification:** re-run MASTG-TEST-0216 (Method A) → no sensitive file is restored, and the positive control is proven excluded
- [ ] **Cross-verification:** MASTG-TEST-0262 (static), MASTG-TEST-0207 (sandbox data), MASTG-TEST-0212 (key not hardcoded)

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0216: Sensitive Data Not Excluded From Backup](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0216/)
- [MASTG-TEST-0262: References to Backup Configurations Not Excluding Sensitive Data](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0262/)
- [MASWE-0006: Sensitive Data Not Excluded From Backup](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0006/)
- [MASTG-DEMO-0020: Data Exclusion using backup_rules.xml with Backup Manager](https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0020/MASTG-DEMO-0020/)
- [MASTG-DEMO-0035: Data Exclusion using backup_rules.xml with adb backup](https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0035/MASTG-DEMO-0035/)
- [MASTG-DEMO-0034: Backup and Restore App Data with semgrep](https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0034/MASTG-DEMO-0034/)
- [MASTG-KNOW-0050: Backups](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0050/)
- [MASTG-BEST-0004: Exclude Sensitive Data from Backups](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0004/)
- [MASTG-TECH-0128: Performing a Backup and Restore of App Data](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0128/)
- [MASTG-TECH-0127: Inspecting an App's Backup Data](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0127/)
- [MASTG-TECH-0117: Obtaining Information from the AndroidManifest](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0117/)
- [MASTG-TECH-0150: Analyzing the AndroidManifest](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0150/)
- [MASTG-TECH-0007: Obtaining Information from the App Package](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0007/)
- [MASTG-TEST-0207: Runtime Storage of Unencrypted Data in the App Sandbox](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0207/)
- [MASTG Rules — `mastg-android-backup-manifest.yml`](https://github.com/OWASP/mastg/blob/master/rules/mastg-android-backup-manifest.yml)
- [MASTG Utils — `mastg-android-backup-bmgr.sh`](https://github.com/OWASP/mastg/blob/master/utils/mastg-android-backup-bmgr.sh)
- [MASTG Utils — `mastg-android-backup-adb.sh`](https://github.com/OWASP/mastg/blob/master/utils/mastg-android-backup-adb.sh)
- [MASVS-STORAGE: Storage](https://mas.owasp.org/MASVS/05-MASVS-STORAGE/)
- [OWASP Mobile Top 10 2024 — M9: Insecure Data Storage](https://owasp.org/www-project-mobile-top-10/2023-risks/m9-insecure-data-storage)

### 5.2 Official Android / Google Documentation

- [Security recommendations for backups — Android Security Risks](https://developer.android.com/privacy-and-security/risks/backup-best-practices)
- [Back up user data with Auto Backup](https://developer.android.com/identity/data/autobackup)
- [Back up key-value pairs with Android Backup Service](https://developer.android.com/identity/data/keyvaluebackup)
- [Data backup overview](https://developer.android.com/identity/data/backup)
- [Test backup and restore (`bmgr`)](https://developer.android.com/identity/data/testingbackup)
- [`<application>` element — `allowBackup` attribute](https://developer.android.com/guide/topics/manifest/application-element#allowbackup)
- [`<application>` element — `fullBackupContent`, `dataExtractionRules`, `backupAgent`, `restoreAnyVersion`](https://developer.android.com/guide/topics/manifest/application-element)
- [Android 12 behavior changes — `adb backup` restrictions](https://developer.android.com/about/versions/12/behavior-changes-12#adb-backup-restrictions)
- [`BackupAgent` — API reference](https://developer.android.com/reference/android/app/backup/BackupAgent)
- [`BackupAgentHelper` — API reference](https://developer.android.com/reference/android/app/backup/BackupAgentHelper)
- [`Context.getNoBackupFilesDir()` — API reference](https://developer.android.com/reference/android/content/Context#getNoBackupFilesDir())
- [Android Keystore system](https://developer.android.com/privacy-and-security/keystore)
- [Support Direct Boot mode (device-protected storage)](https://developer.android.com/privacy-and-security/direct-boot)
- [File-Based Encryption (AOSP)](https://source.android.com/docs/security/features/encryption/file-based)
- [Data storage guidelines](https://developer.android.com/training/data-storage)

### 5.3 Standards & Weakness Taxonomies

- [CWE-530: Exposure of Backup File to an Unauthorized Control Sphere](https://cwe.mitre.org/data/definitions/530.html)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
- [CWE-359: Exposure of Private Personal Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/359.html)
- [CWE-16: Configuration](https://cwe.mitre.org/data/definitions/16.html)
- [SEI CERT Android — DRD10-J: Do not release apps that are debuggable](https://wiki.sei.cmu.edu/confluence/display/android/DRD10-J.+Do+not+release+apps+that+are+debuggable)
- [NIST SP 800-163 Rev.1 — Vetting the Security of Mobile Applications](https://csrc.nist.gov/publications/detail/sp/800-163/rev-1/final)
- [NIST SP 800-124 Rev.2 — Guidelines for Managing the Security of Mobile Devices](https://csrc.nist.gov/publications/detail/sp/800-124/rev-2/final)
- [MITRE ATT&CK Mobile — T1409: Stored Application Data](https://attack.mitre.org/techniques/T1409/)
- [OWASP ASVS — V14 Configuration](https://owasp.org/www-project-application-security-verification-standard/)

### 5.4 Security Research & Technical Articles

- [Pen Test Partners — How to subvert Android backups to export sandboxed app files](https://www.pentestpartners.com/security-blog/how-to-subvert-android-backups-to-export-sandboxed-app-files/)
- [Security Café — Mobile Pentesting 101: The Death of ADB Backup: Modern Data Extraction](https://securitycafe.ro/2026/02/02/mobile-pentesting-101-the-death-of-adb-backup-modern-data-extraction-in-2026/)
- [Ed Holloway-George — Unpacking Android Security Part 2: Insecure Data Storage](https://www.spght.dev/articles/04-06-2022/owasp-m2)
- [Medium — Android's Attribute `android:allowBackup` Demystified](https://medium.com/better-programming/androids-attribute-android-allowbackup-demystified-114b88087e3b)
- [Medium (The Startup) — Android 12 Changelog: Google Finally Restricts the Power of "adb backup"](https://medium.com/swlh/android-12-changelog-google-finally-restricts-the-power-of-adb-backup-44f2216c219)
- [Valency Networks — Backups enabled in AndroidManifest.xml: risk, impact and fix](https://valencynetworks.com/kb/android-allow-backup-enabled-vulnerability-risk-impact-and-fix.html)
- [Fluid Attacks — Insecure service configuration: ADB Backups](https://help.fluidattacks.com/portal/en/kb/articles/criteria-vulnerabilities-055)
- [Mozilla Bugzilla #1021742 — Fennec manifest allows for ADB backup attack](https://bugzilla.mozilla.org/show_bug.cgi?id=1021742)
- [adb-backup-apk-injection — PoC of APK injection into a backup archive](https://github.com/alsan/adb-backup-apk-injection)
- [Oxygen Forensics — Sandboxing in Android: implications for extraction of data via ADB](https://www.oxygenforensics.com/resources/android-sandboxing/)
- [HackTricks — Android Applications Pentesting](https://book.hacktricks.wiki/en/mobile-pentesting/android-app-pentesting/index.html)

### 5.5 Tool Documentation

- [Android Backup Extractor (`abe`)](https://github.com/nelenkov/android-backup-extractor)
- [adb — Android Debug Bridge](https://developer.android.com/tools/adb)
- [`bmgr` — Backup Manager (via testing backup docs)](https://developer.android.com/identity/data/testingbackup)
- [apktool — Reverse engineering Android APK files](https://apktool.org/)
- [aapt2 — Android Asset Packaging Tool](https://developer.android.com/tools/aapt2)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
- [mobsfscan — static analysis for Android/iOS](https://github.com/MobSF/mobsfscan)
- [drozer — Android security assessment framework](https://github.com/WithSecureLabs/drozer)
- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [Frida — Documentation Home](https://frida.re/docs/home/)
- [sqlite3 CLI](https://www.sqlite.org/cli.html)

---

*This document was compiled based on the OWASP MASTG (latest release as of September 2026), official Android Developers documentation, CWE/NIST/SEI CERT standards, and third-party security research and technical articles.*
