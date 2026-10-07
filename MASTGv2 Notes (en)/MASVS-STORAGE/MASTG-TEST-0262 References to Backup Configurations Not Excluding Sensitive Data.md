# MASTG-TEST-0262 References to Backup Configurations Not Excluding Sensitive Data

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0262 |
| **Platform** | Android |
| **MASVS Category** | MASVS-STORAGE (MASVS-STORAGE-2) |
| **Weakness** | MASWE-0006 — *Sensitive Data Not Excluded From Backup* |
| **Test Type** | Static, Code |
| **Profile** | L1, L2, P |
| **Knowledge** | MASTG-KNOW-0050 (Backups) |
| **Best Practice** | MASTG-BEST-0004 |
| **Related Techniques** | MASTG-TECH-0117 (Obtaining AndroidManifest), MASTG-TECH-0150 (Analyzing AndroidManifest), MASTG-TECH-0007 (Extract Layout/Resource Files) |
| **Related Tests** | **MASTG-TEST-0216** (Sensitive Data Not Excluded From Backup) — the **dynamic** counterpart; that test's official overview explicitly states *"See MASTG-TEST-0262 for a static analysis counterpart"* |
| **Related Demo** | — (none) |
| **Official Rule** | **Two** rules: `mastg-android-backup-manifest-allow-backup` and `mastg-android-backup-manifest-backup-rules` — both only check for the **presence** of the attribute, not the **content/adequacy** of the exclude rules file (see §3.2) |
| **Related CWE** | CWE-530 (Exposure of Backup File to an Unauthorized Control Sphere), CWE-200 |

---

## 1. Explanation

### 1.1 Relationship with MASTG-TEST-0216

This test is the **static counterpart** of **MASTG-TEST-0216**, already covered in depth earlier in this research series (including 7 multi-tool methods: `bmgr`/local transport, `adb backup`, Android Backup Extractor, semgrep, apktool+grep/aapt2/MobSF/drozer, cloud/device-transfer verification, and restore integrity testing). The official overview of MASTG-TEST-0216 itself explicitly refers back to this test:

> *"See MASTG-TEST-0262 for a static analysis counterpart."*

Because much of the core methodology (the `adb backup` mechanism, Android Backup Extractor, the basic semgrep rule) has **already been covered in detail** in the MASTG-TEST-0216 document, this document focuses on the **details of pure static evaluation** — reading `AndroidManifest.xml` and the `backup_rules.xml`/`data_extraction_rules.xml` files — without needing to run the application or a device at all.

### 1.2 Two Backup Pathways, Two Different Configuration Schemes

The official overview explains **two available backup approaches** on Android, each with a different exclusion mechanism:

| Approach | Since Version | Exclusion Mechanism |
|---|---|---|
| **Auto Backup** (recommended) | Android 6.0 (API 23)+ | A declarative XML file (`backup_rules.xml`/`data_extraction_rules.xml`) with `<exclude>` tags |
| **Key-Value Backup** | Android 2.2 (API 8)+ | `BackupAgent`/`BackupAgentHelper` — exclusion logic is determined **programmatically** in Java/Kotlin code, not through a declarative XML file |

Auto Backup is the **recommended** approach because it is enabled by default and requires no additional implementation work — but this is also precisely what makes it **the riskiest** when a developer is not aware of the need to explicitly exclude sensitive data, because the default is to **include everything**. Key-Value Backup, by contrast, requires the developer to explicitly write code specifying what gets backed up — a design that indirectly forces awareness, but is rarely used in modern applications.

### 1.3 File Schemes by Android Version — A Nuance Easily Overlooked

This is a crucial point that distinguishes this test from a simple backup evaluation: **the manifest attribute name and the configuration file name differ depending on the targeted Android version**:

| Android Version | Manifest Attribute | Conventional File Name |
|---|---|---|
| Android 11 (API 30) and below | `android:fullBackupContent` | `backup_rules.xml` |
| Android 12 (API 31) and above | `android:dataExtractionRules` | `data_extraction_rules.xml` |

An application targeting a wide API range (e.g., a low `minSdkVersion`, high `targetSdkVersion`) **ideally needs to declare both at once** — one for legacy devices, one for modern devices. A common mistake testers should watch for: a developer who only updates `data_extraction_rules.xml` (following the latest version) but **forgets** the older `backup_rules.xml` — leaving an inconsistent exclusion gap for users on Android 11 and below devices.

### 1.4 The `cloud-backup` vs. `device-transfer` Parameters — A Granularity Often Overlooked

This is a technical nuance **explicitly** highlighted by the official overview and very easy to miss on a cursory inspection:

> *"The `cloud-backup` and `device-transfer` parameters can be used to exclude files from cloud backups and device-to-device transfers, respectively."*

Since `dataExtractionRules` (Android 12+), Android separates **two different data transfer scenarios**:

- **`cloud-backup`**: data synced to the user's Google Drive account (recoverable on any new device logged in with the same account).
- **`device-transfer`**: data moved directly between devices (e.g., via cable/Wi-Fi Direct during new device setup), **without** involving the cloud at all.

Example configuration distinguishing the two:

```xml
<data-extraction-rules>
    <cloud-backup>
        <exclude domain="sharedpref" path="auth_tokens.xml"/>
    </cloud-backup>
    <device-transfer>
        <exclude domain="sharedpref" path="auth_tokens.xml"/>
    </device-transfer>
</data-extraction-rules>
```

**A commonly overlooked evaluation gap**: a developer who only excludes a file within the `<cloud-backup>` block but **forgets** to include the same exclusion in the `<device-transfer>` block (or vice versa) will still leak sensitive data through the unexcluded pathway — even though, at a glance, the `data_extraction_rules.xml` file **appears** correct because it contains an `<exclude>` tag for the file in question. Testers **must check both blocks separately**, not merely confirm that an `<exclude>` tag for the related file "exists somewhere" within that file.

### 1.5 Four FAIL Conditions That Must Be Read as an OR Chain, Not a Single AND

This test's official Evaluation clause has a structure that must be read carefully:

> *"The test case fails if the app allows sensitive data to be backed up. Specifically, if the following conditions are met: `android:allowBackup="true"`... `fullBackupContent` isn't declared (Android 11-)... `dataExtractionRules` isn't declared (Android 12+)... `backup_rules.xml`/`data_extraction_rules.xml` aren't present or don't exclude all sensitive files."*

The absolute prerequisite for a FAIL is **`allowBackup="true"`** (or not declared at all — the default being `true`, as confirmed by MASTG-KNOW-0050: *"When this attribute is unavailable, the allowBackup setting is enabled by default"*). Once this prerequisite is met, the subsequent FAIL conditions branch depending on the relevant Android version (fullBackupContent **or** dataExtractionRules, depending on the target version) **or** — even if the rules file attribute has been declared — the rules file itself **does not exist** or **does not exclude all sensitive files** (§1.4 regarding cloud-backup/device-transfer coverage).

---

## 2. Tools Used for Testing

Since the core methodology (semgrep, apktool, aapt2, drozer) has already been discussed in depth in the MASTG-TEST-0216 document, this section highlights the tools relevant **specifically to this test's precise static evaluation**.

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **jadx --no-src / apktool** | Extracting `AndroidManifest.xml` and `res/xml/*.xml` resources |
| **xmlstarlet / yq** | Structured parsing to precisely distinguish the contents of the `<cloud-backup>` vs. `<device-transfer>` blocks (§1.4) |
| **semgrep** | Running the official rule as a baseline for attribute presence |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **CodeQL** | For applications using Key-Value Backup — tracing the `BackupAgent`/`onBackup()` implementation to verify that sensitive data is indeed excluded programmatically |
| **MobSF** | Displays `allowBackup` status and the presence of rules files in the Manifest Analysis report |
| **androguard** | Programmatic manifest parsing for large-scale/CI audits |

### 2.3 Environment Prerequisites

- **No device/root required** — can be done entirely from the APK file.
- **Extract BOTH configuration files** (`backup_rules.xml` AND `data_extraction_rules.xml`) if both exist — do not assume only one is relevant without checking the application's `minSdkVersion`/`targetSdkVersion` (§1.3).

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0117** to obtain `AndroidManifest.xml`.
2. Use **MASTG-TECH-0150** to obtain the relevant flags and attributes.
3. Use **MASTG-TECH-0007** to extract `backup_rules.xml`/`data_extraction_rules.xml`.

### 3.2 Method A — Official Semgrep Rule + File Content Verification *(official rule exists, but only checks presence)*

```yaml
rules:
  - id: mastg-android-backup-manifest-allow-backup
    severity: WARNING
    languages: [xml]
    message: "[MASVS-STORAGE-2] allowBackup detected as $ARG."
    patterns:
      - pattern: 'android:allowBackup="$ARG"'
  - id: mastg-android-backup-manifest-backup-rules
    severity: WARNING
    languages: [xml]
    message: "[MASVS-STORAGE-2] Backup rules detected."
    pattern-either:
      - pattern: 'android:fullBackupContent="@xml/backup_rules"'
      - pattern: 'android:dataExtractionRules="@xml/data_extraction_rules"'
```

```bash
semgrep --config https://raw.githubusercontent.com/OWASP/mastg/master/rules/mastg-android-backup-manifest.yml ./out/resources/AndroidManifest.xml
```

**Coverage gap**: both rules **only detect the presence** of an attribute/file name pattern, and do **not validate the contents** of `backup_rules.xml`/`data_extraction_rules.xml` at all — i.e., whether that file actually excludes **all** sensitive files (and covers **both** the `cloud-backup`/`device-transfer` blocks, §1.4). An application can pass both rules (attribute exists, file name matches the convention) yet still FAIL substantively if its rules file content is empty or incomplete.

### 3.3 Method B — Structured Extraction and Parsing of Rules File Contents

```bash
jadx --no-src -d ./out target-app.apk

# 1. Check allowBackup
grep -o 'android:allowBackup="[^"]*"' ./out/resources/AndroidManifest.xml

# 2. Check the rules file attribute MATCHING the target version
grep -o 'android:fullBackupContent="[^"]*"\|android:dataExtractionRules="[^"]*"' ./out/resources/AndroidManifest.xml

# 3. Extract and parse the rules file content in a structured way
BACKUP_RULES=./out/resources/res/xml/backup_rules.xml
DATA_EXTRACTION=./out/resources/res/xml/data_extraction_rules.xml

echo "=== backup_rules.xml (Android 11-) ==="
[ -f "$BACKUP_RULES" ] && cat "$BACKUP_RULES" || echo "NOT FOUND"

echo "=== data_extraction_rules.xml (Android 12+) ==="
if [ -f "$DATA_EXTRACTION" ]; then
    echo "-- cloud-backup block contents --"
    xmlstarlet sel -t -c "//cloud-backup" "$DATA_EXTRACTION"
    echo "-- device-transfer block contents --"
    xmlstarlet sel -t -c "//device-transfer" "$DATA_EXTRACTION"
else
    echo "NOT FOUND"
fi
```

### 3.4 Method C — Correlation with the Application's Actual Sensitive File List

The most important step that cannot be purely automated: **the list of what should be excluded** must be compared against **the files the application actually creates** at runtime (databases, SharedPreferences, internal files):

```bash
# Run the application, use features that store sensitive data, then:
adb shell run-as com.target.app find /data/data/com.target.app -type f

# Compare this file list against the <exclude> tags in backup_rules.xml/data_extraction_rules.xml
```

Refer to the MASTG-TEST-0216 document §3 for the complete methodology for definitive verification through an actual backup/restore (`adb backup`, Android Backup Extractor) — the static approach here only validates the **configuration**, whereas MASTG-TEST-0216 validates the **actual outcome**.

### 3.5 Method D — Verifying Key-Value Backup (If Used)

```bash
rg -n 'extends BackupAgent\b|extends BackupAgentHelper\b' ./decompiled/sources/
rg -n -A20 'onBackup\(' ./decompiled/sources/ | grep -i "password\|token\|key\|secret"
```

If a custom `BackupAgent` implementation is found, review `onBackup()` to confirm that sensitive data is explicitly **not** included in the `BackupDataOutput`.

### 3.6 Method Comparison: When to Use Which

| Method | Tool | Validates presence? | Validates content adequacy? | When to use |
|---|---|---|---|---|
| **A** | Official semgrep rule | ✅ | ❌ | Quick baseline |
| **B** | Structured parsing | ✅ | ✅ (content & block separation) | **Mandatory** for a complete evaluation |
| **C** | Correlation with actual files | N/A | ✅ (most definitive statically) | Before concluding a final PASS |
| **D** | BackupAgent code review | ✅ | ✅ | Specific to Key-Value Backup applications |

**Recommended minimum combination:** **B (structured parsing of both blocks) → C (correlation with the application's actual files)**, supplemented by dynamic confirmation via MASTG-TEST-0216 as the final proof that no static analysis alone can replace.

---

### 3.7 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule** (refer to §1.5 for the structure of its condition logic).

---

#### ❌ FAIL / ISSUE — The check is declared FAILED when:

| No | Condition |
|---|---|
| F1 | `allowBackup` is `true` or not declared at all (default `true`), **and** there is no `fullBackupContent`/`dataExtractionRules` relevant to the target version |
| F2 | The rules file attribute exists, but the `backup_rules.xml`/`data_extraction_rules.xml` file **is not found** in the APK resources |
| F3 | The rules file exists, but **does not exclude** files known to store sensitive data (confirmed via Method C) |
| F4 | A sensitive file is excluded in the `<cloud-backup>` block but **not** in `<device-transfer>` (or vice versa) — the granularity gap from §1.4 |

---

#### ✅ PASS — The check is declared PASSED when:

| No | Condition |
|---|---|
| P1 | `allowBackup="false"` is explicitly set — the simplest and most definitive approach |
| P2 | `allowBackup="true"`, **and** the rules file matching the target version exists and is found to exclude **all** sensitive files in **both** the cloud-backup and device-transfer blocks (where applicable) |
| P3 | The application uses Key-Value Backup with a verified `BackupAgent` (Method D) that does not include sensitive data |

---

#### ⚠️ Important Notes on Assessment

1. **The official rule only validates presence, not adequacy** — do not conclude PASS merely from an empty semgrep result; manually/structurally verifying the rules file content (Method B) is mandatory.

2. **Check both the `cloud-backup` and `device-transfer` blocks separately** (§1.4) — this is the subtlest and most easily overlooked gap in this test's evaluation.

3. **Check the attribute-file version correspondence** (§1.3) — an application with a wide API range ideally has both schemes (old and new) consistently declared.

4. **Always correlate with MASTG-TEST-0216** for definitive proof — a configuration that **appears** correct statically still needs to be verified through an actual backup/restore, since a syntax/path error in the `<exclude>` tag could cause the exclusion to fail to function even though the configuration file "exists."

5. **Severity is modulated** by the sensitivity of the data that could potentially be backed up — credentials/cryptographic keys are far more critical than non-sensitive cache data.

6. **Document:** the `allowBackup` status, the application's target version (determines which scheme is relevant), the full content of both rules file blocks, and the correlation result with the application's actual files.

---

## 4. Recommendations

Refer to **the MASTG-TEST-0216 document §4** for in-depth recommendations. Additional specifics from a static-analysis standpoint:

### 4.1 Declare Both Schemes Consistently

```xml
<application
    android:allowBackup="true"
    android:fullBackupContent="@xml/backup_rules"
    android:dataExtractionRules="@xml/data_extraction_rules">
```

```xml
<!-- data_extraction_rules.xml -->
<data-extraction-rules>
    <cloud-backup>
        <exclude domain="sharedpref" path="auth_tokens.xml"/>
        <exclude domain="database" path="secure_vault.db"/>
    </cloud-backup>
    <device-transfer>
        <exclude domain="sharedpref" path="auth_tokens.xml"/>
        <exclude domain="database" path="secure_vault.db"/>
    </device-transfer>
</data-extraction-rules>
```

### 4.2 Integrate into CI/CD

```bash
#!/bin/bash
# ci-check-backup-rules-completeness.sh
DATA_EXTRACTION=./res/xml/data_extraction_rules.xml
CLOUD_EXCLUDES=$(xmlstarlet sel -t -c "//cloud-backup/exclude" "$DATA_EXTRACTION" | wc -l)
TRANSFER_EXCLUDES=$(xmlstarlet sel -t -c "//device-transfer/exclude" "$DATA_EXTRACTION" | wc -l)
if [ "$CLOUD_EXCLUDES" != "$TRANSFER_EXCLUDES" ]; then
    echo "[WARNING] Number of excludes in cloud-backup ($CLOUD_EXCLUDES) differs from device-transfer ($TRANSFER_EXCLUDES)"
fi
```

### 4.3 Remediation Checklist

- [ ] `allowBackup` is evaluated — set to `false` if backup is not needed at all
- [ ] If backup is needed, both schemes (`fullBackupContent`/`dataExtractionRules`) are declared consistently
- [ ] Both the `cloud-backup` and `device-transfer` blocks exclude the same sensitive files
- [ ] The application's actual sensitive file list is correlated with the `<exclude>` tags (Method C)
- [ ] Cross-verification with MASTG-TEST-0216 (actual backup/restore) has been performed
- [ ] **Re-verify:** rerun MASTG-TEST-0262 with every addition of new data storage

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0262: References to Backup Configurations Not Excluding Sensitive Data](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0262/)
- [MASTG-TEST-0216: Sensitive Data Not Excluded From Backup](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0216/)
- [MASWE-0006: Sensitive Data Not Excluded From Backup](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0006/)
- [MASTG-KNOW-0050: Backups](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0050/)
- [MASTG-BEST-0004](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0004/)
- [Official rule: mastg-android-backup-manifest.yml (GitHub)](https://github.com/OWASP/mastg/blob/master/rules/mastg-android-backup-manifest.yml)

### 5.2 Official Android Documentation

- [Android Developers — Back up user data with Auto Backup](https://developer.android.com/identity/data/autobackup)
- [Android Developers — `dataExtractionRules` XML schema](https://developer.android.com/identity/data/autobackup#IncludingFiles)
- [Android Developers — Key/Value Backup](https://developer.android.com/identity/data/keyvaluebackup)
- [Android Developers — `allowBackup` attribute reference](https://developer.android.com/guide/topics/manifest/application-element#allowbackup)

### 5.3 Tool Documentation

- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [xmlstarlet](http://xmlstar.sourceforge.net/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)

---

*This document was compiled based on OWASP MASTG (latest release as of September 2026) and official Android Developers documentation. As the static counterpart of MASTG-TEST-0216, this document focuses on the manifest and rules file configuration evaluation details not repeated from that document. The two most important nuances: (1) the attribute/file scheme differs between Android 11- and 12+, requiring an application with a wide API range to consistently declare both, and (2) the `cloud-backup` vs. `device-transfer` parameters in `data_extraction_rules.xml` must be checked separately — a complete exclusion in one block does not guarantee the same completeness in the other block.*
