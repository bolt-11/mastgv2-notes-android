# MASTG-TEST-0224 Usage of Insecure APK Signature Version

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0224 |
| **Platform** | Android |
| **MASVS Category** | **MASVS-RESILIENCE** (Resilience Against Reverse Engineering and Tampering) |
| **Weakness** | **MASWE-0056** — *Usage of Insecure APK Signature Version* |
| **Test Type** | **Static**, Code |
| **Profile** | **R** (Resilience) — see §1.2 for an explanation of this profile |
| **`available_since`** | **24** — this test's relevance is tied to API level 24 (the introduction of the v2 scheme), see §1.3 |
| **Knowledge** | MASTG-KNOW-0003 (App Signing) |
| **Best Practice** | MASTG-BEST-0006 (Use Up-to-Date APK Signing Schemes) |
| **Related Techniques** | MASTG-TECH-0117 (Obtaining Information from the AndroidManifest), MASTG-TECH-0150 (Analyzing the AndroidManifest), MASTG-TECH-0116 (Obtaining Information about the APK Signature) |
| **Related Demo** | — (MASTG does not yet provide a demo for this test) |
| **Related CVE** | **CVE-2017-13156** ("Janus") |
| **Related CWE** | CWE-345 (Insufficient Verification of Data Authenticity), CWE-353 (Missing Support for Integrity Check), CWE-494 (Download of Code Without Integrity Check) |

---

## 1. Explanation

### 1.1 Testing Objective

Direct quote from the MASTG overview:

> *"Not using newer APK signing schemes means that the app lacks the enhanced security provided by more robust, updated mechanisms."*
>
> *"This test checks if the **outdated v1 signature scheme** is enabled. The v1 scheme is vulnerable to certain attacks, such as the **'Janus' vulnerability** (CVE-2017-13156), because it **does not cover all parts of the APK file**, allowing malicious actors to potentially **modify parts of the APK without invalidating the signature**. Relying solely on v1 signing therefore increases the risk of tampering and compromises app security."*

This test is purely about the APK's **signing configuration** — not about the application's code. Its purpose is to verify that the app does not rely **exclusively** on the outdated v1 signature scheme (JAR signing), but also uses the stronger v2/v3 schemes.

### 1.2 Why the Profile Is "R" (Resilience), Not L1/L2

This is an important mental model for understanding *why* this test exists and how it differs from the crypto/storage tests we have covered previously.

The **R** profile is specifically intended for *"apps that require resilience against reverse engineering and tampering, independently of the security level"* — separate from L1 (baseline security) and L2 (high security for sensitive data). Profile R is relevant for applications where the **binary itself is the target of an attack**: apps with DRM-licensed content, payment apps, apps with proprietary algorithms, or apps where bypassing client-side logic can cause direct financial loss.

The practical consequence for this test: **APK integrity** (ensuring the APK has not been modified since it was signed by the developer) is the first line of defense against **tampering** — modifying the official APK to inject malicious code, remove license checks, or hijack business logic, then redistributing it (repackaging) as if it were the genuine app. This is qualitatively different from the MASVS-STORAGE/CRYPTO tests, which focus on *how data is handled*, not *whether the application binary itself is authentic*.

### 1.3 The Significance of `available_since: 24`

This field indicates that this test's relevance is closely tied to **Android 7.0 (API level 24)** — the Android version in which **APK Signature Scheme v2** was first introduced. This is important context for understanding the evaluation criteria in §3.9: the FAIL criteria explicitly apply only to apps with `minSdkVersion` ≥ 24, because below that version, v2 signing **cannot even be used** (not supported by the platform) — so relying on v1 alone is not a wrong choice, but rather **the only option available**.

### 1.4 Three (Actually Four) APK Signing Schemes

MASTG-KNOW-0003 lists these schemes along with their Android version support:

| Scheme | Introduced in | How it works | Protection coverage |
|---|---|---|---|
| **v1 (JAR signing)** | Android 1.0 | Signs each **ZIP entry individually** within the `META-INF/MANIFEST.MF` manifest | **Only** the explicitly listed ZIP entries — **does not cover any additional bytes** outside the ZIP entries |
| **v2 (APK Signature Scheme v2)** | Android 7.0 (API 24) | Signs the **entire contents of the APK file as a single block** (whole-file signing), inserted between the *Central Directory* and the *End of Central Directory* of the ZIP format | **All bytes of the APK** — far more comprehensive |
| **v3 (APK Signature Scheme v3)** | Android 9 (API 28) | Same as v2, plus support for **key rotation** — allowing developers to change signing keys over time while still maintaining compatibility with the old key | Same as v2, plus key-rotation flexibility |
| **v3.1** | Android 11+ | A v3 variant with improved target-SDK-based handling of key rotation | Same as v3 |
| **v4** | Android 11 (API 30) | An additional scheme to support **incremental APK installation** (ADB Incremental / Android App Bundle) | **Not a replacement** for v2/v3 — v4 **must be paired** with v2 or v3, and does not provide integrity protection on its own |

MASTG-KNOW-0003 reinforces an important principle: *"For each signing scheme the release builds should always be signed via all its previous schemes as well."* — meaning a correctly configured modern APK will show **v1 = true, v2 = true, v3 = true** all at once (not just one of them), for backward compatibility with older Android devices that do not yet support v2/v3.

**MASTG-BEST-0006 reaffirms this for v4:** *"v4 alone does not provide security protections and should be used alongside v2 or v3."* — this is a commonly misunderstood point: enabling v4 **without** v2/v3 provides no security benefit whatsoever, only an installation-speed benefit.

### 1.5 The "Janus" Vulnerability (CVE-2017-13156) — Why v1 Alone Is Dangerous

This is the vulnerability that is the primary reason this test exists, named after the two-faced Roman god Janus — referring to a file's ability to validly be **two things at once**.

**Root technical cause:** a single file can be a valid APK **and** a valid DEX file **simultaneously**. This is possible because:

- The **APK format is a ZIP archive**, which by specification allows arbitrary additional bytes **before** and **between** its ZIP entries, without breaking the validity of the ZIP archive itself.
- The **v1 signature scheme only accounts for the ZIP entries** listed in the manifest — it **ignores any additional bytes** outside those entries when computing or verifying the app's signature.

**How the exploitation works:**

1. The attacker takes a malicious DEX file (containing a payload/malware).
2. The attacker **prepends** the entire contents of the original, legitimately signed APK **after** the malicious DEX.
3. The result is a single file that: (a) remains a **valid APK ZIP** because the original ZIP entries are still located correctly relative to the end of the file, **and** (b) is also a **valid DEX file** because it begins with a legitimate DEX header.
4. Because the Android Runtime (Dalvik/ART on vulnerable versions) loads this file **as DEX first** — while the v1 signature verification system verifies it **as an APK** and only checks the unchanged ZIP entries — **the signature remains valid**, even though the code actually executed is effectively the malicious DEX prepended at the front.

**Impact and scope:**

- This vulnerability affects Android devices running **5.1.1 through 8.0** — at the time it was discovered (2017), this covered **approximately 74% of all active Android devices**.
- **APKs signed with the v2 scheme are protected** from this vulnerability, because — unlike v1 — v2 accounts for **every byte within the APK file**, so prepending any additional bytes (such as a malicious DEX at the front) will **immediately invalidate the signature**.
- GuardSquare reported this vulnerability to Google on July 31, 2017; Google released a patch to partners in November 2017 and publicly disclosed CVE-2017-13156 in the December 2017 Android Security Bulletin.

**Why this matters beyond "just an old version":** Janus is not a theoretical vulnerability — it allows an attacker to **redistribute an app that appears identical** (same package name, icon, and a developer signature that is "valid" according to v1) but actually runs malicious code. This is exactly the kind of **repackaging/tampering** attack that the Resilience profile (§1.2) is focused on — threatening the integrity and brand reputation of the app, not just individual user data.

### 1.6 Why This Isn't Simply "Use the Latest Scheme"

A nuance worth understanding: the MASTG evaluation criteria do **not** require v3 or v4 — they only require **not relying on v1 alone**. This is because:

- **v2 alone is already sufficient** to close the Janus gap, since v2 already validates all bytes of the APK.
- **v3 provides an additional benefit** (key rotation) but is not an absolute requirement for passing this test — although MASTG-BEST-0006 still recommends it *"for optimal security and compatibility."*
- **v4 is irrelevant to security** in the context of this test entirely — it is purely an installation-performance feature.

---

## 2. Tools Used for Testing

### 2.1 Mandatory Tools (Core)

| Tool | MASTG ID | Function |
|---|---|---|
| **apksigner** | MASTG-TOOL-0123 | **Official MASTG tool and official Android SDK tool.** The only tool that can definitively verify the v3/v3.1/v4 schemes |
| **jadx / apktool** | MASTG-TOOL-0018 / 0011 | Extracting `AndroidManifest.xml` to obtain `minSdkVersion` |
| **aapt2** | MASTG-TOOL-0124 | A fast alternative for reading `minSdkVersion` without full decompilation |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **apkanalyzer** (part of the Android SDK) | Google's alternative — displays signing info in the APK Analyzer tab of Android Studio, or via CLI |
| **unzip / zipinfo** | Manual verification of the presence of `META-INF/MANIFEST.MF`, `.SF`, `.RSA`/`.DSA` (indicative of v1) — supplementary visual evidence |
| **Python `pyaxmlparser` / `androguard`** | Scripting for bulk audits of many APKs at once, programmatic extraction of `minSdkVersion` and signing info |
| **MobSF** | Automated analysis, reports the signing scheme used in the APK report |
| **Frida/Objection** | Not directly relevant for this test (the test is purely static, performed on the APK file, not on a running application) |
| **VirusTotal / Koodous** | For APKs already in public circulation, can check signing metadata without manually downloading the file |

### 2.3 Environment Prerequisites

- **No device and no root required** — just the APK file. Fully automatable in CI/CD.
- **Use an actual release build**, not a development debug build — signing configuration is often drastically different between the two, and debug builds are irrelevant for a production security assessment.
- **`apksigner` is part of the Android SDK Build-Tools** — ensure it is available at `$ANDROID_HOME/build-tools/<version>/apksigner`, or install it separately via `sdkmanager`.
- **Check the final distributed APK**, not just the raw AAB (Android App Bundle) — Google Play re-signs APKs generated from an AAB, so the signing scheme on the APK actually installed on a user's device may differ from what is seen in a local build artifact. For a representative audit, obtain the APK produced by `bundletool` that simulates the Play Store process, or extract it directly from a device that already has the app installed.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0117** (*Obtaining Information from the AndroidManifest*) to obtain the `AndroidManifest.xml`.
2. Use **MASTG-TECH-0150** (*Analyzing the AndroidManifest*) to obtain the `minSdkVersion` attribute from the manifest.
3. Use **MASTG-TECH-0116** (*Obtaining Information about the APK Signature*) to list all signature schemes used.

### 3.2 Method A — apksigner *(official MASTG and official Android)*

**Step 1 — Obtain `minSdkVersion`:**

```bash
# Via aapt2 (fastest, no decompilation)
aapt2 d badging YourApp.apk | grep -E "sdkVersion|minSdkVersion"

# Via jadx (if already decompiled for other purposes)
jadx --no-src -d out_dir YourApp.apk
grep -i "minSdkVersion" out_dir/resources/AndroidManifest.xml

# Via apktool
apktool d -f -o out_dir YourApp.apk
cat out_dir/apktool.yml | grep -A2 sdkInfo
```

**Step 2 — Verify the signature scheme:**

```bash
apksigner verify --verbose YourApp.apk
```

Official MASTG-TECH-0116 example output:

```
Verifies
Verified using v1 scheme (JAR signing): false
Verified using v2 scheme (APK Signature Scheme v2): true
Verified using v3 scheme (APK Signature Scheme v3): true
Verified using v3.1 scheme (APK Signature Scheme v3.1): false
Verified using v4 scheme (APK Signature Scheme v4): false
Verified for SourceStamp: false
Number of signers: 1
```

**Step 3 (optional) — Signer certificate details**, useful for verifying developer identity and certificate validity period:

```bash
apksigner verify --print-certs --verbose YourApp.apk
```

```
Signer #1 certificate DN: CN=Example Developers, OU=Android, O=Example
Signer #1 certificate SHA-256 digest: 1fc4de52d0daa33a9c0e3d67217a77c895b46266ef020fad0d48216a6ad6cb70
Signer #1 key algorithm: RSA
Signer #1 key size (bits): 2048
```

### 3.3 Method B — apkanalyzer *(direct alternative from the Android SDK)*

```bash
# Via CLI (part of the Android SDK cmdline-tools)
apkanalyzer apk summary YourApp.apk

# Via Android Studio: Build > Analyze APK... > view the signing info panel
```

Advantage: integrated directly into the Android Studio workflow, making it easier for developers to check for themselves before release without switching to a terminal.

### 3.4 Method C — androguard / pyaxmlparser *(scripting for bulk audits)*

Useful when you need to audit **many APKs at once** (e.g. an organization's entire app portfolio, or monitoring competitor releases).

```python
# check_signing.py
from androguard.core.apk import APK
import subprocess
import glob

def check_signing_schemes(apk_path):
    result = subprocess.run(
        ["apksigner", "verify", "--verbose", apk_path],
        capture_output=True, text=True
    )
    return result.stdout

def get_min_sdk(apk_path):
    a = APK(apk_path)
    return a.get_min_sdk_version()

for apk_path in glob.glob("./apks/*.apk"):
    min_sdk = get_min_sdk(apk_path)
    signing_info = check_signing_schemes(apk_path)
    v1 = "v1 scheme (JAR signing): true" in signing_info
    v2 = "v2 scheme (APK Signature Scheme v2): true" in signing_info
    v3 = "v3 scheme (APK Signature Scheme v3): true" in signing_info

    verdict = "FAIL" if (int(min_sdk) >= 24 and v1 and not v2 and not v3) else "PASS"
    print(f"{apk_path}: minSdk={min_sdk}, v1={v1}, v2={v2}, v3={v3} -> {verdict}")
```

```bash
pip install androguard
python3 check_signing.py
```

### 3.5 Method D — Manual ZIP structure verification *(supporting visual evidence)*

This is not a replacement for `apksigner`, but is useful as **additional, easy-to-understand evidence** in a report — visually showing the presence (or absence) of artifacts for each scheme.

```bash
# v1 (JAR signing) leaves traces as files under META-INF/
unzip -l YourApp.apk | grep -E "META-INF/(MANIFEST\.MF|.*\.SF|.*\.(RSA|DSA|EC))"
# Example output when v1 is active:
#   META-INF/MANIFEST.MF
#   META-INF/CERT.SF
#   META-INF/CERT.RSA

# v2/v3 do not leave a separate file trace within the ZIP structure -
# their signature block is inserted between the Central Directory and
# the End of Central Directory, so it is NOT visible via a regular `unzip -l`.
# For this, the apksigner/APK Signing Block parser is still REQUIRED for v2/v3.
```

> **Important warning:** the absence of `META-INF/*.RSA` files does **not necessarily prove** with certainty that v1 is disabled in all edge cases, and more critically: **you cannot verify v2/v3 at all** just by looking at the ZIP structure, because neither leaves a visible file artifact via `unzip -l`. **Always use `apksigner` as the primary source of truth** — this method is purely an illustrative supplement.

### 3.6 Method E — MobSF *(automated, citation-ready report)*

```bash
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
```

Upload the APK → look for the **Certificate Analysis** / **APK Signing Scheme** section in the report. MobSF typically displays the v1/v2/v3 status along with a warning flag if only v1 is active, and certificate details (validity, algorithm, key size) in a single view.

### 3.7 Method F — bundletool *(for apps distributed via Android App Bundle)*

Because most modern apps are released in **AAB** format, it is important to test the **generated** APK that actually reaches a user's device — not the raw AAB itself (which is not signed with the same scheme).

```bash
# Generate an APK set from the AAB, simulating the Google Play process
bundletool build-apks --bundle=YourApp.aab --output=YourApp.apks \
  --ks=release.keystore --ks-key-alias=release

# Extract the base APK for verification
unzip -p YourApp.apks universal.apk > universal_extracted.apk
apksigner verify --verbose universal_extracted.apk
```

### 3.8 Method Comparison: When to Use Which

| Method | Tool | Verifies v1? | Definitively verifies v2/v3/v4? | Suitable for bulk audits? | When to use |
|---|---|---|---|---|---|
| **A** | apksigner (MASTG) | ✅ | ✅ **(the only definitive option)** | Moderate (requires scripting) | **Official baseline — must always be used** |
| **B** | apkanalyzer | ✅ | ✅ | Low | Quick verification inside Android Studio |
| **C** | androguard/pyaxmlparser | ✅ (via internal apksigner) | ✅ | ✅ **(best for large scale)** | Auditing a portfolio of many APKs, CI integration |
| **D** | unzip / zipinfo manual | Partial (indicative) | ❌ **(cannot)** | Low | **Visual supporting evidence only**, not a source of truth |
| **E** | MobSF | ✅ | ✅ | Partial | A comprehensive, citation-ready report |
| **F** | bundletool | ✅ (on the generated output) | ✅ | Moderate | Apps released via AAB — representative of the actual APK |

**Minimum recommended combination:** **A (apksigner), always, without exception.**
This is a test where a single official tool (`apksigner`) already provides a definitive and complete answer — unlike other static code tests that require multiple paths to close rule gaps. Add **F (bundletool)** if the app is released via AAB, to ensure you're testing a truly representative APK, and **C (androguard)** when you need to automatically audit many APKs at once.

---

### 3.9 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Observation:** *"The output should contain the value of the `minSdkVersion` attribute and the used signature schemes (for example `Verified using v3 scheme (APK Signature Scheme v3): true`)."*
>
> **Evaluation:** *"The test case **fails** if the app has a `minSdkVersion` attribute of **24 and above**, and **only the v1 signature scheme** is enabled."*

Note that this FAIL criteria is a **combination of two conditions that must both be met**:

1. `minSdkVersion` ≥ 24, **AND**
2. Only v1 is active (v2/v3/v3.1/v4 are all `false`)

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition | Example evidence |
|---|---|---|
| F1 | `minSdkVersion` ≥ 24 **and** only v1 is `true`, both v2/v3 are `false` | `minSdkVersion: 26`; `apksigner verify` → v1: true, v2: false, v3: false |
| F2 | `minSdkVersion` ≥ 28 (supports v3) but only v1 is active | Loses v3's additional benefit (key rotation) while also remaining vulnerable to Janus |
| F3 | v4 is enabled **alone** without v2/v3 (a combination that is not security-valid) | `apksigner verify` → v1: true, v2: false, v3: false, v4: true — v4 provides no integrity protection on its own |
| F4 | The APK produced by `bundletool`/the Play Store release shows a different result than the local build APK — only v1 on the final APK | Verification with Method F reveals a signing-scheme downgrade at the distribution stage |
| F5 | The app's susceptibility to Janus can be reproduced: a malicious DEX can be prepended to the original APK without invalidating v1 verification | PoC testing (§3.5 as an indicator, definitive verification still via `apksigner`) |

**Example evidence (illustrative — MASTG does not yet provide an official demo for this test):**

```bash
$ aapt2 d badging LegacyApp.apk | grep sdkVersion
sdkVersion:'26'

$ apksigner verify --verbose LegacyApp.apk
Verifies
Verified using v1 scheme (JAR signing): true
Verified using v2 scheme (APK Signature Scheme v2): false
Verified using v3 scheme (APK Signature Scheme v3): false
Verified using v3.1 scheme (APK Signature Scheme v3.1): false
Verified using v4 scheme (APK Signature Scheme v4): false
Number of signers: 1
```

Interpretation: `minSdkVersion` 26 (≥ 24) **and** only v1 is active → **FAIL**. This app is potentially vulnerable to Janus (CVE-2017-13156) on Android 5.1.1–8.0 devices, and generally lacks the comprehensive integrity protection provided by v2/v3.

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition | Example evidence |
|---|---|---|
| P1 | `minSdkVersion` ≥ 24 **and** v2 and/or v3 is active (regardless of whether v1 is also active for backward compatibility) | `apksigner verify` → v1: true, v2: true, v3: true |
| P2 | `minSdkVersion` < 24 **and** only v1 is active | Reasonable — v2 is not supported by the target platform at all (§1.3) |
| P3 | v4 is active **alongside** v2/v3 (not alone) | v2: true, v3: true, v4: true — a valid combination; v4 provides an installation-speed benefit without sacrificing security |
| P4 | The final released APK (via bundletool/Play Store) shows a scheme as secure as the local build | Verified via Method F |

**Example output indicating PASS:**

```bash
$ aapt2 d badging ModernApp.apk | grep sdkVersion
sdkVersion:'26'

$ apksigner verify --verbose ModernApp.apk
Verifies
Verified using v1 scheme (JAR signing): true
Verified using v2 scheme (APK Signature Scheme v2): true
Verified using v3 scheme (APK Signature Scheme v3): true
Verified using v3.1 scheme (APK Signature Scheme v3.1): false
Verified using v4 scheme (APK Signature Scheme v4): false
Number of signers: 1
```

Interpretation: `minSdkVersion` 26, and both v2 **and** v3 are active → **PASS**. The presence of v1 = true here is **not an issue** — it is in fact recommended by MASTG-KNOW-0003 for backward compatibility with pre-API 24 devices, as long as v2/v3 are also active to protect the full file integrity on devices that support them.

Another PASS example — an app targeting very old devices:

```bash
$ aapt2 d badging OldTargetApp.apk | grep sdkVersion
sdkVersion:'19'

$ apksigner verify --verbose OldTargetApp.apk
Verifies
Verified using v1 scheme (JAR signing): true
Verified using v2 scheme (APK Signature Scheme v2): false
Number of signers: 1
```

Interpretation: `minSdkVersion` 19 (< 24) — v2 genuinely cannot be supported in this case because the target platform does not recognize it. **PASS**, even though only v1 is active — this is consistent with §1.3.

---

#### ⚠️ Important Notes on Evaluation

1. **v1 = true is not a problem as long as v2/v3 are also true.** This is the most common interpretation mistake. The FAIL criteria is "**only** v1" — not "v1 active at all." The presence of v1 alongside v2/v3 is in fact the **correct practice** for backward compatibility.

2. **Pay attention to `minSdkVersion`, not `targetSdkVersion`.** The MASTG evaluation criteria explicitly refer to `minSdkVersion` — the attribute that determines the **lowest** Android version the app supports. `targetSdkVersion` (the version the app is optimized to target) is not relevant for determining the FAIL/PASS criteria in this test.

3. **v4 alone without v2/v3 should be reported as a finding (F3)**, even though it is not literally explicitly mentioned in the official FAIL criteria (which focuses on "only v1"). This is consistent with MASTG-BEST-0006's statement that v4 without v2/v3 **provides no security protection whatsoever** — in practice this combination is just as problematic as relying on v1 alone, even though technically it is not exactly the scenario described in the official evaluation criteria.

4. **Test the final distributed APK, not just the local build.** The Google Play App Signing process can produce a final APK with a different configuration than what you see on your development machine. Always verify the APK that is actually installed on a user's device, ideally extracted directly from a device or via `bundletool` simulating the distribution process.

5. **Manual ZIP structure verification (Method D) cannot prove v2/v3 status.** Do not conclude v2/v3 status solely from the absence/presence of files under `META-INF/` — v2/v3 are inserted at a different location in the ZIP and are not visible via `unzip -l`. `apksigner` is the only reliable source of truth.

6. **Include Janus PoC evidence whenever possible** (within an authorized testing scope) to strengthen a FAIL finding — concretely demonstrating that a malicious DEX can be prepended without invalidating v1 signature verification is far more convincing to non-technical stakeholders than merely citing a CVE number.

7. **Severity is modulated by the application's context (keeping in mind this is the R profile):**

   | Factor | Severity |
   |---|---|
   | Financial/payment/DRM app with `minSdkVersion` ≥ 24, only v1 | **High** — repackaging risk directly impacts financial loss or content piracy |
   | General, non-critical app with `minSdkVersion` ≥ 24, only v1 | **Medium** |
   | `minSdkVersion` < 24, only v1 (technically reasonable) | **Not a finding** |
   | v1 + v2/v3 active together | **Not a finding** |
   | v4 active without v2/v3 | **Medium** — a configuration error that needs fixing, though not as severe a risk as "v1 only" on the range of devices vulnerable to Janus |

8. **Document:** the app's `minSdkVersion`, the full output of `apksigner verify --verbose`, which Android versions are potentially affected by Janus if the result is FAIL (5.1.1–8.0), certificate details (`--print-certs`) for verifying developer identity, and whether the tested APK is a local build or the result of final distribution (bundletool/Play Store).

---

## 4. Recommendations

### 4.1 Core Principle (MASTG-BEST-0006)

MASTG-BEST-0006 states:

> *"Ensure that the app is signed with **at least the v2 or v3** APK signing scheme, as these provide comprehensive integrity checks and protect the entire APK from tampering. For optimal security and compatibility, consider using **v3**, which also supports key rotation."*

**Priority 1 — Enable v2 and v3 signing in the build configuration.**

```kotlin
// build.gradle.kts
android {
    signingConfigs {
        create("release") {
            storeFile = file("release.keystore")
            storePassword = System.getenv("KEYSTORE_PASSWORD")
            keyAlias = "release"
            keyPassword = System.getenv("KEY_PASSWORD")

            enableV1Signing = true   // keep for backward compatibility (< API 24)
            enableV2Signing = true   // REQUIRED — closes the Janus gap
            enableV3Signing = true   // recommended — supports key rotation
        }
    }
}
```

```groovy
// build.gradle (Groovy)
android {
    signingConfigs {
        release {
            storeFile file("release.keystore")
            storePassword System.getenv("KEYSTORE_PASSWORD")
            keyAlias "release"
            keyPassword System.getenv("KEY_PASSWORD")

            enableV1Signing true
            enableV2Signing true
            enableV3Signing true
        }
    }
}
```

**Priority 2 — If adding v4, always pair it with v2/v3.**

```kotlin
signingConfigs {
    create("release") {
        // ...
        enableV3Signing = true
        enableV4Signing = true   // incremental install benefit, NOT a substitute for v2/v3
    }
}
```

**Priority 3 — Consider Google Play App Signing.** This is a Google service that manages the final signing key on the developer's behalf, automatically applying the latest signing scheme per Play Store policy, while also providing an additional safeguard (the upload key is separate from the final signing key, so compromise of the upload key does not immediately expose the production signing key).

**Priority 4 — Verify signing as part of the release pipeline.** Add an automated `apksigner verify` check as a gate before the final APK/AAB is approved for distribution:

```bash
#!/bin/bash
# ci-verify-signing.sh
APK=$1
MIN_SDK=$(aapt2 d badging "$APK" | grep -oP "sdkVersion:'?\K[0-9]+")
V2=$(apksigner verify --verbose "$APK" | grep "v2 scheme" | grep -c "true")
V3=$(apksigner verify --verbose "$APK" | grep "v3 scheme" | grep -c "true")

if [ "$MIN_SDK" -ge 24 ] && [ "$V2" -eq 0 ] && [ "$V3" -eq 0 ]; then
    echo "[FAILED] The APK only uses v1 signing with minSdkVersion >= 24"
    exit 1
fi
echo "[OK] Signing configuration is adequate"
```

**Priority 5 — Raise `minSdkVersion` where business relevance allows.** The population of Android users below version 7.0 (API 24) is very small in 2026 in most markets. Raising `minSdkVersion` to ≥ 24 ensures v2 signing is always available and used, while also unlocking access to various other platform security improvements introduced since API 24.

**Priority 6 — Verify the final APK post-distribution, not just the local build.** Especially for apps using Google Play App Signing or distribution via AAB — periodically audit the APK that actually reaches a user's device (§3.7).

### 4.2 Remediation Checklist

- [ ] The app's `minSdkVersion` is known and documented
- [ ] If `minSdkVersion` ≥ 24: v2 signing is enabled (`enableV2Signing = true`)
- [ ] v3 signing is enabled to gain key-rotation support (`enableV3Signing = true`)
- [ ] v1 is still retained **alongside** v2/v3 for backward compatibility with pre-API 24 devices (not removed)
- [ ] If v4 is used for incremental install, it is confirmed to **always** be paired with v2/v3
- [ ] The signing configuration is verified with `apksigner verify --verbose` before every release
- [ ] The final distributed APK (Play Store/bundletool) is verified separately from the local build
- [ ] Signing-scheme checks are integrated as an automated gate in the release CI/CD pipeline
- [ ] Consider migrating to Google Play App Signing for safer key management
- [ ] The signing certificate has an adequate validity period (≥ 25 years, or expiring after October 22, 2033 per the Google Play requirement)
- [ ] **Re-verify:** re-run MASTG-TEST-0224 after every signing configuration change

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0224: Usage of Insecure APK Signature Version](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0224/)
- [MASWE-0056: Usage of Insecure APK Signature Version](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0056/)
- [MASTG-KNOW-0003: App Signing](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0003/)
- [MASTG-BEST-0006: Use Up-to-Date APK Signing Schemes](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0006/)
- [MASTG-TECH-0116: Obtaining Information about the APK Signature](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0116/)
- [MASTG-TECH-0117: Obtaining Information from the AndroidManifest](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0117/)
- [MASTG-TECH-0150: Analyzing the AndroidManifest](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0150/)
- [MASTG-TOOL-0123: apksigner](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0123/)
- [MASTG — Platform Overview: Signing Process](https://mas.owasp.org/MASTG/0x05a-Platform-Overview/#signing-process)
- [MASVS-RESILIENCE: Resilience Against Reverse Engineering and Tampering](https://mas.owasp.org/MASVS/11-MASVS-RESILIENCE/)
- [MASTG Profiles — MAS-R (Resilience)](https://mas.owasp.org/MASTG/Profiles/)
- [OWASP Mobile Top 10 2024 — M7: Insufficient Binary Protections](https://owasp.org/www-project-mobile-top-10/2023-risks/m7-insufficient-binary-protections.html)
- [OWASP Mobile Top 10 2024 — M8: Security Misconfiguration](https://owasp.org/www-project-mobile-top-10/2023-risks/m8-security-misconfiguration.html)

### 5.2 Official Android / Google Documentation

- [Android — Application Signing](https://developer.android.com/studio/publish/app-signing.html)
- [Android — APK Signature Scheme v2](https://source.android.com/docs/security/features/apksigning/v2)
- [Android — APK Signature Scheme v3](https://source.android.com/docs/security/features/apksigning/v3)
- [Android — APK Signature Scheme v4](https://source.android.com/docs/security/features/apksigning/v4)
- [Android — Sign your app (Android Studio)](https://developer.android.com/studio/publish/app-signing)
- [Android — Google Play App Signing](https://support.google.com/googleplay/android-developer/answer/9842756)
- [Android — Incremental APK installation (Android 11 features)](https://developer.android.com/about/versions/11/features#incremental)
- [Android — apksigner tool reference](https://developer.android.com/tools/apksigner)
- [Android — bundletool reference](https://developer.android.com/tools/bundletool)
- [Android — Signing Considerations (25-year validity, Play Store 2033 requirement)](https://developer.android.com/studio/publish/app-signing#considerations)

### 5.3 The Janus Vulnerability (CVE-2017-13156)

- [NVD — CVE-2017-13156](https://nvd.nist.gov/vuln/detail/CVE-2017-13156)
- [GuardSquare — Janus Vulnerability: Threats and Mitigation](https://www.guardsquare.com/blog/new-android-vulnerability-allows-attackers-to-modify-apps-without-affecting-their-signatures-guardsquare)
- [Trend Micro — Janus Android Vulnerability Allows App Modifications](https://www.trendmicro.com/en_us/research/17/l/janus-android-app-signature-bypass-allows-attackers-modify-legitimate-apps.html)
- [The Hacker News — Android Flaw Lets Hackers Inject Malware Into Apps Without Altering Signatures](https://thehackernews.com/2017/12/android-malware-signature.html)
- [Security Affairs — Android Janus vulnerability allows attackers to inject malware](https://securityaffairs.com/66513/hacking/janus-vulnerability-android.html)
- [XDA Developers — Janus Vulnerability Allows Attackers to Modify Apps without Affecting their Signatures](https://www.xda-developers.com/janus-vulnerability-android-apps/)
- [Medium (mobis3c) — Exploiting Apps vulnerable to Janus (CVE-2017-13156)](https://medium.com/mobis3c/exploiting-apps-vulnerable-to-janus-cve-2017-13156-8d52c983b4e0)
- [Exploit-DB — Android Janus APK Signature Bypass (Metasploit)](https://www.exploit-db.com/exploits/47601)

### 5.4 Standards & Taxonomy

- [CWE-345: Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)
- [CWE-353: Missing Support for Integrity Check](https://cwe.mitre.org/data/definitions/353.html)
- [CWE-494: Download of Code Without Integrity Check](https://cwe.mitre.org/data/definitions/494.html)
- [NIST SP 800-163 Rev.1 — Vetting the Security of Mobile Applications](https://csrc.nist.gov/publications/detail/sp/800-163/rev-1/final)

### 5.5 Tool Documentation

- [apksigner — Android Developers tool reference](https://developer.android.com/tools/apksigner)
- [apkanalyzer — Android Developers tool reference](https://developer.android.com/tools/apkanalyzer)
- [Androguard — Android APK/DEX analysis library](https://github.com/androguard/androguard)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
- [bundletool — Android App Bundle tooling](https://github.com/google/bundletool)

---

*This document was prepared based on the OWASP MASTG (current release as of September 2026), official Android Open Source Project documentation regarding the APK Signature Scheme, and GuardSquare's research report on the Janus vulnerability (CVE-2017-13156). This test does not yet have an official demo (MASTG-DEMO) from MASTG.*
