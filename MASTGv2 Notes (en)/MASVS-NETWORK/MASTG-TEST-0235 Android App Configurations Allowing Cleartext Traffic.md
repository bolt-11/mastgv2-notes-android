# MASTG-TEST-0235 Android App Configurations Allowing Cleartext Traffic

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0235 |
| **Platform** | Android |
| **MASVS Category** | MASVS-NETWORK (MASVS-NETWORK-1: All network traffic is encrypted using TLS) |
| **Weakness** | MASWE-0026 — *Network Traffic Not Encrypted* |
| **Test Type** | Static, Code |
| **Profile** | L1, L2 |
| **Knowledge** | MASTG-KNOW-0014 (Android Network Security Configuration) |
| **Related Techniques** | MASTG-TECH-0013 (Reverse Engineering), MASTG-TECH-0117 (Obtaining Info from AndroidManifest), MASTG-TECH-0150 (Analyzing the AndroidManifest), MASTG-TECH-0151 (Analyzing the Network Security Configuration) |
| **Related Tests** | **MASTG-TEST-0233** (Hardcoded HTTP URLs — finds the **location** of URLs; this test determines whether that URL **can actually work**), **MASTG-TEST-0236** (Cleartext Traffic in Network Traffic Capture — dynamic evidence) |
| **Related Demo** | — (MASTG does not yet provide an official demo for this test) |
| **Official Rule** | — (no semgrep rule exists — the object under test is the manifest/NSC XML, not Java/Kotlin code, so it falls outside the scope of MASTG's existing semgrep rules) |
| **Related CWE** | CWE-319 (Cleartext Transmission of Sensitive Information) |

---

## 1. Explanation

### 1.1 Testing Objective

Quote from the official MASTG overview:

> *"Since Android 9 (API level 28) cleartext HTTP traffic is blocked by default (thanks to the default Network Security Configuration) but there are multiple ways in which an application can still send it."*

This test is the **configuration determinant** in the cleartext-traffic testing trio (see §1.4 of MASTG-TEST-0233): it answers the question "**does the operating system allow** this application to send plaintext HTTP?" — regardless of whether the application code actually attempts to do so. There are two configuration mechanisms that can permit cleartext, and MASTG requires that **both** be examined:

1. **`AndroidManifest.xml`**: the `android:usesCleartextTraffic` attribute on the `<application>` tag.
2. **Network Security Configuration (NSC)**: the `cleartextTrafficPermitted` attribute on the `<base-config>` or `<domain-config>` element.

### 1.2 Crucial Point: The Interaction Between the Manifest and the NSC

This is the most frequently misunderstood part of this test. **`usesCleartextTraffic` in the manifest is entirely ignored if an NSC is configured** — not merged, not resolved by value priority, but rather **the NSC completely takes over the decision** the moment it exists:

> *"Note that this flag is ignored in case the Network Security Configuration is configured."*

The consequence of this rule produces an **official note that runs counter to intuition**, and testers must understand it before drawing any conclusions:

> *"The test doesn't fail if the AndroidManifest sets `usesCleartextTraffic` to `true` and there's a NSC, even if it only has an empty `<network-security-config>` element."*

A concrete example from the official overview:

```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
</network-security-config>
```

Even though `AndroidManifest.xml` declares `android:usesCleartextTraffic="true"`, this combination does **NOT FAIL**, because the NSC (even if empty) still **takes over the decision** from the system, and an empty NSC effectively inherits the safe default (`cleartextTrafficPermitted="false"` for API 28+ per MASTG-KNOW-0014). This means **the inspection order must not stop at the manifest alone** — the presence of any `<network-security-config>` element, even an empty one, completely changes the overall evaluation conclusion.

### 1.3 Inheritance Effect: `base-config` vs `domain-config`

Per MASTG-KNOW-0014, the NSC structure has two levels of scope:

- **`base-config`**: applies to **all** connections made by the application, unless overridden.
- **`domain-config`**: **overrides** `base-config` for specific registered domains.

An example from MASTG-KNOW-0014 showing a common pattern (and a potential trap at the same time):

```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false" />
    <domain-config cleartextTrafficPermitted="true">
        <domain>localhost</domain>
    </domain-config>
</network-security-config>
```

This configuration is **safe overall** (the base-config denies cleartext for all domains), but it carries an **explicit exception** for `localhost` — a pattern often used for local debugging purposes (development proxies, emulator loopback). The real danger arises when an exception like this is **left in place for a production domain** that is not `localhost`, something that must be traced through each `<domain-config>` individually, not simply by checking `<base-config>` alone.

### 1.4 Default Configuration Based on `targetSdkVersion` — Not `minSdkVersion`

An important technical point that is often assumed incorrectly: the NSC default is determined by the application's **`targetSdkVersion`**, not the Android version running it nor its `minSdkVersion`:

| `targetSdkVersion` | Default `cleartextTrafficPermitted` |
|---|---|
| ≥ 28 (Android 9+) | `false` — cleartext **blocked** by default |
| 24–27 (Android 7.0–8.1) | `true` — cleartext **allowed** by default |
| ≤ 23 (Android 6.0 and below) | `true`, **and** the trust anchors also include user-installed certificates (`certificates src="user"`) in addition to the system ones |

The important implication: an **application that deliberately keeps `targetSdkVersion` at a low value** (e.g., for compatibility with older libraries) will **automatically allow cleartext** without the developer ever needing to explicitly write `usesCleartextTraffic="true"` at all — this is a FAIL condition that **will not be visible** by merely searching for the literal strings `usesCleartextTraffic` or `cleartextTrafficPermitted` in the manifest/NSC, because there is no explicit attribute to search for in the first place. The tester **must check the `targetSdkVersion` value** as an inseparable part of this test.

### 1.5 Risk of Manifest Merging from Third-Party Libraries/Modules

This is a nuance not explicitly discussed by the official MASTG overview but highly relevant in practice. The Android build system **merges** the `AndroidManifest.xml` from all modules and library dependencies into a single final APK manifest. This means:

- A **third-party SDK library** (advertising, analytics, payment SDK) can carry its own `AndroidManifest.xml` declaring `android:usesCleartextTraffic="true"` — and if not explicitly handled (`tools:replace` in the application manifest), this value can **get merged** into the final manifest, contradicting the original intent of the application's own developers.
- An NSC configuration considered "safe" by the main application development team guarantees nothing if a **separate module in a multi-module project** (e.g., the `:debug-tools` or `:wear-companion` module) carries a different NSC that also gets bundled into the final APK for a particular build flavor.

Per this document's standard (referring to the user's earlier confirmation that testing must not rely on official methods alone), the tester **must examine the final merged manifest** (the one inside the installed APK), not only the source `AndroidManifest.xml` in the repository — because the two can differ.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | MASTG ID | Function |
|---|---|---|
| **jadx** (`--no-src`) | MASTG-TOOL-0018 | Extracts `AndroidManifest.xml` and NSC resources from the APK (MASTG-TECH-0117), including the `<uses-sdk>` element important for §1.4 |
| **apktool** | MASTG-TOOL-0011 | Alternative manifest and NSC extraction |
| **aapt2** | — | Query the manifest without full extraction, custom decoded format |
| **grep / xmlstarlet / yq** | — | Search for specific attributes in the extracted XML (MASTG-TECH-0150, MASTG-TECH-0151) |

### 2.2 Alternative and Supporting Tools

| Tool | Function |
|---|---|
| **MobSF** | Automated manifest analysis, typically flagging `usesCleartextTraffic="true"` and problematic NSC configurations directly as ready-to-cite findings |
| **androguard** (`androguard axml`) | Programmatic parsing of binary AndroidManifest.xml — well suited for automation/CI without needing full decompilation |
| **apkanalyzer** (bundled with the Android SDK) | `apkanalyzer manifest print app.apk` — a quick official method from the Android SDK without any third-party tool |
| **ostorlab / MASTG-adjacent scanner (APK_USES_CLEAR_TEXT_TRAFFIC check)** | Some commercial/open-source APK analysis platforms have ready-made rules specific to this attribute, useful as a secondary cross-check |
| **Frida** (hooking `NetworkSecurityConfig`) | Runtime confirmation — observing the NSC configuration that is **actually loaded by the system** while the app runs, including the final result of manifest merging (§1.5), which may differ from the source |
| **adb logcat** | The system prints a `D/NetworkSecurityConfig: Using Network Security Config from resource ...` log line when the NSC is loaded — direct evidence of which configuration is active (MASTG-TECH-0009) |

### 2.3 Environment Prerequisites

- **No device/root required** for core static analysis — the APK file alone is sufficient.
- **Device/emulator required** for runtime verification via logcat or Frida (confirming the actual result of manifest merging, §1.5).
- **Always inspect the manifest extracted from the final APK** (not just the source repository) to catch the effects of manifest merging from dependencies.
- **Record the `targetSdkVersion`** at the start of the analysis — it determines the default behavior that must be used as a baseline before looking for any explicit override.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0013** to reverse engineer the application.
2. Use **MASTG-TECH-0117** to obtain `AndroidManifest.xml`.
3. Use **MASTG-TECH-0150** to read the value of `android:usesCleartextTraffic` and check whether `android:networkSecurityConfig` is present.
4. Use **MASTG-TECH-0151** to read the value of `cleartextTrafficPermitted` in `<base-config>` and `<domain-config>` from the NSC file.

### 3.2 Method A — jadx + grep/xmlstarlet *(primary official method)*

```bash
# Extract the manifest (MASTG-TECH-0117)
jadx --no-src -d ./out_dir target-app.apk
MANIFEST=./out_dir/resources/AndroidManifest.xml

# 1. Check targetSdkVersion (§1.4 — REQUIRED as a baseline)
grep -o 'targetSdkVersion="[0-9]*"' "$MANIFEST"

# 2. Check usesCleartextTraffic and networkSecurityConfig (MASTG-TECH-0150)
grep -i "usesCleartextTraffic" "$MANIFEST"
grep -i "networkSecurityConfig" "$MANIFEST"

# 3. If an NSC is found, extract and inspect its contents (MASTG-TECH-0151)
NSC_FILE=$(grep -oP 'networkSecurityConfig="@xml/\K[^"]+' "$MANIFEST")
if [ -n "$NSC_FILE" ]; then
    cat "./out_dir/resources/res/xml/${NSC_FILE}.xml"
    grep -i "cleartextTrafficPermitted" "./out_dir/resources/res/xml/${NSC_FILE}.xml"
fi
```

A structured query with `xmlstarlet`/`yq` for more precise, automation-ready results:

```bash
# Manifest
xmlstarlet sel -N android="http://schemas.android.com/apk/res/android" \
  -t -v "//application/@android:usesCleartextTraffic" -n "$MANIFEST"

# NSC — base-config
yq -p=xml -o=json -r '."network-security-config"."base-config"."+@cleartextTrafficPermitted" // "not-set"' "$NSC_FILE"

# NSC — all domain-config entries along with the domains they cover (MUST be checked one by one, §1.3)
yq -p=xml -o=json '."network-security-config"."domain-config"' "$NSC_FILE"
```

### 3.3 Method B — aapt2 (without full extraction)

```bash
aapt2 dump badging target-app.apk | grep -i "targetSdkVersion\|cleartext"
aapt2 dump xmltree target-app.apk --file AndroidManifest.xml | grep -A2 "usesCleartextTraffic"
```

### 3.4 Method C — androguard (automation/CI, without external Java tooling)

```python
from androguard.core.bytecodes.axml import AXMLPrinter
from androguard.core.apk import APK

apk = APK("target-app.apk")
print("targetSdkVersion:", apk.get_target_sdk_version())
manifest_xml = apk.get_android_manifest_xml()
app_element = manifest_xml.find("application")
uses_cleartext = app_element.get("{http://schemas.android.com/apk/res/android}usesCleartextTraffic")
nsc_ref = app_element.get("{http://schemas.android.com/apk/res/android}networkSecurityConfig")
print("usesCleartextTraffic:", uses_cleartext)
print("networkSecurityConfig ref:", nsc_ref)
```

```bash
pip install androguard
python3 check_cleartext_config.py
```

This approach is ideal for **CI/CD integration** because it does not depend on text-parsing XML, which is fragile against variations in tool output format (see the MASTG-TECH-0150 note about differences between jadx/apktool and aapt2 output formats).

### 3.5 Method D — apkanalyzer (official Android SDK, no extra tooling)

```bash
apkanalyzer manifest print target-app.apk | grep -i "cleartext\|networkSecurityConfig\|targetSdkVersion"
```

### 3.6 Method E — MobSF

```bash
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
```

MobSF's **Manifest Analysis** section automatically flags `usesCleartextTraffic="true"` as a finding with a pre-mapped severity, and also displays NSC contents if present — speeding up the initial triage before deeper manual verification.

### 3.7 Method F — Runtime Verification (addressing the manifest merging risk from §1.5)

```bash
# 1. Install the APK and monitor logcat on app start
adb install target-app.apk
adb logcat -c
adb shell am start -n com.target.app/.MainActivity
adb logcat | grep -i "NetworkSecurityConfig"
```

Expected output when a custom NSC is loaded:

```
D/NetworkSecurityConfig: Using Network Security Config from resource network_security_config
```

If this log **does not appear** even though the source manifest declares a `networkSecurityConfig`, this indicates the configuration was **not actually loaded** in the final APK (possibly due to manifest merging overriding it from a particular build flavor, or a resource linking error) — a signal to investigate further into the **final merged manifest**, not just the source repository.

Frida hooking for deeper cases:

```javascript
// hook-nsc-loaded.js
Java.perform(function () {
    var NetworkSecurityConfig = Java.use("android.security.net.config.NetworkSecurityConfig");
    // Verify the configuration object actually used by the system at runtime
    console.log("[*] Hooking NetworkSecurityConfig...");
});
```

### 3.8 Method Comparison: When to Use Which

| Method | Tool | Coverage | CI/CD Friendly? | When to Use |
|---|---|---|---|---|
| **A** | jadx/apktool + grep/xmlstarlet | Full manifest + NSC | Moderate | **Required official baseline** |
| **B** | aapt2 | Fast, no full extraction | ✅ | Quick verification/spot-check |
| **C** | androguard (Python) | Programmatic, robust against format variation | ✅ | **Best for CI/CD** |
| **D** | apkanalyzer | Official from the Android SDK, no extra tooling | ✅ | Environments that already have the Android SDK installed |
| **E** | MobSF | Ready-to-cite report, fast triage | Partial | Initial audit/finding documentation |
| **F** | adb logcat / Frida | **Runtime evidence** — the configuration actually loaded | ❌ (device required) | Investigating suspected manifest merging (§1.5) |

**Minimum recommended combination:** **A (official baseline) → C (androguard for automation/CI gating) → F (runtime verification)** when a discrepancy is suspected between the source manifest and the final APK manifest due to dependency merging. Always include checking `targetSdkVersion` (§1.4) as the first step before searching for any explicit attribute.

---

### 3.9 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Observation:** *"The output should contain a list of configurations potentially allowing for cleartext traffic."*
>
> **Evaluation:** *"The test case fails if cleartext traffic is permitted."*

With three FAIL conditions defined **explicitly and completely** by MASTG itself:

1. The AndroidManifest sets `usesCleartextTraffic` to `true` **and there is no NSC**.
2. The NSC sets `cleartextTrafficPermitted` to `true` in `<base-config>`.
3. The NSC sets `cleartextTrafficPermitted` to `true` in **any domain-config**.

---

#### ❌ FAIL / ISSUE — The check is declared FAILED when:

| No | Condition | Per official clause |
|---|---|---|
| F1 | `usesCleartextTraffic="true"` in the manifest, **without** any `networkSecurityConfig` at all | Clause #1 |
| F2 | NSC present, `<base-config cleartextTrafficPermitted="true">` | Clause #2 |
| F3 | NSC present, base-config safe, but **one or more** `<domain-config cleartextTrafficPermitted="true">` exist for a production domain (not `localhost`/dev-only) | Clause #3 |
| F4 | `targetSdkVersion` is 24–27 (default `true`) **without** an explicit `cleartextTrafficPermitted="false"` override in base-config — cleartext is "silently" allowed by the system default | §1.4 — not explicitly stated by MASTG but a logical consequence of the documented default behavior |
| F5 | The final merged manifest (inside the installed APK) differs from the source manifest because a third-party library brings its own `usesCleartextTraffic="true"`, and it is not overridden with `tools:replace` | §1.5 — confirmed via Method F |

**Example evidence (illustrative — MASTG does not yet provide an official demo for this test):**

```xml
<!-- AndroidManifest.xml extracted via jadx --no-src -->
<manifest ...>
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="26" />  <!-- targetSdk 26 -->
    <application
        android:networkSecurityConfig="@xml/network_security_config"
        ... >
```

```xml
<!-- res/xml/network_security_config.xml -->
<network-security-config>
    <base-config cleartextTrafficPermitted="false" />
    <domain-config cleartextTrafficPermitted="true">
        <domain>internal-staging-api.example.com</domain>   <!-- NOT localhost! -->
    </domain-config>
</network-security-config>
```

Interpretation: although `base-config` is safe, the `<domain-config>` allows cleartext for `internal-staging-api.example.com` — a domain that sounds like a staging endpoint but could potentially still be used in a production build if it was not cleaned up before release. **FAIL** per clause #3, regardless of the safe `base-config`.

---

#### ✅ PASS — The check is declared PASSED when:

| No | Condition | Example evidence |
|---|---|---|
| P1 | `targetSdkVersion` ≥ 28, **no** explicit `usesCleartextTraffic`, **no** custom NSC — relying on the system's safe default | A clean manifest with no cleartext attributes at all |
| P2 | NSC present with `<base-config cleartextTrafficPermitted="false">` and **no** `<domain-config>` allowing cleartext for a production domain | All domain-config entries (if any) are only for `localhost`/testing domains proven not to be part of the release build |
| P3 | `usesCleartextTraffic="true"` present in the manifest, **but** an NSC exists (even an empty one) — per the official note in §1.2, this combination **does not FAIL** | An empty `<network-security-config></network-security-config>` overrides the manifest flag |
| P4 | `targetSdkVersion` 24-27 (default cleartext `true`) **but** the developer explicitly added `<base-config cleartextTrafficPermitted="false">` to override that default | Explicit override found and confirmed |
| P5 | The final merged manifest (confirmed via Method F) is identical to the already-safe source manifest — no contamination from third-party libraries | Runtime `NetworkSecurityConfig` log matches the source expectation |

**Example output indicating PASS:**

```bash
$ grep -i "usesCleartextTraffic" AndroidManifest.xml
# (not found)
$ grep -o 'targetSdkVersion="[0-9]*"' AndroidManifest.xml
targetSdkVersion="34"
$ cat res/xml/network_security_config.xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false" />
</network-security-config>
```

---

#### ⚠️ Important Notes on Assessment

1. **Do not stop after finding `usesCleartextTraffic="true"` in the manifest — first check whether an NSC exists.** This is the most common mistake that produces a **false positive**: per §1.2, the presence of an NSC (even an empty one) causes that manifest flag to be completely ignored by the system.

2. **`<domain-config>` entries must be checked one by one, not just `<base-config>`.** An NSC file that appears safe at a glance (`base-config` set to `false`) may still hide a dangerous exception in one of potentially many `<domain-config>` entries in a complex application.

3. **`targetSdkVersion` is a mandatory check, not optional** — per §1.4, an application can FAIL without a single explicit attribute being written, purely because it relies on the system default for a low `targetSdkVersion`.

4. **Test the final APK's manifest, not just the source code repository.** Per §1.5, manifest merging from dependencies can change the final result — a report that only reads `AndroidManifest.xml` in the Git repository without building and extracting the final APK risks missing contamination from third-party libraries.

5. **Distinguish legitimate exceptions (localhost/dev-only) from dangerous ones (production domains).** An exception with `cleartextTrafficPermitted="true"` for `localhost` solely for local proxy debugging needs is a common pattern and **low risk** — but the same thing for a domain resembling a real production/staging endpoint must be flagged as high priority.

6. **This test is purely about system PERMISSION, not whether the application actually sends HTTP.** A FAIL result here means "the operating system will not block it" — for evidence that data is actually sent in plaintext, correlate with MASTG-TEST-0233 (location of HTTP code) and MASTG-TEST-0236 (real network capture).

7. **Severity is modulated by the scope of affected domains:**

   | Factor | Severity |
   |---|---|
   | `cleartextTrafficPermitted="true"` in `base-config` (applies to ALL domains) | **Critical** |
   | `cleartextTrafficPermitted="true"` only for specific production domains in `domain-config` | **High** |
   | `cleartextTrafficPermitted="true"` only for `localhost`/testing domains proven not to be used in release | **Informational** — note as code hygiene, not an active vulnerability |
   | Cleartext allowed only because of a low `targetSdkVersion` default without explicit override (F4) | **High** — often an oversight, not a conscious decision |

8. **Document:** the `targetSdkVersion` value, the full content of `usesCleartextTraffic` in the manifest, the presence and full content of the NSC (`base-config` + all `domain-config` entries), the result of the final-APK-vs-source manifest verification (if performed), and correlation with MASTG-TEST-0233/0236 if available.

---

## 4. Recommendations

### 4.1 Implement a Strict, Explicit NSC

```xml
<!-- res/xml/network_security_config.xml -->
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
    <!-- Only add a domain-config for development needs, and MAKE SURE
         it is separate from the production build variant -->
</network-security-config>
```

```xml
<!-- AndroidManifest.xml -->
<application
    android:networkSecurityConfig="@xml/network_security_config"
    android:usesCleartextTraffic="false"
    ... >
```

### 4.2 Raise `targetSdkVersion` to a Current Value

Raising `targetSdkVersion` to ≥28 (ideally the latest API version supported by Google Play) automatically activates the safe default without requiring additional configuration, while also satisfying the Google Play Console policy that requires a current target SDK for publishing new applications.

### 4.3 Separate Development Configuration from Production via Build Variant

```gradle
android {
    buildTypes {
        debug {
            manifestPlaceholders = [nscConfig: "@xml/network_security_config_debug"]
        }
        release {
            manifestPlaceholders = [nscConfig: "@xml/network_security_config_release"]
        }
    }
}
```

```xml
<!-- network_security_config_debug.xml — ONLY for debug builds -->
<network-security-config>
    <base-config cleartextTrafficPermitted="false" />
    <domain-config cleartextTrafficPermitted="true">
        <domain>localhost</domain>
        <domain>10.0.2.2</domain>  <!-- host machine localhost alias from the emulator -->
    </domain-config>
</network-security-config>
```

```xml
<!-- network_security_config_release.xml — WITHOUT any exceptions -->
<network-security-config>
    <base-config cleartextTrafficPermitted="false" />
</network-security-config>
```

### 4.4 Control Manifest Merging from Dependencies

If a dependency library is known to carry `usesCleartextTraffic="true"` in its own manifest, explicitly override it in the application manifest:

```xml
<application
    android:usesCleartextTraffic="false"
    tools:replace="android:usesCleartextTraffic"
    ... >
```

Verify the merging result by inspecting the final manifest:

```bash
./gradlew :app:processReleaseManifest
cat app/build/intermediates/merged_manifest/release/AndroidManifest.xml | grep -i cleartext
```

### 4.5 Integrate into CI/CD

```bash
#!/bin/bash
# ci-check-cleartext-config.sh — run against the final RELEASE build APK
APK=$1
python3 -c "
from androguard.core.apk import APK
apk = APK('$APK')
target_sdk = apk.get_target_sdk_version()
print(f'targetSdkVersion: {target_sdk}')
manifest = apk.get_android_manifest_xml()
app = manifest.find('application')
ns = '{http://schemas.android.com/apk/res/android}'
uct = app.get(f'{ns}usesCleartextTraffic')
nsc = app.get(f'{ns}networkSecurityConfig')
print(f'usesCleartextTraffic: {uct}')
print(f'networkSecurityConfig: {nsc}')
if uct == 'true' and not nsc:
    print('[FAILED] Cleartext traffic is allowed without an NSC!')
    exit(1)
if int(target_sdk) < 28 and not nsc:
    print('[WARNING] targetSdkVersion < 28 without an explicit NSC — cleartext defaults to true')
"
```

### 4.6 Remediation Checklist

- [ ] `targetSdkVersion` has been checked and raised to a current value where possible
- [ ] `usesCleartextTraffic="false"` has been explicitly set in the manifest
- [ ] An explicit NSC with `<base-config cleartextTrafficPermitted="false">` has been implemented
- [ ] All `<domain-config>` entries (if any) have been reviewed one by one — no exceptions for production domains
- [ ] Cleartext exceptions for development needs are separated via build variant and never reach the release build
- [ ] The final merged manifest (release APK) has been verified not to be contaminated with `usesCleartextTraffic="true"` from third-party dependencies
- [ ] Runtime verification (logcat/`NetworkSecurityConfig`) has been performed to confirm the intended configuration is actually loaded
- [ ] Correlation with MASTG-TEST-0233 (HTTP location) and MASTG-TEST-0236 (network capture) has been performed
- [ ] **Re-verify:** rerun MASTG-TEST-0235 on the final release APK after remediation

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0235: Android App Configurations Allowing Cleartext Traffic](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0235/)
- [MASTG-TEST-0233: Hardcoded HTTP URLs](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0233/)
- [MASTG-TEST-0236: Cleartext Traffic in Network Traffic Capture](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0236/)
- [MASWE-0026: Network Traffic Not Encrypted](https://mas.owasp.org/MASWE/MASVS-NETWORK/MASWE-0026/)
- [MASTG-KNOW-0014: Android Network Security Configuration](https://mas.owasp.org/MASTG/knowledge/android/MASVS-NETWORK/MASTG-KNOW-0014/)
- [MASTG-TECH-0013: Reverse Engineering Android Apps](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/)
- [MASTG-TECH-0117: Obtaining Information from the AndroidManifest](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0117/)
- [MASTG-TECH-0150: Analyzing the AndroidManifest](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0150/)
- [MASTG-TECH-0151: Analyzing the Network Security Configuration](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0151/)
- [MASTG Document 0x05g — Testing Network Communication](https://mas.owasp.org/MASTG/0x05g-Testing-Network-Communication/)
- [OWASP Mobile Top 10 2024 — M5: Insecure Communication](https://owasp.org/www-project-mobile-top-10/2023-risks/m5-insecure-communication)

### 5.2 Official Android Documentation

- [Android Developers — Network Security Configuration](https://developer.android.com/training/articles/security-config)
- [Android Developers — `usesCleartextTraffic` attribute reference](https://developer.android.com/guide/topics/manifest/application-element#usesCleartextTraffic)
- [Android Developers — `cleartextTrafficPermitted` reference](https://developer.android.com/privacy-and-security/security-config#CleartextTrafficPermitted)
- [Android Codelab — Network Security Configuration](https://developer.android.com/codelabs/android-network-security-config)
- [Android Developers Blog — Protecting against unintentional regressions to cleartext traffic in your Android apps](https://android-developers.googleblog.com/2016/04/protecting-against-unintentional.html)
- [Android Developers — Manifest merging documentation](https://developer.android.com/build/manage-manifests)

### 5.3 Research and Real-World Cases

- [NCC Group — Bypassing Android's Network Security Configuration](https://www.nccgroup.com/research-blog/bypassing-android-s-network-security-configuration/)
- [NowSecure — A Security Analyst's Guide to Network Security Configuration in Android P](https://www.nowsecure.com/blog/2018/08/15/a-security-analysts-guide-to-network-security-configuration-in-android-p/)
- [GitHub Issue — corona-warn-app/cwa-app-android#2: usesCleartextTraffic/cleartextTrafficPermitted set to true](https://github.com/corona-warn-app/cwa-app-android/issues/2)
- [Haxoris — Cleartext Traffic: Mobile Risk and Fix (M5 Insecure Communication)](https://haxoris.com/haxoris-wiki/mobile-owasp-top-10/m5-insecure-communication/cleartext-traffic)
- [Ostorlab Knowledge Base — Attribute usesCleartextTraffic set](https://docs.ostorlab.co/kb/APK_USES_CLEAR_TEXT_TRAFFIC/index.html)
- [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)

### 5.4 Tool Documentation

- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [apktool](https://apktool.org/)
- [aapt2 — Android Asset Packaging Tool](https://developer.android.com/tools/aapt2)
- [androguard](https://github.com/androguard/androguard)
- [apkanalyzer — Android SDK command-line tool](https://developer.android.com/tools/apkanalyzer)
- [xmlstarlet](http://xmlstar.sourceforge.net/)
- [yq — YAML/XML/JSON processor](https://github.com/mikefarah/yq)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)

---

*This document was compiled based on OWASP MASTG (current release as of September 2026), official Android Developers documentation, research from NCC Group and NowSecure, and real-world cases from open-source projects (Corona Warn App). This test does not yet have an official demo (MASTG-DEMO) or semgrep rule, because its object of testing is the manifest/XML configuration, not Java/Kotlin code — this document emphasizes checking `targetSdkVersion` and the final merged manifest as steps that are often missed by a purely literal reading of attributes.*
