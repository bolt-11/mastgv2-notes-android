# MASTG-TEST-0286 Network Security Configuration Allowing Trust in User-Provided CAs

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0286 |
| **Platform** | Android |
| **MASVS Category** | MASVS-NETWORK (MASVS-NETWORK-2) |
| **Weakness** | MASWE-0027 — *Insecure Certificate Validation* |
| **Test Type** | Static, Code |
| **Knowledge** | MASTG-KNOW-0014 (Android Network Security Configuration) |
| **Related Techniques** | MASTG-TECH-0013, MASTG-TECH-0117, MASTG-TECH-0150, MASTG-TECH-0151 (Analyzing NSC) |
| **Related Tests** | **MASTG-TEST-0285** (Outdated Android Version Allowing Trust in User-Provided CAs) — the **implicit** counterpart; this test targets user CA trust that is **explicitly** configured by the developer, rather than inherited from an outdated platform |
| **Related Demo** | — (none) |
| **Official Rule** | — (not applicable; the test subject is configuration XML, not Java/Kotlin code) |
| **Related CWE** | CWE-295, CWE-926 (Improper Export of Android Application Components — structural analogy: a configuration that loosens a trust boundary) |

---

## 1. Explanation

### 1.1 Testing Objective and Its Relationship to MASTG-TEST-0285

Official MASTG overview excerpt:

> *"This test evaluates whether an Android app **explicitly** trusts user-added CA certificates by including `<certificates src="user"/>` in its Network Security Configuration... Even though starting with Android 7.0 (API level 24) apps no longer trust user-added CAs by default, this configuration overrides that behavior."*

This test is the **mirror counterpart** of MASTG-TEST-0285 already discussed in this research series — both produce the identical end consequence (the app trusts user-added CAs, exposing it to MITM), but via **entirely different causal paths**:

| | MASTG-TEST-0285 | MASTG-TEST-0286 *(this document)* |
|---|---|---|
| **Cause** | **Implicit** — a low `minSdkVersion` inherits the outdated platform's default | **Explicit** — the developer **consciously writes** `<certificates src="user"/>` in the NSC |
| **Applies to** | Devices with API ≤23 only | **All devices**, including the latest modern Android, because this is an **explicit override**, not an inherited default |
| **Nature of the flaw** | Negligence in not raising `minSdkVersion` | A configuration decision (intentional, or unintentionally left behind) |

A crucial point distinguishing the urgency level of these two tests: MASTG-TEST-0286 **can be more dangerous** in practice because it **actively loosens** a protection that has already been the safe default since API 24 — the developer **must take an additional, deliberate step** to trigger this FAIL condition, which usually indicates there is a **specific reason** behind that decision (most commonly: a leftover debugging need, discussed in depth in §1.3).

### 1.2 Mechanism and Syntax

This configuration appears inside the `<trust-anchors>` element of the NSC file (`network_security_config.xml`, referenced via `android:networkSecurityConfig` in the manifest):

```xml
<network-security-config>
    <base-config>
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />  <!-- THIS is what this test checks -->
        </trust-anchors>
    </base-config>
</network-security-config>
```

`src="user"` instructs the system to also trust **every CA certificate manually installed by the user** on the device (via Settings > Security > Install Certificate) — a trust source that is **entirely outside the app developer's control**, and historically the primary vector for MITM attacks before the API 24 default change (discussed in the MASTG-TEST-0285 document).

### 1.3 The Most Critical Nuance: Placement Determines Everything — `<debug-overrides>` vs `<base-config>`/`<domain-config>`

This is the **most important finding** in this document, and represents an evaluation pitfall that **very easily produces false positives** if a tester only performs a simple text search (`grep 'src="user"'`) without paying attention to the **parent element context** in which that line is located.

The Android Network Security Configuration provides a dedicated element, **`<debug-overrides>`**, designed **specifically** for this legitimate use case — trusting user CAs **only during development**, automatically and safely disabled in production builds:

```xml
<!-- SAFE PATTERN — src="user" inside debug-overrides -->
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
    <debug-overrides>
        <trust-anchors>
            <certificates src="user" />
        </trust-anchors>
    </debug-overrides>
</network-security-config>
```

The behavior of the `<debug-overrides>` element according to official Android documentation:

- **Active** only when `android:debuggable="true"` — a flag automatically set by the IDE/build tool for **non-release** (debug/staging) builds, and **explicitly rejected** by the Google Play Store and other app stores for published applications.
- **Completely ignored** when `android:debuggable="false"` — the condition that applies to **every release build** that reaches the Play Store, making the `<debug-overrides>` block **structurally never active** in the hands of end users.

**Critical implication for this test's evaluation**: `<certificates src="user"/>` found **inside** the `<debug-overrides>` element is a **safe and recommended pattern** — this is the **correct** way to meet a developer's legitimate need to test connections through an interception proxy (Charles, Burp, mitmproxy — per the context discussed in the MASTG-TEST-0285 document §1.4) without endangering production users. **The literally identical line of text** (`<certificates src="user" />`) carries a **completely opposite** security meaning depending solely on the **parent XML element** that wraps it — inside `<base-config>`/`<domain-config>` it means a critical FAIL that is always active; inside `<debug-overrides>` it means a safe PASS that follows best practice.

### 1.4 Why the Official Overview Does Not Explicitly Distinguish This — A Potential Evaluation Gap

It should be noted honestly: the official MASTG Evaluation clause for this test reads simply:

> *"The test case fails if `<certificates src="user" />` has been defined as part of the `<trust-anchors>` in the Network Security Configuration file."*

This clause **does not explicitly exclude** the `<debug-overrides>` case from the FAIL condition — the most literal reading of this sentence **could** be interpreted as meaning that **the presence of that line anywhere** in the NSC file (including inside `<debug-overrides>`) satisfies the FAIL condition. However, based on in-depth research into the official Android documentation on the purpose and behavior of `<debug-overrides>` (§1.3), **in security substance**, marking the `<debug-overrides>` pattern as a FAIL equivalent to the `<base-config>` pattern would produce a **significant false positive** against a practice that is actually **officially recommended** by Android Developers themselves as a safe way to perform network debugging.

**This document's methodological recommendation**: testers **must explicitly distinguish** between these two contexts in their report — reporting `<debug-overrides>` as a finding of **equal severity** to `<base-config>`/`<domain-config>` would mislead the development team's remediation priorities and could damage the credibility of the audit report in the eyes of a technical team that understands this mechanism well.

### 1.5 Real-World Risk Scenario: Build Variant Misconfiguration

Even though `<debug-overrides>` itself is safe **as long as** `debuggable=false` is genuinely enforced in release, there is a real failure scenario that still needs to be watched for, consistent with the "leftover debug artifact in production" risk pattern already discussed in depth in the MASTG-TEST-0226 document (debuggable flag) and MASTG-TEST-0263/0264/0265 (StrictMode) in this research series:

- **`android:debuggable="true"` is accidentally left in** the release build (a Gradle misconfiguration) — in this scenario, the `<debug-overrides>` block, previously "safe," will **become active** in the hands of production users. This is **not** a flaw in the NSC file itself, but rather a **failure of the MASTG-TEST-0226** test, which should have caught the `debuggable=true` condition in the release — underscoring the importance of **cross-test correlation** in a thorough audit report.
- **The developer mistakenly places** `<certificates src="user"/>` directly inside `<base-config>`/`<domain-config>` due to unfamiliarity with the more appropriate `<debug-overrides>` mechanism — this is the actual FAIL condition this test targets, most likely stemming from the same debugging need but implemented the wrong way.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **jadx --no-src / apktool** | Extract `AndroidManifest.xml` and the NSC file |
| **grep / xmlstarlet / yq** | Search and structured parsing of the `<certificates src="user"/>` element **along with its parent element** |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **MobSF** | Sometimes displays the full NSC configuration in the Manifest Analysis report, including element structure |
| **CodeQL/Python script with an XML DOM parser** | For large-scale audits, programmatically verifying whether each occurrence of `src="user"` resides within a `<debug-overrides>` element or not |
| **Cross-verification with MASTG-TEST-0226** | Confirms that `android:debuggable` is truly `false` on the build under test — a prerequisite for declaring that `<debug-overrides>` is genuinely inactive (§1.5) |

### 2.3 Environment Prerequisites

- **No device/root required** — can be done entirely from the APK file.
- **MUST use a structured XML parser** (not pure single-line grep) to accurately determine the parent element of every occurrence of `<certificates src="user"/>` — this is the most important methodological prerequisite per §1.3.
- **Test the final release APK**, and correlate it with the `debuggable` status (MASTG-TEST-0226) for an accurate interpretation.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0013** to reverse engineer the application.
2. Use **MASTG-TECH-0117** to obtain `AndroidManifest.xml`.
3. Use **MASTG-TECH-0150** to check whether `android:networkSecurityConfig` is present.
4. Use **MASTG-TECH-0151** to extract every usage of `<certificates src="user" />` from the NSC file.

### 3.2 Method A — Structured Parsing with Parent Element Context *(the correct primary method, avoiding false positives per §1.3)*

```bash
jadx --no-src -d ./out target-app.apk
NSC_FILE=$(grep -oP 'networkSecurityConfig="@xml/\K[^"]+' ./out/resources/AndroidManifest.xml)
NSC_PATH="./out/resources/res/xml/${NSC_FILE}.xml"

# MANDATORY: use xmlstarlet to determine the PARENT element CONTEXT, not single-line grep
echo "=== Occurrences of src=user in BASE-CONFIG (FAIL if found) ==="
xmlstarlet sel -t -c "//base-config//certificates[@src='user']" "$NSC_PATH"

echo "=== Occurrences of src=user in DOMAIN-CONFIG (FAIL if found) ==="
xmlstarlet sel -t -c "//domain-config//certificates[@src='user']" "$NSC_PATH"

echo "=== Occurrences of src=user in DEBUG-OVERRIDES (PASS/safe, DO NOT mark FAIL) ==="
xmlstarlet sel -t -c "//debug-overrides//certificates[@src='user']" "$NSC_PATH"
```

### 3.3 Method B — Python Script with an XML DOM Parser (Automation/CI)

```python
import xml.etree.ElementTree as ET

def check_user_ca_trust(nsc_path):
    tree = ET.parse(nsc_path)
    root = tree.getroot()
    findings = {"fail_base_config": [], "fail_domain_config": [], "safe_debug_overrides": []}

    for base in root.findall('.//base-config'):
        for cert in base.findall('.//certificates[@src="user"]'):
            findings["fail_base_config"].append("base-config")

    for domain in root.findall('.//domain-config'):
        domains = [d.text for d in domain.findall('domain')]
        for cert in domain.findall('.//certificates[@src="user"]'):
            findings["fail_domain_config"].append(domains)

    for debug in root.findall('.//debug-overrides'):
        for cert in debug.findall('.//certificates[@src="user"]'):
            findings["safe_debug_overrides"].append("debug-overrides (safe, if debuggable=false in release)")

    return findings

result = check_user_ca_trust("network_security_config.xml")
if result["fail_base_config"] or result["fail_domain_config"]:
    print(f"[FAIL] src=user found in base-config/domain-config: {result}")
if result["safe_debug_overrides"]:
    print(f"[INFO] src=user found in debug-overrides (verify debuggable=false in release): {result['safe_debug_overrides']}")
```

### 3.4 Method C — Correlation with `debuggable` Status (MASTG-TEST-0226)

```bash
# Verify the debuggable flag on the SAME release APK whose NSC is being checked
aapt2 dump badging target-app-release.apk | grep -i debuggable
```

If this line **appears** (indicating `debuggable=true`), then **every** `<debug-overrides>` finding previously classified as "safe" must be **reclassified as an active FAIL** — per the risk scenario in §1.5.

### 3.5 Method Comparison: When to Use Which

| Method | Tool | Distinguishes parent element context? | When to use |
|---|---|---|---|
| **A** | Structured xmlstarlet/yq | ✅ | **Mandatory**, correct primary method |
| **B** | Python DOM script | ✅ | Automation/CI, large-scale audits |
| **C** | Debuggable correlation | N/A (complementary) | **Mandatory** for an accurate interpretation of `<debug-overrides>` status |

**Minimum recommended combination:** **A or B (structured parsing, DO NOT use naive single-line grep) → C (debuggable status correlation)** for a truly accurate conclusion that does not produce false positives against the `<debug-overrides>` practice, which is actually recommended.

---

### 3.6 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule** (with the important qualifications from §1.3–1.4 added by this document):

> **Evaluation:** *"The test case fails if `<certificates src="user" />` has been defined as part of the `<trust-anchors>` in the Network Security Configuration file."*

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition |
|---|---|
| F1 | `<certificates src="user"/>` is found inside `<base-config>` — applying to **every** connection of the app, under **all** build conditions |
| F2 | `<certificates src="user"/>` is found inside `<domain-config>` for a first-party/security-sensitive domain |
| F3 | `<certificates src="user"/>` is found inside `<debug-overrides>`, **but** it is confirmed (Method C) that `android:debuggable="true"` was **left in** the release build — this condition activates a block that should never be active in production |

**Example evidence (illustrative — MASTG does not yet provide an official demo for this test):**

```xml
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />   <!-- line 5 — DIRECTLY in base-config -->
        </trust-anchors>
    </base-config>
</network-security-config>
```

Interpretation: `src="user"` is placed directly in `<base-config>`, applying to **every** connection of the app unconditionally, not restricted to a debug condition. **Critical FAIL** — the most dangerous pattern, opening an MITM gap for the app's entire traffic on **all** devices, regardless of that build's `debuggable` status.

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition |
|---|---|
| P1 | `<certificates src="user"/>` is **not found** anywhere in the NSC file |
| P2 | `<certificates src="user"/>` is found **only** inside `<debug-overrides>`, **and** `android:debuggable="false"` is confirmed on the release build under test (Method C) — a safe pattern following official Android best practice |

**Example output indicating PASS (with qualification):**

```xml
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors><certificates src="system" /></trust-anchors>
    </base-config>
    <debug-overrides>
        <trust-anchors><certificates src="user" /></trust-anchors>
    </debug-overrides>
</network-security-config>
```

```bash
$ aapt2 dump badging target-app-release.apk | grep -i debuggable
# (no output — debuggable=false confirmed)
```

---

#### ⚠️ Important Notes on Assessment

1. **This is the single most important note in this entire document: DO NOT use naive single-line grep without regard for the parent element.** Per §1.3, a literally identical line of text carries a **completely opposite** security meaning depending on whether it resides inside `<debug-overrides>` (safe) or `<base-config>`/`<domain-config>` (dangerous). A report that fails to distinguish this will produce significant false positives against a practice that is actually officially recommended by Android.

2. **The official MASTG clause does not explicitly make an exception for `<debug-overrides>`** (§1.4) — this document recommends still reporting its **presence** as an observation (per the official Observation clause: *"should contain all the trust-anchors... along with any defined certificates entries"*), but the **FAIL/severity classification** must explicitly take into account the parent element context and `debuggable` status, rather than being treated as equal to a finding in `<base-config>`.

3. **Always correlate with MASTG-TEST-0226** (debuggable flag) — the "safe" status of `<debug-overrides>` **depends entirely** on the correctness of that test's result; do not conclude a PASS on `<debug-overrides>` without this explicit verification.

4. **Check ALL `<domain-config>` elements, not just `<base-config>`** — the same pattern emphasized in the MASTG-TEST-0235 document in this research series: an app can have a `base-config` that looks safe while hiding an exception in one of its domain-configs.

5. **Severity is modulated:**

   | Factor | Severity |
   |---|---|
   | `src="user"` in `base-config`, applying to all connections | **Critical** |
   | `src="user"` in `domain-config` for a specific sensitive domain | **High** |
   | `src="user"` in `debug-overrides`, with `debuggable=true` left in release | **Critical** (equivalent to base-config, since it is effectively just as active) |
   | `src="user"` in `debug-overrides`, with `debuggable=false` confirmed in release | **Informational** — not an active security finding, the correct practice |

6. **Document:** the exact parent element location of every occurrence of `src="user"` (base-config/domain-config/debug-overrides), the `debuggable` status of the build tested, and the affected domain if it is found within a domain-config.

---

## 4. Recommendations

### 4.1 Remove `src="user"` from `<base-config>`/`<domain-config>`

```xml
<!-- BEFORE -->
<base-config>
    <trust-anchors>
        <certificates src="system" />
        <certificates src="user" />
    </trust-anchors>
</base-config>

<!-- AFTER -->
<base-config cleartextTrafficPermitted="false">
    <trust-anchors>
        <certificates src="system" />
    </trust-anchors>
</base-config>
```

### 4.2 Move Debugging Needs into `<debug-overrides>`

```xml
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors><certificates src="system" /></trust-anchors>
    </base-config>
    <debug-overrides>
        <trust-anchors><certificates src="user" /></trust-anchors>
    </debug-overrides>
</network-security-config>
```

### 4.3 Ensure `debuggable=false` Is Maintained in Release (Refer to MASTG-TEST-0226)

```gradle
android {
    buildTypes {
        release {
            debuggable false  // explicit, do not rely solely on the Gradle default
        }
    }
}
```

### 4.4 Apply a Locked-Down Configuration as the Base, Override Only in Non-Release

Per community best-practice recommendations: use a locked-down, safe configuration as the base inherited by the release build, and override it only in the debug/staging source set — so that the release build **automatically** inherits the safe default without requiring any additional action.

### 4.5 Remediation Checklist

- [ ] Every occurrence of `<certificates src="user"/>` is inventoried along with its parent element (base-config/domain-config/debug-overrides)
- [ ] Occurrences in `<base-config>`/`<domain-config>` are removed or moved into `<debug-overrides>`
- [ ] `android:debuggable="false"` is explicitly confirmed for the release build type
- [ ] NSC configuration is separated per source set (debug vs release) to prevent cross-contamination
- [ ] Results are correlated with MASTG-TEST-0226 (debuggable status) and MASTG-TEST-0285 (minSdkVersion)
- [ ] **Re-verify:** re-run MASTG-TEST-0286 on the final release APK after remediation

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0286: Network Security Configuration Allowing Trust in User-Provided CAs](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0286/)
- [MASTG-TEST-0285: Outdated Android Version Allowing Trust in User-Provided CAs](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0285/)
- [MASTG-TEST-0226: Debuggable Flag Enabled in the AndroidManifest](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0226/)
- [MASWE-0027: Insecure Certificate Validation](https://mas.owasp.org/MASWE/MASVS-NETWORK/MASWE-0027/)
- [MASTG-KNOW-0014: Android Network Security Configuration](https://mas.owasp.org/MASTG/knowledge/android/MASVS-NETWORK/MASTG-KNOW-0014/)
- [MASTG-TECH-0151: Analyzing the Network Security Configuration](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0151/)

### 5.2 Official Android Documentation

- [Android Developers — Network Security Configuration: Custom Trust (debug-overrides)](https://developer.android.com/privacy-and-security/security-config#CustomTrust)
- [Android Developers — `<certificates>` element reference](https://developer.android.com/privacy-and-security/security-config#certificates)
- [Android Developers — `android:networkSecurityConfig` attribute](https://developer.android.com/guide/topics/manifest/application-element#networkSecurityConfig)

### 5.3 Community Research and Articles

- [Medium — Android: Different Network Configuration per Build Variant](https://medium.com/@kostadin.georgiev90/android-different-network-configuration-per-build-variant-ade8b299dce7)
- [NowSecure — A Security Analyst's Guide to Network Security Configuration in Android P](https://www.nowsecure.com/blog/2018/08/15/a-security-analysts-guide-to-network-security-configuration-in-android-p/)
- [CWE-295: Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)

### 5.4 Tool Documentation

- [xmlstarlet](http://xmlstar.sourceforge.net/)
- [yq — YAML/XML/JSON processor](https://github.com/mikefarah/yq)
- [aapt2 — Android Asset Packaging Tool](https://developer.android.com/tools/aapt2)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)

---

*This document was prepared based on OWASP MASTG (latest release as of September 2026) and official Android Developers documentation regarding the Network Security Configuration. As the mirror counterpart of MASTG-TEST-0285 (implicit vs. explicit), this document's most important finding: the literally identical configuration line `<certificates src="user"/>` carries a completely opposite security meaning depending on its parent XML element — inside `<debug-overrides>` (with `debuggable=false` in release) it is a safe practice officially recommended by Android, whereas inside `<base-config>`/`<domain-config>` it is a critical FAIL condition active under all build conditions. A valid evaluation requires structured XML parsing to distinguish this context, not merely a naive text search, as well as mandatory correlation with the `android:debuggable` status (MASTG-TEST-0226) on the build under test.*
