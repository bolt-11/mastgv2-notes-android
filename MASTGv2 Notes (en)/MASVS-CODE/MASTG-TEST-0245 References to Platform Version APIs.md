# MASTG-TEST-0245 References to Platform Version APIs

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0245 |
| **Platform** | Android |
| **MASVS Category** | MASVS-CODE (Code Quality) — *note: the official semgrep rule message refers to `[MASVS-PLATFORM]`, a metadata inconsistency, see §3.2* |
| **Weakness** | MASWE-0041 — *Running on a Recent Platform Version Not Ensured* |
| **Highlighted API** | `Build` (specifically `Build.VERSION.SDK_INT`) |
| **Test Type** | Static, Code |
| **Profile** | **L2 only** |
| **Best Practice** | MASTG-BEST-0010 (Use Up-to-Date minSdkVersion) |
| **Related Techniques** | MASTG-TECH-0013 (Reverse Engineering), MASTG-TECH-0014 (Static Analysis) |
| **Related Tests** | Same MASWE-0041/0042/0043 family under MASVS-CODE (e.g. tests related to `targetSdkVersion` and enforced updating — see §1.4) |
| **Related Demo** | — (none) |
| **Official Rule** | `mastg-android-sdk-version.yml` (exists, but narrow in scope — see §3.2) |
| **Related CWE** | CWE-1104 (Use of Unmaintained Third Party Components — a conceptual analog), closely tied to the general risk of outdated platform versions |

---

## 1. Explanation

### 1.1 Testing Objective

Official MASTG overview quote:

> *"This test verifies whether an app is running on a recent version of the Android operating system."*

More precisely, this test checks whether the application **contains code** that actively checks the OS version at runtime — via `Build.VERSION.SDK_INT` — and compares it against a specific version constant (`Build.VERSION_CODES.*`) in order to **make a decision** (enable a new security feature, restrict functionality on older OS, etc.), rather than simply running identically regardless of the underlying OS version.

```kotlin
if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
    // Android 14 (API 34) — can use security features only available here
} else {
    // fallback for older versions
}
```

### 1.2 A Crucial Distinction: `minSdkVersion` (Build-Time) vs `Build.VERSION.SDK_INT` (Runtime) — Two Complementary Layers, Not Substitutes for Each Other

This is the single most important concept to understand before evaluating this test, and it's explained in depth in MASTG-BEST-0010:

> *"`minSdkVersion`: Defines the lowest API level the app is allowed to run on... If you set a low `minSdkVersion`, your app completely misses out on these protections on older devices."*
>
> *"While a high `minSdkVersion` reduces the need for runtime version checks, dynamically verifying the OS version using `Build.VERSION.SDK_INT` remains beneficial."*

These two mechanisms operate at **different layers** and **both are needed** — neither substitutes for the other:

| Mechanism | When evaluated | What it controls |
|---|---|---|
| **`minSdkVersion`** (in `build.gradle`) | **At install time** (the Play Store/package manager refuses to install on a device with an API below this value) | The **device population** that can run the app at all |
| **`Build.VERSION.SDK_INT`** (in code, at runtime) | **While the app is running**, on a device that already passed the `minSdkVersion` filter | The **app's behavior** — which features are active on that device |

The implication: **raising `minSdkVersion` alone isn't enough** if the app's code doesn't take advantage of the higher API range that's now guaranteed, to actually enable new security features. Conversely, **having many `SDK_INT` checks in code alone isn't enough** if `minSdkVersion` is set very low (e.g. API 21/Android 5.0) — devices with that API level will **forever be stuck** on the `else` (legacy fallback) branch, because they will never satisfy the higher `if (SDK_INT >= ...)` condition. This test specifically checks for the **existence of the second mechanism** (runtime checking), as evidence that the app is genuinely **designed to leverage** differences in OS version, rather than applying one uniform behavior across all versions.

### 1.3 A Common Misconception: `targetSdkVersion` Is Not `minSdkVersion`

MASTG-BEST-0010 highlights a very common confusion between two similarly named Gradle attributes:

> *"`targetSdkVersion`: Defines the highest API level the app is designed to run on. The app can run on lower API levels, but it won't necessarily take advantage of all new security enforcements."*

Even Android's own official documentation has been acknowledged to contribute to this confusion — MASTG-BEST-0010 gives a concrete example:

> *"Even if an app targets API 28+ but is running on an older Android version (below API 28), cleartext traffic is still allowed unless explicitly disabled. Developers might assume that just increasing `targetSdkVersion` automatically blocks cleartext, which is incorrect."*

This is a **direct connection** to the `targetSdkVersion` nuance already discussed in depth in document **MASTG-TEST-0235** (§1.4 of that document) — the default for `cleartextTrafficPermitted` is determined by `targetSdkVersion`, **not** by the actual Android device in use. This MASTG-TEST-0245 test completes that understanding from another angle: even with a high `targetSdkVersion`, a device running an old OS version (below that `targetSdkVersion`) **does not automatically** receive the newer protections — unless the app explicitly checks `Build.VERSION.SDK_INT` and adjusts its behavior, or `minSdkVersion` is raised to fully exclude such devices from the user population.

### 1.4 Compounding Effect with Other Weaknesses

MASWE-0041 explicitly names the compounding effect of this issue:

> *"The weakness compounds when combined with deprecated APIs and removal of compiler-provided security features in older platforms, creating a compounding risk profile for affected users."*

This links this test to MASWE-0045 (*Compiler-Provided Security Features Not Used* — discussed in depth in documents **MASTG-TEST-0222/0223** on PIE and stack canaries) and MASWE-0046 (*Use of Deprecated APIs*). Devices running very old OS versions lose not only application-level protections, but also **operating-system-level protections** (SELinux enforcement, more mature ASLR, the runtime permission model, etc.) — this combination creates a much larger risk surface than each weakness alone.

### 1.5 Timeline of Android Platform Security Improvements (Context for Assessing the Impact of a Low `minSdkVersion`)

MASTG-BEST-0010 provides a timeline of Android security improvements by version — useful as a quick reference for assessing **how significant** the lost protections are when an app's `minSdkVersion` is set below a given version:

| Android Version (API) | Significant Security Improvement |
|---|---|
| 4.2 (16) | Introduction of SELinux |
| 4.3 (18) | SELinux enabled by default |
| 5.0 (21) | ART by default, many new features |
| 6.0 (23) | Granular runtime permission model (no longer all-or-nothing at install) |
| 8.0-8.1 (26-27) | Many security improvements |
| 9 (28) | **Cleartext HTTP blocked by default**, background mic/camera restrictions |
| 10 (29) | **TLS 1.3 enforced**, "only while using app" location |
| 11 (30) | **Scoped storage enforced**, auto permission reset, APK Signature Scheme v4 |
| 13 (33) | Safer exporting of context-registered receivers |

This table confirms that a low `minSdkVersion` (e.g. below API 28/Android 9) means the app **structurally** loses the default cleartext protection, enforced scoped storage, and various other hardening features already discussed in earlier documents in this research series (MASTG-TEST-0201, 0235, etc.).

### 1.6 A Real-World Case: CVE-2012-6636 and `addJavascriptInterface()`

Community research provides concrete evidence of the real-world impact of missing platform-version checks:

> CVE-2012-6636 allows code execution via the JavaScript bridge and reflection on APIs below 17. In practical testing, when an app was run on API 15, exploitation successfully produced a **remote shell**, while on API 27 it only showed a generic error page.

A further empirical study found **909 apps** calling `addJavascriptInterface()`, of which **413 were vulnerable** to private information leakage — because those apps did not check the API version before exposing a dangerous JavaScript interface on vulnerable Android versions (below API 17). This is a concrete example of how **the absence of a `Build.VERSION.SDK_INT` check** before enabling a certain feature can lead to remote code execution on devices with an old OS.

---

## 2. Tools Used for Testing

### 2.1 Required (Core) Tools

| Tool | Function |
|---|---|
| **jadx** | DEX decompilation → Java/Kotlin-like code to search for `Build.VERSION.SDK_INT` patterns |
| **grep / ripgrep** | API pattern search — fills in the gaps left by the narrow official rule |
| **semgrep** | Runs the official rule as a baseline |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **aapt2 / apkanalyzer** | Extracting `minSdkVersion`/`targetSdkVersion` from the manifest for evaluation context (§1.2) — a low `minSdkVersion` value is relevant to judging the significance of findings |
| **CodeQL** | Tracing more complex version-check patterns, including usage of `androidx.core.os.BuildCompat` or reflection-based version checking |
| **MobSF** | Shows `minSdkVersion`/`targetSdkVersion` in the Manifest Analysis summary as supporting context |
| **Android Lint** (`ObsoleteSdkInt`, `NewApi`) | A built-in Android Studio lint rule that approaches the problem from the **opposite direction** — detecting code that calls a new API **without** an adequate version check (`NewApi`), or a version check that's already obsolete/unnecessary because `minSdkVersion` already exceeds it (`ObsoleteSdkInt`) — a highly relevant complement for assessing the *quality* of existing version checks, not merely their presence |

### 2.3 Environment Prerequisites

- **No device/root needed** — just the APK or source code is enough.
- **Always extract `minSdkVersion` and `targetSdkVersion` first** as mandatory context (§1.2/§1.3) — any `SDK_INT` check found must be assessed relative to these two values, not in isolation.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0013** to reverse engineer the application.
2. Use **MASTG-TECH-0014** to search for relevant APIs.

### 3.2 Method A — Official Semgrep Rule *(exists, but needs to be expanded)*

```yaml
rules:
  - id: mastg-android-sdk-version
    languages:
      - java
    severity: WARNING
    metadata:
      summary: This rule scans for API that checks the version of the operating system
    message: "[MASVS-PLATFORM] Make sure to verify that your app runs on a device with an up-to-date OS version to make sure it satisfy your security requirements"
    patterns:
      - pattern: Build.VERSION.SDK_INT
```

```bash
jadx -d ./decompiled ./target-app.apk
semgrep --config https://raw.githubusercontent.com/OWASP/mastg/master/rules/mastg-android-sdk-version.yml ./decompiled/sources/
```

**Notes on this rule:**

1. **Metadata inconsistency**: the rule message references `[MASVS-PLATFORM]`, while the official test's own frontmatter (MASTG-TEST-0245) and the related weakness (MASWE-0041) both classify this test under **MASVS-CODE**. This is a similar metadata-inconsistency pattern already found earlier in this research series (e.g. MASTG-KNOW-0007 in the MASTG-TEST-0226 document). It doesn't change the testing method, but should be noted so it doesn't cause confusion when reporting results to a tracking system that groups findings by MASVS category.
2. **`languages: [java]` only** — same recurring pattern found in several other official rules in this series, explicitly scoped only to Java even though the official overview actually gives its example in **Kotlin**. Since `Build.VERSION.SDK_INT` is a simple syntax pattern identical in both languages, the risk of a gap here is relatively low, but it still needs to be verified against complex, purely Kotlin codebases.
3. **The rule only detects the literal presence of the `Build.VERSION.SDK_INT` pattern** — it does not catch alternative approaches such as `androidx.core.os.BuildCompat` (Google's official API-compatibility helper), comparisons of `Build.VERSION.RELEASE` (the version string, an older/less-recommended approach), or reflection-based version checking sometimes used to evade static detection.
4. **Does not assess the quality of the check** — this rule merely detects presence, not whether the check genuinely protects a security-critical feature or is only used for something cosmetic (e.g. adjusting UI/theme).

### 3.3 Method B — grep/ripgrep for Alternative Patterns *(closes the gap from §3.2)*

```bash
D=./decompiled/sources

# Standard pattern
rg -n 'Build\.VERSION\.SDK_INT' $D

# Alternative pattern — BuildCompat (AndroidX)
rg -n 'BuildCompat\.' $D

# Alternative pattern — version string comparison (less recommended but still found)
rg -n 'Build\.VERSION\.RELEASE' $D

# Search usage context — is it used for a security decision, or just UI
rg -n -B3 -A5 'Build\.VERSION\.SDK_INT' $D | grep -i "encrypt\|keystore\|permission\|biometric\|storage\|cert\|tls\|ssl"
```

### 3.4 Method C — Android Lint (`NewApi`, `ObsoleteSdkInt`) — Assessing Quality, Not Just Presence

```bash
cd android-project/
./gradlew lint
```

- **`NewApi`**: flags calls to an API only available from a certain level **without** an adequate `SDK_INT` check — this actually detects the **absence** of a version check where one should exist, complementing the official MASTG rule, which only detects presence.
- **`ObsoleteSdkInt`**: flags `SDK_INT` checks that are **no longer relevant** because the project's `minSdkVersion` already exceeds the value being checked — useful for cleaning up technical debt and ensuring `minSdkVersion` has genuinely been raised in line with the codebase's progress.

### 3.5 Method D — Extracting `minSdkVersion`/`targetSdkVersion` Context (Required for Interpreting Results)

```bash
jadx --no-src -d ./out target-app.apk
grep -o 'minSdkVersion="[0-9]*"\|targetSdkVersion="[0-9]*"' ./out/resources/AndroidManifest.xml
```

This result **must** be paired with the findings of Method A/B/C — per §1.2/§1.5, an app with a high `minSdkVersion` (e.g. API 28+) structurally already inherits many default protections without needing extensive manual `SDK_INT` checks, while a low `minSdkVersion` demands far more extensive checking to compensate.

### 3.6 Method Comparison: When to Use Which

| Method | Tool | Detects presence? | Detects quality/gaps? | When to use |
|---|---|---|---|---|
| **A** | Official semgrep rule | ✅ | ❌ | Quick baseline |
| **B** | grep for alternative patterns | ✅ (+ broader coverage) | ❌ | Fills in the official rule's coverage gaps |
| **C** | Android Lint `NewApi`/`ObsoleteSdkInt` | Indirect | ✅ | **Most valuable** — answers the real question: is the existing check adequate? |
| **D** | Manifest extraction | N/A | N/A (context) | **Mandatory** as the basis for interpreting all other findings |

**Minimum recommended combination:** **D (minSdkVersion/targetSdkVersion context) → A+B (baseline+supplement) → C (Android Lint to assess quality)**. Method C provides the most significant added value compared to the official MASTG rule, because it answers the more security-relevant question: not "is there a version check somewhere," but "is the API that needs a version check actually guarded by an adequate check."

---

### 3.7 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Observation:** *"The output should contain a list of locations where relevant APIs are used."*
>
> **Evaluation:** *"The test case fails if the app does not include any API calls to verify the operating system version."*

---

#### ❌ FAIL / ISSUE — The check is declared FAILED when:

| No | Condition |
|---|---|
| F1 | **No** reference to `Build.VERSION.SDK_INT` (or its alternatives) is found anywhere in the codebase |
| F2 | `minSdkVersion` is set low (below API 28, per the timeline in §1.5), **and** there is no version check to compensate for security features missing on older devices |
| F3 | Android Lint `NewApi` finds calls to a high-level API **without** a corresponding `SDK_INT` guard — an indication that even though version checks *exist* elsewhere, coverage is not comprehensive |
| F4 | A security-critical feature (encryption, biometrics, secure storage) is implemented without considering the minimum API level that feature requires, potentially causing crashes or unexpected fallback behavior on older devices |

**Example evidence (illustrative — MASTG does not yet provide an official demo for this test):**

```bash
$ grep -o 'minSdkVersion="[0-9]*"' AndroidManifest.xml
minSdkVersion="21"    # Android 5.0 — misses full SELinux enforcement, runtime permissions, etc.

$ rg -c 'Build\.VERSION\.SDK_INT' ./decompiled/sources/
0   # NO version check anywhere in the whole app
```

Interpretation: a low `minSdkVersion` (API 21) combined with **zero** `SDK_INT` checks — the app runs identical behavior across the entire device range from Android 5.0 to the latest version, missing the opportunity to enable security features available on higher APIs. **FAIL** per the official clause.

---

#### ✅ PASS — The check is declared PASSED when:

| No | Condition |
|---|---|
| P1 | A `Build.VERSION.SDK_INT` check is found being used to condition a security-critical feature based on API level |
| P2 | `minSdkVersion` is already sufficiently high (e.g. API 28+) so core platform protections are already structurally guaranteed, **and** additional version checks still exist to leverage newer features from that API |
| P3 | Android Lint finds no `NewApi` violations — all high-level API calls are already guarded by an appropriate version check |

**Example output indicating PASS:**

```bash
$ rg -n 'Build\.VERSION\.SDK_INT' ./decompiled/sources/com/example/target/crypto/KeyManager.java
42:    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
43:        // Uses Android Keystore StrongBox / newer biometric features
```

---

#### ⚠️ Important Notes on Evaluation

1. **Always evaluate alongside `minSdkVersion`, not in isolation.** Per §1.2, the existence of minimal `SDK_INT` checking may be **reasonable** if the app's `minSdkVersion` is already high (devices below it are already fully excluded) — conversely, a low `minSdkVersion` **demands** much more extensive checking.

2. **Focus on checks that guard security-critical features**, not simply counting total `SDK_INT` occurrences in code. A version check used to adjust a UI theme or status-bar icon carries different value from one used to enable hardware-backed encryption.

3. **Leverage Android Lint as a more precise complement** than the official MASTG rule — `NewApi` answers a more security-relevant question than simply "is `SDK_INT` mentioned somewhere."

4. **Remember the nuance between `targetSdkVersion`, `minSdkVersion`, and the actual device OS** (§1.3) — don't conflate the three when writing a report. A high `targetSdkVersion` doesn't guarantee automatic protection on a device with an old OS, per the cleartext example already discussed in depth in document MASTG-TEST-0235.

5. **Severity is modulated as follows:**

   | Factor | Severity |
   |---|---|
   | `minSdkVersion` very low (below API 23) with no version checking at all | **High** |
   | Low `minSdkVersion`, some checks exist but don't cover security-critical features | **Medium** |
   | `minSdkVersion` already high (28+), few version checks | **Low/Informational** — risk already mitigated by `minSdkVersion` |

6. **Document:** the `minSdkVersion`/`targetSdkVersion` values, a list of `SDK_INT` check locations along with the feature each one guards, the Android Lint `NewApi`/`ObsoleteSdkInt` results, and an assessment of whether check coverage is adequate relative to the configured `minSdkVersion`.

---

## 4. Recommendations

### 4.1 Raise `minSdkVersion` to a Reasonable Value

```gradle
android {
    defaultConfig {
        minSdkVersion 28  // Android 9 — default cleartext protection, etc.
        targetSdkVersion 34
    }
}
```

### 4.2 Implement Version Checks for Security-Critical Features

```kotlin
fun getSecureKeyGenSpec(alias: String): KeyGenParameterSpec.Builder {
    val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT)
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
        builder.setIsStrongBoxBacked(true)  // only available from API 28+
    }
    return builder
}
```

### 4.3 Enable Android Lint `NewApi` as a Build-Blocking Check

```gradle
android {
    lintOptions {
        error 'NewApi'
    }
}
```

### 4.4 Remediation Checklist

- [ ] `minSdkVersion` has been evaluated and raised to a value proportionate to the app's security needs
- [ ] Security-critical features are guarded by appropriate `Build.VERSION.SDK_INT` checks
- [ ] Android Lint `NewApi` is enabled as a build-blocking check
- [ ] `ObsoleteSdkInt` is checked to clean up version checks that are no longer relevant
- [ ] **Re-verify:** re-run MASTG-TEST-0245 after any change to `minSdkVersion` or the addition of new features

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0245: References to Platform Version APIs](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0245/)
- [MASTG-TEST-0235: Android App Configurations Allowing Cleartext Traffic](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0235/)
- [MASWE-0041: Running on a Recent Platform Version Not Ensured](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0041/)
- [MASTG-BEST-0010: Use Up-to-Date minSdkVersion](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0010/)
- [MASTG-TECH-0013: Reverse Engineering Android Apps](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/)
- [MASTG-TECH-0014: Static Analysis on Android](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/)
- [Official rule: mastg-android-sdk-version.yml (GitHub)](https://github.com/OWASP/mastg/blob/master/rules/mastg-android-sdk-version.yml)

### 5.2 Official Android Documentation

- [Android Developers — `Build.VERSION` reference](https://developer.android.com/reference/android/os/Build.VERSION)
- [Android Developers — Meet Google Play's target API level requirement](https://support.google.com/googleplay/android-developer/answer/11926878)
- [Android Security Bulletins](https://source.android.com/docs/security/bulletin)
- [Android Developers — `androidx.core.os.BuildCompat`](https://developer.android.com/reference/androidx/core/os/BuildCompat)

### 5.3 Research and Real-World Cases

- [Digital Interruption Research — How Does The SDK Version Affect The Security of Android Applications?](https://research.digitalinterruption.com/2019/01/25/how-does-the-sdk-version-affect-the-security-of-android-applications/)
- [arXiv — Measuring the Declared SDK Versions and Their Consistency with API Calls in Android Apps](https://arxiv.org/pdf/1702.04872)
- [arXiv — An Empirical Study on Android-related Vulnerabilities](https://arxiv.org/pdf/1704.03356)
- [Valency Networks — Application Supports Insecure or Outdated Android Versions](https://valencynetworks.com/kb/android-app-vulnerability-supporting-insecure-or-outdated-android-versions.html)

### 5.4 Tool Documentation

- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [Android Lint — Documentation](https://developer.android.com/studio/write/lint)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)

---

*This document was compiled based on OWASP MASTG (latest release as of September 2026), official Android Developers documentation, and academic and community research (including the real-world CVE-2012-6636 case) on the security impact of a low `minSdkVersion`. The most important nuance: runtime `Build.VERSION.SDK_INT` checks and build-time `minSdkVersion` are two complementary control layers, not substitutes for each other — a proper evaluation requires assessing both together, not in isolation.*
