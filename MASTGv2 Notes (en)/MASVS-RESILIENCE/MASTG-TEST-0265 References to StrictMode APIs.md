# MASTG-TEST-0265 References to StrictMode APIs

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0265 |
| **Platform** | Android |
| **MASVS Category** | MASVS-RESILIENCE |
| **Weakness** | MASWE-0061 — *Debug Artifacts Not Removed* |
| **Highlighted API** | `StrictMode` |
| **Test Type** | **Static, Code** |
| **Profile** | **R (Resilience) only** |
| **Related Techniques** | MASTG-TECH-0013 (Reverse Engineering), MASTG-TECH-0014 (Static Analysis) |
| **Related Test** | **MASTG-TEST-0263** (Logging of StrictMode Violations — dynamic/logs), **MASTG-TEST-0264** (Runtime Use of StrictMode APIs — dynamic/hooks). All three tests form a **complete trio** targeting the same risk (MASWE-0061) from three different methodological angles: static, dynamic-hooking, dynamic-logging |
| **Related Demo** | — (none) |
| **Official Rule** | `mastg-android-strictmode.yml` — only matches `setVmPolicy(...)`, does not cover `setThreadPolicy` (same as discussed in the MASTG-TEST-0263 document §3.2) |
| **Related CWE** | CWE-215, CWE-489 |

---

## 1. Explanation

### 1.1 This Test's Position in the Complete MASWE-0061 Trio

Together with MASTG-TEST-0263 and MASTG-TEST-0264, this test completes a **full methodological trio** for a single shared weakness (MASWE-0061 — Debug Artifacts Not Removed) applied to `StrictMode`:

| Test | Type | What Is Checked |
|---|---|---|
| **MASTG-TEST-0265** *(this document)* | Static | Does the **source code/bytecode** contain any `StrictMode` API reference at all? |
| **MASTG-TEST-0264** | Dynamic, Hooks | Is the `StrictMode` API **actually called** while the application is running? |
| **MASTG-TEST-0263** | Dynamic, Logs | Does active `StrictMode` **actually produce** exploitable violation logs? |

All three move from **the broadest but least certain coverage** (static — the code could merely be dead/unexecuted code) toward **the narrowest but most certain coverage** (logs — direct proof of real impact). The entire in-depth conceptual context of why `StrictMode` is dangerous (stack trace leakage, class names, code lines that ease reverse engineering) has already been fully discussed in the **MASTG-TEST-0263** document — this document focuses on the nuances **specific to the static approach**.

### 1.2 The Most Important Nuance: The Object of Analysis Determines the Validity of the Result — Source Code vs. Release APK Bytecode

This is the most significant methodological nuance unique to this static test, and it **does not apply** to MASTG-TEST-0263/0264 (both of which inherently already test a real production build because of their dynamic nature). The question is: **what object** is the tester actually analyzing?

**Scenario 1 — Whitebox, analyzing the project's source code:**

```kotlin
class MyApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        if (BuildConfig.DEBUG) {
            StrictMode.setVmPolicy(...)  // <-- this reference is ALWAYS PRESENT in the source code
        }
    }
}
```

If a tester performs `grep`/a direct pattern search on the project's **source code**, a reference to `StrictMode.setVmPolicy` will **always be found** — regardless of whether the `BuildConfig.DEBUG` guard has been correctly applied or not. This is because the guard is a **condition evaluated at compile/runtime**, not something that removes the code text from the source itself. **Concluding FAIL purely from this kind of source-code search result is potentially wrong** — that code may **never actually make it** into the production build.

**Scenario 2 — Blackbox, analyzing bytecode decompiled from the RELEASE APK:**

This is where the mechanism that actually determines the validity of this test's evaluation lies: **R8** (Android's official release-build shrinker/optimizer) performs **dead-code elimination**. If `BuildConfig.DEBUG` has already been compiled as a `false` constant on the release build (the Android Gradle Plugin's standard behavior), R8 is **able to recognize** that the `if (BuildConfig.DEBUG) { ... }` block will never execute, and **removes that entire block** — including the `StrictMode.setVmPolicy()` call inside it — from the final `classes.dex` bytecode that is actually packaged into the APK.

**Crucial implication**: this test's results are **only valid and meaningful** when performed against **bytecode decompiled from the final release APK** (via jadx/apktool), **not** against the project's source code. Analyzing source code will produce a **systematic false positive** for every application that has correctly implemented the `BuildConfig.DEBUG` guard — the code exists in the source, but **never** actually reaches the user's/attacker's hands in an executable form.

### 1.3 Why the Absence of References in Release Bytecode Is a Strong PASS Signal

Precisely because of the R8 mechanism above, **a PASS result from this static test (on release bytecode) is a very convincing signal** — far stronger than merely "no violation found during one test session" (MASTG-TEST-0263) or "no hook triggered during one test session" (MASTG-TEST-0264), both of which remain vulnerable to limitations in interaction coverage (code paths that were not triggered during the test session). If `grep`/decompiling the release APK **finds no `StrictMode` symbol at all** anywhere in `classes.dex`, this means the API **structurally cannot be called** — no matter what interaction scenario a tester might try in any dynamic session.

### 1.4 But Conversely — Finding a Reference in Release Bytecode Is a Very Strong FAIL Signal

The reverse holds with equal strength: if `StrictMode.setVmPolicy` (or another related symbol) is **still found** in bytecode decompiled from the release APK, this is a FAIL signal that **cannot be refuted** by the argument "but it just happened not to be triggered during dynamic testing" — because its presence in the final bytecode **proves** that the `BuildConfig.DEBUG` guard **failed** to remove it (either because the guard was not applied at all, was applied incorrectly, or the build/shrinking configuration did not run as intended). This is the unique advantage of the static approach compared to the two dynamic approaches in this trio — it provides **structural certainty**, not merely "evidence from one observation session".

---

## 2. Tools Used for Testing

### 2.1 Mandatory Tools (Core)

| Tool | Function |
|---|---|
| **jadx** | Decompile DEX → Java from the **final release APK** (not the project source) — crucial per §1.2 |
| **grep / ripgrep** | Pattern search for the `StrictMode` API |
| **semgrep** | Runs the official rule as a baseline |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **rabin2 / strings** | Extracts strings directly from `classes.dex` without full decompilation — a quick way to check for the presence of the `StrictMode` symbol in raw bytecode |
| **CodeQL** | For whitebox testing on source code — if used, it **must** be combined with `BuildConfig.DEBUG` guard verification (see §3.4) to avoid the false positive described in §1.2 |
| **diff between debug and release builds** | Comparing decompilation results of both build variants to empirically confirm that R8 actually removes `StrictMode` code in the release build |

### 2.3 Environment Prerequisites

- **No device/root required** — this can be done entirely from the APK file.
- **MUST analyze the final release APK**, not the project's source code or a debug APK — this is the most critical prerequisite per §1.2, different from most other static tests in this research series, which are more flexible about the object of analysis.
- If only source code is available (pure whitebox without a release APK), it is **mandatory** to supplement the result with `BuildConfig.DEBUG` guard verification (§3.4) before concluding anything.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0013** to reverse engineer the application.
2. Use **MASTG-TECH-0014** to search for the relevant API.

### 3.2 Method A — Official Semgrep Rule on Release Bytecode *(primary method)*

```yaml
rules:
  - id: mastg-android-strictmode
    severity: WARNING
    languages: [java]
    message: "[MASVS-RESILIENCE] Detected usage of StrictMode"
    patterns:
      - pattern: StrictMode.setVmPolicy(...)
```

```bash
# MANDATORY: decompile from the RELEASE APK, not the project source
jadx -d ./decompiled_release target-app-release.apk
semgrep --config https://raw.githubusercontent.com/OWASP/mastg/master/rules/mastg-android-strictmode.yml ./decompiled_release/sources/
```

**The same coverage gap discussed in the MASTG-TEST-0263 document**: this rule only covers `setVmPolicy()`, not `setThreadPolicy()`. Supplement with Method B.

### 3.3 Method B — grep/ripgrep and Direct Bytecode String Extraction

```bash
D=./decompiled_release/sources

# Comprehensive coverage of both configuration APIs
rg -n 'StrictMode\.setVmPolicy\(|StrictMode\.setThreadPolicy\(|penaltyLog\(\)' $D

# Direct verification on raw bytecode WITHOUT full decompilation (faster, hard to evade via class-name obfuscation)
unzip -o target-app-release.apk classes.dex -d /tmp/dex_check
strings /tmp/dex_check/classes.dex | grep -i "strictmode\|StrictMode"
```

**Important note**: searching for strings directly in `classes.dex` (rather than decompiled output) has an advantage — system class names like `android.os.StrictMode` are **never obfuscated** by ProGuard/R8 (because they are framework APIs, not the application's own code), so this simple string search is **quite reliable** even on an APK that has been aggressively obfuscated.

### 3.4 Method C — Verifying the `BuildConfig.DEBUG` Guard (Mandatory for Source-Code Whitebox)

If the analysis is performed on source code (not a release APK), it is **mandatory** to verify that every reference found is inside the correct guard condition:

```bash
rg -n -B5 'StrictMode\.setVmPolicy\(' ./src/ | grep -B5 "BuildConfig.DEBUG"
```

```ql
// CodeQL — ensure EVERY StrictMode call is inside a BuildConfig.DEBUG guard
import java

class StrictModeCall extends MethodAccess {
  StrictModeCall() {
    this.getMethod().hasName(["setVmPolicy", "setThreadPolicy"]) and
    this.getMethod().getDeclaringType().hasQualifiedName("android.os", "StrictMode")
  }
}

from StrictModeCall call
where not exists(IfStmt guard |
  guard.getCondition().toString().matches("%BuildConfig.DEBUG%") and
  guard.getAChild*() = call.getEnclosingStmt())
select call, "StrictMode call WITHOUT a BuildConfig.DEBUG guard — potentially leaking into the release build"
```

### 3.5 Method D — Empirical Comparison of Debug vs. Release Builds

To directly validate that the R8 dead-code elimination mechanism truly works as expected (§1.2):

```bash
./gradlew assembleDebug assembleRelease

jadx -d ./out_debug app-debug.apk
jadx -d ./out_release app-release.apk

echo "=== StrictMode references in the DEBUG build ==="
rg -c 'StrictMode\.setVmPolicy' ./out_debug/sources/ | awk -F: '{sum+=$2} END {print sum+0}'

echo "=== StrictMode references in the RELEASE build ==="
rg -c 'StrictMode\.setVmPolicy' ./out_release/sources/ | awk -F: '{sum+=$2} END {print sum+0}'
```

If the debug build result shows a count **>0** while the release build shows **0**, this is direct empirical proof that the guard and shrinking configuration are working correctly — this is the most convincing PASS pattern for this test.

### 3.6 Method Comparison: When to Use Which

| Method | Tool | Object of analysis | When to use |
|---|---|---|---|
| **A** | Official semgrep rule | Release APK bytecode | Baseline, but narrow API coverage |
| **B** | grep + strings on dex | Release APK bytecode | **Mandatory primary baseline**, robust against obfuscation |
| **C** | CodeQL on source | Source code | Only meaningful when combined with guard verification |
| **D** | Debug vs. release comparison | Both builds | **Strongest empirical evidence**, validates the mechanism end to end |

**Minimum combination recommended:** **B (on the final release APK) → D (empirical debug vs. release comparison)** as the most convincing evidence. Method C is only relevant as a supplement when only source code is available, and its result **must** be qualified by the guard verification status, not concluded on its own.

---

### 3.7 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Observation:** *"The output should identify all instances of `StrictMode` usage in the app."*
>
> **Evaluation:** *"The test case fails if the app uses `StrictMode` APIs."*

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition |
|---|---|
| F1 | A reference to `StrictMode.setVmPolicy`/`setThreadPolicy` **is found in the bytecode decompiled from the RELEASE APK** — an irrefutable FAIL signal (§1.4) |
| F2 | The debug-release build comparison (Method D) shows the reference count **does not decrease** in the release build — indicating the guard/shrinking failed to work |
| F3 | Source code analysis (whitebox) finds a `StrictMode` call **without** any `BuildConfig.DEBUG` guard at all |

**Example evidence (illustrative — MASTG does not yet provide an official demo for this test):**

```bash
$ jadx -d ./decompiled_release target-app-release.apk
$ rg -n 'StrictMode\.setVmPolicy' ./decompiled_release/sources/
com/target/app/MyApplication.java:22:    StrictMode.setVmPolicy(policy)
```

Interpretation: the reference is found in the bytecode of a **release APK** that has gone through a full production build process — this is definitive proof that the guard (if any) failed to prevent this code from entering the final build. **FAIL**, regardless of the MASTG-TEST-0263/0264 results from any dynamic test session.

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition |
|---|---|
| P1 | **No** `StrictMode` reference whatsoever is found in the bytecode decompiled from the final release APK (confirmed by Method B) — the strongest PASS signal per §1.3 |
| P2 | The debug-release build comparison (Method D) confirms the reference count drops to exactly zero in the release build |
| P3 | For source-code-only analysis (without access to the release APK): every `StrictMode` call found is inside a correct `BuildConfig.DEBUG` guard (but qualify this conclusion as a "conditional PASS" — refer to §1.2) |

---

#### ⚠️ Important Assessment Notes

1. **This is the most important note in this entire document: the object of analysis determines the validity of the result.** Running a pattern search on the project's source code and concluding FAIL purely from that, without verifying whether that code actually reaches the release bytecode, is the **most common methodological mistake** for this test. Always prioritize analysis against the **final release APK**.

2. **A PASS result on release bytecode is the strongest evidence among the three tests in this trio** (0263/0264/0265) — because it is structural in nature (there is no API that can be called because it does not exist in the bytecode), not merely "not observed during one test session".

3. **The `StrictMode` symbol name is never obfuscated** (§3.3) — take advantage of this to perform a quick and reliable string search directly on `classes.dex`, even on an application with aggressive application-class-name obfuscation.

4. **Always correlate all three tests in this trio for the most convincing report** — static (structural), hooking (confirms the call), logs (confirms real impact). Together, all three give a much more complete picture than any single test alone.

5. **Severity follows the same pattern as MASTG-TEST-0263/0264.**

6. **Document:** the object of analysis used (source code vs. release APK — MUST be noted explicitly), the debug vs. release build comparison result if performed, the location of the reference found, and the `BuildConfig.DEBUG` guard status if analyzing source code.

---

## 4. Recommendations

The recommendations are identical to **the MASTG-TEST-0263 document §4** — wrap all `StrictMode` calls in a `BuildConfig.DEBUG` guard.

Additional specifics for static validation:

### 4.1 Verify Active Shrinking/R8 Configuration for the Release Build

```gradle
// app/build.gradle
android {
    buildTypes {
        release {
            minifyEnabled true  // MUST be active for R8 dead-code elimination to run
            proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-rules.pro'
        }
    }
}
```

Without `minifyEnabled true`, R8 shrinking **does not run at all**, and the `if (BuildConfig.DEBUG)` block — even though it logically will never be `true` at runtime — **remains textually present** in the release bytecode (even though it is functionally harmless because the condition will never be satisfied at runtime, it will still be detected by this test's static pattern search).

### 4.2 Integrate Empirical Verification into CI/CD

```bash
#!/bin/bash
# ci-verify-strictmode-removed-from-release.sh
./gradlew assembleRelease
jadx -d /tmp/release_check app-release.apk 2>/dev/null
COUNT=$(rg -c 'StrictMode\.(setVmPolicy|setThreadPolicy)' /tmp/release_check/sources/ 2>/dev/null | awk -F: '{sum+=$2} END {print sum+0}')
if [ "$COUNT" -gt "0" ]; then
    echo "[FAILED] StrictMode still found in RELEASE APK bytecode ($COUNT references)!"
    exit 1
fi
echo "[OK] No StrictMode references found in the release APK."
```

### 4.3 Remediation Checklist

- [ ] All `StrictMode` calls are wrapped in a `BuildConfig.DEBUG` guard
- [ ] `minifyEnabled true` is active for the release build type
- [ ] Empirical verification (Method D) confirms references are completely gone in the release bytecode
- [ ] CI/CD includes an automated gate to detect regressions (§4.2)
- [ ] Results are correlated with MASTG-TEST-0263/0264 for a thorough validation
- [ ] **Re-verification:** re-run MASTG-TEST-0265 on the final release APK for every release

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0265: References to StrictMode APIs](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0265/)
- [MASTG-TEST-0263: Logging of StrictMode Violations](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0263/)
- [MASTG-TEST-0264: Runtime Use of StrictMode APIs](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0264/)
- [MASWE-0061: Debug Artifacts Not Removed](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0061/)
- [MASTG-TECH-0013: Reverse Engineering Android Apps](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/)
- [MASTG-TECH-0014: Static Analysis on Android](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/)
- [Official rule: mastg-android-strictmode.yml (GitHub)](https://github.com/OWASP/mastg/blob/master/rules/mastg-android-strictmode.yml)

### 5.2 Official Android Documentation

- [Android Developers — `StrictMode` API reference](https://developer.android.com/reference/android/os/StrictMode)
- [Android Developers — Shrink, obfuscate, and optimize your app (R8)](https://developer.android.com/build/shrink-code)
- [Android Developers — `BuildConfig` reference](https://developer.android.com/reference/tools/gradle-api/8.0/com/android/build/api/variant/BuildConfigField)

### 5.3 Tool Documentation

- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [radare2 / rabin2](https://github.com/radareorg/radare2)

---

*This document was compiled based on OWASP MASTG (latest release as of September 2026) and official Android Developers documentation on R8/ProGuard. As the third part of the complete trio targeting MASWE-0061 on `StrictMode` (together with MASTG-TEST-0263 and 0264), the most important nuance of this document is that **the object of analysis fundamentally determines the validity of the result** — a pattern search on the project's source code can produce a systematic false positive if the `BuildConfig.DEBUG` guard has already been correctly implemented, because R8 dead-code elimination will remove that code entirely from the release APK's bytecode. A valid evaluation requires the analysis to be performed against **bytecode decompiled from the final release APK**, not source code alone.*
