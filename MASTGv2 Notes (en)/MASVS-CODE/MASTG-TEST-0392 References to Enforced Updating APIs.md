# MASTG-TEST-0392 References to Enforced Updating APIs

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0392 |
| **Platform** | Android |
| **MASVS Category** | MASVS-CODE |
| **Weakness** | MASWE-0043 |
| **Test Type** | Static, Code, **Manual** |
| **Related Techniques** | MASTG-TECH-0013, MASTG-TECH-0014, MASTG-TECH-0023 |
| **Related Knowledge** | MASTG-KNOW-0023 (Enforced Updating) |
| **Related Tests** | **MASTG-TEST-0382** — **dynamic** counterpart that confirms enforcement is actually effective at runtime (already covered in depth in this research series) |
| **Official Rule** | — (none exists; purely manual) |

---

## 1. Explanation

### 1.1 Testing Objective and Its Relationship to MASTG-TEST-0382

Quote from the official MASTG overview:

> *"Android apps may fail to enforce updates when critical security patches or minimum version requirements are needed... This test checks whether the app contains code that implements update enforcement, either through Play In-App Updates or through a custom version-based gating mechanism."*

This test is the **static counterpart** of MASTG-TEST-0382 (already covered in depth earlier in this research series) — following a pattern that has recurred repeatedly throughout this series (root detection TEST-0324/0325, debugging detection TEST-0352/0353, etc.): the static test finds **code references** to the enforcement mechanism, while the dynamic test confirms that mechanism is **actually effective** when actively exploited. All the in-depth context on *why* enforced updating matters (vulnerability response, cryptographic key rotation, API migration), the two available mechanisms (Play In-App Updates vs backend-gated), and the limitations of the Play Console recovery prompt — has already been covered fully in the MASTG-TEST-0382 document and fully applies here as background context for this test.

### 1.2 Concrete List of Target APIs to Search For

The overview provides a very specific list of APIs for both mechanisms, more detailed than the TEST-0382 overview:

**Play In-App Updates API:**
> `AppUpdateManagerFactory.create`, `AppUpdateManager#getAppUpdateInfo`, `UpdateAvailability.UPDATE_AVAILABLE`, `UpdateAvailability.DEVELOPER_TRIGGERED_UPDATE_IN_PROGRESS`, `AppUpdateType.IMMEDIATE`, `AppUpdateOptions`, `startUpdateFlowForResult`

**Backend-Gated Flow:**
> `BuildConfig.VERSION_NAME`/`BuildConfig.VERSION_CODE`, `PackageInfo` via `PackageManager`

This list provides a complete "dictionary" for manual pattern searching (§3), given that no automated Semgrep rule is available.

### 1.3 Key Evaluation Nuance: A "Dismissible Dialog" Is Explicitly Considered an Incorrect Implementation

This is a very important detail, given explicitly in the overview, unlike most other tests that only discuss quality nuances in a "Further Validation Required" section:

> *"If these mechanisms are absent, implemented incorrectly (for example, using only a dismissible dialog for a mandatory update), or not triggered before access to protected functionality or backend services, an outdated app may continue to be used."*

This means that **finding code that looks like enforcement** (a dialog appears asking for an update) **is not enough** for a PASS — the tester must specifically check whether that dialog **can be closed/dismissed** by the user. A dismissible dialog for an update that should be **mandatory** is explicitly considered an "incorrect implementation," not a "weak but acceptable implementation" — this is a firm classification the tester needs to hold onto.

### 1.4 Further Validation: Four Questions Requiring Call-Graph Analysis

The "Further Validation Required" section demands deeper analysis than simply finding API references:

> *"Determine whether the update check executes before access to protected functionality or backend services and cannot be bypassed (for example, by checking the call graph or entry point context)."*

The phrase *"checking the call graph or entry point context"* confirms that this test is **not just simple grepping** — the tester needs to understand the **application's structure** to assess whether the update check is actually on a path that **cannot be avoided** before accessing protected functionality (for example, in the main activity's `onCreate()`, which is always traversed, rather than in an optional activity that can be skipped via a direct deep link).

The other three further-validation questions **directly parallel** the three specific failure scenarios already covered in depth in the MASTG-TEST-0382 document — reaffirming the consistent design between these two tests:

> *"For Google Play In-App Updates, determine whether the app handles cancellation or denial... checks update state when returning to the foreground, and restarts the immediate update flow when `UpdateAvailability.DEVELOPER_TRIGGERED_UPDATE_IN_PROGRESS` is reported."*
>
> *"For backend-gated flows, determine whether the app compares the installed version against a backend-supplied minimum version and blocks access when the current version does not meet the policy."*

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **jadx** | Decompiles DEX → Java for searching API references (MASTG-TECH-0013, MASTG-TECH-0014) |
| **grep/ripgrep** | Searching for API patterns from the complete list in §1.2 — the only approach available since there is no official Semgrep rule |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **MobSF** | Automated reporting that sometimes includes basic detection of Play Core library usage |
| **Androguard** | Call-graph analysis to assess the position of the update check relative to the app's entry point (§1.4) |

### 2.3 Environment Prerequisites

- No device/root needed — purely static analysis.
- Understand the application's navigation structure (which activity is the main entry point) to assess the call graph (§1.4).

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0013** to reverse engineer the application.
2. Use **MASTG-TECH-0014** to search for relevant APIs.

### 3.2 Method A — grep/ripgrep for the Play In-App Updates API

```bash
D=./decompiled/sources

rg -n 'AppUpdateManagerFactory\.create|getAppUpdateInfo\(|startUpdateFlowForResult\(' $D
rg -n 'UpdateAvailability\.(UPDATE_AVAILABLE|DEVELOPER_TRIGGERED_UPDATE_IN_PROGRESS)' $D
rg -n 'AppUpdateType\.IMMEDIATE' $D
```

### 3.3 Method B — grep/ripgrep for Backend-Gated Flow

```bash
rg -n 'BuildConfig\.VERSION_(NAME|CODE)' $D
rg -n 'getPackageInfo\(.*\)\.versionName|getLongVersionCode\(' $D
rg -n 'minVersion|min_version|minimumVersion' $D -i
```

### 3.4 Method C — Call-Graph Analysis for Entry-Point Position (Mandatory, Per §1.4)

```bash
# Trace call sites relative to the main activity's onCreate()
rg -n -B20 'getAppUpdateInfo\(|minVersion' $D | grep -E 'class \w+Activity|onCreate\('
```

Manual verification: is the update check located in an activity that is **always** traversed by the user (splash screen, main activity `onCreate`), or in an optional activity that could be avoided?

### 3.5 Method D — Manual Review for the Dismissible Dialog Criterion (Mandatory, Per §1.3)

For each update dialog/UI found:

1. Check whether the dialog has a "Later"/"Cancel"/"Skip" button, or can be closed via the back button/tapping outside the dialog.
2. Check whether the application still permits further navigation after the dialog is closed.

### 3.6 Method Comparison: When to Use Which

| Method | Tool | When to Use |
|---|---|---|
| **A/B** | grep/ripgrep | Mandatory baseline — the only approach available since there is no automated rule |
| **C** | Call-graph analysis | **Required** — assessing the entry-point position |
| **D** | Manual UI review | **Required** — assessing the dismissible-dialog criterion |

**Minimum recommended combination:** **A/B (mandatory) → C + D (mandatory)**, followed by **MASTG-TEST-0382** to confirm runtime effectiveness.

---

### 3.7 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Evaluation:** *"The test case fails if no code locations show an update enforcement mechanism."*

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition |
|---|---|
| F1 | Not a single reference to the Play In-App Updates API or a backend-gated version check is found anywhere in the codebase |

**Critical note (§1.3):** if an API reference is found, but its implementation is a **dismissible dialog** for an update that should be mandatory, this is **still considered a qualitative FAIL** even though technically "update-check code exists" — the official evaluation explicitly classifies this as "implemented incorrectly," equivalent to having no mechanism at all in terms of final outcome.

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition |
|---|---|
| P1 | An enforcement API reference is found (Play In-App Updates or backend-gated), **and** |
| P2 | The check's location is at an unavoidable entry point (§1.4), **and** |
| P3 | The implementation uses the immediate update flow or a non-dismissible blocking screen, not a dialog that can be closed (§1.3) |

---

#### ⚠️ Important Notes on Assessment

1. **Do not stop at "an API reference was found"** — per §1.3, the quality of implementation (dismissible vs non-dismissible) is just as important as the presence of the code; this test explicitly classifies a dismissible dialog as an error, not merely a weakness.

2. **Verify the position in the call graph, not just the existence of a code line** — per §1.4, a check that exists but is placed on a path that can be avoided (an optional activity, rather than the main entry point) effectively provides no real protection.

3. **Always proceed to MASTG-TEST-0382 for confirmation** — the static finding here only identifies a **candidate mechanism**; whether that mechanism actually blocks access when actively tested (including the backgrounding/cancel scenarios) can only be confirmed through dynamic testing.

4. **Severity is modulated as follows:**

   | Factor | Severity |
   |---|---|
   | No enforcement mechanism at all | **High** (if the app has a history of client-side vulnerabilities requiring mandatory patches) |
   | A mechanism exists but is a dismissible dialog | **High** (classified as equivalent to none, per §1.3) |
   | A mechanism exists, non-dismissible, but the call-graph position can be avoided | **Medium** |
   | All PASS criteria are fully met | **Not a finding** (pending dynamic confirmation via MASTG-TEST-0382) |

5. **Document:** the location of the enforcement API code, the type of mechanism (Play In-App Updates/backend-gated), the result of the call-graph analysis, and the dismissible/non-dismissible classification of the UI found.

---

## 4. Recommendations

The recommendations are identical to its dynamic counterpart (MASTG-TEST-0382) — see that document for full implementation details (handling `DEVELOPER_TRIGGERED_UPDATE_IN_PROGRESS`, dual client+backend enforcement). Additional points specific to static-analysis findings:

### Remediation Checklist

- [ ] Enforcement API references are found, and their position is verified to be at an unavoidable entry point
- [ ] The update UI for mandatory cases is confirmed to be non-dismissible (no "Later"/"Skip" button, cannot be closed via the back button)
- [ ] Static analysis results are confirmed with dynamic testing via MASTG-TEST-0382 before being treated as final

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0392 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-CODE/MASTG-TEST-0392.md)
- [MASTG-TEST-0382: Runtime Use of Enforced Updating APIs (dynamic counterpart document in this research series)](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0382/)
- [MASTG-KNOW-0023: Enforced Updating](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0023/)

### 5.2 Official Documentation

- [Android Developers: In-App Updates](https://developer.android.com/guide/playcore/in-app-updates)

### 5.3 Tool Documentation

- [Androguard](https://github.com/androguard/androguard)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)

---

*This document was prepared based on official OWASP MASTG content (`tests-beta/android/MASVS-CODE/MASTG-TEST-0392.md`, `MASTG-KNOW-0023`), supplemented by an in-depth cross-reference with the MASTG-TEST-0382 document (its dynamic counterpart) in this research series, which already covers the full context of why enforced updating matters and the three specific enforcement failure scenarios. The most important and firmest methodological nuance of this test: the official evaluation explicitly classifies an implementation consisting of a **dismissible dialog** for a mandatory update as "implemented incorrectly" — equivalent to having no enforcement mechanism at all in terms of final outcome, not merely a minor weakness. This requires the tester to explicitly assess the quality of the enforcement UI/UX, rather than simply confirming the presence of API references in the code.*
