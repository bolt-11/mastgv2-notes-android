# MASTG-TEST-0340 References to Overlay Attack Protections

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0340 |
| **Platform** | Android |
| **MASVS Category** | MASVS-PLATFORM |
| **Weakness** | MASWE-0036 |
| **Test Type** | Static, Code |
| **Related API** | `onFilterTouchEventForSecurity`, `setFilterTouchesWhenObscured`, `FLAG_WINDOW_IS_OBSCURED`, `FLAG_WINDOW_IS_PARTIALLY_OBSCURED` |
| **Related Techniques** | MASTG-TECH-0013, MASTG-TECH-0014, MASTG-TECH-0117 (Obtain Manifest), MASTG-TECH-0150 (Obtain targetSdkVersion), MASTG-TECH-0126 (Obtain Permissions) |
| **Related Knowledge** | MASTG-KNOW-0022 (Overlay Attacks) |
| **Related Best Practice** | MASTG-BEST-0040 (Preventing Overlay Attacks) |
| **Official Rule** | `mastg-android-overlay-protection.yml` — 7 complete patterns, all severity INFO, see §1.4 |

---

## 1. Explanation

### 1.1 Testing Objective

Official MASTG overview excerpt:

> *"Overlay attacks (also known as tapjacking) allow malicious apps to place deceptive UI elements over a legitimate app's interface, potentially tricking users into performing unintended actions such as granting permissions, revealing credentials, or authorizing payments."*

Just like MASTG-TEST-0324 (root detection), this is a "presence-based" test — the focus is on **whether a protection mechanism exists**, not on targeting a dangerous code pattern.

### 1.2 Historical Evolution of Overlay Attacks: Three Different Generations of Attacks

MASTG-KNOW-0022 explains that "overlay attack" is not a single type of attack, but rather **three distinct generations of techniques**, each targeting a different platform weakness throughout Android's history:

| Generation | API Level Range | Mechanism |
|---|---|---|
| **Classic tapjacking** | Android 6.0 (API 23) and below | Exploiting the screen overlay feature to listen for taps and intercept information passed to the activity underneath |
| **Cloak & Dagger** | Android 5.0–7.1 (API 21-25) | Abusing the combination of `SYSTEM_ALERT_WINDOW` ("draw on top") **and** `BIND_ACCESSIBILITY_SERVICE` — both permissions were **granted automatically without notification** when an app was installed from the Play Store within that API range |
| **Toast Overlay** | Up to Android 8.0 (API 26) | A variant that **requires no permission at all** from the user, patched via CVE-2017-0752 |

The significance of the Cloak & Dagger point is very important for threat context: *"When apps were installed from the Play Store, users did not need to explicitly grant these permissions and were not even notified."* This means during that era, users **had no way to realize** that a malicious application had obtained the capability to draw over other applications — no permission dialog appeared at all.

### 1.3 Real-World Evidence: Banking Malware Explicitly Cited by MASTG Itself

Unlike many other tests where I needed external research to find real-world evidence, MASTG-KNOW-0022 **itself** already explicitly lists the names of real malware that exploits this vulnerability class, specifically targeting the banking sector:

> *"Over the years, malware such as MazorBot, BankBot, and MysteryBot have exploited screen overlays to target business-critical applications, particularly in the banking sector."*

Large-scale academic research on market-level overlay malware detection also empirically reinforces the scale of this problem, showing that this is not a niche threat discussed only in research papers without real-world impact, but rather a sufficiently common malware category to be studied at large scale across the entire ecosystem of apps in circulation.

### 1.4 Analysis of the Official Rule: A Complete 1-to-1 Mapping, All Severity INFO

Unlike many other rules in this research series that have a significant coverage gap, the `mastg-android-overlay-protection.yml` rule shows **very good design completeness** — every API/attribute mentioned in the official overview (§1.1's list of five mechanisms) has its own separate Semgrep pattern:

| Pattern ID | Targets |
|---|---|
| `-setfiltertoucheswhenobscured` | `setFilterTouchesWhenObscured()` |
| `-onfiltertoucheventforsecurity` | Overriding `onFilterTouchEventForSecurity()` |
| `-flag-window-is-obscured` | Checking `FLAG_WINDOW_IS_OBSCURED` (2 bitwise expression variations) |
| `-flag-window-is-partially-obscured` | Checking `FLAG_WINDOW_IS_PARTIALLY_OBSCURED` (2 variations) |
| `-xml-attribute` | The XML attribute `android:filterTouchesWhenObscured="true"` — **the only rule in this set that targets the XML language**, not Java |
| `-sethideoverlaywindows` | `setHideOverlayWindows()` |
| `-hide-overlay-windows-permission` | Declaration of the `HIDE_OVERLAY_WINDOWS` permission in the manifest |

Analytical note: all seven of these patterns are **consistently given severity `INFO`**, in line with this test's "presence-based" nature — the presence of these patterns is not an indication of danger, but rather a **positive signal** that must be recorded as evidence of mitigation, similar to the severity pattern of the root detection rule (TEST-0324). One design strength worth noting: separating the XML pattern from the Java pattern shows awareness that `android:filterTouchesWhenObscured` can be configured in **two different places** (static layout XML or dynamic Java code) — reflecting a deep understanding of how real Android developers actually write code.

### 1.5 The `targetSdkVersion` Nuance: Why Official Step 4 Explicitly Requests This Information

Note that the official steps (§ Steps) explicitly request `targetSdkVersion` extraction (MASTG-TECH-0150) as part of the observation — this is not a coincidence. The official FAIL criteria has a clause that is **conditional on the API version**:

> *"The app targets API level 31 or higher but does not use `setHideOverlayWindows(true)` and declare the `HIDE_OVERLAY_WINDOWS` permission."*

This is consistent with a recurring pattern in this research series (e.g., TEST-0285, TEST-0315) where `targetSdkVersion`/`minSdkVersion` becomes the determining parameter for **whether a mechanism is even available or technically relevant** — `setHideOverlayWindows()` **does not exist** as an API before API level 31, so it makes no sense to demand its presence on an application targeting below that. However, for applications that **already** target API 31+, the absence of this strongest mechanism (full prevention, not merely touch filtering) becomes a finding worth noting.

### 1.6 Robustness Hierarchy: Prevention vs Detection, Not All Mechanisms Are Equal

MASTG-BEST-0040 explicitly orders the mechanisms from **most robust to weakest** — an important nuance that differentiates the quality evaluation of a PASS finding, not just a binary present/absent:

> *"The following approaches are listed from most robust to least robust: 1. HIDE_OVERLAY_WINDOWS + setHideOverlayWindows(true) — most robust, prevents overlays entirely. 2. filterTouchesWhenObscured — filters touch events when obscured. 3. onFilterTouchEventForSecurity — custom policy, granular."*

And separately, the two **detection** mechanisms (`FLAG_WINDOW_IS_OBSCURED`/`PARTIALLY_OBSCURED`) are noted as a different category — they **only detect**, not automatically prevent:

> *"These mechanisms detect when overlays are present but do not automatically prevent them. They allow the app to respond accordingly... Note that this approach requires custom implementation to decide how to handle detected overlays."*

An important implication: an application that **only** checks a detection flag without the correct response logic (e.g., checking the flag but continuing a sensitive action regardless of the result) technically "has an API reference" but **is not actually protected** — this once again confirms this test's purely `type: [static, code]` nature, which **does not verify the effectiveness of the logic**, only the presence of a reference.

### 1.7 Honestly Acknowledged Limitation: Not All Attacks Can Be Mitigated at the Application Level

MASTG-BEST-0040 provides an important acknowledgment of the limits of application-level control:

> *"Some attacks, particularly those exploiting system-level vulnerabilities (for example, Toast Overlay on Android versions before 8.0), cannot be fully mitigated at the app level."*

And a note about the risk of over-engineering:

> *"Applying touch filtering too broadly may impact legitimate use cases where overlays are expected (for example, system dialogs, accessibility features)."*

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **jadx** | DEX → Java decompilation and layout XML extraction (MASTG-TECH-0013) |
| **Semgrep** + official rule `mastg-android-overlay-protection.yml` | Detecting all 7 API/attribute patterns (MASTG-TECH-0014) |
| **aapt / Androguard** | Extraction of `AndroidManifest.xml` for `targetSdkVersion` and permissions (MASTG-TECH-0117, MASTG-TECH-0150, MASTG-TECH-0126) |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **grep/ripgrep** | Additional verification of patterns possibly written with expression variations outside Semgrep's coverage |
| **MobSF** | Automated reports that sometimes include `targetSdkVersion` and permission extraction as part of the summary |
| **Overlay simulation application (for manual dynamic verification)** | Creating a real overlay on a test device to empirically confirm whether sensitive UI is genuinely protected |

### 2.3 Environment Prerequisites

- No device/root required for static analysis.
- For (optional) dynamic verification, a test device capable of running a simple overlay application (`SYSTEM_ALERT_WINDOW`) is needed to test the target application's behavior directly.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0013** to reverse engineer the application.
2. Use **MASTG-TECH-0014** to find relevant APIs.
3. Use **MASTG-TECH-0117** to obtain `AndroidManifest.xml`.
4. Use **MASTG-TECH-0150** to obtain `targetSdkVersion`.
5. Use **MASTG-TECH-0126** to obtain the relevant permissions.

### 3.2 Method A — Semgrep with the Official Rule (Full Coverage)

```bash
semgrep --config mastg-android-overlay-protection.yml ./decompiled/sources ./resources/layout
```

### 3.3 Method B — Manifest Extraction for targetSdkVersion and Permissions

```bash
aapt dump badging app.apk | grep -E 'targetSdkVersion|HIDE_OVERLAY_WINDOWS'
```

### 3.4 Method C — grep/ripgrep for Additional Verification

```bash
D=./decompiled/sources
L=./resources/layout

rg -n 'setFilterTouchesWhenObscured|onFilterTouchEventForSecurity|setHideOverlayWindows' $D
rg -n 'filterTouchesWhenObscured' $L
```

### 3.5 Method D — Dynamic Verification with a Simulated Overlay

```
Manual procedure:
1. Build/install a simple application that requests SYSTEM_ALERT_WINDOW and draws a transparent overlay
2. Run the target application, navigate to a sensitive screen (login, payment confirmation)
3. Activate the overlay from the simulation application on top of the target screen
4. Try interacting with the sensitive UI element — observe whether the tap is blocked/filtered (PASS) or passed through normally (FAIL)
```

This gives the most conclusive evidence about real-world effectiveness, complementing the limitation noted in §1.6 that pure static analysis does not verify response logic.

### 3.6 Method Comparison: When to Use Which

| Method | Tool | When to Use |
|---|---|---|
| **A** | Semgrep + official rule | Baseline — its coverage is already complete for this test |
| **B** | aapt/manifest | Mandatory — determines whether the API 31+ criterion applies |
| **C** | grep/ripgrep | Supplementary verification |
| **D** | Dynamic simulation | Proof of real effectiveness, closing the gap of pure static analysis |

**Minimum combination I recommend:** **A + B (mandatory)**, with **D** strongly recommended for sensitive UI in financial-category applications given the real-world history of banking malware (§1.3).

---

### 3.7 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Evaluation:** *"The test fails if the app handles sensitive user interactions (such as login, payment confirmation, permission requests, or security settings) and does not implement any overlay attack protections on those sensitive UI elements."*

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition |
|---|---|
| F1 | No `setFilterTouchesWhenObscured(true)`/`android:filterTouchesWhenObscured="true"` exists on sensitive UI |
| F2 | No `onFilterTouchEventForSecurity` override exists |
| F3 | No check for `FLAG_WINDOW_IS_OBSCURED`/`PARTIALLY_OBSCURED` exists in the sensitive UI's touch handler |
| F4 | `targetSdkVersion` ≥ 31 **but** does not use `setHideOverlayWindows(true)` + the `HIDE_OVERLAY_WINDOWS` permission |

**Example evidence:**

```xml
<!-- layout/activity_payment_confirm.xml, without filterTouchesWhenObscured -->
<Button
    android:id="@+id/btn_confirm_payment"
    android:text="Confirm Payment" />
```

```java
// setFilterTouchesWhenObscured/onFilterTouchEventForSecurity not found anywhere in the codebase
// targetSdkVersion = 33, no setHideOverlayWindows/HIDE_OVERLAY_WINDOWS
```

Interpretation: the payment confirmation button (very sensitive UI) has no overlay protection whatsoever, and the application targets API 31+ without taking advantage of the strongest prevention mechanism available. **FAIL**.

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition |
|---|---|
| P1 | Sensitive UI uses at least one mechanism from §1.6, **prioritizing** a prevention mechanism (`setHideOverlayWindows` for API 31+) over mere detection |
| P2 | If only a detection mechanism is used (`FLAG_WINDOW_IS_OBSCURED`), there is clear response logic (rejecting input, showing a warning) — not just reading the flag without any action |

---

#### ⚠️ Important Notes on Evaluation

1. **Always check `targetSdkVersion` before assessing criterion F4** — it makes no sense to demand `setHideOverlayWindows` on an application targeting below API 31 (that API does not yet exist there).

2. **Assess quality, not just presence** — per the hierarchy in §1.6, a PASS with `setHideOverlayWindows` is far stronger than a PASS that only relies on checking a detection flag without clear response logic; note this quality difference in the report even though both are technically "PASS."

3. **Consider dynamic verification for financial-category UI** — given the real history of banking malware (MazorBot, BankBot, MysteryBot) that specifically targets this category (§1.3), a direct overlay simulation (Method D) gives far higher confidence than merely finding an API reference in code.

4. **Do not overly aggressively recommend filtering everywhere** — per MASTG-BEST-0040's warning, apply it only on genuinely sensitive UI; excessive application could disrupt legitimate scenarios (system dialogs, accessibility features).

5. **Severity is modulated:**

   | Factor | Severity |
   |---|---|
   | No protection whatsoever on financial/credential/critical-permission UI | **High** |
   | Only a detection mechanism without clear response logic | **Medium** |
   | A strong prevention mechanism (`setHideOverlayWindows`) correctly applied | **Not a finding** |

6. **Document:** the location of the sensitive UI checked, the mechanism found (or not found), `targetSdkVersion`, and the dynamic verification results if performed.

---

## 4. Recommendations

### 4.1 Prioritize Prevention for API 31+

```kotlin
// On an Activity with sensitive UI, targetSdkVersion >= 31
override fun onResume() {
    super.onResume()
    window.setHideOverlayWindows(true)
}
```

```xml
<uses-permission android:name="android.permission.HIDE_OVERLAY_WINDOWS" />
```

### 4.2 Apply Touch Filtering for Backward Compatibility

```xml
<Button
    android:id="@+id/btn_confirm_payment"
    android:filterTouchesWhenObscured="true"
    android:text="Confirm Payment" />
```

### 4.3 Remediation Checklist

- [ ] All sensitive UI (login, payment, permissions, security settings) has at least one overlay protection mechanism
- [ ] Applications with `targetSdkVersion` ≥ 31 take advantage of `setHideOverlayWindows` + the related permission
- [ ] The detection mechanism (if used) is accompanied by clear response logic, not merely reading the flag
- [ ] Dynamically verified with a real overlay simulation for financial-category UI
- [ ] Filtering is not applied excessively such that it disrupts legitimate scenarios

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0340 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0340.md)
- [MASTG-KNOW-0022: Overlay Attacks](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0022/)
- [MASTG-BEST-0040: Preventing Overlay Attacks](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0040.md)

### 5.2 Official Android Documentation

- [Android Developers: Tapjacking](https://developer.android.com/privacy-and-security/risks/tapjacking)
- [Window#setHideOverlayWindows](https://developer.android.com/reference/android/view/Window#setHideOverlayWindows(boolean))

### 5.3 Research and Real-World Cases

- [Cloak & Dagger — Official Research Site](https://cloak-and-dagger.org/)
- [Black Hat US-17: Cloak and Dagger — From Two Permissions to Complete Control of the UI Feedback Loop](https://www.blackhat.com/docs/us-17/thursday/us-17-Fratantonio-Cloak-And-Dagger-From-Two-Permissions-To-Complete-Control-Of-The-UI-Feedback-Loop-wp.pdf)
- [Unit 42: Android Toast Overlay Attack — Cloak and Dagger with No Permissions (CVE-2017-0752)](https://unit42.paloaltonetworks.com/unit42-android-toast-overlay-attack-cloak-and-dagger-with-no-permissions/)
- [Understanding and Detecting Overlay-based Android Malware at Market Scales](https://tianyin.github.io/pub/overlay.pdf)

### 5.4 Tool Documentation

- [Semgrep Documentation](https://semgrep.dev/docs/)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)

---

*This document is compiled based on official OWASP MASTG content (`tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0340.md`, `MASTG-KNOW-0022`, `MASTG-BEST-0040`), an analysis of the `mastg-android-overlay-protection.yml` rule that shows complete 1-to-1 design coverage against every API mentioned in the overview, and Black Hat/academic research on Cloak & Dagger and Toast Overlay. MASTG-KNOW-0022 itself explicitly cites real banking malware (MazorBot, BankBot, MysteryBot) that exploits this vulnerability class. The most important methodological nuance: this test is "presence-based" like root detection (TEST-0324) — all rule patterns are given severity INFO, and PASS quality evaluation must consider the robustness hierarchy (prevention > detection) as well as the dependence of the FAIL criteria on `targetSdkVersion` for the `setHideOverlayWindows` mechanism, which is only available since API 31.*
