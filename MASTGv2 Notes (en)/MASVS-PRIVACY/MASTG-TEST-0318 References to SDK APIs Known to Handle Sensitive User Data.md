# MASTG-TEST-0318 References to SDK APIs Known to Handle Sensitive User Data

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0318 |
| **Platform** | Android |
| **MASVS Category** | MASVS-PRIVACY |
| **Weakness** | MASWE-0073 — *Inadequate Data Collection Declarations* |
| **Test Type** | Static, Code |
| **Related Techniques** | MASTG-TECH-0013, MASTG-TECH-0014 |
| **Related Tests** | **MASTG-TEST-0319** — the counterpart that **confirms** real data is actually sent (this test only detects **potential**, see §1.3); **MASTG-TEST-0206** (Undeclared PII in Network Traffic Capture) in this research series also refers back to this test as a complement to the static analysis |
| **Related Demo** | — (none) |
| **Official Rule** | — (no generic rule exists; every third-party SDK has different API entry points, which demands custom rules per SDK, see §3.2) |
| **Related CWE** | CWE-200, CWE-359 |

---

## 1. Explanation

### 1.1 Testing Objective

Quote from the official MASTG overview:

> *"This test verifies whether an app uses SDK (third-party library) APIs known to handle sensitive user data (e.g., as defined in Google Play's Data safety section or the relevant privacy regulations)."*

This test targets a risk whose **source is not the application's own code**, but rather **third-party SDKs** (analytics, advertising, crash reporting, etc.) bundled into the application — specifically, the **entry point** APIs of those SDKs that are **known, per the SDK's own documentation**, to be designed to collect user data. This is an important distinction from many other tests in this research series that focus on code written directly by the app developer — here, the developer **may not write any data-collection logic directly**, yet they remain regulatorily responsible the moment they **call** an SDK API that triggers such collection.

### 1.2 A Unique Methodological Prerequisite: Understanding the "Dictionary" of APIs per SDK

Unlike most other tests that target a uniform, standard Android/Java API, this test demands **SDK-specific understanding** — every third-party library has a **different set of data-collection entry-point APIs**, and the tester must **review that library's documentation/codebase** before being able to search for patterns effectively:

> *"As a prerequisite, we need to identify the SDK API methods it uses as entry points for data collection by reviewing the library's documentation or codebase."*

The concrete example given by the official overview — **Firebase Analytics** (the `FirebaseAnalytics` class) — provides several data-collection entry points with different functions:

| Method | Function | Type of Data Potentially Collected |
|---|---|---|
| `setUserId(String)` | Sets a unique user identifier for cross-session tracking | User identifier (could be PII if an email/phone number is used) |
| `setUserProperty(String, String)` | Sets a custom user attribute (e.g., customer tier, preferences) | User profile attributes, potentially sensitive depending on the name/value sent |
| `logEvent(String, Bundle)` | Logs a custom event along with additional parameters | The `Bundle` content can carry **anything** the developer passes in, including sensitive data if used carelessly |

This confirms that this test **cannot be run generically** the way other tests targeting standard Android APIs can — the tester needs to build a **reference list** of API entry points for **every SDK** bundled into the target application, based on each SDK's own official documentation.

### 1.3 A Crucial Nuance: "Potential" vs. "Confirmed" — Relationship to MASTG-TEST-0319

This is the most important methodological distinction, explicitly stated by the official overview in very clear terms:

> *"Note: This test detects only **potential** sensitive user data handling. For **confirming** that actual user data are being shared, please refer to MASTG-TEST-0319."*

This is consistent with the recurring "static finds candidates, dynamic confirms" pattern already discussed for various other test pairs in this research series — but here the nuance is **sharper**: merely **finding a call** to `setUserId()`/`logEvent()` in the code **does not automatically mean sensitive data is actually sent**. A developer could call `logEvent("button_clicked", bundle)` with a `Bundle` that **contains only the button name** (non-sensitive data) — the API call is detected, but **no** sensitive data is actually flowing. **Genuine confirmation** — whether the value passed to that API parameter is actually sensitive data — requires **MASTG-TEST-0319** (parameter value analysis) and/or correlation with an actual network capture (refer to the **MASTG-TEST-0206** document in this research series, which explicitly refers back to this test as a complementary static-analysis component).

### 1.4 Regulatory Context: Google Play Data Safety Section

This test has a **concrete regulatory/marketplace anchor** — the official overview refers directly to the **Google Play Data Safety section**, the mandatory declaration form developers must fill out when publishing an app to the Play Store, explaining **what kinds of data** the app collects/shares and **for what purpose**. This test fundamentally helps **verify the consistency** between what the application code **actually does** (via SDK calls) and what the developer **declares** in that form — a compliance gap that, based on independent research, turns out to be **extremely widespread** across the real Play Store ecosystem.

### 1.5 The Real Scale of the Problem: Mozilla's Research on Data Safety Label Accuracy

This is the strongest evidence of the **real-world scale** of the problem this test attempts to address — independent research by the **Mozilla Foundation** found:

> *"Mozilla Foundation accused Google of incorrectly labelling apps as 'Data Safe' as much as **80 percent** of the time in its Play digital bazaar, with **TikTok, Facebook and Twitter** among the misdescribed software."*

The fact that apps from the **largest and most scrutinized** tech companies (TikTok, Facebook, Twitter) are among the findings of label mismatches shows that the **gap between declaration and actual code behavior** is a **systemic** problem, not a minor oversight limited to small app developers lacking compliance resources. The research also highlighted definitional loopholes that are deliberately exploited:

> *"Data sharing with 'service providers' doesn't have to be reported, and Google has narrow definitions for the 'collection' and 'sharing' of data, which makes it possible for developers to conceal details and mislead users."*

### 1.6 Google's Real Enforcement Mechanism

It is important to note that this is not merely a reputational issue without real consequences — Google has active detection and enforcement mechanisms:

> *"Google detects user data transmitted off device that developers have not disclosed in their app's Data safety form as user data collected... store teams can force edits, require updates, or remove apps whose labels are persistently inaccurate."*

This means findings from this test **carry real business implications** beyond abstract security risk — a mismatch between detected SDK calls and a published Data Safety declaration could trigger **direct enforcement from Google** (blocking updates, removing the app from the Play Store), making this test relevant not only to security teams but also to legal/compliance and product teams.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **jadx** | Decompiles DEX → Java for searching patterns of SDK API calls |
| **grep / ripgrep** | Searches for SDK-specific API patterns (built from documentation research, §1.2) |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **Exodus Privacy** | A database of known SDK trackers — provides an initial list of detected analytics/ad SDKs in the APK without needing to build a reference list from scratch for commonly known SDKs |
| **AppBrain / ClassyShark** | Identifies bundled third-party libraries based on package structure in the APK |
| **CodeQL** | Traces the correlation between SDK API calls and the data sources passed to them (bridging to MASTG-TEST-0319) |
| **MobSF** | Automated reports that sometimes identify known tracker SDKs along with their APIs |

### 2.3 Environment Prerequisites

- **No device/root required** for the core static analysis.
- **SDK documentation research is a mandatory prerequisite** per §1.2 — without knowing the specific API entry points of the SDKs used by the target app, pattern searching cannot be done effectively.
- **Obtain a copy of the target app's Data Safety form** from its Play Store listing (if publicly available) to verify consistency per §1.4.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0013** to reverse engineer the application.
2. Use **MASTG-TECH-0014** to search for the relevant APIs.

### 3.2 Method A — Identify SDKs and Build a Reference API List *(mandatory prerequisite step)*

```bash
jadx -d ./decompiled ./target-app.apk

# Identify bundled third-party SDK packages
find ./decompiled/sources -maxdepth 3 -type d | grep -vE "com/example/target|android/|androidx/"
```

For each identified SDK (e.g., `com/google/firebase/analytics`, `com/facebook/appevents`, `com/adjust/sdk`), **review that SDK's official documentation** to build a reference list of relevant data-collection entry-point APIs — an example for Firebase Analytics is already given in §1.2.

### 3.3 Method B — grep/ripgrep Based on the Reference List

```bash
D=./decompiled/sources

# Example for Firebase Analytics (adjust for other identified SDKs)
rg -n 'FirebaseAnalytics.*setUserId\(|FirebaseAnalytics.*setUserProperty\(|FirebaseAnalytics.*logEvent\(' $D

# Example for the Facebook SDK
rg -n 'AppEventsLogger.*setUserID\(|AppEventsLogger.*logEvent\(' $D

# Other common patterns that frequently serve as entry points for analytics/ad SDKs
rg -n '\.setUserId\(|\.setUserProperty\(|\.logEvent\(|\.identify\(|\.trackEvent\(' $D
```

### 3.4 Method C — Exodus Privacy for Identifying Known SDKs

```bash
# Via web upload or the exodus-standalone CLI
exodus-standalone target-app.apk
```

The Exodus results provide a list of trackers already identified in their database, speeding up step 3.2 for commonly known SDKs without needing documentation research from scratch.

### 3.5 Method D — CodeQL for Correlating with Data Sources (Bridging to MASTG-TEST-0319)

```ql
import java

class SdkDataCollectionCall extends MethodAccess {
  SdkDataCollectionCall() {
    this.getMethod().hasName(["setUserId", "setUserProperty", "logEvent"]) and
    this.getMethod().getDeclaringType().getName().matches("%Analytics%")
  }
}

from SdkDataCollectionCall call
select call, call.getAnArgument(), "SDK data-collection API call found — proceed to MASTG-TEST-0319 to confirm whether the passed value is actually sensitive data"
```

### 3.6 Method E — Verifying Consistency with the Data Safety Section

```
Manual procedure:
1. Download/copy the target app's Data Safety form from its public Play Store listing
2. Compare the DECLARED data categories against the SDK APIs DETECTED via Method B/C
3. Flag inconsistencies: APIs detected collecting a data category NOT mentioned in the declaration
```

### 3.7 Method Comparison: When to Use Which

| Method | Tool | When to Use |
|---|---|---|
| **A** | SDK identification + documentation research | **Mandatory first step** before other methods |
| **B** | grep based on the reference list | Main baseline |
| **C** | Exodus Privacy | Speeds things up for commonly known SDKs |
| **D** | CodeQL | Bridges to MASTG-TEST-0319 |
| **E** | Data Safety verification | Regulatory/compliance context, relevant for legal teams |

**Minimum combination I recommend:** **A (mandatory) → B/C (detection) → E (compliance context)**, followed by **MASTG-TEST-0319** to confirm actual data before concluding a final finding.

---

### 3.8 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Observation:** *"The output should list the locations where SDK methods are called."*
>
> **Evaluation:** *"The test case fails if you can find the use of these SDK methods in the app code, indicating that the app is sharing sensitive user data with the third-party SDK."*

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition |
|---|---|
| F1 | A call to an SDK API entry point known to handle sensitive data is found (per the reference list built in §1.2) |
| F2 | An inconsistency is detected between the API called and the app's Data Safety declaration (Method E) — the data category detected from the code is **not** mentioned in the public declaration form |

**Example evidence (illustrative — MASTG does not yet provide an official demo for this test):**

```java
// Found in com/example/target/analytics/UserTracker.java
FirebaseAnalytics analytics = FirebaseAnalytics.getInstance(context);
analytics.setUserId(user.getEmail());  // User's email passed as the User ID
```

Interpretation: `setUserId()` is called with the **user's email** as the value — an SDK data-collection entry point is confirmed to be used to handle data that is clearly potential PII. **FAIL** (strong candidate; full confirmation requires MASTG-TEST-0319 to verify the parameter value at runtime).

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition |
|---|---|
| P1 | **No** calls to known SDK data-collection entry-point APIs from the relevant reference list are found |
| P2 | An API entry point is found, but the value passed is verified (via manual review/MASTG-TEST-0319) to **not** be sensitive data (e.g., `logEvent("button_clicked")` with no sensitive parameters) |
| P3 | The app's Data Safety declaration is **consistent** with the APIs detected in the code |

---

#### ⚠️ Important Notes on Assessment

1. **This test demands SDK-specific research, not a generic pattern search** — without building a reference list of API entry points for the specific SDKs used by the target app, the search results will be incomplete/irrelevant.

2. **"API call found" ≠ "confirmed that sensitive data is actually sent"** — per §1.3, this only identifies a **candidate**; always proceed to MASTG-TEST-0319 before concluding a confident final FAIL.

3. **Leverage the regulatory context to raise urgency** — a mismatch with the Data Safety section carries real business consequences (Google enforcement), not just abstract security risk; this is a strong argument for remediation priority in the eyes of product/legal teams.

4. **This problem is systemic in scale** (§1.5) — even giant applications (TikTok, Facebook, Twitter) were found to be inconsistent; do not assume an app from a large company is automatically correct.

5. **Severity is modulated as follows:**

   | Factor | Severity |
   |---|---|
   | API called with a value that is clearly PII (email, phone number) and not declared | **High** (regulatory + privacy risk) |
   | API called but the value is not sensitive, or already correctly declared | **Not a finding**/Informational |

6. **Document:** the identified SDKs, the API entry points called along with their code locations, parameter values (if verifiable), and the result of comparing them against the Data Safety declaration.

---

## 4. Recommendations

### 4.1 Audit and Minimize Data-Collection API Calls

```java
// BEFORE — sending the email as the User ID
analytics.setUserId(user.getEmail());

// AFTER — use a hashed/pseudonymized identifier instead of raw PII
analytics.setUserId(hashUserId(user.getId()));
```

### 4.2 Ensure the Data Safety Section Declaration Is Accurate and Up to Date

Make the SDK API audit (the result of this test) a **routine input** for updating the Data Safety form whenever a new SDK is added or an API call changes — not something filled out only once at first release and then left stale.

### 4.3 Remediation Checklist

- [ ] All bundled third-party SDKs have been identified and their data-collection entry-point APIs researched
- [ ] API calls carrying sensitive data have been minimized/anonymized
- [ ] The Data Safety section declaration has been verified to be consistent with the code audit findings
- [ ] Results have been correlated with MASTG-TEST-0319 to confirm actual data
- [ ] **Re-verify:** re-run MASTG-TEST-0318 whenever a new third-party SDK is added

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0318: References to SDK APIs Known to Handle Sensitive User Data](https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/MASTG-TEST-0318/)
- [MASTG-TEST-0319](https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/MASTG-TEST-0319/) — confirmation counterpart
- [MASTG-TEST-0206: Undeclared PII in Network Traffic Capture](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0206/)
- [MASWE-0073: Inadequate Data Collection Declarations](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0073/)

### 5.2 Official Documentation

- [Google Play Console — Provide Information for Data Safety Section](https://support.google.com/googleplay/android-developer/answer/10787469?hl=en)
- [Android Developers Blog — New Safety Section in Google Play](https://android-developers.googleblog.com/2021/05/new-safety-section-in-google-play-will.html)
- [Firebase — Google Analytics for Firebase Documentation](https://firebase.google.com/docs/analytics)

### 5.3 Research and Real-World Cases

- [Android Police — Mozilla: Google Play Store's Fancy Data Safety Labels Are Essentially Worthless](https://www.androidpolice.com/mozilla-google-play-store-data-privacy-labels-misleading/)
- [The Register — Mozilla Says 80 Percent of Google Play's App Safety Labels Are Inaccurate](https://forums.theregister.com/forum/all/2023/02/24/mozilla_says_safety_labels_on/)
- [GitHub commons-app/apps-android-commons#5708 — App Rejected by Google Play Due to Data Safety Section](https://github.com/commons-app/apps-android-commons/issues/5708)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [CWE-359: Exposure of Private Personal Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/359.html)

### 5.4 Tool Documentation

- [Exodus Privacy](https://exodus-privacy.eu.org/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)

---

*This document was compiled based on OWASP MASTG (latest release as of September 2026), official Google Play Console documentation, and Mozilla Foundation research on Data Safety label accuracy, which revealed the systemic scale of the problem (80% inconsistency, including giant apps such as TikTok, Facebook, Twitter). The most important methodological nuance: this test demands SDK-specific documentation research as a prerequisite (not a generic pattern search), and an "API call found" result only identifies **potential**, not **confirmation** — full certainty requires proceeding to MASTG-TEST-0319 to verify the actual parameter values.*
