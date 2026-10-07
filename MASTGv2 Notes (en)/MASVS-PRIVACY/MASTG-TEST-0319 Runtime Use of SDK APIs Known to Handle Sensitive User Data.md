# MASTG-TEST-0319 Runtime Use of SDK APIs Known to Handle Sensitive User Data

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0319 |
| **Platform** | Android |
| **MASVS Category** | MASVS-PRIVACY |
| **Weakness** | MASWE-0073 — *Inadequate Data Collection Declarations* |
| **Test Type** | Dynamic, Hooks |
| **Related Technique** | MASTG-TECH-0005 (Installing Apps), MASTG-TECH-0043 (Method Hooking) |
| **Prerequisite** | `identify-sensitive-data` — a definition of "sensitive data" must be established before testing begins |
| **Related Tests** | **MASTG-TEST-0318** — the **static** counterpart that detects **potential** (this test is the **dynamic** pair that **confirms**, see §1.1) |

> **Source verification note:** The first WebFetch request to the official page for this test initially returned content that was **incorrect/inconsistent** (citing MASWE-0069 and a generic "Runtime Test" type, not matching the pattern of its counterpart MASTG-TEST-0318). After direct verification against the official `OWASP/mastg` source on GitHub — this file was found to reside in the **`tests-beta/android/MASVS-PRIVACY/`** directory (not yet promoted to the final `tests/`) — the correct content was successfully obtained and confirmed: **MASWE-0073** (same as TEST-0318) and type `[dynamic, hooks]`. This document was compiled based on that verified content.

---

## 1. Explanation

### 1.1 Testing Objective and Relationship to MASTG-TEST-0318

Excerpt from the official MASTG overview:

> *"This test is the dynamic counterpart to MASTG-TEST-0318. In this case we will hook any SDK methods known to handle sensitive user data."*

This test is the direct **resolution** of a limitation already explicitly explained in the **MASTG-TEST-0318** document — there, it is stated that static analysis (finding calls to `setUserId()`, `logEvent()`, etc. in code) only identifies **potential**, not **confirmation**, because the actual value of the parameter passed to that API **cannot be determined from source code alone** (for instance, the value comes from user input, a runtime calculation result, or another API's response). This test closes that gap by **hooking the SDK API directly while the application is running** and capturing the **actual argument values** passed — this is what distinguishes "candidate found in code" from "sensitive data confirmed to actually be sent".

### 1.2 Three Required Observation Components: Location, Stack Trace, and Arguments

The official Observation section specifies three layers of information that must be recorded, not just one:

> *"The output should list the locations where SDK methods are called, their stacktrace (call hierarchy leading to the call), and the arguments (values) passed to the SDK method at runtime."*

These three components serve different functions:

| Component | Function |
|---|---|
| **Call location** | Identifies the point in the application code where the SDK is called |
| **Stack trace / call hierarchy** | Shows the **triggering path** — whether the call happens automatically at startup, is triggered by a specific user action (login, checkout, etc.), or is triggered by another SDK in a chain |
| **Arguments (values) at runtime** | **Conclusive evidence** — this is what distinguishes this test from TEST-0318; the actual value passed determines whether truly sensitive data is being sent |

The stack trace is especially important for **root-cause** investigation — if sensitive data is found being sent, the stack trace shows **which code module** triggers that flow, allowing remediation to be precisely targeted rather than guessed at.

### 1.3 Methodological Prerequisite: Defining "Sensitive Data" Before Starting

This test explicitly lists the `identify-sensitive-data` prerequisite — an official MASTG supporting document that asserts the importance of a **clear definition** before testing begins:

> *"A definition of 'sensitive data' must be decided before testing begins because detecting sensitive data leakage without a definition may be impossible."*

That document provides a reference category list for cases without an organizational data classification policy:

- User authentication information (credentials, PINs, etc.)
- PII that could be misused for identity theft (SSN, credit card numbers, bank account numbers, health data)
- Device identifiers that can identify a person
- Highly sensitive data that would cause reputational/financial harm if compromised
- Data whose protection is a legal obligation
- Technical data used to protect other data/systems (e.g. encryption keys)

This is relevant because without an agreed-upon definition, a runtime hooking result (for instance, capturing the string `"premium_tier"` as a `setUserProperty` argument) can be debated as to whether it is "sensitive" or not — defining it up front avoids ambiguity in the final evaluation.

### 1.4 Why the Official Method (Frida/Manual Hooking) Has Real Limitations

The official MASTG approach — manual per-method SDK hooking using Frida — is highly **precise** but requires the tester to already know exactly which API to hook (a research result from TEST-0318 §1.2). Academic research on **system-wide taint-tracking** approaches such as **TaintDroid** demonstrates an alternative approach with broader reach — not merely hooking known APIs, but tracing **data flow** from sensitive sources (contacts, location, IMEI) to any sink (including previously unknown SDKs):

> *"TaintDroid uses taint sources (from which sensitive information like IMEI, text messages, contacts, GPS data, or camera pictures are obtained) and taint sinks (interfaces to the outside world like data networks or SMS) where tainted information is usually not expected to be sent."*

Real findings from TaintDroid research on 30 popular applications give a picture of the scale of this problem in the real world:

> *"Researchers found 68 instances of potential private information misuse, with 18 applications reporting users' locations to remote advertising servers, and seven collecting device ID, phone number, and SIM card serial number — in all, two-thirds of applications used sensitive data suspiciously."*

However, system-wide taint-tracking also has limitations worth noting for testers:

> *"TaintDroid has limitations: taint-based tracking can be easily circumvented using indirect information flows, requires trade-offs between false positives and false negatives, and misses native code."*

This confirms that **targeted manual hooking (the official MASTG method)** and **system-wide taint-tracking (the academic approach)** are two approaches that **complement**, not replace, each other — manual hooking is more precise for already-known SDKs, while taint-tracking is better for discovering **unexpected** data flows to SDKs that have never previously been examined.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core, Per MASTG-TECH-0043)

| Tool | Function |
|---|---|
| **Frida** | Dynamically hooking SDK methods, capturing arguments and stack traces at runtime |
| **ADB** | Installing the APK (MASTG-TECH-0005) and communicating with the device/emulator |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **Objection** | A high-level Frida front end — provides ready-to-use REPL commands for hooking without writing JavaScript scripts from scratch |
| **Frida CodeShare** | A community repository of ready-made Frida scripts, including generic scripts for logging the arguments of any method |
| **TaintDroid** *(academic research, not an actively maintained production tool)* | A system-wide taint-tracking approach to trace sensitive data flows to unexpected sinks, complementing targeted hooking |
| **mitmproxy / Burp Suite** | Correlation with real network traffic — verifying whether the data captured in SDK arguments is actually forwarded out of the device (bridging to MASTG-TEST-0206) |

### 2.3 Environment Prerequisites

- **A rooted device / emulator** with `frida-server` running.
- The target application **must be exercised extensively**, covering as many flows as possible (login, checkout, form filling, etc.) — passive hooking is useless if the triggering feature is never run.
- **A definition of sensitive data has already been agreed upon** before the testing session begins (§1.3).

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0005** to install the application.
2. Use **MASTG-TECH-0043** to hook the relevant API calls.
3. Run/exercise the application extensively to trigger as many flows as possible, and enter sensitive data wherever possible.

### 3.2 Method A — Manual Frida, Direct Hook with Stack Trace

```javascript
Java.perform(function () {
    var FirebaseAnalytics = Java.use("com.google.firebase.analytics.FirebaseAnalytics");

    FirebaseAnalytics.setUserId.overload('java.lang.String').implementation = function (userId) {
        console.log("[setUserId] value: " + userId);
        console.log("[setUserId] stacktrace:\n" +
            Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
        return this.setUserId(userId);
    };

    FirebaseAnalytics.logEvent.overload('java.lang.String', 'android.os.Bundle').implementation = function (name, bundle) {
        console.log("[logEvent] name: " + name + " | bundle: " + bundle.toString());
        return this.logEvent(name, bundle);
    };
});
```

```bash
frida -U -f com.example.targetapp -l hook_sdk.js --no-pause
```

### 3.3 Method B — Objection for Fast Hooking Without a Custom Script

```bash
objection -g com.example.targetapp explore

# Inside the objection REPL
android hooking watch class_method com.google.firebase.analytics.FirebaseAnalytics.setUserId --dump-args
android hooking watch class_method com.google.firebase.analytics.FirebaseAnalytics.logEvent --dump-args
```

This method is much faster for initial exploration compared to writing a custom Frida script, especially when the tester is not yet sure exactly which methods to monitor.

### 3.4 Method C — Correlation with Network Traffic (mitmproxy)

```bash
mitmproxy --mode transparent -p 8080
```

Run in parallel with Frida hooking — compare the argument value captured at the SDK (Method A/B) with the payload actually sent in the network request. This provides **dual evidence**: the SDK is called with sensitive data AND that data actually leaves the device.

### 3.5 Method D — Taint-Tracking Approach (Research Context, Not a Ready-Made Tool)

For cases where the suspected SDK is **not yet known** beforehand (no reference API list from the TEST-0318 §1.2 research), a system-wide taint-tracking approach such as the one pioneered by TaintDroid can conceptually help discover unexpected data flows — though modern production tooling for this approach is limited, the concept can be manually adapted by marking sensitive data sources (e.g. `Location.getLatitude()`) and manually checking the binding process with Frida against all observed network/SDK sinks.

### 3.6 Method Comparison: When to Use Which

| Method | Tool | When to use |
|---|---|---|
| **A** | Manual Frida | SDK & method are already known for certain from TEST-0318, detailed stack trace needed |
| **B** | Objection | Fast exploration, many methods need to be monitored at once |
| **C** | mitmproxy | Final verification — data actually leaves the device |
| **D** | Taint-tracking (conceptual) | Suspected SDK is unknown / deep investigation |

**Minimum recommended combination:** **A or B (core hooking, mandatory) → C (network verification)**. Method D is only relevant for further large-scale investigation.

---

### 3.7 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Evaluation:** *"The test case fails if you can find sensitive user data being passed to these SDK methods in the app code, indicating that the app is sharing sensitive user data with the third-party SDK."*

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition |
|---|---|
| F1 | The Frida hooking results capture a **real argument value** belonging to a sensitive data category (§1.3) passed to an SDK method |
| F2 | The stack trace shows the call occurs **automatically** (e.g. at startup) without any prior explicit consent/opt-in from the user |

**Example evidence (illustrative):**

```
[setUserId] value: budi.santoso@gmail.com
[setUserId] stacktrace:
  at com.example.targetapp.analytics.UserTracker.trackLogin(UserTracker.java:42)
  at com.example.targetapp.auth.LoginActivity.onLoginSuccess(LoginActivity.java:88)
```

Interpretation: the captured argument value is a **real user email**, not merely a variable name in the code as in TEST-0318's static analysis — this is **full confirmation**, not merely a candidate. **FAIL**.

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition |
|---|---|
| P1 | Hooking is run extensively, covering all major flows (login, checkout, profile filling, etc.), and **no** argument value belonging to a sensitive data category is found |
| P2 | The argument passed is already **anonymized/hashed** before being sent to the SDK (e.g. `setUserId(sha256(userId))`) |

---

#### ⚠️ Important Notes on Assessment

1. **This is a CONFIRMATION test, and its results are more definitive than TEST-0318's** — if TEST-0318 found a candidate but TEST-0319 did not capture sensitive data in the runtime argument, prioritize the TEST-0319 result as the final conclusion (provided app exercise coverage is adequate — see point 2).

2. **A PASS result is only valid if exercise coverage is adequate** — if the tester did not get around to triggering a certain flow (e.g. never logged in), a method only called within that flow will never be hooked at all, producing a **false negative**. Explicitly document which flows **were successfully** triggered during the testing session.

3. **The stack trace is forensic information, not just a nice-to-have** — use it to determine whether the call is triggered automatically (riskier, since the user has no opportunity to decline) or triggered by an explicit user action.

4. **Correlate with network verification (Method C) for the strongest evidence** — the argument captured at the SDK level is what is **given to the SDK**, not automatic proof that the data **leaves the device** (the SDK could perform internal filtering/anonymization before transmission — though this rarely happens with commercial analytics SDKs).

5. **Severity is modulated by:**

   | Factor | Severity |
   |---|---|
   | Sensitive data confirmed sent to a third-party SDK without explicit consent | **High** |
   | Data sent but already anonymized/hashed before being forwarded | **Low/Informational** |
   | No sensitive data found after thorough exercise | **Not a finding** |

6. **Document:** the list of methods successfully hooked, the captured argument values (redacted if needed for the report), stack traces, and the application flow triggered to reach each call.

---

## 4. Recommendations

### 4.1 Avoid Passing Raw Data to Third-Party SDKs

```java
// BEFORE — raw email passed as User ID
analytics.setUserId(user.getEmail());

// AFTER — use a hashed identifier, not direct PII
analytics.setUserId(hashUserId(user.getId()));
```

### 4.2 Require Explicit Consent Before Calling SDK Data Collection

Ensure calls to methods like `setUserId`/`logEvent` only occur **after** the user has given explicit consent (opt-in), not automatically at application startup — use the relevant SDK's consent API (e.g. Firebase's `setAnalyticsCollectionEnabled(false)` until consent is obtained).

### 4.3 Remediation Checklist

- [ ] Every SDK method identified in TEST-0318 has been hooked and its runtime argument value verified
- [ ] No raw sensitive data (PII, credentials) is passed without anonymization
- [ ] Data collection API calls are conditioned on explicit user consent
- [ ] Hooking results are correlated with network capture for final verification
- [ ] **Re-verify** after any change to third-party SDK integration

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0319 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-PRIVACY/MASTG-TEST-0319.md)
- [MASTG-TEST-0318: References to SDK APIs Known to Handle Sensitive User Data](https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/MASTG-TEST-0318/)
- [MASTG-TECH-0043: Method Hooking](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/)
- [MASTG-TECH-0005: Installing Apps](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0005/)
- [MASWE-0073: Inadequate Data Collection Declarations](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0073/)
- [Prerequisite: Identifying Sensitive Data](https://github.com/OWASP/mastg/blob/master/prerequisites/identify-sensitive-data.md)

### 5.2 Academic Research

- [TaintDroid: An Information-Flow Tracking System for Realtime Privacy Monitoring on Smartphones (USENIX OSDI 2010)](https://www.usenix.org/legacy/event/osdi10/tech/full_papers/Enck.pdf)
- [TaintDroid (ACM Transactions on Computer Systems, Vol 32)](https://dl.acm.org/doi/10.1145/2619091)
- [MobileAppScrutinator: A Simple yet Efficient Dynamic Analysis Approach for Detecting Privacy Leaks across Mobile OSs (arXiv)](https://arxiv.org/pdf/1605.08357)

### 5.3 Tool Documentation

- [Frida — Dynamic Instrumentation Toolkit](https://frida.re/docs/home/)
- [Objection — Runtime Mobile Exploration](https://github.com/sensepost/objection)
- [Frida CodeShare](https://codeshare.frida.re/)
- [mitmproxy Documentation](https://docs.mitmproxy.org/stable/)

---

*This document was compiled based on official OWASP MASTG content (directly verified from the `tests-beta/android/MASVS-PRIVACY/MASTG-TEST-0319.md` source in the `OWASP/mastg` repository, after discovering a discrepancy in the first fetch result), TaintDroid academic research as context for the system-wide taint-tracking approach that complements targeted hooking, as well as Frida/Objection/mitmproxy tool documentation. The most important methodological nuance: this test is the **dynamic confirmation** counterpart of MASTG-TEST-0318 — hooking results that capture the actual argument value provide far more definitive evidence than merely finding an API call in static code, but the validity of a PASS result depends entirely on how thoroughly the application's flows were triggered during the testing session.*
