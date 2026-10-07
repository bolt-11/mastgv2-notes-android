# MASTG-TEST-0374 References to Implicit Intents Carrying Sensitive Extras

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0374 |
| **Platform** | Android |
| **MASVS Category** | MASVS-CODE |
| **Weakness** | MASWE-0032 |
| **Test Type** | Static, Code, **Manual** |
| **Related Techniques** | MASTG-TECH-0013, MASTG-TECH-0014, MASTG-TECH-0023 |
| **Related Knowledge** | MASTG-KNOW-0025 (Explicit vs Implicit Intents) |
| **Related Best Practice** | MASTG-BEST-0056 (Use Explicit Intents for Internal IPC) |
| **Related Tests** | **MASTG-TEST-0372** — related document in this research series; the difference in focus is explained in §1.1 |
| **Official Rule** | `mastg-android-implicit-intent-leaking-extras.yml` — **two distinct types of gaps** were found, see §1.4 |

---

## 1. Explanation

### 1.1 Difference in Focus from MASTG-TEST-0372: Data, Not Just Mechanism

Quote from the official MASTG overview:

> *"The issue appears when the app attaches sensitive or security-relevant extras to an implicit intent without constraining the recipient. During intent resolution, any installed app with a matching `<intent-filter>` can become the selected recipient and receive the full extras Bundle."*

This test is a **close sibling** of MASTG-TEST-0372 (already covered in this research series), but with a fundamentally different evaluation focus:

| | MASTG-TEST-0372 | MASTG-TEST-0374 (this test) |
|---|---|---|
| **Evaluation focus** | **Mechanism** — whether an intent intended for internal communication is implicit | **Data** — whether the extras carried by the implicit intent are sensitive |
| **Applies to "legitimate" external intents?** | No — ACTION_VIEW/ACTION_SEND are out of scope | **Can still be a finding** if it carries sensitive data, even though the action appears legitimate mechanically |

This second nuance is what makes this test broader in one particular aspect — even an intent **deliberately** designed for external delegation (ACTION_SEND, chooser) can still become a finding in this test if the **content of its extras** contains data that should never be broadcast to any app that registers for it.

### 1.2 More Concrete and Varied Impact

The overview provides a much more specific list of impacts than TEST-0372, because it focuses directly on the consequences of data leakage:

> *"This can disclose credentials, session tokens, one-time codes, personal data, account identifiers, or internal state to an untrusted app. Depending on the data, the impact can include privacy leakage, session compromise, account takeover, or unauthorized use of backend APIs."*

The phrase *"account takeover"* here is important — this is not merely a passive privacy-leakage risk, but a **direct escalation path** toward full account compromise, if an exposed token/OTP code can be used by an attacker to authenticate as the victim.

### 1.3 Broader Ways to Expose Extras Beyond Just putExtra

The overview lists several different extras-adding APIs, not just `putExtra`:

> *"Relevant patterns include creating an Intent with an action, adding extras with `putExtra`, `putExtras`, `replaceExtras`, or a `Bundle`."*

The difference between `putExtra` and `putExtras`/`replaceExtras` matters for analysis — `putExtras(Bundle)`/`replaceExtras(Bundle)` accept an **entire `Bundle` already constructed elsewhere**, which means its contents are **not always directly visible** at the call site; the tester must trace back to where that `Bundle` is built to assess the sensitivity of its data, unlike `putExtra(key, value)`, which usually displays the key-value pair directly on the same line of code.

### 1.4 Analytical Finding: The Official Rule Has Two Distinct Types of Issues

The rule `mastg-android-implicit-intent-leaking-extras.yml` has a coverage gap **similar** to TEST-0372 (only `startActivity` + `putExtra`, only Java, missing `startService`/`bindService`/`sendBroadcast`/`startActivityForResult`/`ActivityResultLauncher.launch` and `putExtras`/`replaceExtras`), but this test has an **additional, oppositely-directed problem**:

```yaml
patterns:
  - pattern: |
      $I = new Intent(...);
      ...
      $I.putExtra($KEY, $VAL);
      ...
      $CTX.startActivity($I);
  # pattern-not for explicit constructor/setPackage/setComponent
```

This rule **does not distinguish at all** between custom internal actions (`"com.example.app.SYNC"`) and standard system actions that are specifically designed for external delegation (`Intent.ACTION_SEND`). This means the rule will **also flag** the entirely legitimate `ACTION_SEND` + `putExtra` pattern (e.g., sharing plain text to a chat app chosen by the user) as a "WARNING", creating potential for **high-volume false positives** in applications that heavily use the standard share feature — the opposite direction from the coverage gaps (false negatives) that dominate the other rules found throughout this research series. The official evaluation itself acknowledges the need for a manual filtering step for this:

> *"Check whether the dispatch is an intentional user-selected share/open flow, such as ACTION_SEND or a chooser."*

This confirms that for this test, **false-positive filtering** (not just closing false negatives as in other tests) is an important and unavoidable part of the manual work.

### 1.5 The Most Significant Real-World Evidence in This Research Series: CVE-2014-8889 "DroppedIn" in the Dropbox SDK

This is one of the strongest pieces of real-world evidence found throughout the entire research series — a vulnerability in Dropbox's **own official SDK** (not a niche app), meaning **every third-party application** that integrated that SDK (versions 1.5.4–1.6.1) was automatically affected as well:

> *"IBM discovered a vulnerability in the Dropbox SDK for Android, identified as CVE-2014-8889, known as the 'DroppedIn' vulnerability. The vulnerability involves the consumption of an Intent extra parameter named INTERNAL_WEB_HOST, which can be controlled by the attacker. An attacker can determine which web host the mobile browser surfs to when authenticating to Dropbox by manipulating this parameter... lets adversaries insert an arbitrary access token into the Dropbox SDK, completely bypassing the nonce protection."*

The documented attack vector covers both local **and** remote scenarios:

> *"The vulnerability can be exploited in two ways: using a malicious application installed on the users' device or remotely using malicious links to drive-by download websites."*

This precisely illustrates the "account takeover" risk mentioned in the overview (§1.2) — by manipulating the `INTERNAL_WEB_HOST` extra passed through the intent, an attacker could inject a fake access token that the SDK would then accept as a legitimate token belonging to the victim, completely bypassing the nonce mechanism designed to prevent exactly that.

A general case related to OAuth token redirection via implicit intent is also documented more broadly:

> *"If an implicit intent handling sensitive data passes a session token within an extra URL string to open a WebView, any application specifying the proper intent filters can read this token... OAuth tokens can be returned via an implicit Intent targeting an app's unique URI scheme, creating a threat of stealing the returned OAuth access token."*

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **jadx** | Decompiles DEX → Java/Kotlin |
| **Semgrep** + official rule | Basic detection of `startActivity` + `putExtra` (coverage limited in two directions, §1.4) |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **grep/ripgrep** | **Required** — closes the gap for other dispatch APIs, `putExtras`/`replaceExtras`, and Kotlin code |

### 2.3 Environment Prerequisites

- No device/root needed — purely static analysis.
- Prepare a list of extras key-name keywords that commonly indicate sensitive data (`token`, `password`, `otp`, `session`, `auth`) to speed up triage.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0013** to reverse engineer the application.
2. Use **MASTG-TECH-0014** to search for relevant APIs.

### 3.2 Method A — Semgrep with the Official Rule

```bash
semgrep --config mastg-android-implicit-intent-leaking-extras.yml ./decompiled/sources
```

**Mandatory note:** manually verify every result to filter out false positives from legitimate `ACTION_SEND`/chooser flows (§1.4).

### 3.3 Method B — grep/ripgrep for Full Coverage and Sensitive-Key-Name Triage

```bash
D=./decompiled/sources

# All extras-adding APIs, including those not covered by the official rule
rg -n '\.putExtra\(|\.putExtras\(|\.replaceExtras\(' $D

# Quick triage by key names that indicate sensitivity
rg -n 'putExtra\("[^"]*(token|password|otp|session|auth|secret|key)[^"]*"' $D -i

# Five other dispatch APIs not covered by the official rule (same as TEST-0372)
rg -n '\.startService\(|\.bindService\(|\.sendBroadcast\(|\.startActivityForResult\(' $D
```

### 3.4 Method C — Manual Review to Distinguish Legitimate Share Flows from Internal Ones (Mandatory)

For each result from Method A/B:

1. Is the action a standard `ACTION_SEND`/`ACTION_SENDTO`/chooser (likely legitimate, §1.4)?
2. Does the extras key indicate sensitive data (token, credential, OTP)?
3. Trace back the source of the `putExtras(Bundle)`/`replaceExtras(Bundle)` value, if used, to find its actual content.

### 3.5 Method Comparison: When to Use Which

| Method | Tool | When to Use |
|---|---|---|
| **A** | Semgrep + official rule | Baseline, requires manual filtering (false positives) |
| **B** | grep/ripgrep manual | **Required** — full coverage + key-name triage |
| **C** | Manual review | **Required** — distinguish legitimate share flows from actual leaks |

**Minimum recommended combination:** **B (real baseline) → C (mandatory)**.

---

### 3.6 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Evaluation:** *"The test case fails if an implicit intent carries sensitive or security-relevant extras and another app can declare or register a matching component to receive them."*

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition |
|---|---|
| F1 | An implicit intent carries extras containing credentials/tokens/OTP/personal data/account identifiers, **and** the intent is not explicit (no `setPackage`/`setComponent`) |

**Evidence example (reflecting the real pattern of CVE-2014-8889, §1.5):**

```java
Intent intent = new Intent("com.example.app.AUTH_CALLBACK");
intent.putExtra("access_token", sessionToken);
intent.putExtra("web_host", userControlledHost); // also vulnerable to manipulation, the DroppedIn pattern
sendBroadcast(intent); // implicit, not covered by the official rule (startActivity only)
```

**FAIL** — the session token can be intercepted by any application that registers a receiver with the same action.

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition |
|---|---|
| P1 | The intent carrying sensitive data uses `setPackage`/`setComponent`/an explicit constructor, **or** |
| P2 | The implicit intent is indeed a legitimate `ACTION_SEND`/chooser **and** its extras are verified to contain only content that the user actually intended to share (not internal tokens/credentials) |

---

#### ⚠️ Important Notes on Assessment

1. **Actively filter out false positives** — unlike most other tests in this research series, where the rule under-matches, this rule can over-match on legitimate share flows; do not report all Semgrep results as findings without verification.

2. **Trace back `putExtras(Bundle)`/`replaceExtras(Bundle)`** — the actual contents are often not directly visible at the call site (§1.3).

3. **Watch for configuration parameters that can be abused**, not just directly credential-like data — as in the DroppedIn case (§1.5), an extra that looks non-sensitive (`web_host`) became a real attack vector when combined with logic that trusted it without validation.

4. **Severity is modulated as follows:**

   | Factor | Severity |
   |---|---|
   | Token/credential/OTP carried by an implicit intent, potential account takeover | **High** |
   | Non-credential personal data carried by an implicit intent | **Medium** |
   | Legitimate share flow (ACTION_SEND) with content the user intended to share | **Not a finding** |

5. **Document:** code location, action, extras key and value (redacted if necessary), dispatch API, presence/absence of `setPackage`/`setComponent`, and the classification of whether this is a legitimate share flow or a leak.

---

## 4. Recommendations

### 4.1 Use Explicit Intents for Sensitive Data (Per MASTG-BEST-0056)

```java
// BEFORE — implicit, the token can be intercepted
Intent intent = new Intent("com.example.app.AUTH_CALLBACK");
intent.putExtra("access_token", sessionToken);
sendBroadcast(intent);

// AFTER — explicit, received only by the intended component
Intent intent = new Intent(context, AuthCallbackReceiver.class);
intent.putExtra("access_token", sessionToken);
context.sendBroadcast(intent); // or LocalBroadcastManager/modern alternative for in-app communication
```

### 4.2 Remediation Checklist

- [ ] All intents carrying sensitive data use `setComponent`/an explicit constructor, or at minimum `setPackage`
- [ ] Verification covers `putExtras`/`replaceExtras`, not just `putExtra`
- [ ] Legitimate share flows (ACTION_SEND) are verified to not carry internal tokens/credentials
- [ ] Configuration parameters passed via intent (as in the DroppedIn case) are validated, not trusted blindly from extras

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0374 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-CODE/MASTG-TEST-0374.md)
- [MASTG-TEST-0372 (related document in this research series)](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0372/)
- [MASTG-KNOW-0025: Explicit vs Implicit Intents](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0025/)
- [MASTG-BEST-0056: Use Explicit Intents for Internal IPC](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0056.md)

### 5.2 Research and Real-World Cases

- [SecurityWeek: Dropbox Android SDK Flaw Exposes Mobile Users to Attack (CVE-2014-8889 "DroppedIn")](https://www.securityweek.com/dropbox-android-sdk-flaw-exposes-mobile-users-attack-ibm/)
- [Full Disclosure: Vulnerability in the Dropbox SDK for Android (CVE-2014-8889)](https://seclists.org/fulldisclosure/2015/Mar/61)
- [Android Developers: Implicit Intent Hijacking](https://developer.android.com/privacy-and-security/risks/implicit-intent-hijacking)
- [Ostorlab: One Scheme to Rule Them All — OAuth Account Takeover](https://blog.ostorlab.co/one-scheme-to-rule-them-all.html)

### 5.3 Tool Documentation

- [Semgrep Documentation](https://semgrep.dev/docs/)

---

*This document was prepared based on official OWASP MASTG content (`tests-beta/android/MASVS-CODE/MASTG-TEST-0374.md`, `MASTG-KNOW-0025`, `MASTG-BEST-0056`), analysis of the `mastg-android-implicit-intent-leaking-extras.yml` rule, and one of the strongest pieces of real-world evidence in this research series: CVE-2014-8889 "DroppedIn" in the official Dropbox SDK, which allowed injection of a fake access token via manipulation of the `INTERNAL_WEB_HOST` extra, impacting every third-party application that integrated the vulnerable SDK version. The most important and unique methodological nuance for this test: unlike most other rules in this research series, which tend to under-match (false negatives), the official rule for this test also risks **over-matching** on legitimate share flows (`ACTION_SEND`) because it does not distinguish internal actions from legitimate external delegation actions — false-positive filtering is a part of the manual work just as important as closing coverage gaps.*
