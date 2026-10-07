# MASTG-TEST-0366 Exported And Unprotected Broadcast Receivers That Expose Sensitive Functionality

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0366 |
| **Platform** | Android |
| **MASVS Category** | MASVS-PLATFORM |
| **Weakness** | MASWE-0018 |
| **Test Type** | Static, Config, Code, **Manual** |
| **Related Techniques** | MASTG-TECH-0013, MASTG-TECH-0117, MASTG-TECH-0162 (Enumerating Broadcast Receivers), MASTG-TECH-0014, MASTG-TECH-0023 |
| **Related Knowledge** | MASTG-KNOW-0134 (Android Broadcast Receivers), MASTG-KNOW-0017, MASTG-KNOW-0020 |
| **Related Best Practice** | MASTG-BEST-0052 |
| **Related Tests** | **MASTG-TEST-0364/0365** — an identical methodology pattern for Activity and Service; this document targets the **Broadcast Receiver** component, with additional nuances for context-registered receivers (§1.2) |
| **Official rule** | — (none; purely manual, consistent with the TEST-0364/0365 pattern) |

---

## 1. Explanation

### 1.1 Testing Objective

Quote from the official MASTG overview:

> *"If an exported receiver does not define `android:permission` with a proper protection level and performs or grants access to sensitive functionality, another third-party app outside the intended trust boundary can send a broadcast to it and invoke that functionality."*

This is the third test in the "exported component" series within this research series (after Activity/TEST-0364 and Service/TEST-0365). The evaluation pattern is structurally identical, but Broadcast Receiver carries one unique nuance that **neither** Activity nor Service has: the possibility of being registered **dynamically in code**, not only in the manifest.

### 1.2 Unique Nuance: Context-Registered Receivers Do Not Appear in the Manifest at All

This is the most significant differentiator from the two previous tests. MASTG-TECH-0162 states explicitly:

> *"Note that context-registered receivers (registered at runtime with Context.registerReceiver) don't appear in the manifest and require code or runtime analysis."*

This means **manifest enumeration alone is not sufficient** for this test — unlike TEST-0364/0365 where the manifest is the primary source of truth. A receiver registered via `registerReceiver()` in code (for example in an `Activity`'s or `Service`'s `onCreate()`) is entirely **invisible** in a manifest-only audit, and can only be found through direct code searches for calls to `registerReceiver`/`ContextCompat.registerReceiver`.

The access-control mechanism for a context-registered receiver is also different — not an XML attribute, but a **function parameter**:

> *"`flags`: controls whether the receiver can receive broadcasts from other apps. Use RECEIVER_EXPORTED when the receiver needs to receive broadcasts from other apps, and use RECEIVER_NOT_EXPORTED when it should receive broadcasts only from the same app... Since Android 14 (API level 34), apps targeting Android 14 or higher must explicitly specify the runtime export flags."*
>
> *"`broadcastPermission`: requires the sender to hold the named permission before the broadcast is delivered to the receiver. If broadcastPermission is null, no sender permission is required."*

This means the tester must check **two different kinds of sources** for complete coverage: the `<receiver>` element in the manifest, **and** every call to `registerReceiver()` in the code — each with its own distinct access-control mechanism and API.

### 1.3 Sticky Broadcast: An Old Mechanism with No Access Control at All

MASTG-KNOW-0134 mentions one historical detail relevant to legacy applications:

> *"Sticky broadcasts, sent with the deprecated sendStickyBroadcast family of methods, persist after delivery and offer no access control."*

Although this API is already deprecated, older applications that still use it (or that use an old third-party library) may have broadcasts that, **by design, have no access-control mechanism whatsoever** — relevant to check in applications with a long-lived codebase.

### 1.4 Two Receiver-Specific Validation Criteria: Intent Content and Data Validation

Slightly different from TEST-0364/0365, further validation for receivers focuses on **how data from the incoming Intent is processed**:

> *"Determine whether `onReceive` performs a security-relevant action or discloses sensitive data based on the received intent (for example, reading extras and using them to send a message or change state). Determine whether the receiver validates the data it reads from the intent before acting on it."*

This confirms that the risk is not only "who can call it," but also **what is done with the content** of the received `Intent` — an `onReceive()` that reads `extras` and immediately uses them to trigger an action without validation is a risk pattern specific to this component, because `onReceive()` is, by design, **meant to receive arbitrary data** from a sender that (if exported without control) is entirely untrusted.

### 1.5 Concrete Evidence: Phone Numbers and Passwords Extracted Directly from Intent Extras

Pentest research documents a real-world case that precisely illustrates the risk in §1.4:

> *"MyBroadCastReceiver processes actions with name theBroadcast, is exported and not protected by a permission. Parameters are retrieved from the Intent including phone numbers and passwords."*

This case shows a classic pattern: a receiver designed to receive configuration/credential data from an internal application component, but because it was exported without a permission, **the same sensitive data could be injected by any malicious application** — either to read an existing value (if the receiver returns something) or to **overwrite** a stored credential value with an attacker-controlled value.

Another case shows a risk relevant even to a popular third-party library:

> *"A third-party library, @voximplant/react-native-foreground-service, was found to register the receiver as exported, meaning any app, including malicious ones, can trigger the event."*

And at the level of the Android system itself, **CVE-2024-27207** (CVSS 9.1, Critical) shows that this vulnerability class is relevant even in core framework components:

> *"Exported broadcast receivers allowing malicious apps to bypass broadcast protection."*

A CVSS severity of 9.1 for a vulnerability at the framework level underscores how serious this risk category generally is, even though that specific vulnerability lies outside the scope of the individual application audited with this test.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **aapt2 / xmlstarlet** | Enumeration of manifest-declared receivers (MASTG-TECH-0162) |
| **grep/ripgrep** | **Mandatory** — searching for `registerReceiver()` calls for context-registered receivers that do not appear in the manifest (§1.2) |
| **jadx** | Review of the `onReceive()` implementation (MASTG-TECH-0014, MASTG-TECH-0023) |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **ADB (`am broadcast`)** | Direct dynamic verification — sending a broadcast with tester-controlled extras |
| **Drozer** | Automated enumeration and sending of broadcasts (`app.broadcast.info`, `app.broadcast.send`) |
| **`adb shell dumpsys activity broadcasts`** | Inspection of recent broadcasts (without extras) for additional context |

### 2.3 Environment Prerequisites

- Static manifest analysis does not require a device/root, **but** code analysis for context-registered receivers is still required (§1.2).
- Dynamic verification requires a device/emulator with the target application installed.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0013** to reverse engineer the application.
2. Use **MASTG-TECH-0117** to obtain the `AndroidManifest.xml`.
3. Use **MASTG-TECH-0162** to list exported receivers **including context-registered receivers** in the code.
4. Use **MASTG-TECH-0014** to examine the `onReceive` implementation of each exported receiver.

### 3.2 Method A — Manifest Enumeration with xmlstarlet

```bash
xmlstarlet sel -t -m "//receiver" \
  -v "@android:name" -o " exported=" -v "@android:exported" \
  -o " permission=" -v "@android:permission" \
  -o " intent_filters=" -v "count(intent-filter)" -n \
  AndroidManifest.xml
```

### 3.3 Method B — Searching for Context-Registered Receivers in Code (Mandatory, §1.2)

```bash
D=./decompiled/sources

# Search for all calls to registerReceiver
rg -n 'registerReceiver\(|ContextCompat\.registerReceiver\(' $D

# Verify the flag used
rg -n 'RECEIVER_EXPORTED|RECEIVER_NOT_EXPORTED' $D

# Search for use of the old sticky broadcast (§1.3)
rg -n 'sendStickyBroadcast' $D
```

### 3.4 Method C — Review onReceive() for Intent Data Validation (Mandatory, §1.4)

For each identified exported receiver:

1. Check whether `onReceive()` reads `intent.getExtras()`/`intent.getStringExtra()`, etc.
2. Trace whether that value is used directly to trigger an action (send an SMS, change a setting, store credentials) without validating its type/format/source.

### 3.5 Method D — Dynamic Verification via ADB

```bash
adb shell am broadcast -a com.example.app.ACTION_UPDATE_CONFIG \
  --es "api_key" "attacker_controlled_value"
```

### 3.6 Method E — Drozer for Automated Enumeration and Sending

```bash
dz> run app.broadcast.info -a com.example.app
dz> run app.broadcast.send --action com.example.app.ACTION_UPDATE_CONFIG --extra string api_key "malicious_value"
```

### 3.7 Method Comparison: When to Use Which

| Method | Tool | When to use |
|---|---|---|
| **A** | xmlstarlet/aapt2 | Mandatory baseline — manifest-declared receivers |
| **B** | grep/ripgrep | **Mandatory** — closes the context-registered receiver gap not covered by the manifest |
| **C** | Manual review | **Mandatory** — assessing Intent data validation |
| **D/E** | ADB/Drozer | Conclusive dynamic verification |

**Minimum recommended combination:** **A + B (mandatory, complete coverage) → C (mandatory) → D/E (verification)**.

---

### 3.8 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Evaluation:** *"The test case fails if any exported broadcast receiver is not protected by an appropriate android:permission that restricts which apps can send broadcasts to it and exposes or performs sensitive functionality."*

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition |
|---|---|
| F1 | A receiver is exported (manifest **or** context-registered with `RECEIVER_EXPORTED`) without an adequate permission, **and** `onReceive()` performs a sensitive action based on Intent data without validation |

**Example evidence (reflecting the real-world case in §1.5):**

```xml
<receiver android:name=".ConfigReceiver" android:exported="true">
    <intent-filter><action android:name="com.example.app.UPDATE_CONFIG" /></intent-filter>
</receiver>
```

```java
public void onReceive(Context context, Intent intent) {
    String apiKey = intent.getStringExtra("api_key"); // not validated
    SharedPreferences.Editor editor = prefs.edit();
    editor.putString("api_key", apiKey).apply(); // stored directly
}
```

**FAIL** — any application can overwrite the stored `api_key` without any authorization.

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition |
|---|---|
| P1 | The receiver does not need external access and is set to `exported="false"` (manifest) or `RECEIVER_NOT_EXPORTED` (context-registered), **or** |
| P2 | The receiver is exported with `android:permission`/`broadcastPermission` having `protectionLevel="signature"`, **and** |
| P3 | `onReceive()` validates the Intent data before using it for a sensitive action |

---

#### ⚠️ Important Notes on Assessment

1. **Do not rely on manifest auditing alone** — per §1.2, a context-registered receiver is entirely invisible there; a code search for `registerReceiver()` is a mandatory step that cannot be replaced.

2. **Specifically check the runtime flag for context-registered receivers** — `RECEIVER_EXPORTED` vs. `RECEIVER_NOT_EXPORTED`, and the `broadcastPermission` passed in (not `null`).

3. **Validating Intent data is just as important as component access control** — per §1.4, even a receiver that is "intentionally" exported for a legitimate purpose must still validate the content of `extras` before using it for a sensitive action.

4. **Severity is modulated:**

   | Factor | Severity |
   |---|---|
   | Receiver allows changing credentials/security state without validation/authorization | **High** |
   | Receiver exposes sensitive data without validation/authorization | **Medium-High** |
   | Permission exists but `protectionLevel` is weak, or there is no Intent data validation | **Medium** |
   | Non-exported/`RECEIVER_NOT_EXPORTED`, or `signature` + complete data validation | **Not a finding** |

5. **Document:** the receiver name, type (manifest/context-registered), exported status/flag, permission and protectionLevel, the result of the `onReceive()` review, and the result of dynamic verification.

---

## 4. Recommendations

### 4.1 Non-Exported If Not Needed (Manifest and Context-Registered)

```xml
<receiver android:name=".ConfigReceiver" android:exported="false" />
```

```java
ContextCompat.registerReceiver(context, receiver, filter, ContextCompat.RECEIVER_NOT_EXPORTED);
```

### 4.2 Signature Permission for External Access That Is Genuinely Needed

```xml
<receiver
    android:name=".PartnerNotifyReceiver"
    android:exported="true"
    android:permission="com.example.app.permission.TRUSTED_PARTNER" />
```

### 4.3 Validate Intent Data Before Use

```java
public void onReceive(Context context, Intent intent) {
    String apiKey = intent.getStringExtra("api_key");
    if (apiKey == null || !apiKey.matches("^[A-Za-z0-9]{32}$")) {
        return; // reject a value that does not match the expected format
    }
    // continue processing
}
```

### 4.4 Remediation Checklist

- [ ] Both manifest AND context-registered receivers have been evaluated for export necessity
- [ ] Receivers that don't need to be exported are set to `exported="false"`/`RECEIVER_NOT_EXPORTED`
- [ ] Required exported receivers are protected by a `signature` permission
- [ ] `onReceive()` validates all data from the Intent before triggering an action
- [ ] No use of `sendStickyBroadcast` (deprecated, no access control)
- [ ] Verified dynamically with `adb shell am broadcast`/Drozer

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0366 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0366.md)
- [MASTG-TEST-0364/0365 (related documents in this research series)](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0364/)
- [MASTG-KNOW-0134: Android Broadcast Receivers](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0134/)
- [MASTG-BEST-0052: Restrict Access to Android App Components](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0052.md)
- [MASTG-TECH-0162: Enumerating Broadcast Receivers](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0162/)

### 5.2 Research and Real-World Cases

- [Android Developers: Insecure Broadcast Receivers](https://developer.android.com/privacy-and-security/risks/insecure-broadcast-receiver)
- [GitHub Advisory: CVE-2024-20853 — ThemeStore Broadcast Receiver Arbitrary File Write](https://github.com/advisories/GHSA-j4j9-wc5g-p586)
- [CyberStrike: CVE-2024-27207 — Android Exported Broadcast Receiver Bypass (CVSS 9.1)](https://cyberstrike.io/cve/CVE-2024-27207/)
- [Mattermost: Investigating and Mitigating Security Risks in a React Native App](https://mattermost.com/blog/mitigating-broadcast-receiver-security-risks-in-a-react-native-app/)
- [CWE-925: Improper Verification of Intent by Broadcast Receiver](https://cwe.mitre.org/data/definitions/925.html)

### 5.3 Tool Documentation

- [Drozer — Android Security Assessment Framework](https://github.com/WithSecureLabs/drozer)
- [Android Developers: Broadcasts Overview](https://developer.android.com/guide/components/broadcasts)

---

*This document was compiled based on official OWASP MASTG content (`tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0366.md`, `MASTG-KNOW-0134/0017/0020`, `MASTG-BEST-0052`), together with community research documenting a real-world case of phone number and password extraction via an exported broadcast receiver without a permission, a vulnerability in a popular third-party library (`@voximplant/react-native-foreground-service`), and a critical CVE at the Android framework level (CVE-2024-27207, CVSS 9.1). The most important methodological nuance compared to TEST-0364/0365: a Broadcast Receiver can be registered dynamically via `registerReceiver()` in code, entirely invisible in a manifest-only audit — a code search for context-registered receivers and a check of the `RECEIVER_EXPORTED`/`RECEIVER_NOT_EXPORTED` flag are mandatory steps unique to this component class, beyond what is already sufficient coverage for Activity and Service.*
