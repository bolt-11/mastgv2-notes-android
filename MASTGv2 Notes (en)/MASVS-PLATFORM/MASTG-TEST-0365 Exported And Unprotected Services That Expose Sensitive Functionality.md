# MASTG-TEST-0365 Exported And Unprotected Services That Expose Sensitive Functionality

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0365 |
| **Platform** | Android |
| **MASVS Category** | MASVS-PLATFORM |
| **Weakness** | MASWE-0018 |
| **Test Type** | Static, Config, Code, **Manual** |
| **Related Techniques** | MASTG-TECH-0013, MASTG-TECH-0117, MASTG-TECH-0161 (Enumerating Services), MASTG-TECH-0014, MASTG-TECH-0023 |
| **Related Knowledge** | MASTG-KNOW-0133 (Android Services), MASTG-KNOW-0017 (App Permissions), MASTG-KNOW-0020 (IPC Mechanisms) |
| **Related Best Practice** | MASTG-BEST-0052 (Restrict Access to Android App Components) |
| **Related Tests** | **MASTG-TEST-0364** — an identical methodology pattern for Activities; this document targets the **Service** component, with additional nuances for bound services (§1.3) |
| **Official rule** | — (none; purely manual, consistent with TEST-0364) |

---

## 1. Explanation

### 1.1 Testing Objective

Quote from the official MASTG overview:

> *"If an exported service does not define `android:permission` with a proper protection level and performs or grants access to sensitive functionality, another third-party app outside the intended trust boundary can start or bind to it and invoke that functionality."*

This test's evaluation structure is **methodologically identical** to MASTG-TEST-0364 (Activities), already discussed in this research series — the main difference is the type of component being targeted. However, Service carries an **additional risk nuance** that Activity does not have: the ability to be accessed via **two different methods** — `startService()` (fire-and-forget) and `bindService()` (two-way communication via an interface).

### 1.2 Two Interaction Models with Services and Their Implications for Attack Surface

MASTG-KNOW-0133 distinguishes two usage models for services:

> *"Started services: launched with startService... and run until they stop themselves or are stopped."*
>
> *"Bound services: other components bind to them with bindService to interact through a client-server interface. A bound service must return an IBinder from onBind."*

This distinction is important for attack surface: a **started service** generally only receives a single `Intent` and processes it once (similar to an Activity/Broadcast Receiver). A **bound service**, on the other hand, opens an **interactive two-way connection** — an attacker can send many requests and receive many responses through a mechanism such as:

> *"A Messenger, which serializes requests into Message objects delivered to a Handler. This is the simplest cross-process interface."*
>
> *"The Android Interface Definition Language (AIDL), which generates the marshalling code for a remote interface and allows concurrent calls across processes."*

A bound service via AIDL effectively **exposes the entire internal API** defined by its interface to the external caller — this is a much broader risk class than merely "one Intent triggers one action," because a single bound service can have **dozens of methods**, all of which simultaneously become an attack surface if not properly protected.

### 1.3 An Additional Defense Layer Unique to Services: Runtime Permission Verification

This is the most significant differentiator from TEST-0364 — the overview explicitly adds a fourth validation criterion that **does not exist** in the Activity test:

> *"Determine whether the service verifies the caller's permission at runtime (for example, with `checkCallingPermission` or `enforceCallingPermission`) before processing sensitive requests."*

This is relevant because, for a bound service via AIDL/Binder, `android:permission` in the manifest **only protects the initial step** (`bindService()`/`startService()`), but **after** the connection/binding has been successfully established, **each individual method call** on that interface may potentially need to be re-verified separately — especially if the service serves **many clients with different levels of trust** simultaneously. MASTG-KNOW-0133 explains the mechanism:

> *"Inside the service, `Context.checkCallingPermission` and related methods can verify at runtime whether the caller holds a required permission before processing a Binder transaction."*

This is a form of **method-level defense-in-depth**, not just component-level — particularly relevant for complex services that expose many operations with varying levels of sensitivity through the same single interface.

### 1.4 Concrete Evidence: Password Reset via an Exported MessengerService Without Any Authentication

This is a real-world case that perfectly illustrates exactly the second scenario in the official evaluation criteria (§ Evaluation: *"allowing a caller to invoke a bound-service interface without authorization"*):

> *"The app initialized shared preferences with username 'root' and a SHA256 password hash, but any installed application could interact with this exported, unprotected service. The MessengerService accepted two message types: display toast notifications, and update the password hash... An attacker created a malicious app that bound to the victim app's service using an explicit intent, sent a message with what=2 containing a known password hash, and successfully reset the login credentials without authentication. This allowed bypassing the login entirely and accessing the protected admin panel."*

This case concretely shows how a **bound service via Messenger** (§1.2) can be a far more dangerous attack vector than merely "displaying data" — here, the attacker **changes the application's security state** (password hash) via a single simple message (`what=2`), without needing to go through even one login screen. This research's author's recommendation fully aligns with the MASTG-BEST-0052 principle:

> *"The author recommends using 'signature-level' permissions to restrict service access only to applications signed with the same certificate."*

### 1.5 Additional Context: Risk at the System Level (Not Just Individual Applications)

Advanced security research shows that this Binder/bound-service vulnerability class is also relevant at the level of the **Android operating system itself**, not just third-party applications — **CVE-2023-20938** is a use-after-free in the Binder driver that can be exploited for privilege escalation up to root from an untrusted application. Although this is a kernel/framework-level vulnerability (outside the direct scope of the individual application test), it reinforces that **Binder as a fundamental IPC mechanism** has a serious and ongoing history of vulnerabilities across multiple layers — adding urgency to why an individual application should not add unnecessary attack surface through a loosely configured service.

---

## 2. Tools Used for Testing

### 2.1 Required Tools (Core)

| Tool | Function |
|---|---|
| **aapt2 / xmlstarlet** | Enumeration of exported services along with their permissions (MASTG-TECH-0161) |
| **jadx** | Code review of `onBind()`/`onStartCommand()`/`handleMessage()` to assess the sensitivity of functionality (MASTG-TECH-0014, MASTG-TECH-0023) |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **ADB (`am startservice`)** | Dynamic verification for started services |
| **Drozer** | Especially useful for services — provides `app.service.send` to send a structured `Message` to a bound service without needing to write a custom exploit app |
| **`adb shell dumpsys package`** | Inspection of the Service Resolver Table for runtime confirmation |

### 2.3 Environment Prerequisites

- Static manifest analysis does not require a device/root.
- Dynamic verification requires a device/emulator with the target application installed.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0013** to reverse engineer the application.
2. Use **MASTG-TECH-0117** to obtain the `AndroidManifest.xml`.
3. Use **MASTG-TECH-0161** to list exported services along with their `android:permission`.
4. Use **MASTG-TECH-0014** to examine the code of each exported service.

### 3.2 Method A — Manifest Enumeration with xmlstarlet

```bash
xmlstarlet sel -t -m "//service" \
  -v "@android:name" -o " exported=" -v "@android:exported" \
  -o " permission=" -v "@android:permission" \
  -o " intent_filters=" -v "count(intent-filter)" -n \
  AndroidManifest.xml
```

### 3.3 Method B — Code Review to Identify the Exposed Interface (Mandatory)

For each exported service without a permission identified:

1. Check `onBind()` — what interface is returned (AIDL stub, `Messenger`, custom `Binder`)?
2. For `Messenger`, check the `Handler.handleMessage()` implementation — what happens for each `what` value?
3. For AIDL, check the `.aidl` file and its stub implementation — which methods are exposed?
4. Check whether `checkCallingPermission`/`enforceCallingPermission` is called inside those methods (§1.3).

### 3.4 Method C — Dynamic Verification with Drozer (Replicating the Real-World Scenario in §1.4)

```bash
dz> run app.service.info -a com.example.app
dz> run app.service.send com.example.app com.example.app.AdminMessengerService --msg 2 0 0 --extra string password_hash "known_hash_value"
```

### 3.5 Method D — Dynamic Verification for Started Services via ADB

```bash
adb shell am startservice -n com.example.app/.BackgroundSyncService
adb shell dumpsys package com.example.app | grep -A10 'Service Resolver Table'
```

### 3.6 Method Comparison: When to Use Which

| Method | Tool | When to use |
|---|---|---|
| **A** | xmlstarlet/aapt2 | Mandatory baseline — complete enumeration |
| **B** | Manual review | **Mandatory** — identifying the exposed interface and methods, assessing sensitivity |
| **C** | Drozer | Most practical dynamic verification for bound services (Messenger/AIDL) |
| **D** | ADB `am startservice` | Dynamic verification for simple started services |

**Minimum recommended combination:** **A → B (mandatory) → C/D (depending on the service type)**.

---

### 3.7 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Evaluation:** *"The test case fails if any exported service is not protected by an appropriate android:permission that restricts which apps can start or bind to it and exposes or performs sensitive functionality... for example by returning sensitive data, performing a security-relevant action, or allowing a caller to invoke a bound-service interface without authorization."*

---

#### ❌ FAIL / ISSUE — The check is declared FAILED if:

| No | Condition |
|---|---|
| F1 | A service with `exported="true"` lacks an adequate `android:permission`, **and** exposes sensitive data/actions via a started or bound interface |

**Example evidence (reflecting the real-world case in §1.4):**

```xml
<service android:name=".AdminMessengerService" android:exported="true" />
```

```java
class IncomingHandler extends Handler {
    public void handleMessage(Message msg) {
        switch (msg.what) {
            case 2: // update password hash — NO permission/authentication check
                prefs.edit().putString("password_hash", (String) msg.obj).apply();
                break;
        }
    }
}
```

**FAIL** — an action that changes credentials can be triggered by any application without authorization.

---

#### ✅ PASS — The check is declared PASSED if:

| No | Condition |
|---|---|
| P1 | The service does not need external access and is set to `exported="false"`, **or** |
| P2 | The service is exported with `android:permission` having `protectionLevel="signature"`, **and** |
| P3 | *(for bound services with many operations of different sensitivities)* Each sensitive method/handler independently verifies permission at runtime via `checkCallingPermission`/`enforceCallingPermission` (§1.3) |

---

#### ⚠️ Important Notes on Assessment

1. **Distinguish started vs. bound services when assessing attack surface** — a bound service via AIDL/Messenger can potentially expose many operations at once through a single component, requiring each method/message type to be audited individually; it is not sufficient to assess only a single entry point as with an Activity.

2. **`android:permission` in the manifest only protects the initial bind/start step** — for complex bound services, also check whether runtime permission verification exists inside the implementation of individual methods (§1.3), especially if the service serves clients with different levels of trust.

3. **Ask the export-necessity question first**, the same principle as in TEST-0364 — if there is no legitimate reason for a third party to call that service, `exported="false"` is the strongest solution.

4. **Severity is modulated:**

   | Factor | Severity |
   |---|---|
   | A bound service allows changing credentials/security state without authorization | **High** |
   | A bound service exposes sensitive data via a read-only interface | **Medium-High** |
   | `android:permission` exists but `protectionLevel` is weak, or there is no per-method runtime verification on a complex bound service | **Medium** |
   | Non-exported, or `signature` + complete runtime verification | **Not a finding** |

5. **Document:** the service name, type (started/bound), the exposed interface (AIDL/Messenger/custom Binder), the available methods/message types, the permission and protectionLevel status, and the result of dynamic verification.

---

## 4. Recommendations

### 4.1 Non-Exported If Not Needed (Per MASTG-BEST-0052)

```xml
<service android:name=".AdminMessengerService" android:exported="false" />
```

### 4.2 Signature Permission + Per-Method Runtime Verification (Per §1.3)

```xml
<service
    android:name=".PartnerSyncService"
    android:exported="true"
    android:permission="com.example.app.permission.TRUSTED_PARTNER" />
```

```java
class IncomingHandler extends Handler {
    public void handleMessage(Message msg) {
        if (msg.what == UPDATE_CREDENTIALS) {
            // Additional method-level verification for the most sensitive operation
            if (context.checkCallingPermission("com.example.app.permission.ADMIN_ACTION")
                    != PackageManager.PERMISSION_GRANTED) {
                return; // reject silently or throw a SecurityException
            }
            // continue processing
        }
    }
}
```

### 4.3 Remediation Checklist

- [ ] Every exported service has been evaluated for whether external access is genuinely needed
- [ ] Services that don't need to be exported are set to `exported="false"`
- [ ] Required exported services are protected by a `signature` permission
- [ ] Bound services with many operations independently verify permission per method/message type at runtime
- [ ] Verified dynamically with Drozer (`app.service.send`) for every exposed message type

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0365 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0365.md)
- [MASTG-TEST-0364 (related document in this research series — a similar methodology pattern for Activities)](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0364/)
- [MASTG-KNOW-0133: Android Services](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0133/)
- [MASTG-BEST-0052: Restrict Access to Android App Components](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0052.md)
- [MASTG-TECH-0161: Enumerating Services](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0161/)

### 5.2 Research and Real-World Cases

- [alright21.me: Exploiting Exported Services — IPC Messenger (Reset Password Case)](https://blog.alright21.me/security/exploiting_ipc_messenger/)
- [Android Offensive Security Blog: Attacking Android Binder — Analysis and Exploitation of CVE-2023-20938](https://androidoffsec.withgoogle.com/posts/attacking-android-binder-analysis-and-exploitation-of-cve-2023-20938/)
- [Black Hat US-15: Fuzzing Android System Services by Binder Call to Escalate Privilege](https://www.blackhat.com/docs/us-15/materials/us-15-Gong-Fuzzing-Android-System-Services-By-Binder-Call-To-Escalate-Privilege.pdf)
- [CWE-926: Improper Export of Android Application Components](https://cwe.mitre.org/data/definitions/926.html)

### 5.3 Tool Documentation

- [Drozer — Android Security Assessment Framework](https://github.com/WithSecureLabs/drozer)
- [Android Developers: Bound Services](https://developer.android.com/guide/components/bound-services)

---

*This document was compiled based on official OWASP MASTG content (`tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0365.md`, `MASTG-KNOW-0133/0017/0020`, `MASTG-BEST-0052`), together with community research documenting a real-world password reset case via an exported `MessengerService` without authentication, and Binder-level research (CVE-2023-20938) reinforcing the fundamental risk of Android's IPC mechanism. The most important methodological nuance compared to MASTG-TEST-0364 (Activity): a Service — especially a bound service via AIDL/Messenger — can expose **many operations at once** through a single component, requiring an audit per method/message type individually, and `android:permission` in the manifest alone is not always sufficient — runtime permission verification (`checkCallingPermission`/`enforceCallingPermission`) inside the method implementation becomes an additional defense layer specifically relevant to this component class.*
