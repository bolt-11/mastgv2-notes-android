# MASTG-TEST-0244 Missing Certificate Pinning in Network Traffic

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0244 |
| **Platform** | Network (implementation-agnostic) |
| **MASVS Category** | MASVS-NETWORK |
| **Weakness** | MASWE-0028 — *Insecure Identity Pinning* |
| **Test Type** | Dynamic, Network |
| **Related Knowledge** | MASTG-KNOW-0015 (Certificate Pinning) |
| **Prerequisite** | `identify-first-party-domains` — mandatory for this test to be valid (already discussed in depth in the MASTG-TEST-0242 document) |
| **Related Techniques** | MASTG-TECH-0005, MASTG-TECH-0011 (Setting Up an Interception Proxy), MASTG-TECH-0009 (Monitoring System Logs) |
| **Related Tests** | **MASTG-TEST-0242** — a related document in this research series; that test targets **one specific mechanism** (NSC `<pin-set>`), whereas this test is **implementation-agnostic** |
| **Official Rule** | — (none; purely dynamic via MITM) |

---

## 1. Explanation

### 1.1 Testing Objective and the Fundamental Difference from MASTG-TEST-0242

Quote from the official MASTG overview:

> *"There are multiple ways an application can implement certificate pinning, including via the Android Network Security Config, custom TrustManager implementations, third-party libraries, and native code. Since some implementations might be difficult to identify through static analysis, especially when obfuscation or dynamic code loading is involved, this test uses network interception techniques to determine if certificate pinning is enforced at runtime."*

This difference is explicitly asserted by MASTG itself:

> *"Unlike MASTG-TEST-0242, which specifically assesses certificate pinning configured through the Android Network Security Configuration, this test is implementation-agnostic. It verifies at runtime whether pinning is enforced regardless of whether it is implemented through the Network Security Configuration, application code, a third-party library, or native code."*

This is the "narrow static coverage vs. broad dynamic coverage" pattern that has already appeared in several other test pairs in this research series — however, here the coverage gap is **very wide**: TEST-0242 can only assess **one** of **four** possible implementation mechanisms (NSC, custom `TrustManager`, third-party library, native code). This test, by approaching the problem from the angle of the **end result** (whether MITM succeeds or not), automatically covers **all four** mechanisms simultaneously without needing to know which mechanism the app actually uses.

### 1.2 Testing Logic: MITM as the Oracle of Truth

> *"The goal of this test case is to observe whether a MITM attack can intercept HTTPS traffic from the app. A successful MITM interception indicates that the app is either not using certificate pinning or implementing it incorrectly. If the app is properly implementing certificate pinning, the MITM attack should fail because the app rejects certificates issued by an unauthorized CA, even if the CA is trusted by the system."*

The crucial point here: *"even if the CA is trusted by the system"* — this is the core value-add of certificate pinning that distinguishes it from standard TLS validation. The root CA of a MITM proxy (Burp/mitmproxy) **could** be installed and fully trusted by the system (test device, or even a production device compromised via social engineering into installing a fake CA) — however, an app with correct pinning **still rejects** the connection because the **specific public key** expected does not match, regardless of the system's trust status for that CA. This is why "MITM succeeds" becomes a reliable **oracle** for concluding the absence/incorrect implementation of pinning — if pinning is genuinely functioning, this most common attack method **should be impossible to succeed**, regardless of the implementation mechanism behind the scenes.

### 1.3 Additional Diagnostic Signal: System Logs as Supporting Evidence

A practical note useful for interpreting ambiguous test results:

> *"While performing the MITM attack, it can be useful to monitor the system logs. If a certificate pinning/validation check fails, an event similar to the following log entry might be visible: `I/X509Util: Failed to validate the certificate chain, error: Pin verification failed`"*

This provides an **independent signal** beyond simply observing "connection failed/succeeded" — the system log explicitly confirms the **reason** for the connection failure (genuinely due to pin verification failure, rather than a generic unrelated network error). This is relevant for distinguishing two scenarios that look similar from the outside: (a) the connection fails because pinning is actually working correctly, versus (b) the connection fails for another reason entirely (e.g., the app simply runs offline/has a network error unrelated to MITM).

### 1.4 Prerequisite Inherited from MASTG-TEST-0242: First-Party Domains

The `identify-first-party-domains` prerequisite applies identically to both tests — already discussed in depth in the MASTG-TEST-0242 document. Its key point is explicitly restated in this test's overview:

> *"This test focuses on relevant first-party domains, which are remote endpoints under the developer's control that support the app's core or security-sensitive functionality. Third-party domains outside the developer's control should not be reported only because their traffic can be intercepted."*

This is very practically important — the **majority** of traffic that successfully gets intercepted by MITM on modern apps usually originates from third-party analytics/advertising/crash-reporting SDKs that **do not** implement pinning (and reasonably do not need to, since they are not owned by the app developer). A tester who does not filter out these third-party domains will produce a report inflated with false positives — any generic analytics domain that is successfully intercepted is **not** a finding for this test.

### 1.5 Further Validation: An Identification Challenge Requiring Context Beyond the Binary

> *"Determining which of the intercepted domains are first-party and security-relevant typically requires information that is not present in the app binary and may require contact with the developers."*

This is consistent with the note in the MASTG-TEST-0242 document — identifying first-party domains is **inherently** a process that requires external context (architecture documentation, communication with the development team, or inference from branding/bundle identifier when official information is unavailable).

### 1.6 Real-World Evidence: Pinning Implementation Flaws in Banking Apps

Security research confirms that implementation flaws in pinning — not merely its absence — are a real and recurring problem in the category of apps that most need it:

> *"A vulnerability in the mobile apps of several major banks exposed customers to potential data theft, with certificate pinning errors leaving customers susceptible to man-in-the-middle attacks that put their credentials — usernames, passwords, personal information, and banking info — at risk. Research found that many banks offer certificate pinning as a security feature, but fail to authenticate the hostname, leaving systems open to man-in-the-middle attacks."*

This case is highly relevant to reinforce the point from §1.2 — the banks in question **were not lacking** a pinning feature at all (they "offer certificate pinning as a security feature"), but their implementation was **flawed** (failing to properly validate hostnames) so that MITM still succeeded even though pinning superficially "existed." This precisely illustrates why this test's approach (observing the **outcome** of MITM, rather than merely confirming the **existence** of pinning code) is far more reliable — a static audit that only confirms "a pinning API call exists" could entirely miss such implementation flaws, while this dynamic test will still catch them because the attempted MITM will **still succeed** on an app with a flawed implementation.

---

## 2. Tools Used for Testing

### 2.1 Mandatory Tools (Core)

| Tool | Function |
|---|---|
| **Burp Suite / mitmproxy** | Interception proxy for launching MITM attempts (MASTG-TECH-0011) |
| **ADB (`adb logcat`)** | Monitoring system logs for a diagnostic signal of pin verification failure (MASTG-TECH-0009) |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **Frida** | Additional verification — actively attempting to bypass pinning to distinguish "no pinning at all" vs. "pinning exists but can be bypassed via hooking" (a nuance of implementation strength) |

### 2.3 Environment Prerequisites

- A device/emulator with the MITM proxy's CA certificate installed and trusted by the system.
- A **list of first-party domains** already identified per the prerequisite in §1.4, before starting the test session.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0005** to install the app.
2. Use **MASTG-TECH-0011** to set up an interception proxy and intercept communications.

### 3.2 Method A — Basic MITM via Interception Proxy

```bash
# Configure the proxy on the device, install the proxy's CA cert as trusted
mitmproxy --mode regular
```

Run the app, exercising all flows that contact the identified first-party domains. Observe in the proxy: whether that domain's traffic is successfully intercepted (appearing with readable content) or the connection fails/is rejected by the app.

### 3.3 Method B — Parallel System Log Monitoring (Per §1.3)

```bash
adb logcat | grep -iE "pin.*verification|X509Util|certificate.*pin"
```

Run alongside Method A to confirm the **reason** for a connection failure, if one occurs.

### 3.4 Method C — Cross-Verification with Frida Bypass (Complementary, Assessing Strength)

```bash
frida -U -f com.example.app -l universal-ssl-pinning-bypass.js --no-pause
```

If basic MITM (Method A) **fails** (indicating an initial PASS), try again with an active Frida bypass — if MITM **only succeeds** after an explicit bypass, this confirms pinning does exist and function (a strong PASS). If MITM still fails even after attempting a common bypass, consider a more non-standard/robust pinning implementation (a very strong PASS) or another confounding factor.

### 3.5 Method Comparison: When to Use Which

| Method | Tool | When to use |
|---|---|---|
| **A** | Interception proxy | Mandatory baseline — the primary oracle for MITM success/failure |
| **B** | adb logcat | Supporting diagnostic signal to confirm the reason for failure |
| **C** | Frida bypass | Complementary — assesses the relative strength of the pinning implementation |

**Minimum recommended combination:** **A + B (mandatory)**, with **C** as a complement for a deeper strength assessment.

---

### 3.6 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rules:**

> **Evaluation:** *"The test case fails if any relevant first-party domain appears in the intercepted traffic capture. The test case should not fail only because unrelated third-party domains are intercepted."*

---

#### ❌ FAIL / ISSUE — The check is considered FAILED if:

| No | Condition |
|---|---|
| F1 | HTTPS traffic to a **first-party** domain is successfully intercepted and its content read via MITM, regardless of what pinning mechanism was (supposedly) implemented |

**Example evidence (reflecting the real-world pattern of hostname validation errors in §1.6):**

```
[Burp Proxy] Intercepted: https://api.bankingapp.com/v1/login
Request body: {"username":"budi","password":"s3cr3t"}
```

The system log shows no pin verification error of any kind. Interpretation: pinning is not effective for the authentication backend domain — login credentials are fully readable via MITM. **FAIL**.

---

#### ✅ PASS — The check is considered PASSED if:

| No | Condition |
|---|---|
| P1 | All first-party domains **fail** to be intercepted (the connection is rejected by the app), **and** |
| P2 | *(Supporting)* The system log confirms that failure is indeed caused by a pin verification failure, not another reason |

---

#### ⚠️ Important Notes on Assessment

1. **Do not report third-party domains as findings** — per §1.4, this is the most common source of false positives for this test; always filter MITM results to only those domains already identified as first-party.

2. **"MITM fails" is a strong oracle regardless of mechanism** — per §1.1-1.2, this test does not need to know *how* pinning is implemented to conclude its result; this is its main value-add over TEST-0242.

3. **Beware the case of "pinning exists but is flawed in implementation"** — per the real-world evidence in §1.6, do not assume an app is "definitely secure" just because the development team confirms they "have already implemented pinning"; this dynamic test must still be run because a flawed implementation (e.g., failed hostname validation) will still show MITM succeeding.

4. **Severity is modulated:**

   | Factor | Severity |
   |---|---|
   | MITM succeeds on an authentication/financial domain, credentials/tokens are readable | **High** |
   | MITM succeeds on a non-credential first-party domain | **Medium** |
   | All first-party domains fail to be intercepted | **Not a finding** |

5. **Document:** the list of domains tested (first-party vs. third-party), the interception result per domain, system logs related to pin verification, and the results of a Frida bypass verification if performed.

---

## 4. Recommendations

### 4.1 Ensure Hostname Validation Is Applied Alongside Pinning (Addressing the Real-World Case in §1.6)

```java
// Ensure a custom TrustManager/HostnameVerifier does NOT skip hostname validation
// just because the pin matches — both validations must run independently
HostnameVerifier hostnameVerifier = HttpsURLConnection.getDefaultHostnameVerifier();
if (!hostnameVerifier.verify(expectedHost, session)) {
    throw new SSLException("Hostname mismatch");
}
```

### 4.2 Test Pinning Routinely with Basic MITM as Part of CI/Regression Testing

Make basic MITM testing (Method A) part of the routine release cycle — not just a one-time audit — given that minor changes to TLS configuration/libraries can inadvertently weaken a pinning implementation that previously functioned correctly.

### 4.3 Remediation Checklist

- [ ] All first-party domains are confirmed to reject basic MITM
- [ ] Hostname validation runs independently and is not bypassed by the pinning logic
- [ ] System logs are confirmed to show the appropriate pin verification failure
- [ ] MITM testing is included in the routine regression cycle, not just a one-time audit
- [ ] Correlated with the results of MASTG-TEST-0242 to understand the actual implementation mechanism used

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0244 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/network/MASVS-NETWORK/MASTG-TEST-0244.md)
- [MASTG-TEST-0242: Missing Certificate Pinning in Network Security Configuration (a related document in this research series)](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0242/)
- [MASTG-KNOW-0015: Certificate Pinning](https://mas.owasp.org/MASTG/knowledge/android/MASVS-NETWORK/MASTG-KNOW-0015/)
- [Prerequisite: Identifying First-Party Domains](https://github.com/OWASP/mastg/blob/master/prerequisites/identify-first-party-domains.md)
- [MASTG-TECH-0009: Monitoring System Logs](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0009/)

### 5.2 Research and Real-World Cases

- [TheSSLStore: Banking Apps Vulnerability — Man-In-The-Middle Flaw in Certificate Pinning](https://www.thesslstore.com/blog/banking-apps-vulnerability-mitm/)
- [OWASP: Certificate and Public Key Pinning](https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning)
- [Schneier on Security: Security Vulnerabilities in Certificate Pinning](https://www.schneier.com/blog/archives/2017/12/security_vulner_10.html)

### 5.3 Tool Documentation

- [Burp Suite Documentation](https://portswigger.net/burp/documentation)
- [mitmproxy Documentation](https://docs.mitmproxy.org/stable/)
- [Frida — Dynamic Instrumentation Toolkit](https://frida.re/docs/home/)

---

*This document was prepared based on official OWASP MASTG content (`tests-beta/network/MASVS-NETWORK/MASTG-TEST-0244.md`, `MASTG-KNOW-0015`), supplemented with an in-depth cross-reference to the MASTG-TEST-0242 document (the NSC-specific counterpart) in this research series, as well as real-world research on pinning implementation flaws in banking apps (hostname validation failures despite pinning "existing"). The most important methodological nuance: this test is implementation-agnostic — making "MITM success/failure" a truth oracle that does not require knowledge of the implementation mechanism behind the scenes, enabling it to catch the "pinning exists but is implementation-flawed" case, which is structurally undetectable by static audits that only confirm the existence of pinning code.*
