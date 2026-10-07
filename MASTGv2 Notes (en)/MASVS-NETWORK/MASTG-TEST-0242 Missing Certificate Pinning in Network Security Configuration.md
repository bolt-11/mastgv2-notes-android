# MASTG-TEST-0242 Missing Certificate Pinning in Network Security Configuration

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0242 |
| **Platform** | Android |
| **MASVS Category** | MASVS-NETWORK (MASVS-NETWORK-2: The app verifies the identity of the server endpoint) |
| **Weakness** | MASWE-0028 — *Insecure Identity Pinning* |
| **Test Type** | Static, Code |
| **Profile** | **L2 only** (not L1 — pinning is an additional *hardening practice*, not a baseline security control) |
| **Knowledge** | MASTG-KNOW-0014 (Android Network Security Configuration), MASTG-KNOW-0015 (Certificate Pinning) |
| **Prerequisite** | `identify-first-party-domains` — **mandatory** before this test can be validly executed (see §1.3) |
| **Related Techniques** | MASTG-TECH-0013 (Reverse Engineering), MASTG-TECH-0117 (Obtaining AndroidManifest), MASTG-TECH-0150 (Analyzing AndroidManifest), MASTG-TECH-0151 (Analyzing NSC), MASTG-TECH-0022 (Information Gathering - Network Communication), MASTG-TECH-0023 (Reviewing Decompiled Java Code) |
| **Related Tests** | **MASTG-TEST-0244** (Missing Certificate Pinning in Network Traffic — the dynamic counterpart, **implementation-agnostic**, not limited to NSC alone) |
| **Related Demo** | — (none) |
| **Official Rule** | — (no official MASTG semgrep rule exists; CodeQL has a ready-to-use public query — see §3.4) |
| **Related CWE** | CWE-295 (Improper Certificate Validation) |

---

## 1. Explanation

### 1.1 Testing Objective

Quote from the official MASTG overview:

> *"Apps can configure certificate pinning using the Network Security Configuration (NSC)... This test checks whether the app configures certificate pinning in the NSC for the relevant first-party domains it connects to."*

This test purely targets **one specific mechanism** out of the many ways to implement certificate pinning on Android: the `<pin-set>` declaration inside a Network Security Configuration file. This is important to understand from the outset — this test is **not** a comprehensive check of "does the app use pinning in any way whatsoever," but specifically "is pinning configured via the NSC for the relevant domains."

### 1.2 Certificate Pinning Mechanism via NSC

Per MASTG-KNOW-0015, when the NSC declares a `<pin-set>` for a domain, the system performs the following process every time it tries to establish a connection:

1. Retrieve and validate the incoming certificate chain.
2. Extract the public key from the certificate.
3. Compute a digest (SHA-256) over the extracted public key.
4. Compare that digest against the locally declared set of pins.

A connection is only considered valid if **at least one** of the declared pins matches the computed digest — this is what makes pinning far stricter than standard TLS validation (which only ensures the certificate was issued by any trusted CA, regardless of which specific CA).

```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <domain-config>
        <domain includeSubdomains="true">owasp.org</domain>
        <pin-set expiration="2028-12-31">
            <pin digest="SHA-256">YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=</pin>
            <pin digest="SHA-256">Vjs8r4z+80wjNcr1YKepWQboSIRi63WsWXhIMN+eWys=</pin>
        </pin-set>
    </domain-config>
</network-security-config>
```

**Important scope to understand**: the NSC only applies to **connections managed by the Android framework** — `HttpsURLConnection` and libraries built on top of it, as well as `WebView` (unless it uses a custom `TrustManager`). **For communication originating from native code, the NSC does not apply**, and other mechanisms must be considered (see §1.5).

### 1.3 Crucial Prerequisite: Identifying First-Party Domains — Not Just "Domains That Appear in Traffic"

This is the single most important and most commonly misunderstood part of this entire test. The official overview states explicitly:

> *"Relevant domains are remote endpoints under the developer's control that support the app's core or security-sensitive functionality. Third-party domains outside the developer's control should not be reported as missing pins only because they appear in app traffic."*

The official prerequisite document (`identify-first-party-domains`) provides concrete criteria:

**First-party domains** (relevant for pinning evaluation):
- Authentication/identity endpoints (login, token issuance, session management)
- Account and user content APIs (reading/writing user data)
- App-specific backend APIs providing core functionality

**Third-party domains** (out of scope for this test, **should not be reported** simply because they are not pinned):
- Analytics, crash-reporting, advertising, social media SDKs

The rationale for this distinction is very practical: **third-party domains are managed by external parties** whose certificates/keys may be rotated at any time without notifying the app developer — forcing pinning onto such domains risks **breaking the app's connectivity** whenever the provider performs routine certificate rotation, without providing any significant security benefit (since the data exchanged with third-party SDKs is generally not the app's most sensitive data).

**Methodological consequence**: the prerequisite document explicitly acknowledges that this information is **generally not derivable from the app binary alone**:

> *"This information is generally not derivable from the app binary alone. Compile a list of first-party domains and services the app is expected to contact, ideally in cooperation with the development team or from architecture and infrastructure documentation. When such information is unavailable, infer likely first-party domains from the app's branding, bundle identifier, and observed traffic, and document the assumptions made."*

This places this test in a category of testing that **structurally requires external context** (collaboration with the development team, architecture documentation) — a pure black-box tester without such access must **explicitly document the assumptions** used to determine which domains are considered first-party, and must not conclude FAIL/PASS without this qualification.

### 1.4 Important Nuance: "Not Found in the NSC" ≠ "No Pinning at All"

The official overview includes a very specific note that is often overlooked:

> *"Note that the app may implement certificate pinning through other mechanisms covered in other tests."*

And in the Evaluation section:

> *"If another certificate pinning implementation is identified for the same domains, such as a custom `TrustManager` or a third-party library, the result should be treated as **not covered by NSC pinning** rather than as a **confirmed absence** of certificate pinning."*

This is a subtle but critical evaluation nuance. Per MASTG-KNOW-0015, there are **four different pinning mechanisms** that an app might use:

| Mechanism | Covered by MASTG-TEST-0242? |
|---|---|
| **Network Security Configuration** (`<pin-set>`) | ✅ Yes — this is what this test checks |
| **Custom `TrustManager`** (`javax.net.ssl`) | ❌ No — out of scope; checked by other static tests (Java/Kotlin code) |
| **Third-party library** (e.g., OkHttp `CertificatePinner`) | ❌ No — same, the scope is code, not the NSC |
| **Native code** (C/C++/Rust) | ❌ No — the NSC does not apply to native code at all |

This means an app could "fail" MASTG-TEST-0242 (no `<pin-set>` in the NSC) while still having solid pinning via `OkHttp.CertificatePinner` configured in Kotlin code. The correct conclusion in this case is **not** "FAIL — no pinning," but rather **"not covered by the NSC mechanism — check other mechanisms before concluding."** This is consistent with why the **dynamic** test MASTG-TEST-0244 was designed to be *implementation-agnostic* — to definitively answer the real question ("is pinning actually enforced, whatever the mechanism?").

### 1.5 Scope by Technology Context (from MASTG-KNOW-0015)

To guide triage, here is a summary of how the NSC interacts with different technology contexts within an app:

| Context | Does the NSC apply? |
|---|---|
| `HttpsURLConnection` and libraries built on top of it | ✅ Yes |
| `WebView` (without a custom `TrustManager`) | ✅ Yes — the NSC is automatically applied to WebView traffic within the same app |
| Native code (JNI, C/C++/Rust) | ❌ No — a separate mechanism is required |
| **Cross-platform frameworks** (Flutter, React Native, Cordova) | **Varies** — Flutter uses `dart:io HttpClient` with its own BoringSSL (see the in-depth discussion of this in the MASTG-TEST-0237 document), so the NSC **does not always apply**; Cordova operates via JavaScript in a WebView and so is generally subject to the NSC |

### 1.6 Pinning's Nature as a *Hardening* Practice, Not an Absolute Control

MASTG-KNOW-0015 honestly acknowledges pinning's limitations:

> *"Certificate pinning is a hardening practice, but it is not foolproof."*

An attacker with access to the APK can **modify the certificate validation logic in the `TrustManager`**, **replace the pinned certificates** in `res/raw/`/`assets/`, or **remove the pins** in the NSC — however, this **invalidates the APK signature**, forcing the attacker to **repackage and re-sign** the APK. This is why MASTG-KNOW-0015 refers to the need for **integrity checks, runtime verification, and additional obfuscation** (MASTG-TECH-0012) as complements to pinning — not pinning itself as the sole layer of defense.

### 1.7 Real-World Case: Certificate Validation Failures in Financial Apps

Two recent CVEs (2025) illustrate the real-world impact of weaknesses related to this area:

- **CVE-2025-56146** (IndSMART banking app, India): a combination of an insecure WebView (JavaScript enabled, loading URLs directly from an Intent without adequate validation) and **no TLS/SSL error handling** — allowing a MITM attacker on the same network to intercept login flows, OTPs, and UPI payments.
- **CVE-2025-63432** (Xtool AnyScan, a vehicle diagnostic app): the app **failed to validate the TLS certificate** from its update server, allowing a MITM attacker to intercept, decrypt, and modify the app's update traffic.

While both cases are more accurately classified as basic certificate validation failures (rather than specifically "no pinning"), both illustrate the **real-world consequences** of the broader risk category (MASWE-0028/CWE-295) that pinning aims to mitigate as an additional defensive layer — especially for endpoints handling financial/credential data, as exemplified by both cases.

---

## 2. Tools Used for Testing

### 2.1 Mandatory Tools (Core)

| Tool | Function |
|---|---|
| **jadx / apktool** | Extraction of AndroidManifest.xml and the NSC (same as MASTG-TEST-0235) |
| **grep / xmlstarlet / yq** | Searching and parsing `<pin-set>`, `<domain>` elements in the NSC |
| **jadx (full decompile)** | Searching for hardcoded domain references in code for first-party identification (MASTG-TECH-0022) |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **CodeQL** (`java-android-missing-certificate-pinning` — public query) | Ready-to-use query from the GitHub Security Lab that detects network connections **without any pinning** (covers NSC, `CertificatePinner`, and custom `TrustManager` simultaneously) — broader coverage than pure MASTG-TEST-0242, useful as a comprehensive cross-check |
| **apkleaks / MASTG-TOOL for string extraction** | Collects all domains referenced in the APK as first-party candidates (MASTG-TECH-0022) |
| **MobSF** | Displays the list of domains found in the APK along with indication of the presence/absence of NSC and pinning |
| **Frida** | Hooking `CertificatePinner`/`X509TrustManager`/`HostnameVerifier` to dynamically confirm pinning is actually active (complements MASTG-TEST-0244) |
| **mitmproxy / Burp Suite with a CA not trusted by the system** | Definitive dynamic test — if a MITM with a CA that is **not** in the pinning trust anchor succeeds, pinning is not enforced (this is the core methodology of MASTG-TEST-0244) |
| **testssl.sh** | A supplement to check the validity/characteristics of the first-party server's certificate from an external perspective |

### 2.3 Environment Prerequisites

- **Static NSC analysis does not require a device/root** — an APK is sufficient.
- **Cooperation with the development team/architecture documentation is highly recommended** before concluding final results, per §1.3 — without this, the tester must explicitly document the assumptions used for first-party domain identification.
- **Dynamic testing (Frida/mitmproxy) requires a device** to confirm non-NSC pinning layers (§1.4) before reaching a final FAIL conclusion.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0013** to reverse engineer the app.
2. Use **MASTG-TECH-0117** to obtain the `AndroidManifest.xml`.
3. Use **MASTG-TECH-0150** to check whether `networkSecurityConfig` is set in the `<application>` tag.
4. Use **MASTG-TECH-0151** to extract all domains from `<domain-config>` elements that have a `<pin-set>`.
5. Use **MASTG-TECH-0022** to identify the first-party domains the app contacts.

### 3.2 Method A — NSC Extraction + Correlation with First-Party Domains *(official primary method)*

```bash
jadx --no-src -d ./out target-app.apk
MANIFEST=./out/resources/AndroidManifest.xml

# 1. Check whether the NSC is set
grep -i "networkSecurityConfig" "$MANIFEST"

# 2. Extract all domains that have a pin-set
NSC_FILE=$(grep -oP 'networkSecurityConfig="@xml/\K[^"]+' "$MANIFEST")
yq -p=xml -o=json './out/resources/res/xml/'"${NSC_FILE}"'.xml' | jq '.["network-security-config"]["domain-config"]'

# 3. Collect ALL domains referenced in the code (first-party candidates)
jadx -d ./decompiled target-app.apk
rg -ohI '([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}' ./decompiled/sources/ | sort -u > all_domains_found.txt

# 4. Compare pinned domains vs. domains found in the code
diff <(sort all_domains_found.txt) <(yq -p=xml -o=json "./out/resources/res/xml/${NSC_FILE}.xml" | jq -r '.. | .domain? // empty' | sort)
```

**Crucial next step (not automated)**: from the list of domains in `all_domains_found.txt`, **manually classify** which ones are first-party (authentication, account APIs, core backend) vs. third-party (analytics, advertising, SDKs) per the criteria in §1.3 — do not treat every domain that appears in the code as a candidate that "must" be pinned.

### 3.3 Method B — Contextualization via MASTG-TECH-0022 (Domain Classification with Code Context)

```bash
# Find domains WITH the context of their invocation — the class/method referencing them
rg -n -B5 '([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}' ./decompiled/sources/ | grep -B5 "login\|auth\|token\|account\|payment"
```

Domains that appear in the context of classes/functions named `AuthManager`, `LoginActivity`, `PaymentService`, etc. are strong first-party candidates — while domains appearing in known third-party vendor classes/packages (`com.google.firebase.analytics`, `com.facebook.ads`) are strong third-party candidates.

### 3.4 Method C — Public CodeQL Query (Broader Coverage Than NSC Alone)

```bash
codeql database create ./cqldb --language=java --command="./gradlew assembleRelease"
codeql database analyze ./cqldb java/android-missing-certificate-pinning --format=sarif-latest --output=result.sarif
```

This public query (from CodeQL Query Help, CWE-295) detects network connections that **do not implement pinning via any means** — whether via the NSC, `OkHttp CertificatePinner`, or a custom `TrustManager` — making its results useful as a **full-coverage comparison** against the results of Method A, which purely targets the NSC. If CodeQL finds unpinned connections that were **not** caught as "missing" by Method A, this is an indication that the domain might use a non-NSC mechanism that **successfully implements** pinning (a PASS case via another mechanism, §1.4) — or conversely, truly has no pinning at all through any path.

### 3.5 Method D — Checking for Non-NSC Mechanisms (Complementary, Not a Replacement)

Because a "not found in the NSC" result does not automatically mean an absolute FAIL (§1.4), also check for other mechanisms before concluding:

```bash
# Custom TrustManager
rg -n 'class \w+ implements X509TrustManager|extends X509TrustManager' ./decompiled/sources/

# OkHttp CertificatePinner
rg -n 'CertificatePinner\.Builder\(\)|new CertificatePinner' ./decompiled/sources/

# Native code — check for native libraries that might handle TLS themselves
find . -name "*.so" | xargs -I{} sh -c 'rabin2 -zz {} | grep -i "pin\|sha256\|certificate"' 2>/dev/null
```

If either is found for the same first-party domain, change the conclusion from "FAIL — no pinning" to "not covered by NSC — check the security of that alternative mechanism's implementation" (continue analyzing the quality of its implementation, rather than stopping at "found to exist").

### 3.6 Method E — Dynamic Verification (Correlation with MASTG-TEST-0244)

```bash
# Set up mitmproxy with a CA NOT in the app's pin-set
mitmproxy --mode transparent
# Monitor logcat for indications pinning is functioning
adb logcat | grep -i "X509Util\|Pin verification failed\|CertificatePinner"
```

If the system log shows `Pin verification failed` or similar, and the app's connection **fails** — pinning is proven active and functional (a definitive PASS for that domain, regardless of mechanism). If the connection **succeeds** despite an unauthorized proxy CA — pinning is not enforced for that domain (FAIL, complementing the static result).

### 3.7 Method Comparison: When to Use Which

| Method | Coverage | Answers first-party classification? | When to use |
|---|---|---|---|
| **A** | Pure NSC | ❌ (requires separate manual classification) | Mandatory official baseline |
| **B** | Code contextualization | ✅ (aids classification) | Mandatory complement to Method A |
| **C** | All mechanisms (CodeQL) | ❌ | Full-coverage cross-check |
| **D** | Specific non-NSC mechanisms | ❌ | Before reaching a final FAIL conclusion (§1.4) |
| **E** | Runtime, implementation-agnostic | ❌ | **Mandatory final confirmation** — the most definitive answer |

**Minimum recommended combination:** **A+B (baseline + first-party classification) → D (check other mechanisms before concluding FAIL) → E (final dynamic confirmation, ideally via MASTG-TEST-0244)**. Never report a pure FAIL based solely on Method A's result without steps D and E, per the official overview's explicit warning about the risk of premature conclusions (§1.4).

---

### 3.8 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rules:**

> **Observation:** *"The output should contain a list of domains that enable certificate pinning. The output should also identify any relevant first-party domains that were found in the app but do not have a pin set."*
>
> **Evaluation:** *"The test case fails if the app connects to relevant first-party domains but no `networkSecurityConfig` is set, or if `networkSecurityConfig` is set but does not enable certificate pinning for those domains. The test case should not fail only because unrelated third-party domains are not pinned."*

With the official **Further Validation Required** clause:

> *"Before reporting a missing pin, confirm that the app actually establishes connections to the relevant first-party domains"* — either via static tracing (MASTG-TECH-0023) or dynamic capture/hooking.

---

#### ❌ FAIL / ISSUE — The check is considered FAILED if:

| No | Condition | Per official clause |
|---|---|---|
| F1 | The app is confirmed to connect to relevant first-party domains, **but there is no** `networkSecurityConfig` at all | Main clause |
| F2 | `networkSecurityConfig` exists, **but there is no** `<pin-set>` for that first-party domain | Main clause |
| F3 | A `<pin-set>` exists for a first-party domain, **and** it is confirmed there is no other pinning mechanism (custom TrustManager/library/native) covering it (Method D) | Main clause + "Further Validation" |
| F4 | Dynamic verification (Method E/MASTG-TEST-0244) confirms a MITM **successfully** penetrated a connection to that first-party domain | Definitive evidence |

**Example evidence (illustrative — MASTG does not yet provide an official demo for this test):**

```xml
<!-- res/xml/network_security_config.xml -->
<network-security-config>
    <domain-config>
        <domain includeSubdomains="true">cdn.example.com</domain>  <!-- Static asset CDN, third-party-ish -->
        <pin-set><pin digest="SHA-256">...</pin></pin-set>
    </domain-config>
    <!-- NO domain-config for api-auth.example.com -->
</network-security-config>
```

```bash
$ rg -n 'api-auth\.example\.com' ./decompiled/sources/com/example/target/auth/AuthManager.java
com/example/target/auth/AuthManager.java:22:    private static final String AUTH_ENDPOINT = "https://api-auth.example.com/v2/token";
```

Interpretation: `api-auth.example.com` — a clearly first-party and security-sensitive authentication endpoint — **has no pin-set** in the NSC, while `cdn.example.com` (a likely third-party/less sensitive candidate) is the one that is pinned. **FAIL**, with the note that the pinning in place is in fact misprioritized.

---

#### ✅ PASS — The check is considered PASSED if:

| No | Condition |
|---|---|
| P1 | All confirmed first-party domains contacted by the app have a valid `<pin-set>` in the NSC |
| P2 | A first-party domain has no `<pin-set>` in the NSC, **but** is confirmed to use another well-functioning pinning mechanism (custom TrustManager/OkHttp CertificatePinner, confirmed via Method D+E) |
| P3 | The unpinned domain is **confirmed to be purely third-party** (analytics/advertising/SDK) per the criteria in §1.3 — not considered a finding |
| P4 | Dynamic verification (Method E) confirms a MITM **fails** to penetrate connections to all first-party domains |

---

#### ⚠️ Important Notes on Assessment

1. **Classifying first-party vs. third-party is the single most decisive and most easily misjudged step in this entire test.** Never report a domain as "missing pin" simply because it appears in traffic/code — perform explicit classification per the criteria in §1.3, and **document the assumptions** if authoritative information from the development team is not available.

2. **"Not found in the NSC" must be further verified before concluding FAIL** — per §1.4, other pinning mechanisms (custom TrustManager, OkHttp `CertificatePinner`, native code) may well cover the same domain. A report that concludes FAIL purely from the absence of a `<pin-set>` without checking other mechanisms **does not meet the official evaluation standard for this test**.

3. **The "Further Validation Required" clause is mandatory, not optional** — confirm that the app actually connects to the suspected first-party domain (via static MASTG-TECH-0023 or dynamic capture/hooking) before reporting a missing pin.

4. **This test is L2 profile only** — not because it's unimportant, but because this reflects that pinning is an additional *hardening* measure on top of an already-correct TLS baseline (MASTG-TEST-0217/0218/0234/0235), relevant especially for apps with higher security requirements (financial, health, very sensitive data).

5. **Do not demand pinning on third-party domains** — this is explicitly prohibited by the official evaluation ("should not fail only because unrelated third-party domains are not pinned") and is also operationally unrealistic (risk of downtime due to external provider certificate rotation).

6. **Cross-platform frameworks require special attention** (§1.5) — for Flutter apps, the absence of a `<pin-set>` in the NSC may be entirely irrelevant if Dart traffic is not subject to the NSC at all (see the in-depth discussion of this in the MASTG-TEST-0237 document) — pinning for Flutter likely needs to be implemented at the `dio`/`http` package level directly.

7. **Severity is modulated by the sensitivity of the function of the unpinned first-party domain:**

   | Factor | Severity |
   |---|---|
   | Authentication/payment/fund-transfer endpoint not pinned at all (without an alternative mechanism) | **High** |
   | General account/user data API endpoint not pinned | **Medium** |
   | A pin-set exists but has expired (`expiration` passed) without an update | **Medium-High** — may cause pinning to fail-open depending on implementation |
   | Third-party domain not pinned | **Not a finding** |

8. **Document:** the complete list of domains found in the code, first-party/third-party classification with justification (including the source — team documentation/independent assumption), pin-set status for each first-party domain, the results of checking non-NSC mechanisms, and the results of dynamic verification.

---

## 4. Recommendations

### 4.1 Apply a Pin-Set for All First-Party Domains

```xml
<network-security-config>
    <domain-config>
        <domain includeSubdomains="true">api-auth.example.com</domain>
        <domain includeSubdomains="true">api.example.com</domain>
        <pin-set expiration="2027-06-30">
            <pin digest="SHA-256">[digest of the current leaf/intermediate certificate's public key]</pin>
            <pin digest="SHA-256">[backup digest — e.g. from another CA/intermediate, MUST be present]</pin>
        </pin-set>
    </domain-config>
</network-security-config>
```

**Always include a backup pin** — per MASTG-KNOW-0015, this is crucial to maintain connectivity if the primary certificate changes unexpectedly (emergency rotation, CA compromise) without requiring an urgent app update.

### 4.2 Proactively Manage the Pin Lifecycle

Establish an operational process to update pins **before** the `expiration` date is reached, and before production certificates are actually rotated — expired pins can potentially cause service disruption or, depending on implementation, cause pinning to silently stop functioning.

### 4.3 Consider Layered Pinning for Non-NSC Contexts

For components not covered by the NSC (native code, certain cross-platform frameworks), implement a separate pinning mechanism appropriate to that context — e.g., OkHttp `CertificatePinner` for non-`HttpsURLConnection` Kotlin/Java code, or a plugin-level pinning solution for Flutter (`http_certificate_pinning`, a custom `dio` interceptor).

### 4.4 Supplement with Integrity Checks and Obfuscation

Per MASTG-KNOW-0015, pinning alone is vulnerable to APK modification (repackaging). Combine it with runtime integrity checks (MASTG-TECH-0012) and obfuscation to make bypass attempts more difficult.

### 4.5 Integrate into CI/CD

```bash
#!/bin/bash
# ci-check-cert-pinning.sh
APK=$1
jadx --no-src -d /tmp/nsc_check "$APK" 2>/dev/null
NSC=$(grep -oP 'networkSecurityConfig="@xml/\K[^"]+' /tmp/nsc_check/resources/AndroidManifest.xml)
if [ -z "$NSC" ]; then
    echo "[WARNING] No networkSecurityConfig found — manually verify first-party domains"
else
    grep -c "pin-set" "/tmp/nsc_check/resources/res/xml/${NSC}.xml"
fi
```

### 4.6 Remediation Checklist

- [ ] The list of first-party domains has been compiled in cooperation with the development team/architecture documentation (or documented assumptions where unavailable)
- [ ] All first-party domains have a `<pin-set>` in the NSC with at least one backup pin
- [ ] Domains not covered by the NSC have been checked for alternative pinning mechanisms (TrustManager/library/native)
- [ ] A process for updating pins before expiration is established as a routine operational practice
- [ ] Dynamic verification (MASTG-TEST-0244) has been performed to confirm pinning is actually functioning
- [ ] Pinning is supplemented with integrity checks/obfuscation for apps with high security requirements
- [ ] **Re-verify:** re-run MASTG-TEST-0242 on the final release APK after remediation

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0242: Missing Certificate Pinning in Network Security Configuration](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0242/)
- [MASTG-TEST-0244: Missing Certificate Pinning in Network Traffic](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0244/)
- [MASWE-0028: Insecure Identity Pinning](https://mas.owasp.org/MASWE/MASVS-NETWORK/MASWE-0028/)
- [MASTG-KNOW-0014: Android Network Security Configuration](https://mas.owasp.org/MASTG/knowledge/android/MASVS-NETWORK/MASTG-KNOW-0014/)
- [MASTG-KNOW-0015: Certificate Pinning](https://mas.owasp.org/MASTG/knowledge/android/MASVS-NETWORK/MASTG-KNOW-0015/)
- [MASTG-TECH-0022: Information Gathering - Network Communication](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0022/)
- [MASTG Prerequisite: Identifying First-Party Domains](https://mas.owasp.org/MASTG/prerequisites/identify-first-party-domains/)
- [OWASP Mobile Top 10 2024 — M5: Insecure Communication](https://owasp.org/www-project-mobile-top-10/2023-risks/m5-insecure-communication)

### 5.2 Official Android Documentation

- [Android Developers — Network Security Configuration (Certificate Pinning section)](https://developer.android.com/privacy-and-security/security-config#CertificatePinning)
- [Android Developers — Security with network protocols](https://developer.android.com/training/articles/security-ssl)

### 5.3 Research and Real-World Cases

- [Securevale — Deep Dive into Certificate Pinning on Android](https://securevale.blog/articles/deep-dive-into-certificate-pinning-on-android/)
- [CodeQL Query Help — Android Missing Certificate Pinning](https://codeql.github.com/codeql-query-help/java/java-android-missing-certificate-pinning/)
- [CVE-2025-56146 — Missing SSL Certificate Validation in Indian Bank IndSMART Android App](https://medium.com/@parvbajaj2000/cve-2025-56146-missing-ssl-certificate-validation-in-indian-bank-indsmart-android-app-9db200ac1c69)
- [CVE-2025-63432 — Xtool AnyScan Missing SSL Certificate Validation](https://api.osv.dev/v1/vulns/CVE-2025-63432)
- [Approov — How to Protect Against Certificate Pinning Bypassing](https://approov.io/blog/how-to-protect-against-certificate-pinning-bypassing)
- [CWE-295: Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)

### 5.4 Tool Documentation

- [OkHttp CertificatePinner — Documentation](https://square.github.io/okhttp/features/https/#certificate-pinning-kotlinjava)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [Frida — Dynamic instrumentation toolkit](https://frida.re/docs/javascript-api/)
- [mitmproxy](https://mitmproxy.org/)
- [testssl.sh](https://testssl.sh/)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)

---

*This document was prepared based on OWASP MASTG (latest release as of September 2026), official Android Developers documentation, public CodeQL queries, and real-world research and CVE cases related to certificate validation in Android applications. The most important nuance of this test is the necessity of classifying first-party vs. third-party domains before reporting findings, and ensuring that the absence of a pin in the NSC is not automatically concluded to be an absolute absence of pinning — other mechanisms (custom TrustManager, third-party library, native code) must be checked first, per the official "Further Validation Required" clause.*
