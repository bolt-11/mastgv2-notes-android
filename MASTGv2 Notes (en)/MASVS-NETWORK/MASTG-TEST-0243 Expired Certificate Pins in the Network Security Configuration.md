# MASTG-TEST-0243 Expired Certificate Pins in the Network Security Configuration

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0243 |
| **Platform** | Android |
| **MASVS Category** | MASVS-NETWORK (MASVS-NETWORK-2: The app verifies the identity of the server endpoint) |
| **Weakness** | MASWE-0028 — *Insecure Identity Pinning* |
| **Test Type** | Static, Code |
| **Profile** | **L2 only** |
| **Knowledge** | MASTG-KNOW-0014 (Android Network Security Configuration), MASTG-KNOW-0015 (Certificate Pinning) |
| **Prerequisite** | `identify-first-party-domains` — same as MASTG-TEST-0242 |
| **Related Techniques** | MASTG-TECH-0013, MASTG-TECH-0117, MASTG-TECH-0150, MASTG-TECH-0151, MASTG-TECH-0022, MASTG-TECH-0023 |
| **Related Tests** | **MASTG-TEST-0242** (Missing Certificate Pinning in NSC — a conceptual prerequisite; this test assumes a pin **exists**, then checks whether it **remains valid**) |
| **Related Demo** | — (none) |
| **Official Rule** | — (no MASTG semgrep rule; an **official Android AOSP lint rule** is available, `PinSetExpiry` — see §2.1/§3.2) |
| **Related CWE** | CWE-295 (Improper Certificate Validation), CWE-298 (Improper Validation of Certificate Expiration) |

---

## 1. Explanation

### 1.1 Testing Objective

Quote from the official MASTG overview:

> *"Apps can configure expiration dates for pinned certificates in the Network Security Configuration (NSC) by using the `expiration` attribute. When a pin expires, the app no longer enforces certificate pinning and instead relies on its configured trust anchors."*

This test is a **direct complement** to MASTG-TEST-0242. While TEST-0242 asks *"does a pin exist?"*, this test asks *"if a pin exists, is it still valid* (has its `expiration` date not yet passed)?"* — an expired pin is effectively **the same as having no pin at all** from the perspective of the protection it provides, even though it remains textually present in the XML file.

### 1.2 The "Fail-Open" Mechanism — A Deliberate Design Choice, Not a Bug

This is the core concept that must be understood before assessing the findings of this test proportionately. The behavior when a pin expires is **not an Android implementation flaw**, but a **deliberate design decision**, explicitly documented by Android Developers:

> *"Once a pin set expires, Android stops enforcing it (this is done to prevent connectivity issues in apps which do not get updates to their pin set). Connections are then authenticated using the applicable trust anchors."*

This behavior is known in the security community as **"fail open"** — the opposite of **"fail closed"** (which would sever all connections once a pin expires). The rationale behind it is practical: many apps have a user base that **does not always update the app in a timely manner** (updates disabled, legacy devices, app store approval delay). If Android chose **fail closed**, millions of users running older app versions would **lose connectivity entirely** once their pin's `expiration` date passed — even if the server were actually still presenting a valid certificate from a trusted CA.

Community research (CommonsWare, *"Certificate Pinning and Failing Open"*) aptly summarizes this trade-off:

> *"This reduces security temporarily for older app versions but maintains functionality. Users who update get new pins for new certificates, while outdated apps continue working without breaking user experience."*

### 1.3 Why This Is Still Worth Testing Despite Being "By Design"

Precisely **because** this behavior is a deliberate reduction in security (not a bug), a crucial question arises that becomes the core of this test's evaluation: **does the development team actually realize this trade-off, or do they believe pinning is still active when it hasn't been for a long time?**

The official overview highlights this risk explicitly with a concrete example:

> *"If developers assume pinning is still in effect but don't realize it has expired, the app may start trusting CAs it was never intended to."*
>
> Example: *"A financial app previously pinned to its own private CA but, after the pin expires, any certificate valid under the app's configured trust anchors may be accepted, whereas previously it also had to satisfy the pinning policy."*

This scenario describes a **silent security regression** — there is no crash, no conspicuous error log, no visible change in behavior for the user. The app continues to function normally, but the defensive layer against MITM that pinning previously provided (particularly for the private CA in the financial example above) **silently disappears** once that date passes — and because its nature is silent, **the development team may not realize it for months or years** without an active monitoring process.

### 1.4 Not Automatically a FAIL — Depends on the App's Threat Model

This is an important evaluation nuance that distinguishes this test from most other tests in this series. The official overview does not state "an expired pin = always bad," but rather:

> *"Determine whether this behavior is intentional and consistent with the application's threat model."*

Per CommonsWare's research, **an intentionally expired pin with fail-open** is in fact an explicitly recommended best practice stated by the author:

> *"Always set expiration dates on pins and fail open... prepare emergency update procedures for urgent certificate replacements."*

This means the existence of the `expiration` attribute itself is **not a problem** — it is, in fact, recommended over a pin that never expires (which risks permanently bricking connectivity for legacy app versions if a certificate changes unexpectedly). **The real problem arises when**:
- The `expiration` date **has already passed in the past** and **there is no update plan/process** for the pin running — an indication that the pin has been "forgotten," rather than the result of a deliberate decision.
- The affected domain is **first-party and security-sensitive** (financial, authentication), where the silent loss of pinning has real consequences for the app's threat model.

### 1.5 Relationship with MASTG-TEST-0242

| | MASTG-TEST-0242 | MASTG-TEST-0243 *(this document)* |
|---|---|---|
| **Question** | Does a pin **exist** for the first-party domain? | Is the existing pin **still valid** (not yet expired)? |
| **FAIL condition** | No `<pin-set>` at all | A `<pin-set>` exists, but its `expiration` has passed |
| **Prerequisite** | `identify-first-party-domains` (same) | `identify-first-party-domains` (same) |

Logical testing order: run MASTG-TEST-0242 first to map which domains have pins, then MASTG-TEST-0243 to check the temporal validity of the pins found.

---

## 2. Tools Used for Testing

### 2.1 Mandatory Tools (Core)

| Tool | Function |
|---|---|
| **jadx / apktool** | Extraction of AndroidManifest.xml and the NSC |
| **grep / xmlstarlet / yq** | Parsing the `expiration` attribute in `<pin-set>` elements |
| **Android Lint (`PinSetExpiry`)** | **Official AOSP lint rule** (Issue ID: `PinSetExpiry`, Correctness category, since Android Studio 2.3.0/2017) that specifically validates that the `expiration` attribute is valid and **has not expired/is not about to expire soon** — run directly from Android Studio or the `lint` CLI, far more precise for this case than manual parsing because it automatically computes date comparisons |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **date/dateutils (bash)** | Comparing the `expiration` date against the current date for CI/CD automation without requiring the full Android SDK |
| **Python `datetime`** | Same as above, for validation scripts that are more flexible and easier to integrate into non-Gradle pipelines |
| **MobSF** | Sometimes displays the full contents of the NSC including the expiration attribute in the Manifest/Network Analysis report |
| **git blame / git log on `network_security_config.xml`** | For whitebox testing — tracing when the pin was last updated, providing an indication of whether the pin update process runs routinely or has long been neglected (supports the §1.4 assessment of "deliberate vs. forgotten") |

### 2.3 Environment Prerequisites

- **No device/root required** — an APK is sufficient, or, for optimal results, access to the project source code to run Android Lint directly.
- **Need to know the test date** as a comparison baseline (`expiration` in the past relative to when this test is run, not the APK's release date).
- **As with MASTG-TEST-0242**, identifying first-party domains is a mandatory prerequisite before drawing conclusions.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0013** to reverse engineer the app.
2. Use **MASTG-TECH-0117** to obtain the `AndroidManifest.xml`.
3. Use **MASTG-TECH-0150** to check whether `android:networkSecurityConfig` is set.
4. Use **MASTG-TECH-0151** to extract the `expiration` date from every pin in the NSC.
5. Use **MASTG-TECH-0022** to identify the first-party domains.

### 3.2 Method A — Android Lint `PinSetExpiry` *(official Android method, most precise — whitebox)*

If project source code is available (whitebox testing/internal audit):

```bash
cd android-project/
./gradlew lint

# Or target this specific check directly
./gradlew lint -PlintCheck=PinSetExpiry
```

The result will appear in `app/build/reports/lint-results.html`, giving a precise warning for every `<pin-set>` whose `expiration` attribute **has already passed or will soon pass** (not only past-due — this lint check even proactively warns before expiration occurs, per its official description: *"has not already expired or is expiring soon"*).

**Important note**: this built-in Android Lint coverage makes it **the only case in this document series** where an official platform vendor tool (not MASTG) already provides precise detection without needing a custom rule — make it the primary method when source code is available.

### 3.3 Method B — Manual Extraction + Date Comparison (black-box, from the APK only)

```bash
jadx --no-src -d ./out target-app.apk
NSC_FILE=$(grep -oP 'networkSecurityConfig="@xml/\K[^"]+' ./out/resources/AndroidManifest.xml)
NSC_PATH="./out/resources/res/xml/${NSC_FILE}.xml"

# Extract every expiration attribute along with the domains it covers
yq -p=xml -o=json "$NSC_PATH" | jq -r '
  .["network-security-config"]["domain-config"][]? |
  {domains: (.domain // [] | if type=="array" then [.[]."+content"] else [."+content"] end),
   expiration: .["pin-set"]["+@expiration"]}
'
```

```bash
# Compare each expiration date with today's date
TODAY=$(date +%Y-%m-%d)
for exp_date in $(yq -p=xml '.."+@expiration"' "$NSC_PATH" 2>/dev/null); do
    if [[ "$exp_date" < "$TODAY" ]]; then
        echo "[EXPIRED] Expired pin: $exp_date (today: $TODAY)"
    fi
done
```

### 3.4 Method C — Python Script for CI/CD Automation

```python
import xml.etree.ElementTree as ET
from datetime import date

def check_expired_pins(nsc_path):
    tree = ET.parse(nsc_path)
    root = tree.getroot()
    today = date.today()
    findings = []

    for domain_config in root.findall('.//domain-config'):
        domains = [d.text for d in domain_config.findall('domain')]
        pin_set = domain_config.find('pin-set')
        if pin_set is not None:
            exp_str = pin_set.get('expiration')
            if exp_str:
                exp_date = date.fromisoformat(exp_str)
                if exp_date < today:
                    findings.append({
                        'domains': domains,
                        'expiration': exp_str,
                        'days_expired': (today - exp_date).days
                    })
    return findings

results = check_expired_pins('network_security_config.xml')
for f in results:
    print(f"[EXPIRED] Domain: {f['domains']}, expired {f['days_expired']} days ago ({f['expiration']})")
```

### 3.5 Method D — Change History Correlation (Whitebox — Assessing "Deliberate vs. Forgotten")

Per the discussion in §1.4, to assess whether an expired pin reflects a conscious decision or negligence, review the change history of the NSC file:

```bash
git log --follow -p -- app/src/main/res/xml/network_security_config.xml | head -100
git log --follow --format="%ad %s" --date=short -- app/src/main/res/xml/network_security_config.xml
```

If the history shows **no NSC-related commits** for a period far exceeding the recorded `expiration` date, this is a strong indication that the pin was **forgotten**, rather than part of an actively managed fail-open strategy.

### 3.6 Method E — Dynamic Verification (Confirming the Fail-Open Behavior Actually Occurs)

```bash
# Set the test device's system date past expiration (test environment/emulator only)
adb shell date $(date -d "+2 years" +%m%d%H%M%Y.%S)

# Run the app and observe whether a MITM with a system CA (not the pinned CA) now SUCCEEDS
mitmproxy --mode transparent
```

If a MITM using an ordinary system CA certificate (not the previously pinned CA) **succeeds** in penetrating the connection after the pin is declared expired, this is definitive confirmation of fail-open behavior per official Android documentation — useful for validating the team's understanding of the real impact of that pin's expiration.

### 3.7 Method Comparison: When to Use Which

| Method | Tool | Precision | When to use |
|---|---|---|---|
| **A** | Android Lint `PinSetExpiry` | Highest — official AOSP, even proactive (warns before expiration) | **Mandatory if source code is available** |
| **B** | Manual extraction + bash | Good | Black-box, from the APK only |
| **C** | Python script | Good, easy to integrate into CI/CD | Pipeline automation |
| **D** | git history | Contextual — assesses intentionality | Assessing §1.4 (deliberate vs. forgotten) |
| **E** | Dynamic verification | Definitive evidence of runtime behavior | Final confirmation/team education |

**Minimum recommended combination:** **A (if whitebox is available) or B/C (black-box) → D (for intentionality context) → correlate with the first-party classification results from MASTG-TEST-0242**. Integrate Method A into the project's CI/CD pipeline as a proactive preventive measure — it is far better to prevent expired pins than to find them after the fact.

---

### 3.8 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rules:**

> **Observation:** *"The output should contain a list of expiration dates for pinned certificates, along with the domains they apply to... identify which of those domains are relevant first-party domains."*
>
> **Evaluation:** *"The test case fails if any certificate pin configured for a relevant first-party domain has an expiration date in the past. The test case should not fail only because pins for unrelated third-party domains have expired."*

With a **Further Validation Required** clause structurally identical to MASTG-TEST-0242 — confirm that the app actually connects to the affected first-party domain before reporting.

---

#### ❌ FAIL / ISSUE — The check is considered FAILED if:

| No | Condition |
|---|---|
| F1 | A `<pin-set>` for a first-party domain has an `expiration` dated **in the past** relative to the date testing is performed |
| F2 | It is confirmed (Method D) that no pin-update process is running — an indication of negligence, not a consciously managed fail-open strategy |
| F3 | The affected domain is a security-sensitive endpoint (authentication, financial), per the official overview's explicit example, where the loss of pinning significantly impacts the threat model |
| F4 | Dynamic verification (Method E) confirms a MITM using an ordinary system CA successfully penetrates the connection that was previously protected by that pin |

**Example evidence (illustrative — MASTG does not yet provide an official demo for this test):**

```xml
<!-- res/xml/network_security_config.xml -->
<network-security-config>
    <domain-config>
        <domain includeSubdomains="true">api-payment.example.com</domain>
        <pin-set expiration="2023-01-15">   <!-- Tested on 2026-09-15 — expired 3+ years ago -->
            <pin digest="SHA-256">...</pin>
        </pin-set>
    </domain-config>
</network-security-config>
```

```bash
$ TODAY=2026-09-15
$ echo "2023-01-15" # expiration found
[EXPIRED] Expired pin: 2023-01-15 (today: 2026-09-15) — 1339 days ago

$ git log --follow --format="%ad" --date=short -- res/xml/network_security_config.xml
2022-11-03   # last commit — no updates since before the expiration date
```

Interpretation: `api-payment.example.com` — a payment endpoint, clearly first-party and security-sensitive — has a pin that expired **more than 3 years ago**, with no commit history updating it since. **FAIL**, with strong indication of negligence (not a deliberate strategy), matching exactly the scenario the official overview warns about.

---

#### ✅ PASS — The check is considered PASSED if:

| No | Condition |
|---|---|
| P1 | All pins for first-party domains have an `expiration` in the **future** relative to the test date |
| P2 | A first-party domain's pin has indeed expired, **but** is confirmed (Method D + team documentation) to be part of a consciously managed fail-open strategy consistent with the app's threat model (e.g., explicitly documented as an architectural decision, with active monitoring of that fail-open period) |
| P3 | The expired pin only applies to **third-party** domains, out of scope for this test's evaluation |
| P4 | The `<pin-set>` does not include an `expiration` attribute at all (the pin never expires) — not a FAIL condition, but noted as a different trade-off (long-term connectivity risk vs. permanent security, see §1.4) |

**Example output indicating a PASS:**

```bash
$ ./gradlew lint -PlintCheck=PinSetExpiry
BUILD SUCCESSFUL — no PinSetExpiry warnings found
```

---

#### ⚠️ Important Notes on Assessment

1. **This is the test that most demands contextual judgment regarding "intentionality," rather than mere mechanical date detection.** Per §1.4, an expired pin is **not automatically bad** — it is a deliberate feature, even recommended by the security community (fail-open is better than fail-closed to prevent bricking connectivity). Focus the assessment on **whether the team is aware of it and managing it consciously**, not merely "whether the date has passed."

2. **Leverage git history (Method D) as the primary contextual evidence** to distinguish negligence from a deliberate strategy — this is an approach not explicitly mentioned by MASTG but highly practically relevant for satisfying the clause "Determine whether this behavior is intentional."

3. **As with MASTG-TEST-0242, do not demand this of third-party domains.** Focus purely on first-party and security-sensitive domains.

4. **Leverage Android Lint `PinSetExpiry` as prevention, not just detection.** Because this tool is official from AOSP and already integrated into the standard Android Studio build toolchain, recommend the development team enable it as a **build-blocking check** (not just a warning) to prevent expired pins from reaching production in the first place — far more efficient than discovering them through periodic security audits.

5. **Pay attention to proximity to the expiration date, not just whether it has passed.** Per the lint rule's official description (*"has not already expired or **is expiring soon**"*), a pin that will expire soon (e.g., within 30 days) should be reported as a **proactive warning** even though it technically hasn't FAILED yet — giving the team time to update before it actually becomes a problem.

6. **Severity is modulated:**

   | Factor | Severity |
   |---|---|
   | A financial/authentication domain's pin expired long ago, with no evidence of conscious management | **High** |
   | A first-party domain's pin has expired but is confirmed to be part of a well-documented, consciously managed fail-open strategy | **Informational** — not a security finding, recorded as an observation |
   | A pin will expire soon (<30 days) with no scheduled update process | **Low/Medium** — proactive warning |
   | A third-party pin has expired | **Not a finding** |

7. **Document:** the affected domain, the exact expiration date, how long it has been/will be expired, contextual evidence regarding intentionality (git history/team documentation), and the results of dynamic verification if performed.

---

## 4. Recommendations

### 4.1 Implement a Scheduled Pin Update Process

Establish an operational process (ideally integrated with the release calendar) to update the `expiration` date and pin digests **before** the expiration date is reached — do not wait for an incident or an audit to realize it.

### 4.2 Enable Android Lint `PinSetExpiry` as a Build-Blocking Check

```gradle
// app/build.gradle
android {
    lintOptions {
        error 'PinSetExpiry'  // make it an error, not just a warning, so the build fails if detected
    }
}
```

### 4.3 Set an Expiration Period Proportional to the Release Cycle

Per general industry recommendations, set `expiration` with a sufficient margin (e.g., 6-12 months ahead) relative to the app's release cycle, and schedule pin updates as a routine part of every few releases — rather than setting an `expiration` far in the future (multi-year), which risks being forgotten, or too close, which risks being frequently missed without being noticed.

### 4.4 Explicitly Document the Fail-Open Strategy

If the team consciously chooses a fail-open strategy with a particular period (per CommonsWare's recommendation), explicitly document this decision in the app's security architecture documentation, including emergency plans (*"emergency update procedures"*) for cases requiring urgent certificate replacement.

### 4.5 Integrate Proactive Monitoring into CI/CD

```bash
#!/bin/bash
# ci-check-pin-expiration.sh — run as part of a ROUTINE pipeline, NOT only at release time
python3 check_expired_pins.py network_security_config.xml
# Add warnings for pins expiring within the next 60 days
python3 -c "
from datetime import date, timedelta
import check_expired_pins as c
today = date.today()
warning_threshold = today + timedelta(days=60)
# ... proactive warning logic
"
```

### 4.6 Remediation Checklist

- [ ] All first-party domain pins have an `expiration` in the future
- [ ] Android Lint `PinSetExpiry` is enabled as a build-blocking check in the CI/CD pipeline
- [ ] A scheduled pin update process is established as a routine part of the release cycle
- [ ] If a fail-open strategy is deliberately used, it is explicitly documented along with an emergency plan
- [ ] Proactive monitoring for pins expiring soon (60-90 days) is in place
- [ ] **Re-verify:** re-run MASTG-TEST-0243 periodically (not just once during an audit), because this test's temporal nature means its results change over time without any code changes

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0243: Expired Certificate Pins in the Network Security Configuration](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0243/)
- [MASTG-TEST-0242: Missing Certificate Pinning in Network Security Configuration](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0242/)
- [MASWE-0028: Insecure Identity Pinning](https://mas.owasp.org/MASWE/MASVS-NETWORK/MASWE-0028/)
- [MASTG-KNOW-0014: Android Network Security Configuration](https://mas.owasp.org/MASTG/knowledge/android/MASVS-NETWORK/MASTG-KNOW-0014/)
- [MASTG-KNOW-0015: Certificate Pinning](https://mas.owasp.org/MASTG/knowledge/android/MASVS-NETWORK/MASTG-KNOW-0015/)
- [MASTG Prerequisite: Identifying First-Party Domains](https://mas.owasp.org/MASTG/prerequisites/identify-first-party-domains/)
- [OWASP Mobile Top 10 2024 — M5: Insecure Communication](https://owasp.org/www-project-mobile-top-10/2023-risks/m5-insecure-communication)

### 5.2 Official Android Documentation

- [Android Developers — Network Security Configuration (`pin-set` reference)](https://developer.android.com/privacy-and-security/security-config#pin-set)
- [Android Custom Lint Rules — PinSetExpiry](https://googlesamples.github.io/android-custom-lint-rules/checks/PinSetExpiry.md.html)

### 5.3 Research and Community Discussion

- [CommonsWare — Certificate Pinning and Failing Open](https://commonsware.com/blog/2016/11/28/certificate-pinning-failing-open.html)
- [NowSecure — A Security Analyst's Guide to Network Security Configuration in Android P](https://www.nowsecure.com/blog/2018/08/15/a-security-analysts-guide-to-network-security-configuration-in-android-p/)
- [Securevale — Deep Dive into Certificate Pinning on Android](https://securevale.blog/articles/deep-dive-into-certificate-pinning-on-android/)
- [CWE-295: Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)
- [CWE-298: Improper Validation of Certificate Expiration](https://cwe.mitre.org/data/definitions/298.html)

### 5.4 Tool Documentation

- [Android Lint — Documentation](https://developer.android.com/studio/write/lint)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [yq — YAML/XML/JSON processor](https://github.com/mikefarah/yq)
- [mitmproxy](https://mitmproxy.org/)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)

---

*This document was prepared based on OWASP MASTG (latest release as of September 2026), official Android Developers documentation, and security community discussion (CommonsWare) regarding the fail-open design trade-off in certificate pinning. The most important nuance of this test: an expired pin is **not automatically a vulnerability** — it is a deliberate Android design feature intended to prevent connectivity disruption. A correct evaluation requires a contextual assessment of whether that condition reflects a consciously managed security strategy or negligence that went unnoticed by the development team, per the official clause "Determine whether this behavior is intentional and consistent with the application's threat model."*
