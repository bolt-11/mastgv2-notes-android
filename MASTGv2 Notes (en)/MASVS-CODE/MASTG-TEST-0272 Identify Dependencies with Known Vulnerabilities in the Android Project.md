# MASTG-TEST-0272 Identify Dependencies with Known Vulnerabilities in the Android Project

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0272 |
| **Platform** | Android |
| **MASVS Category** | MASVS-CODE (Code Quality) |
| **Weakness** | MASWE-0044 — *Dependencies with Known Vulnerabilities* |
| **Test Type** | Static, Code |
| **Profile** | L1, L2 |
| **Related Techniques** | MASTG-TECH-0131 (Software Composition Analysis of Android Dependencies at Build Time) |
| **Related Demo** | — (none) |
| **Official Rule** | — (not applicable; this is a **Software Composition Analysis (SCA)** test category, not ordinary static pattern-matching) |
| **Related CWE** | CWE-1104 (Use of Unmaintained Third Party Components), CWE-937 (OWASP Top Ten 2013 A9 - Using Components with Known Vulnerabilities) |

---

## 1. Explanation

### 1.1 Testing Objective

The official MASTG overview for this test is very brief:

> *"In this test case we will identify dependencies in Android Studio."*

However, the substantial detail actually lives in **MASTG-TECH-0131**, which it references — a technique specifically about **Software Composition Analysis (SCA)**: the practice of identifying every third-party library used by a project, then matching its name and version against public vulnerability databases (such as the **National Vulnerability Database/NVD**) to find known CVEs.

### 1.2 Key Principle: Scan the Build Environment, Not Just the Final APK

This is the most important methodological point from MASTG-TECH-0131:

> *"In Android development, dependencies are resolved and compiled during the build process and eventually become part of the app's DEX files. Therefore, it is essential to scan dependencies as they appear in the build environment, not just within the final APK. This approach ensures that all libraries, including transitive ones, are analyzed accurately."*

There are two reasons the **build environment** (not the final APK) is the right target:

1. **Transitive dependencies**: a library declared by the app (e.g. Retrofit) **brings along** its own dependencies (e.g. OkHttp, Okio), which are never explicitly declared in the app's `build.gradle` — yet are still compiled into the final DEX. Scanning only the final APK (after R8 shrinking/obfuscation) risks losing clear version metadata (package names/versions may change or disappear after obfuscation), whereas the **build environment** (`~/.gradle/caches/modules-2/files-2.1`) still holds `.jar`/`.aar` artifacts with intact version metadata that can be matched accurately against a CVE database.
2. **Matching accuracy**: SCA relies on precise metadata (group ID, artifact ID, version) — this is why integrating with the **build system** (Gradle, Android Studio's default tool) is the most effective strategy, rather than trying to guess a library's version from strings remaining in the bytecode after obfuscation.

### 1.3 A Real-World Case: IOSched (Google's Official I/O App)

Independent research found a surprising real example, even on an app affiliated with Google itself:

> Dependency analysis of the **IOSched** app (the official Google I/O conference app) found a **vulnerable OkHttp version** explicitly declared by the developers — a CVE that had been known since **2016** (allowing an attacker to perform a MITM attack bypassing certificate pinning by presenting a certificate chain from a trusted, non-pinned CA alongside the pinned certificate), while the latest release of the app examined was from **2019** — three years after the vulnerability was publicly disclosed and fixed upstream.

This case illustrates a very common risk pattern: developers declare a dependency version once at the start of a project, then **rarely update it** unless a new feature is needed — leaving a long-publicly-known vulnerability unnoticed, even in a project maintained by an experienced team.

### 1.4 Vulnerable Dependencies Commonly Found in the Android Ecosystem

SCA research on Android apps frequently finds recurring patterns in the following popular libraries (per vulnerable versions identified in various studies):

- **OkHttp** (version < 2.7.4 / < 3.1.2) — certificate pinning bypass (the IOSched case above)
- **Gson** 2.8.0 — deserialization vulnerability
- **commons-compress** 1.19 — several CVEs related to path traversal/DoS during archive extraction
- **jackson-databind** 2.9.8 — a deserialization vulnerability widely known across the JVM ecosystem
- **snakeyaml** 1.16 — YAML deserialization vulnerability

The same pattern also applies to **Retrofit**, which transitively inherits all of OkHttp's and Okio's risk — a point that reaffirms the importance of analyzing transitive dependencies (§1.2), not just directly declared ones.

---

## 2. Tools Used for Testing

### 2.1 Required (Core) Tools, Per MASTG-TECH-0131

| Tool | Function |
|---|---|
| **OWASP Dependency-Check** (Gradle plugin `org.owasp.dependencycheck`) | The official SCA tool recommended by MASTG — scans dependencies in the build environment against the NVD |
| **Gradle** | The build system the SCA tool integrates with |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **OSV-Scanner** (Google) | An SCA scanner based on Google's **OSV (Open Source Vulnerabilities)** database — supports the Maven/Gradle ecosystem, often faster to update its data than the NVD, and requires no API key |
| **Snyk** | A commercial SCA platform with a free tier, integrated with CI/CD and IDEs, with a proprietary vulnerability database that's often faster to update than the public NVD |
| **GitHub Dependabot** | For projects hosted on GitHub — automated scanning and automatic version-fix pull requests, integrated directly into the repository workflow with no extra configuration |
| **Sonatype OSS Index / Nexus IQ** | An alternative open-source vulnerability database, with a free API for basic use |
| **Trivy** (Aqua Security) | A versatile scanner that also supports Java/Kotlin dependency scanning, popular in the container ecosystem but also supports filesystem scans of Gradle projects |
| **MobSF** | A built-in feature for detecting third-party libraries along with known-vulnerable versions, as an additional cross-check at the APK level |
| **JFrog Xray** | An enterprise SCA solution integrated with Artifactory, commonly used by large organizations with complex CI/CD pipelines |

### 2.3 Environment Prerequisites

- **Requires access to the source project/build environment** — the Gradle cache directory (`~/.gradle/caches/modules-2/files-2.1`), not just the final APK file (§1.2).
- **An NVD API key is recommended** for OWASP Dependency-Check to get current CVE data — it can be requested for free at https://nvd.nist.gov/developers/request-an-api-key.
- **For purely blackbox testing** (only the APK, no source access), a tool like MobSF can provide an initial signal based on version strings still readable in the bytecode, though its accuracy is lower than direct build-environment analysis.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0131** to scan the Android Studio build environment via Gradle.

### 3.2 Method A — OWASP Dependency-Check *(the official MASTG-TOOL-0131 method)*

In the `app` module's `build.gradle` (not the project-level `build.gradle`):

```groovy
plugins {
    id("org.owasp.dependencycheck") version "12.1.1"
}

dependencyCheck {
    formats = listOf("HTML", "XML", "JSON")
    nvd {
        apiKey = "<YOUR_NVD_API_KEY>"
        delay = 16000
    }
}
```

```bash
./gradlew dependencyCheckAnalyze
```

Reports are generated in `app/build/reports` in three formats (HTML/JSON/XML).

**Important technical note**: in plugin versions up to 12.1.1, a `NoSuchMethodError` related to `ZipFile.builder()` can occur — the fix is to **pin the version** of `org.apache.commons:commons-compress` per the issue already documented by the community (GitHub `dependency-check/DependencyCheck#7405`).

**Filtering false positives** with a suppression file:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<suppressions xmlns="https://jeremylong.github.io/DependencyCheck/dependency-suppression.1.3.xsd">
    <suppress>
        <notes><![CDATA[This library does not actually end up in the final APK]]></notes>
        <packageUrl regex="true">^pkg:maven/io\.grpc/grpc.*</packageUrl>
        <vulnerabilityName regex="true">.*</vulnerabilityName>
    </suppress>
</suppressions>
```

### 3.3 Method B — OSV-Scanner (A Quick Alternative Without an API Key)

```bash
# Extract the Gradle lockfile first (if one doesn't exist)
./gradlew :app:dependencies --configuration releaseRuntimeClasspath > deps.txt

# Or use the native Gradle lockfile format
osv-scanner --lockfile=gradle.lockfile
```

```bash
# Install and scan directly on the project directory
go install github.com/google/osv-scanner/cmd/osv-scanner@latest
osv-scanner -r /path/to/android-project
```

### 3.4 Method C — GitHub Dependabot (Continuous Automation)

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "gradle"
    directory: "/"
    schedule:
      interval: "weekly"
```

Dependabot will automatically open a pull request every time a dependency with a known vulnerability is detected, along with a suggested fix version — reducing the risk of cases like IOSched (§1.3), where an old vulnerability went unnoticed for years.

### 3.5 Method D — Snyk (A Commercial Alternative with a Free Tier)

```bash
npm install -g snyk
snyk auth
snyk test --file=build.gradle
```

### 3.6 Method E — MobSF (APK-Level Cross-Check, for Blackbox Testing)

```bash
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
```

The MobSF report section on **third-party libraries** can provide an initial signal when only the APK is available (without access to source/build environment) — though its accuracy is lower than Methods A-D, since it depends on metadata strings that may already have been affected by shrinking/obfuscation.

### 3.7 Method Comparison: When to Use Which

| Method | Tool | Needs an API key? | Transitive coverage? | When to use |
|---|---|---|---|---|
| **A** | OWASP Dependency-Check | Yes (NVD) | ✅ | **Official MASTG baseline** |
| **B** | OSV-Scanner | No | ✅ | A quick alternative, the OSV database is often more current |
| **C** | GitHub Dependabot | No (integrated into the repo) | ✅ | Continuous automation, prevents the IOSched case from recurring |
| **D** | Snyk | Yes (free tier) | ✅ | A commercial alternative, a responsive proprietary database |
| **E** | MobSF | No | Limited | Purely blackbox testing with no source access |

**Minimum recommended combination:** **A (official baseline) + B/D (cross-checking different vulnerability databases, since no single database is always the most complete/current) → C (continuous automation via Dependabot)** to prevent long-term regression, rather than a one-time audit only.

---

### 3.8 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Observation:** *"The output should include the dependency and the CVE identifiers for any dependency with known vulnerabilities."*
>
> **Evaluation:** *"The test case fails if you can find dependencies with known vulnerabilities."*

---

#### ❌ FAIL / ISSUE — The check is declared FAILED when:

| No | Condition |
|---|---|
| F1 | A dependency (direct or transitive) is found with a published CVE that has **not been fixed** (no patch/upgrade is yet available) or has **not been applied** even though a patch is available |
| F2 | A found CVE has a high/critical severity (e.g. CVSS ≥7) and is **relevant** to how the app uses that library (not an unused feature) |
| F3 | A transitive dependency (not one directly declared) carries an unnoticed vulnerability because it doesn't explicitly appear in the app's `build.gradle` |

**Example evidence (illustrative — MASTG does not yet provide an official demo for this test):**

```bash
$ ./gradlew dependencyCheckAnalyze
...
com.squareup.okhttp3:okhttp:3.12.0
    CVE-2016-2402 (CVSS 5.9): Certificate pinning bypass via non-pinned CA in chain
```

Interpretation: `okhttp:3.12.0`, declared (directly or transitively via Retrofit), carries a publicly known CVE that already has a fix in a newer version — **FAIL**, exactly the pattern found in the real-world IOSched case (§1.3).

---

#### ✅ PASS — The check is declared PASSED when:

| No | Condition |
|---|---|
| P1 | All dependencies (direct and transitive) are on versions **without** a known, unfixed CVE |
| P2 | A detected CVE has been confirmed **not relevant** (e.g. the vulnerable library feature is never used by the app) and is documented via a suppression file with a clear justification — not ignored without reason |
| P3 | A routine dependency-update process (e.g. via Dependabot) is already in place, and its history shows patches are applied promptly after release |

---

#### ⚠️ Important Notes on Evaluation

1. **Don't only check `build.gradle` — transitive dependencies are often a hidden source of risk** (§1.2, §1.4). Always run the scan against the full resolved dependency graph (`./gradlew :app:dependencies`), not just the list of direct declarations.

2. **Don't assume one SCA tool is enough** — vulnerability databases (NVD, OSV, Snyk's proprietary database) differ in coverage and update speed; a combination of at least two sources (§3.7) reduces the risk of false negatives from a single database's lag.

3. **Prioritize based on BOTH severity and relevance of usage** — a high-CVSS CVE in a library feature the app never calls is still worth recording, but its remediation priority is lower than a CVE clearly relevant to how the app actually uses that library.

4. **A suppression file is not a reason to ignore something without investigation** — every suppression must come with a clear written justification (§3.2), not merely a way to hide a warning that's cluttering CI/CD output.

5. **This is a test category that ideally should be continuous, not a one-time event** — the IOSched case (§1.3) shows that a missed vulnerability can persist for years without a routine update process. Recommend automated integration (Dependabot/Snyk CI) over a one-time manual audit.

6. **Severity is modulated as follows:**

   | Factor | Severity |
   |---|---|
   | A critical CVE (RCE, authentication/pinning bypass) on a dependency clearly in active use | **Critical/High** |
   | A medium CVE on a dependency used by a non-core feature | **Medium** |
   | A CVE on a transitive dependency whose feature is proven unused (suppressed with justification) | **Informational** |

7. **Document:** the full list of dependencies (direct + transitive) with their versions, the detected CVE ID per dependency, CVSS severity, patch-availability/applied status, and suppression justification if any.

---

## 4. Recommendations

### 4.1 Update Dependencies to Patched Versions

```groovy
dependencies {
    implementation("com.squareup.okhttp3:okhttp:4.12.0") // current version, not 3.12.0
}
```

### 4.2 Implement Dependency Locking for Reproducibility

```groovy
dependencyLocking {
    lockAllConfigurations()
}
```

```bash
./gradlew dependencies --write-locks
```

This ensures versions already verified as safe don't change accidentally during dynamic dependency resolution (`+` version ranges).

### 4.3 Integrate SCA as a Mandatory CI/CD Gate (Not Just a Manual Audit)

```yaml
# Example GitHub Actions
- name: Run OWASP Dependency-Check
  run: ./gradlew dependencyCheckAnalyze
- name: Fail build on high severity
  run: |
    if grep -q "CVSS.*[7-9]\.[0-9]\|CVSS.*10\.0" app/build/reports/dependency-check-report.xml; then
      echo "High-severity vulnerability found!"
      exit 1
    fi
```

### 4.4 Enable Dependabot for Continuous Updates

Refer to the `.github/dependabot.yml` configuration in §3.4 — this prevents the accumulation of old vulnerabilities such as the IOSched case.

### 4.5 Remediation Checklist

- [ ] All direct and transitive dependencies have been scanned (at least 2 different SCA tools)
- [ ] CVEs with high/critical severity have been fixed via a version upgrade
- [ ] Suppression files (if any) are accompanied by written justification
- [ ] Dependency locking is applied to prevent accidental version regression
- [ ] SCA is integrated as a mandatory CI/CD gate, not just a periodic manual audit
- [ ] Dependabot or a similar automated update mechanism is enabled
- [ ] **Re-verify:** re-run MASTG-TEST-0272 on every new dependency addition/update

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0272: Identify Dependencies with Known Vulnerabilities in the Android Project](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0272/)
- [MASWE-0044: Dependencies with Known Vulnerabilities](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0044/)
- [MASTG-TECH-0131: Software Composition Analysis (SCA) of Android Dependencies at Build Time](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0131/)
- [OWASP Dependency-Check — Project Page](https://owasp.org/www-project-dependency-check/)
- [OWASP Top 10 — A06:2021 Vulnerable and Outdated Components](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/)

### 5.2 Official Android Documentation

- [Android Developers — Declaring Dependencies (Gradle)](https://developer.android.com/build/dependencies)
- [Android Developers — Insecure API or Library](https://developer.android.com/privacy-and-security/risks/insecure-library)

### 5.3 Research and Real-World Cases

- [Appmattus — Android Security: Scanning Your App for Known Vulnerabilities](https://appmattus.medium.com/android-security-scanning-your-app-for-known-vulnerabilities-421384603fc5)
- [GitHub dotanuki-labs/android-oss-cves-research — Analysis of Open-Source Android Apps and Vulnerable Dependencies](https://github.com/dotanuki-labs/android-oss-cves-research)
- [Guardsquare — Mobile App Security Risks in Android Libraries](https://www.guardsquare.com/blog/hidden-mobile-app-security-risks-in-android-libraries-guardsquare)
- [NVD — CVE-2016-2402 (OkHttp Certificate Pinning Bypass)](https://nvd.nist.gov/vuln/detail/CVE-2016-2402)
- [CWE-1104: Use of Unmaintained Third Party Components](https://cwe.mitre.org/data/definitions/1104.html)

### 5.4 Tool Documentation

- [OWASP Dependency-Check — Documentation](https://jeremylong.github.io/DependencyCheck/)
- [OSV-Scanner (Google)](https://google.github.io/osv-scanner/)
- [Snyk](https://snyk.io/)
- [GitHub Dependabot Documentation](https://docs.github.com/en/code-security/dependabot)
- [Sonatype OSS Index](https://ossindex.sonatype.org/)
- [Trivy — Aqua Security](https://trivy.dev/)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)

---

*This document was compiled based on OWASP MASTG (latest release as of September 2026), official Android Developers documentation, and independent research (including the real-world case of Google's official I/O app, IOSched) on vulnerable dependencies in the Android ecosystem. The most important nuance: scanning must be performed on the **build environment** (covering transitive dependencies), not just the final APK, and no single SCA tool always has the most complete vulnerability-database coverage — a combination of at least two data sources plus continuous integration (rather than a one-time audit) is key to preventing the accumulation of missed vulnerabilities for years, as seen in the real-world case discussed.*
