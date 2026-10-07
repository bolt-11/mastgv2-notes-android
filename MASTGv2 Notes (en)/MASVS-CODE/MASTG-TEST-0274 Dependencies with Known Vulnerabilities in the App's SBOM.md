# MASTG-TEST-0274 Dependencies with Known Vulnerabilities in the App's SBOM

| Attribute | Value |
|---|---|
| **Test ID** | MASTG-TEST-0274 |
| **Platform** | Android |
| **MASVS Category** | MASVS-CODE (Code Quality) |
| **Weakness** | MASWE-0044 — *Dependencies with Known Vulnerabilities* (same as MASTG-TEST-0272) |
| **Test Type** | **Static, Developer** — the `developer` tag indicates this test can/ideally should involve cooperation with the development team, rather than being purely independent blackbox testing |
| **Profile** | L1, L2 |
| **Related Techniques** | MASTG-TECH-0130 (SCA of Android Dependencies by Creating a SBOM), MASTG-TOOL-0134 (cdxgen — CycloneDX Generator), MASTG-TOOL-0132 (OWASP Dependency-Track) |
| **Related Tests** | **MASTG-TEST-0272** (Identify Dependencies with Known Vulnerabilities in the Android Project) — both target MASWE-0044, but through a **different artifact and workflow** (see §1.2) |
| **Related Demo** | — (none) |
| **Official Rule** | — (not applicable; based on SBOM/SCA, not code pattern-matching) |
| **Related CWE** | CWE-1104, CWE-937 |

---

## 1. Explanation

### 1.1 Testing Objective

Official MASTG overview:

> *"In this test case we are identifying dependencies with known vulnerabilities by relying on a Software Bill of Material (SBOM)."*

A **SBOM (Software Bill of Materials)** is a structured, machine-readable list of all the components of a piece of software — analogous to the ingredient list on food packaging, but for code. This test specifically targets an **SBOM-based** workflow using the **CycloneDX** format (an SBOM standard developed by the OWASP project itself), differing from MASTG-TEST-0272, which scans the build environment directly.

### 1.2 The Difference from MASTG-TEST-0272: Not Just a Duplicate

Although both target MASWE-0044, these two tests have a significant philosophical difference:

| | MASTG-TEST-0272 | MASTG-TEST-0274 *(this document)* |
|---|---|---|
| **Workflow** | Scanner integrated directly into the build system (Gradle plugin) | Generate a **standardized SBOM artifact** first, then analyze it separately |
| **Intermediate artifact** | None — the result is directly a vulnerability report | **SBOM in CycloneDX format** — can be stored, shared, re-audited at any time |
| **Test-type tag** | `static, code` | `static, developer` — implying cooperation with the development team as an alternative path |
| **Unique added value** | Fast detection directly from the build environment | **Portability and compliance** — the SBOM can be handed off to auditors, regulators, or a separate security team without needing direct access to the source code/build environment |

The most important difference: **an SBOM is a standalone artifact**. Once generated, it can be re-examined, compared across release versions, and shared with third parties (security auditors, regulators, business partners) — without that party needing direct access to the source code or the ability to run the project's build tooling. This is a value the "one-shot" MASTG-TEST-0272 approach, tied to a specific build session, does not have.

### 1.3 The Regulatory and Compliance Context Underlying SBOM's Importance

Unlike most other tests in this research series, this test has a significant **external regulatory push** that explains why SBOM has become an increasingly important topic in the industry:

- **Executive Order 14028** (US, signed May 2021, following the SolarWinds and Colonial Pipeline incidents): mandates SBOMs for software procurement by the US federal government — driving widespread SBOM adoption across the software industry, including vendors selling to the government sector.
- **NTIA Minimum Elements for a SBOM**: a standard of the minimum elements that must be present in a valid SBOM, and **CycloneDX** (the format used by this test) is explicitly designed to **exceed** those minimum elements.
- **App Defense Alliance (ADA) — Mobile Application Security Assessment (MASA)**: an industry standard that specifically requires **identification of third-party dependency risk** for mobile apps — directly relevant for developers who want to distribute an app via Google Play with validated MASA status.

This means this test is **not merely a technical alternative** to MASTG-TEST-0272, but a **response to a real compliance need** that increasingly comes up in the context of enterprise/government procurement and formal security audits — an SBOM is a **common language** understood by compliance auditors, not just engineers.

### 1.4 Two Workflow Components: SBOM Generator and Analysis Platform

The official workflow involves two separate, complementary tool categories:

1. **SBOM Generator** (MASTG-TOOL-0134 — **cdxgen**): a tool that analyzes a project and produces an SBOM file in CycloneDX format (JSON/XML), listing all direct **and transitive** dependencies — the official MASTG-TECH-0130 note confirms: *"Transitive dependencies are supported by [Dependency-Track] for Java and Kotlin"*, consistent with the same emphasis on transitive coverage discussed in depth in document MASTG-TEST-0272.
2. **Analysis Platform** (MASTG-TOOL-0132 — **OWASP Dependency-Track**): a platform that accepts an SBOM as input, then **continuously** matches each component against vulnerability databases (NVD and other sources) — unlike Dependency-Check (used in MASTG-TEST-0272), which performs a one-shot scan per Gradle execution, Dependency-Track is designed as a **living platform** — an uploaded SBOM will continue to be re-monitored as the vulnerability database is updated, without needing to re-run the build/scan each time.

### 1.5 Flexibility of the SBOM Source: Generate It Yourself, or Request It from the Development Team

The official first step gives **two explicitly equal paths**:

> *"Use MASTG-TECH-0130 to generate a SBOM, or **request one in CycloneDX format from the development team**."*

This is consistent with the `developer` tag on this test type (§1.1) — MASTG explicitly acknowledges that a tester (especially during a third-party/external audit) may **not have direct access** to the target app's source code/build environment, but can still carry out this evaluation if the app's development team **has already generated an SBOM as part of their own release process** (an increasingly common practice given the regulatory push in §1.3). This is a cooperation pattern similar to the `identify-first-party-domains` prerequisite discussed in documents MASTG-TEST-0242/0243 in this research series — some aspects of modern security testing **structurally require** collaboration with a party that holds information/artifacts that cannot be derived purely from blackbox analysis.

---

## 2. Tools Used for Testing

### 2.1 Required (Core) Tools, Per MASTG-TECH-0130

| Tool | Function |
|---|---|
| **cdxgen** (MASTG-TOOL-0134) | Generates an SBOM in CycloneDX format from a Java/Kotlin/Android project |
| **OWASP Dependency-Track** (MASTG-TOOL-0132) | A continuous SBOM analysis platform — receives an SBOM via API, matches it against vulnerability databases |

### 2.2 Alternative & Supporting Tools

| Tool | Function |
|---|---|
| **Syft** (Anchore) | An alternative SBOM generator supporting multiple formats (CycloneDX, SPDX) and ecosystems, popular in the container world but also supports Java/Gradle projects |
| **CycloneDX Gradle Plugin** (`org.cyclonedx.bom`) | A native Gradle alternative for generating an SBOM directly from the build, without an external CLI like cdxgen |
| **Trivy** | Besides being a scanner (discussed in MASTG-TEST-0272), Trivy can also **generate** a CycloneDX/SPDX SBOM while analyzing it at the same time |
| **Grype** (Anchore) | A vulnerability scanner that accepts SBOM input (including Syft's output) as an alternative to Dependency-Track for local analysis without a separate server |
| **GUAC** (Google/OpenSSF) | A newer supply-chain metadata aggregation platform, able to consume SBOMs for cross-project dependency-graph analysis at large organizational scale |

### 2.3 Environment Prerequisites

- **Access to the source project** to run `cdxgen`, **or** cooperation with the development team to obtain an SBOM directly (§1.5).
- **A running OWASP Dependency-Track instance** (locally via Docker, or an existing organizational instance) to upload and analyze the SBOM.
- **A Dependency-Track API key** for authentication when uploading an SBOM via API.

---

## 3. Testing Methodology

### 3.1 Official MASTG Steps

1. Use **MASTG-TECH-0130** to generate an SBOM, or request one from the development team in CycloneDX format.
2. Upload the SBOM to **MASTG-TOOL-0132** (Dependency-Track).
3. Check the project in Dependency-Track for use of vulnerable dependencies.

### 3.2 Method A — cdxgen + Dependency-Track *(the main official method)*

```bash
# 1. Generate the SBOM at the root of the Android Studio project
npm install -g @cyclonedx/cdxgen
cdxgen -t java -o sbom.json

# 2. Base64-encode and upload to Dependency-Track via API
BOM_BASE64=$(cat sbom.json | base64 -w 0)
curl -X "PUT" "http://localhost:8081/api/v1/bom" \
     -H 'Content-Type: application/json' \
     -H 'X-API-Key: <YOUR_API_KEY>' \
     -d "{
  \"project\": \"<YOUR_PROJECT_ID>\",
  \"bom\": \"${BOM_BASE64}\"
}"

# 3. Open the Dependency-Track frontend (default: http://localhost:8080)
#    and check the "Vulnerabilities" tab on the uploaded project
```

### 3.3 Method B — CycloneDX Gradle Plugin (Native, No External CLI)

```groovy
// build.gradle
plugins {
    id("org.cyclonedx.bom") version "1.8.2"
}
```

```bash
./gradlew cyclonedxBom
# Output: build/reports/bom.json
```

### 3.4 Method C — Syft + Grype (An Alternative Without a Separate Server)

```bash
# Generate the SBOM
syft dir:. -o cyclonedx-json=sbom.json

# Analyze directly without needing a Dependency-Track instance
grype sbom:sbom.json
```

This approach is suitable for **quick/local audits** without needing to set up Dependency-Track infrastructure (Docker, database) — the trade-off is losing the continuous monitoring capability that is Dependency-Track's main added value (§1.4).

### 3.5 Method D — Trivy as Both Generator and Scanner

```bash
trivy fs --format cyclonedx --output sbom.json .
trivy sbom sbom.json
```

### 3.6 Method E — Requesting an SBOM from the Development Team (An Official Alternative Path)

If direct access to the source code is unavailable (an external third-party audit), submit a formal request:

```
Template request to the development team:
"Please provide the SBOM for [app name] version [release version] in
CycloneDX format (JSON or XML), covering all direct and transitive
dependencies, for the purpose of the MASTG-TEST-0274 security audit."
```

Once received, proceed to Method A steps 2-3 (upload to Dependency-Track) without needing to run the generator yourself.

### 3.7 Method Comparison: When to Use Which

| Method | Tool | Needs a separate server? | Continuous monitoring? | When to use |
|---|---|---|---|---|
| **A** | cdxgen + Dependency-Track | Yes (Dependency-Track) | ✅ | **Official baseline**, best for organizations with long-term compliance needs |
| **B** | CycloneDX Gradle Plugin | No (generation only) | ❌ | Generating an SBOM without an external CLI |
| **C** | Syft + Grype | No | ❌ | Quick/local audits without extra infrastructure |
| **D** | Trivy | No | ❌ | All-in-one, suited to simple CI/CD pipelines |
| **E** | Developer request | N/A | Depends on the team's internal process | A third-party audit without source access |

**Minimum recommended combination:** **A (if the organization has an ongoing compliance/monitoring need) or C/D (for a quick one-time audit)**, complemented by **E** as a formal path when the tester has no direct source-code access.

---

### 3.8 Evaluation Criteria: Positive Case & Negative Case

**Official MASTG rule:**

> **Observation:** *"The output should include a list of dependencies with names and CVE identifiers, if any."*
>
> **Evaluation:** *"The test case fails if you can find dependencies with known vulnerabilities."*

These evaluation criteria are **substantively identical** to MASTG-TEST-0272 — refer to that document's §3.8 for a detailed discussion of severity prioritization, usage relevance, and suppression qualification. The main difference here is purely in the **source of evidence**: an SBOM uploaded to Dependency-Track, rather than a direct report from Dependency-Check.

---

#### ❌ FAIL / ISSUE — The check is declared FAILED when:

| No | Condition |
|---|---|
| F1 | Dependency-Track shows a dependency (direct or transitive) with an unfixed CVE, per the contents of the uploaded SBOM |
| F2 | The SBOM received from the development team is **incomplete/stale** (doesn't reflect the release version being audited) — this condition on its own is worth recording as a process finding, separate from a technical vulnerability finding |

---

#### ✅ PASS — The check is declared PASSED when:

| No | Condition |
|---|---|
| P1 | All dependencies in the SBOM are free of known, unfixed CVEs |
| P2 | The SBOM is verified to be accurate and current (reflecting the release version being audited) |
| P3 | SBOM publication has already become a routine part of the release cycle (not generated specifically only for this audit) — an indicator of compliance-practice maturity |

---

#### ⚠️ Important Notes on Evaluation

1. **Verify the SBOM's freshness and completeness before analyzing its contents** — especially when the SBOM is obtained from the development team (§1.5/§3.6), make sure it was genuinely generated from the version of the code currently being audited, not an old version that happened to be available.

2. **Correlate with MASTG-TEST-0272 when possible** — if the tester has access to both (source code and the ability to request an SBOM), run both as a cross-check; a discrepancy between the two results can indicate an inaccurate/stale SBOM.

3. **Leverage Dependency-Track's continuous monitoring capability** when used — a significant advantage over a one-time audit is that an already-uploaded SBOM will continue to be re-monitored as the vulnerability database grows, without needing to repeat the whole generate-upload process.

4. **Consider compliance value beyond purely technical findings** — even if no active CVE is found, the **complete absence of any SBOM process** in the organization's release cycle is a lower process-maturity signal compared to an organization that already routinely publishes SBOMs — relevant to the compliance audit context (EO 14028, App Defense Alliance MASA) even though it's outside the purely technical scope of "is there a CVE or not."

5. **Severity follows the same pattern as document MASTG-TEST-0272.**

6. **Document:** the SBOM's source (self-generated vs. received from the development team), the SBOM's version/date, the full Dependency-Track analysis results including CVE IDs, and the organization's SBOM-process maturity status (ad-hoc vs. routinely integrated into releases).

---

## 4. Recommendations

Refer to **document MASTG-TEST-0272 §4** for identical technical dependency remediation recommendations (version upgrades, dependency locking, CI/CD gates).

Additional recommendations specific to the SBOM-based workflow:

### 4.1 Integrate SBOM Generation into the Release Pipeline

```yaml
# Example GitHub Actions
- name: Generate SBOM
  run: ./gradlew cyclonedxBom
- name: Upload SBOM to Dependency-Track
  run: |
    curl -X "PUT" "${DTRACK_URL}/api/v1/bom" \
      -H "X-API-Key: ${DTRACK_API_KEY}" \
      -d "{\"project\": \"${PROJECT_ID}\", \"bom\": \"$(base64 -w0 build/reports/bom.json)\"}"
```

### 4.2 Publish an SBOM as Part of Every Release

Store the SBOM as a release artifact (e.g. attached to a GitHub Release) — enabling historical auditing and satisfying compliance expectations (§1.3) without needing to retroactively regenerate old SBOMs.

### 4.3 Leverage Dependency-Track's Automated Notifications

Configure Dependency-Track to send a notification (Slack/email/webhook) whenever a new vulnerability is found in an already-uploaded component — making full use of its continuous monitoring nature, rather than only checking manually from time to time.

### 4.4 Remediation Checklist

- [ ] An SBOM is generated (or received from the development team) and verified to reflect the release version being audited
- [ ] The SBOM is uploaded to and analyzed via Dependency-Track or an equivalent SBOM analysis tool
- [ ] Found vulnerabilities have been prioritized and have a remediation plan
- [ ] The SBOM generation process is integrated into the release pipeline (not an ad-hoc manual process)
- [ ] Automated notifications for new vulnerabilities are configured
- [ ] **Re-verify:** generate and analyze a new SBOM at every app release

---

## 5. References

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0274: Dependencies with Known Vulnerabilities in the App's SBOM](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0274/)
- [MASTG-TEST-0272: Identify Dependencies with Known Vulnerabilities in the Android Project](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0272/)
- [MASWE-0044: Dependencies with Known Vulnerabilities](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0044/)
- [MASTG-TECH-0130: Software Composition Analysis of Android Dependencies by Creating a SBOM](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0130/)

### 5.2 Standards and Regulations

- [OWASP CycloneDX — Authoritative Guide to SBOM](https://cyclonedx.org/guides/sbom/introduction/)
- [Dependency-Track — U.S. Executive Order 14028](https://docs.dependencytrack.org/usage/executive-order-14028/)
- [NowSecure — Executive Order 14028 Updates & Why SBOMs Are Important](https://www.nowsecure.com/blog/2022/06/08/executive-order-14028-updates-why-sboms-are-important/)
- [NowSecure — 4 Things You Can Do with a Mobile SBOM](https://www.nowsecure.com/blog/2022/08/24/4-things-you-can-do-with-a-mobile-sbom/)
- [App Defense Alliance — Mobile Application Security Assessment (MASA)](https://appdefensealliance.dev/masa)
- [NTIA — Minimum Elements for a Software Bill of Materials](https://www.ntia.gov/report/2021/minimum-elements-software-bill-materials-sbom)
- [CWE-1104: Use of Unmaintained Third Party Components](https://cwe.mitre.org/data/definitions/1104.html)

### 5.3 Tool Documentation

- [cdxgen — CycloneDX Generator](https://github.com/CycloneDX/cdxgen)
- [OWASP Dependency-Track](https://dependencytrack.org/)
- [CycloneDX Gradle Plugin](https://github.com/CycloneDX/cyclonedx-gradle-plugin)
- [Syft (Anchore)](https://github.com/anchore/syft)
- [Grype (Anchore)](https://github.com/anchore/grype)
- [Trivy — Aqua Security](https://trivy.dev/)
- [GUAC — Graph for Understanding Artifact Composition](https://github.com/guacsec/guac)

---

*This document was compiled based on OWASP MASTG (latest release as of September 2026), the OWASP CycloneDX standard, and the regulatory context (Executive Order 14028, App Defense Alliance MASA) underlying the importance of SBOM adoption in the modern software industry. Unlike MASTG-TEST-0272, which is a direct one-shot scan, this test's unique value lies in the **portability of the SBOM artifact** — it can be generated once, shared with auditors/regulators, and continuously re-monitored via a platform like Dependency-Track — as well as MASTG's explicit acknowledgment that a tester can obtain an SBOM through cooperation with the development team, not only through independent analysis.*
