# MASTG-TEST-0272 Identify Dependencies with Known Vulnerabilities in the Android Project

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0272 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-CODE (Code Quality) |
| **Weakness** | MASWE-0044 — *Dependencies with Known Vulnerabilities* |
| **Tipe Pengujian** | Static, Code |
| **Profile** | L1, L2 |
| **Teknik terkait** | MASTG-TECH-0131 (Software Composition Analysis of Android Dependencies at Build Time) |
| **Demo terkait** | — (tidak ada) |
| **Rule resmi** | — (tidak relevan; ini kategori pengujian **Software Composition Analysis/SCA**, bukan pattern-matching kode statis biasa) |
| **CWE terkait** | CWE-1104 (Use of Unmaintained Third Party Components), CWE-937 (OWASP Top Ten 2013 A9 - Using Components with Known Vulnerabilities) |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Overview resmi MASTG untuk test ini sangat ringkas:

> *"In this test case we will identify dependencies in Android Studio."*

Namun rincian substansial justru berada di **MASTG-TECH-0131** yang dirujuknya — teknik yang secara spesifik membahas **Software Composition Analysis (SCA)**: praktik mengidentifikasi seluruh library pihak ketiga yang dipakai proyek, lalu mencocokkan nama dan versinya terhadap basis data kerentanan publik (seperti **National Vulnerability Database/NVD**) untuk menemukan CVE yang sudah diketahui.

### 1.2 Prinsip Kunci: Pindai di Lingkungan Build, Bukan Hanya APK Final

Ini poin metodologis paling penting dari MASTG-TECH-0131:

> *"In Android development, dependencies are resolved and compiled during the build process and eventually become part of the app's DEX files. Therefore, it is essential to scan dependencies as they appear in the build environment, not just within the final APK. This approach ensures that all libraries, including transitive ones, are analyzed accurately."*

Ada dua alasan mengapa **build environment** (bukan APK final) menjadi target yang tepat:

1. **Dependency transitif**: sebuah library yang dideklarasikan aplikasi (mis. Retrofit) **membawa** dependency-nya sendiri (mis. OkHttp, Okio) yang tidak pernah dideklarasikan secara eksplisit di `build.gradle` aplikasi — namun tetap ikut terkompilasi ke dalam DEX final. Memindai APK final saja (setelah shrinking/obfuscation R8) berisiko kehilangan metadata versi yang jelas (nama package/versi bisa berubah atau hilang setelah obfuscation), sementara **build environment** (`~/.gradle/caches/modules-2/files-2.1`) masih menyimpan artefak `.jar`/`.aar` dengan metadata versi utuh yang bisa dicocokkan akurat terhadap basis data CVE.
2. **Akurasi pencocokan**: SCA bergantung pada metadata precise (group ID, artifact ID, versi) — inilah sebabnya integrasi ke **sistem build** (Gradle, sebagai default tool Android Studio) menjadi strategi paling efektif dibanding mencoba menebak versi library dari string yang tersisa di bytecode setelah obfuscation.

### 1.3 Kasus Nyata: IOSched (Aplikasi Resmi Google I/O)

Riset independen menemukan contoh nyata yang mengejutkan justru pada aplikasi berafiliasi Google sendiri:

> Analisis dependency pada aplikasi **IOSched** (aplikasi resmi konferensi Google I/O) menemukan **versi OkHttp yang rentan** dideklarasikan secara eksplisit oleh developer — CVE yang sudah diketahui sejak **2016** (memungkinkan penyerang MITM melewati certificate pinning dengan menyajikan rantai sertifikat dari CA tepercaya non-pinned bersama sertifikat yang di-pin), sementara rilis terbaru aplikasi tersebut yang diperiksa berasal dari **2019** — tiga tahun setelah kerentanan tersebut dipublikasikan dan diperbaiki upstream.

Kasus ini menggambarkan pola risiko yang sangat umum: developer men-deklarasikan versi dependency sekali di awal proyek, lalu **jarang memperbarui** kecuali ada kebutuhan fitur baru — meninggalkan kerentanan yang sudah lama diketahui publik tanpa disadari, bahkan pada proyek yang dikelola tim berpengalaman.

### 1.4 Dependency Rentan yang Umum Ditemukan di Ekosistem Android

Riset SCA pada aplikasi Android sering menemukan pola berulang pada beberapa library populer berikut (per versi rentan yang teridentifikasi dalam berbagai studi):

- **OkHttp** (versi < 2.7.4 / < 3.1.2) — bypass certificate pinning (kasus IOSched di atas)
- **Gson** 2.8.0 — kerentanan deserialisasi
- **commons-compress** 1.19 — beberapa CVE terkait path traversal/DoS pada ekstraksi arsip
- **jackson-databind** 2.9.8 — kerentanan deserialisasi yang terkenal luas di ekosistem JVM
- **snakeyaml** 1.16 — kerentanan deserialisasi YAML

Pola yang sama juga berlaku untuk **Retrofit**, yang secara transitif mewarisi seluruh risiko OkHttp dan Okio — poin yang menegaskan kembali pentingnya analisis dependency transitif (§1.2), bukan hanya dependency yang dideklarasikan langsung.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core, Sesuai MASTG-TECH-0131)

| Tool | Fungsi |
|---|---|
| **OWASP Dependency-Check** (plugin Gradle `org.owasp.dependencycheck`) | Tool SCA resmi yang direkomendasikan MASTG — memindai dependency di build environment terhadap NVD |
| **Gradle** | Sistem build yang diintegrasikan tool SCA |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **OSV-Scanner** (Google) | Scanner SCA berbasis basis data **OSV (Open Source Vulnerabilities)** yang dikelola Google — mendukung ekosistem Maven/Gradle, seringkali lebih cepat memperbarui data dibanding NVD dan tidak memerlukan API key |
| **Snyk** | Platform SCA komersial dengan free tier, terintegrasi CI/CD dan IDE, database kerentanan proprietary yang sering lebih cepat dibanding NVD publik |
| **GitHub Dependabot** | Untuk proyek yang di-host di GitHub — pemindaian otomatis dan pull request perbaikan versi otomatis, terintegrasi langsung ke workflow repository tanpa konfigurasi tambahan |
| **Sonatype OSS Index / Nexus IQ** | Basis data kerentanan open-source alternatif, API gratis untuk penggunaan dasar |
| **Trivy** (Aqua Security) | Scanner serbaguna yang juga mendukung pemindaian dependency Java/Kotlin, populer di ekosistem container namun mendukung filesystem scan proyek Gradle |
| **MobSF** | Fitur bawaan untuk mendeteksi library pihak ketiga beserta versi yang diketahui rentan, sebagai cross-check tambahan pada level APK |
| **JFrog Xray** | Solusi enterprise SCA terintegrasi dengan Artifactory, umum dipakai organisasi besar dengan pipeline CI/CD kompleks |

### 2.3 Prasyarat Lingkungan

- **Butuh akses ke source project/build environment** — direktori cache Gradle (`~/.gradle/caches/modules-2/files-2.1`), bukan hanya file APK final (§1.2).
- **API key NVD direkomendasikan** untuk OWASP Dependency-Check agar mendapat data CVE terkini — dapat diminta gratis lewat https://nvd.nist.gov/developers/request-an-api-key.
- **Untuk pengujian blackbox murni** (hanya APK tanpa akses source), tool seperti MobSF dapat memberi sinyal awal berdasarkan string versi yang masih terbaca di bytecode, meski akurasinya lebih rendah dibanding analisis build environment langsung.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0131** untuk memindai build environment Android Studio lewat Gradle.

### 3.2 Metode A — OWASP Dependency-Check *(metode resmi MASTG-TOOL-0131)*

Pada `build.gradle` modul `app` (bukan `build.gradle` level proyek):

```groovy
plugins {
    id("org.owasp.dependencycheck") version "12.1.1"
}

dependencyCheck {
    formats = listOf("HTML", "XML", "JSON")
    nvd {
        apiKey = "<API_KEY_NVD_ANDA>"
        delay = 16000
    }
}
```

```bash
./gradlew dependencyCheckAnalyze
```

Laporan dihasilkan di `app/build/reports` dalam tiga format (HTML/JSON/XML).

**Catatan teknis penting**: pada versi plugin hingga 12.1.1, dapat muncul error `NoSuchMethodError` terkait `ZipFile.builder()` — solusinya adalah **memaku (pin) versi** `org.apache.commons:commons-compress` sesuai isu yang sudah didokumentasikan komunitas (GitHub `dependency-check/DependencyCheck#7405`).

**Menyaring false positive** dengan file suppression:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<suppressions xmlns="https://jeremylong.github.io/DependencyCheck/dependency-suppression.1.3.xsd">
    <suppress>
        <notes><![CDATA[Library ini tidak benar-benar masuk ke APK final]]></notes>
        <packageUrl regex="true">^pkg:maven/io\.grpc/grpc.*</packageUrl>
        <vulnerabilityName regex="true">.*</vulnerabilityName>
    </suppress>
</suppressions>
```

### 3.3 Metode B — OSV-Scanner (Alternatif Cepat Tanpa API Key)

```bash
# Ekstrak lockfile Gradle terlebih dahulu (bila belum ada)
./gradlew :app:dependencies --configuration releaseRuntimeClasspath > deps.txt

# Atau gunakan format lockfile Gradle native
osv-scanner --lockfile=gradle.lockfile
```

```bash
# Instalasi dan pemindaian langsung pada direktori proyek
go install github.com/google/osv-scanner/cmd/osv-scanner@latest
osv-scanner -r /path/to/android-project
```

### 3.4 Metode C — GitHub Dependabot (Otomatisasi Berkelanjutan)

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "gradle"
    directory: "/"
    schedule:
      interval: "weekly"
```

Dependabot akan secara otomatis membuka pull request setiap kali dependency dengan kerentanan yang diketahui terdeteksi, beserta saran versi perbaikan — mengurangi risiko kasus seperti IOSched (§1.3) di mana kerentanan lama terlewat bertahun-tahun.

### 3.5 Metode D — Snyk (Alternatif Komersial dengan Free Tier)

```bash
npm install -g snyk
snyk auth
snyk test --file=build.gradle
```

### 3.6 Metode E — MobSF (Cross-Check Level APK, untuk Blackbox)

```bash
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
```

Bagian laporan MobSF terkait **library pihak ketiga** dapat memberi sinyal awal bila hanya APK yang tersedia (tanpa akses source/build environment) — namun akurasinya lebih rendah dibanding Metode A-D karena bergantung pada string metadata yang mungkin sudah terpengaruh shrinking/obfuscation.

### 3.7 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Butuh API key? | Cakupan transitif? | Kapan dipakai |
|---|---|---|---|---|
| **A** | OWASP Dependency-Check | Ya (NVD) | ✅ | **Baseline resmi MASTG** |
| **B** | OSV-Scanner | Tidak | ✅ | Alternatif cepat, database OSV sering lebih update |
| **C** | GitHub Dependabot | Tidak (terintegrasi repo) | ✅ | Otomatisasi berkelanjutan, mencegah kasus IOSched terulang |
| **D** | Snyk | Ya (free tier) | ✅ | Alternatif komersial, database proprietary responsif |
| **E** | MobSF | Tidak | Terbatas | Blackbox murni tanpa akses source |

**Kombinasi minimum yang aku rekomendasikan:** **A (baseline resmi) + B/D (cross-check basis data kerentanan berbeda, karena tidak ada satu database yang selalu paling lengkap/terkini) → C (otomatisasi berkelanjutan via Dependabot)** untuk mencegah regresi jangka panjang, bukan hanya audit satu kali.

---

### 3.8 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Observation:** *"The output should include the dependency and the CVE identifiers for any dependency with known vulnerabilities."*
>
> **Evaluation:** *"The test case fails if you can find dependencies with known vulnerabilities."*

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Ditemukan dependency (langsung atau transitif) dengan CVE yang sudah dipublikasikan dan **belum diperbaiki** (belum ada patch/upgrade tersedia) atau **belum diterapkan** meski patch sudah tersedia |
| F2 | CVE yang ditemukan memiliki severity tinggi/kritis (mis. CVSS ≥7) dan **relevan** dengan cara aplikasi memakai library tersebut (bukan fitur yang tidak dipakai) |
| F3 | Dependency transitif (bukan yang dideklarasikan langsung) membawa kerentanan yang tidak disadari karena tidak muncul di `build.gradle` aplikasi secara eksplisit |

**Contoh bukti (ilustratif — MASTG belum menyediakan demo resmi untuk test ini):**

```bash
$ ./gradlew dependencyCheckAnalyze
...
com.squareup.okhttp3:okhttp:3.12.0
    CVE-2016-2402 (CVSS 5.9): Certificate pinning bypass via non-pinned CA in chain
```

Interpretasi: `okhttp:3.12.0` yang dideklarasikan (langsung atau transitif lewat Retrofit) membawa CVE yang sudah diketahui publik dan sudah ada perbaikan di versi lebih baru — **FAIL**, persis pola yang ditemukan pada kasus nyata IOSched (§1.3).

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Seluruh dependency (langsung dan transitif) berada pada versi **tanpa** CVE yang diketahui dan belum diperbaiki |
| P2 | CVE yang terdeteksi sudah dikonfirmasi **tidak relevan** (mis. fitur library yang rentan tidak pernah dipakai aplikasi) dan didokumentasikan lewat suppression file dengan justifikasi jelas — bukan diabaikan tanpa alasan |
| P3 | Proses pembaruan dependency rutin (mis. via Dependabot) sudah berjalan dan riwayatnya menunjukkan patch diterapkan tepat waktu setelah rilis |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Jangan hanya memeriksa `build.gradle` — dependency transitif seringkali menjadi sumber risiko tersembunyi** (§1.2, §1.4). Selalu jalankan pemindaian pada resolved dependency graph penuh (`./gradlew :app:dependencies`), bukan hanya daftar deklarasi langsung.

2. **Jangan menganggap satu tool SCA cukup** — basis data kerentanan (NVD, OSV, database proprietary Snyk) memiliki cakupan dan kecepatan update yang berbeda-beda; kombinasi minimal dua sumber (§3.7) mengurangi risiko false negative dari keterlambatan database tunggal.

3. **Prioritaskan berdasarkan severity DAN relevansi pemakaian** — CVE dengan CVSS tinggi pada fitur library yang tidak pernah dipanggil aplikasi tetap layak dicatat, tapi prioritas remediasi lebih rendah dibanding CVE yang jelas relevan dengan cara aplikasi memakai library tersebut.

4. **Suppression file bukan alasan untuk mengabaikan tanpa investigasi** — setiap suppression harus disertai justifikasi tertulis yang jelas (§3.2), bukan sekadar cara menyembunyikan warning yang mengganggu output CI/CD.

5. **Ini adalah kelas pengujian yang idealnya berkelanjutan, bukan satu kali** — kasus IOSched (§1.3) menunjukkan bahwa kerentanan yang terlewat bisa bertahan bertahun-tahun tanpa proses pembaruan rutin. Rekomendasikan integrasi otomatis (Dependabot/Snyk CI) di atas audit manual satu kali.

6. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | CVE kritis (RCE, bypass autentikasi/pinning) pada dependency yang jelas dipakai aktif | **Kritis/Tinggi** |
   | CVE menengah pada dependency yang dipakai fitur non-inti | **Menengah** |
   | CVE pada dependency transitif yang fiturnya terbukti tidak dipakai (suppressed dengan justifikasi) | **Informational** |

7. **Dokumentasikan:** daftar lengkap dependency (langsung + transitif) beserta versi, CVE ID yang terdeteksi per dependency, severity CVSS, status patch tersedia/diterapkan, dan justifikasi suppression bila ada.

---

## 4. Rekomendasi Perbaikan

### 4.1 Perbarui Dependency ke Versi Terpatch

```groovy
dependencies {
    implementation("com.squareup.okhttp3:okhttp:4.12.0") // versi terkini, bukan 3.12.0
}
```

### 4.2 Terapkan Dependency Locking untuk Reproducibility

```groovy
dependencyLocking {
    lockAllConfigurations()
}
```

```bash
./gradlew dependencies --write-locks
```

Ini memastikan versi yang sudah diverifikasi aman tidak berubah tanpa sengaja saat resolusi dependency dinamis (`+` version range).

### 4.3 Integrasikan SCA sebagai Gate CI/CD Wajib (Bukan Hanya Audit Manual)

```yaml
# Contoh GitHub Actions
- name: Run OWASP Dependency-Check
  run: ./gradlew dependencyCheckAnalyze
- name: Fail build on high severity
  run: |
    if grep -q "CVSS.*[7-9]\.[0-9]\|CVSS.*10\.0" app/build/reports/dependency-check-report.xml; then
      echo "Kerentanan severity tinggi ditemukan!"
      exit 1
    fi
```

### 4.4 Aktifkan Dependabot untuk Pembaruan Berkelanjutan

Rujuk konfigurasi `.github/dependabot.yml` di §3.4 — ini mencegah akumulasi kerentanan lama seperti kasus IOSched.

### 4.5 Checklist Remediasi

- [ ] Seluruh dependency langsung dan transitif sudah dipindai (minimal 2 tool SCA berbeda)
- [ ] CVE dengan severity tinggi/kritis sudah diperbaiki lewat upgrade versi
- [ ] Suppression file (bila ada) disertai justifikasi tertulis
- [ ] Dependency locking diterapkan untuk mencegah regresi versi tak sengaja
- [ ] SCA diintegrasikan sebagai gate CI/CD wajib, bukan hanya audit manual berkala
- [ ] Dependabot/mekanisme pembaruan otomatis serupa sudah diaktifkan
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0272 pada setiap penambahan/pembaruan dependency baru

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0272: Identify Dependencies with Known Vulnerabilities in the Android Project](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0272/)
- [MASWE-0044: Dependencies with Known Vulnerabilities](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0044/)
- [MASTG-TECH-0131: Software Composition Analysis (SCA) of Android Dependencies at Build Time](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0131/)
- [OWASP Dependency-Check — Project Page](https://owasp.org/www-project-dependency-check/)
- [OWASP Top 10 — A06:2021 Vulnerable and Outdated Components](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/)

### 5.2 Dokumentasi Resmi Android

- [Android Developers — Declaring Dependencies (Gradle)](https://developer.android.com/build/dependencies)
- [Android Developers — Insecure API or Library](https://developer.android.com/privacy-and-security/risks/insecure-library)

### 5.3 Riset dan Kasus Nyata

- [Appmattus — Android Security: Scanning Your App for Known Vulnerabilities](https://appmattus.medium.com/android-security-scanning-your-app-for-known-vulnerabilities-421384603fc5)
- [GitHub dotanuki-labs/android-oss-cves-research — Analysis of Open-Source Android Apps and Vulnerable Dependencies](https://github.com/dotanuki-labs/android-oss-cves-research)
- [Guardsquare — Mobile App Security Risks in Android Libraries](https://www.guardsquare.com/blog/hidden-mobile-app-security-risks-in-android-libraries-guardsquare)
- [NVD — CVE-2016-2402 (OkHttp Certificate Pinning Bypass)](https://nvd.nist.gov/vuln/detail/CVE-2016-2402)
- [CWE-1104: Use of Unmaintained Third Party Components](https://cwe.mitre.org/data/definitions/1104.html)

### 5.4 Dokumentasi Tools

- [OWASP Dependency-Check — Documentation](https://jeremylong.github.io/DependencyCheck/)
- [OSV-Scanner (Google)](https://google.github.io/osv-scanner/)
- [Snyk](https://snyk.io/)
- [GitHub Dependabot Documentation](https://docs.github.com/en/code-security/dependabot)
- [Sonatype OSS Index](https://ossindex.sonatype.org/)
- [Trivy — Aqua Security](https://trivy.dev/)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026), dokumentasi resmi Android Developers, serta riset independen (termasuk kasus nyata aplikasi resmi Google I/O, IOSched) tentang dependency vulnerable di ekosistem Android. Nuansa terpenting: pemindaian harus dilakukan pada **build environment** (mencakup dependency transitif), bukan hanya APK final, dan tidak ada satu tool SCA tunggal yang selalu memiliki cakupan basis data kerentanan paling lengkap — kombinasi minimal dua sumber data serta integrasi berkelanjutan (bukan audit satu kali) adalah kunci mencegah akumulasi kerentanan yang terlewat bertahun-tahun seperti terlihat pada kasus nyata yang dibahas.*
