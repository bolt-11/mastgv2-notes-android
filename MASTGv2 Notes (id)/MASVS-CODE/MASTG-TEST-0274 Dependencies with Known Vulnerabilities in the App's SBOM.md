# MASTG-TEST-0274 Dependencies with Known Vulnerabilities in the App's SBOM

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0274 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-CODE (Code Quality) |
| **Weakness** | MASWE-0044 — *Dependencies with Known Vulnerabilities* (sama seperti MASTG-TEST-0272) |
| **Tipe Pengujian** | **Static, Developer** — tag `developer` mengindikasikan test ini dapat/idealnya melibatkan kerja sama dengan tim developer, bukan murni blackbox independen |
| **Profile** | L1, L2 |
| **Teknik terkait** | MASTG-TECH-0130 (SCA of Android Dependencies by Creating a SBOM), MASTG-TOOL-0134 (cdxgen — CycloneDX Generator), MASTG-TOOL-0132 (OWASP Dependency-Track) |
| **Test terkait** | **MASTG-TEST-0272** (Identify Dependencies with Known Vulnerabilities in the Android Project) — sama-sama menyasar MASWE-0044, namun lewat **artefak dan alur kerja yang berbeda** (lihat §1.2) |
| **Demo terkait** | — (tidak ada) |
| **Rule resmi** | — (tidak relevan; berbasis SBOM/SCA, bukan pattern-matching kode) |
| **CWE terkait** | CWE-1104, CWE-937 |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Overview resmi MASTG:

> *"In this test case we are identifying dependencies with known vulnerabilities by relying on a Software Bill of Material (SBOM)."*

**SBOM (Software Bill of Materials)** adalah daftar terstruktur dan dapat dibaca mesin dari seluruh komponen software — analog dengan daftar bahan pada kemasan makanan, tapi untuk kode. Test ini secara spesifik menyasar alur kerja **berbasis SBOM** menggunakan format **CycloneDX** (standar SBOM yang dikembangkan proyek OWASP sendiri), berbeda dari MASTG-TEST-0272 yang langsung memindai build environment secara langsung.

### 1.2 Perbedaan dengan MASTG-TEST-0272: Bukan Sekadar Duplikasi

Meski keduanya sama-sama menyasar MASWE-0044, kedua test ini punya perbedaan filosofis yang signifikan:

| | MASTG-TEST-0272 | MASTG-TEST-0274 *(dokumen ini)* |
|---|---|---|
| **Alur kerja** | Scanner terintegrasi langsung ke build system (plugin Gradle) | Hasilkan **artefak SBOM terstandarisasi** terlebih dahulu, baru dianalisis terpisah |
| **Artefak perantara** | Tidak ada — hasil langsung berupa laporan kerentanan | **SBOM format CycloneDX** — dapat disimpan, dibagikan, diaudit ulang kapan saja |
| **Tag tipe test** | `static, code` | `static, developer` — mengisyaratkan kerja sama tim developer sebagai jalur alternatif |
| **Nilai tambah unik** | Deteksi cepat langsung dari lingkungan build | **Portabilitas dan compliance** — SBOM dapat diserahkan ke auditor, regulator, atau tim keamanan terpisah tanpa perlu akses langsung ke source code/build environment |

Perbedaan paling penting: **SBOM adalah artefak yang berdiri sendiri**. Begitu dihasilkan, ia dapat diperiksa ulang, dibandingkan antar versi rilis, dibagikan ke pihak ketiga (auditor keamanan, regulator, mitra bisnis) — tanpa pihak tersebut perlu memiliki akses langsung ke source code atau kemampuan menjalankan build tool proyek. Inilah nilai yang tidak dimiliki pendekatan MASTG-TEST-0272 yang bersifat "sekali jalan" terikat pada sesi build tertentu.

### 1.3 Konteks Regulasi dan Compliance yang Mendasari Pentingnya SBOM

Berbeda dari kebanyakan test lain dalam seri riset ini, test ini memiliki **dorongan regulasi eksternal** yang signifikan yang menjelaskan mengapa SBOM menjadi topik yang semakin penting di industri:

- **Executive Order 14028** (AS, ditandatangani Mei 2021, pasca insiden SolarWinds dan Colonial Pipeline): mewajibkan SBOM untuk pengadaan software oleh pemerintah federal AS — mendorong adopsi SBOM secara luas di seluruh industri software, termasuk vendor yang menjual ke sektor pemerintah.
- **NTIA Minimum Elements for a SBOM**: standar elemen minimum yang harus ada dalam SBOM yang valid, dan **CycloneDX** (format yang dipakai test ini) secara eksplisit dirancang untuk **melampaui** elemen minimum tersebut.
- **App Defense Alliance (ADA) — Mobile Application Security Assessment (MASA)**: standar industri yang secara khusus mensyaratkan **identifikasi risiko dependency pihak ketiga** untuk aplikasi mobile — relevan langsung bagi developer yang ingin mendistribusikan aplikasi lewat Google Play dengan status MASA tervalidasi.

Ini artinya test ini **bukan sekadar alternatif teknis** dari MASTG-TEST-0272, melainkan **jawaban terhadap kebutuhan compliance nyata** yang semakin sering muncul dalam konteks pengadaan enterprise/pemerintah dan audit keamanan formal — SBOM adalah **bahasa umum** yang dipahami auditor compliance, bukan hanya engineer.

### 1.4 Dua Komponen Alur Kerja: Generator SBOM dan Platform Analisis

Alur kerja resmi melibatkan dua kategori tool yang terpisah dan saling melengkapi:

1. **Generator SBOM** (MASTG-TOOL-0134 — **cdxgen**): tool yang menganalisis proyek dan menghasilkan file SBOM dalam format CycloneDX (JSON/XML), mencantumkan seluruh dependency langsung **dan transitif** — catatan resmi MASTG-TECH-0130 menegaskan: *"Transitive dependencies are supported by [Dependency-Track] for Java and Kotlin"*, konsisten dengan penekanan pada cakupan transitif yang sama seperti dibahas mendalam di dokumen MASTG-TEST-0272.
2. **Platform Analisis** (MASTG-TOOL-0132 — **OWASP Dependency-Track**): platform yang menerima SBOM sebagai input, lalu **secara berkelanjutan** mencocokkan setiap komponen terhadap basis data kerentanan (NVD dan sumber lain) — berbeda dari Dependency-Check (dipakai di MASTG-TEST-0272) yang bersifat pemindaian sekali jalan per eksekusi Gradle, Dependency-Track dirancang sebagai **platform yang hidup** — SBOM yang sudah diunggah akan terus dipantau ulang seiring basis data kerentanan diperbarui, tanpa perlu menjalankan ulang build/scan setiap kali.

### 1.5 Fleksibilitas Sumber SBOM: Generate Sendiri atau Minta dari Tim Developer

Langkah resmi pertama memberi **dua jalur** yang eksplisit setara:

> *"Use MASTG-TECH-0130 to generate a SBOM, or **request one in CycloneDX format from the development team**."*

Ini konsisten dengan tag `developer` pada tipe test ini (§1.1) — MASTG secara eksplisit mengakui bahwa penguji (terutama pada audit pihak ketiga/eksternal) mungkin **tidak memiliki akses langsung** ke source code/build environment aplikasi target, namun tetap dapat menjalankan evaluasi ini bila tim developer aplikasi **sudah menghasilkan SBOM sebagai bagian dari proses rilis mereka sendiri** (praktik yang semakin umum sesuai dorongan regulasi §1.3). Ini pola kerja sama yang mirip dengan prasyarat `identify-first-party-domains` yang dibahas di dokumen MASTG-TEST-0242/0243 dalam seri riset ini — beberapa aspek pengujian keamanan modern **secara struktural membutuhkan** kolaborasi dengan pihak yang memiliki informasi/artefak yang tidak dapat diturunkan murni dari analisis blackbox.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core, Sesuai MASTG-TECH-0130)

| Tool | Fungsi |
|---|---|
| **cdxgen** (MASTG-TOOL-0134) | Menghasilkan SBOM format CycloneDX dari proyek Java/Kotlin/Android |
| **OWASP Dependency-Track** (MASTG-TOOL-0132) | Platform analisis SBOM berkelanjutan — menerima SBOM via API, mencocokkan terhadap basis data kerentanan |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **Syft** (Anchore) | Generator SBOM alternatif yang mendukung berbagai format (CycloneDX, SPDX) dan ekosistem, populer di dunia container namun mendukung proyek Java/Gradle |
| **CycloneDX Gradle Plugin** (`org.cyclonedx.bom`) | Alternatif native Gradle untuk menghasilkan SBOM langsung dari build tanpa CLI eksternal seperti cdxgen |
| **Trivy** | Selain sebagai scanner (dibahas di MASTG-TEST-0272), Trivy juga dapat **menghasilkan** SBOM CycloneDX/SPDX sekaligus menganalisisnya |
| **Grype** (Anchore) | Scanner kerentanan yang menerima input SBOM (termasuk hasil Syft) sebagai alternatif Dependency-Track untuk analisis lokal tanpa server terpisah |
| **GUAC** (Google/OpenSSF) | Platform agregasi metadata supply-chain yang lebih baru, dapat mengonsumsi SBOM untuk analisis grafik dependency lintas-proyek dalam skala organisasi besar |

### 2.3 Prasyarat Lingkungan

- **Akses ke source project** untuk menjalankan `cdxgen`, **atau** kerja sama dengan tim developer untuk memperoleh SBOM langsung (§1.5).
- **Instance OWASP Dependency-Track** yang berjalan (lokal via Docker, atau instance organisasi yang sudah ada) untuk mengunggah dan menganalisis SBOM.
- **API key Dependency-Track** untuk autentikasi saat mengunggah SBOM via API.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0130** untuk menghasilkan SBOM, atau minta dari tim developer dalam format CycloneDX.
2. Unggah SBOM ke **MASTG-TOOL-0132** (Dependency-Track).
3. Periksa proyek di Dependency-Track untuk penggunaan dependency yang rentan.

### 3.2 Metode A — cdxgen + Dependency-Track *(metode resmi utama)*

```bash
# 1. Generate SBOM di root direktori proyek Android Studio
npm install -g @cyclonedx/cdxgen
cdxgen -t java -o sbom.json

# 2. Encode Base64 dan unggah ke Dependency-Track via API
BOM_BASE64=$(cat sbom.json | base64 -w 0)
curl -X "PUT" "http://localhost:8081/api/v1/bom" \
     -H 'Content-Type: application/json' \
     -H 'X-API-Key: <API_KEY_ANDA>' \
     -d "{
  \"project\": \"<PROJECT_ID_ANDA>\",
  \"bom\": \"${BOM_BASE64}\"
}"

# 3. Buka frontend Dependency-Track (default: http://localhost:8080)
#    dan periksa tab "Vulnerabilities" pada proyek yang diunggah
```

### 3.3 Metode B — CycloneDX Gradle Plugin (Native, Tanpa CLI Eksternal)

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

### 3.4 Metode C — Syft + Grype (Alternatif Tanpa Server Terpisah)

```bash
# Generate SBOM
syft dir:. -o cyclonedx-json=sbom.json

# Analisis langsung tanpa perlu instance Dependency-Track
grype sbom:sbom.json
```

Pendekatan ini cocok untuk **audit cepat/lokal** tanpa perlu men-setup infrastruktur Dependency-Track (Docker, database) — trade-off-nya, kehilangan kemampuan monitoring berkelanjutan yang menjadi nilai tambah utama Dependency-Track (§1.4).

### 3.5 Metode D — Trivy sebagai Generator sekaligus Scanner

```bash
trivy fs --format cyclonedx --output sbom.json .
trivy sbom sbom.json
```

### 3.6 Metode E — Permintaan SBOM dari Tim Developer (Jalur Alternatif Resmi)

Bila akses langsung ke source code tidak tersedia (audit pihak ketiga eksternal), ajukan permintaan formal:

```
Template permintaan ke tim developer:
"Mohon disediakan SBOM aplikasi [nama aplikasi] versi [versi rilis] dalam format
CycloneDX (JSON atau XML), mencakup seluruh dependency langsung dan transitif,
untuk keperluan audit keamanan MASTG-TEST-0274."
```

Setelah diterima, lanjutkan ke Metode A langkah 2-3 (unggah ke Dependency-Track) tanpa perlu menjalankan generator sendiri.

### 3.7 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Butuh server terpisah? | Monitoring berkelanjutan? | Kapan dipakai |
|---|---|---|---|---|
| **A** | cdxgen + Dependency-Track | Ya (Dependency-Track) | ✅ | **Baseline resmi**, terbaik untuk organisasi dengan kebutuhan compliance jangka panjang |
| **B** | CycloneDX Gradle Plugin | Tidak (hanya generate) | ❌ | Menghasilkan SBOM tanpa CLI eksternal |
| **C** | Syft + Grype | Tidak | ❌ | Audit cepat/lokal tanpa infrastruktur tambahan |
| **D** | Trivy | Tidak | ❌ | All-in-one, cocok untuk pipeline CI/CD sederhana |
| **E** | Permintaan ke developer | N/A | Tergantung proses internal tim | Audit pihak ketiga tanpa akses source |

**Kombinasi minimum yang aku rekomendasikan:** **A (bila organisasi punya kebutuhan compliance/monitoring berkelanjutan) atau C/D (untuk audit cepat satu kali)**, dilengkapi **E** sebagai jalur formal bila penguji tidak memiliki akses source code langsung.

---

### 3.8 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Observation:** *"The output should include a list of dependencies with names and CVE identifiers, if any."*
>
> **Evaluation:** *"The test case fails if you can find dependencies with known vulnerabilities."*

Kriteria evaluasi ini **identik secara substansi** dengan MASTG-TEST-0272 — rujuk dokumen tersebut §3.8 untuk pembahasan detail soal prioritisasi severity, relevansi pemakaian, dan kualifikasi suppression. Perbedaan utama di sini murni pada **sumber bukti**: SBOM yang diunggah ke Dependency-Track, bukan laporan langsung dari Dependency-Check.

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Dependency-Track menampilkan dependency (langsung atau transitif) dengan CVE yang belum diperbaiki, sesuai kandungan SBOM yang diunggah |
| F2 | SBOM yang diterima dari tim developer **tidak lengkap/usang** (tidak mencerminkan versi rilis yang sedang diaudit) — kondisi ini sendiri layak dicatat sebagai temuan proses, terpisah dari temuan kerentanan teknis |

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Seluruh dependency dalam SBOM bebas dari CVE yang diketahui dan belum diperbaiki |
| P2 | SBOM terverifikasi akurat dan mutakhir (mencerminkan versi rilis yang diaudit) |
| P3 | Proses penerbitan SBOM sudah menjadi bagian rutin siklus rilis (bukan dihasilkan khusus untuk keperluan audit ini saja) — indikasi kematangan praktik compliance |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Verifikasi kesegaran dan kelengkapan SBOM sebelum menganalisis isinya** — terutama bila SBOM diperoleh dari tim developer (§1.5/§3.6), pastikan SBOM tersebut benar-benar dihasilkan dari versi kode yang sedang diaudit, bukan versi lama yang kebetulan tersedia.

2. **Korelasikan dengan MASTG-TEST-0272 bila memungkinkan** — bila penguji punya akses ke keduanya (source code dan kemampuan meminta SBOM), jalankan keduanya sebagai cross-check; perbedaan hasil di antara keduanya bisa mengindikasikan SBOM yang tidak akurat/usang.

3. **Manfaatkan kemampuan monitoring berkelanjutan Dependency-Track** bila dipakai — nilai tambah signifikan dibanding audit satu kali adalah SBOM yang sudah diunggah akan terus dipantau ulang seiring basis data kerentanan bertambah, tanpa perlu mengulang seluruh proses generate-upload.

4. **Pertimbangkan nilai compliance di luar temuan teknis murni** — bahkan bila tidak ditemukan CVE aktif, **ketiadaan proses SBOM sama sekali** dalam siklus rilis organisasi adalah sinyal kematangan proses yang lebih rendah dibandingkan organisasi yang sudah rutin menerbitkan SBOM — relevan untuk konteks audit compliance (EO 14028, App Defense Alliance MASA) meski di luar cakupan teknis murni "ada/tidaknya CVE".

5. **Severity mengikuti pola yang sama seperti dokumen MASTG-TEST-0272.**

6. **Dokumentasikan:** sumber SBOM (di-generate sendiri vs diterima dari tim developer), versi/tanggal SBOM, hasil analisis Dependency-Track lengkap dengan CVE ID, dan status kematangan proses SBOM organisasi (ad-hoc vs rutin terintegrasi rilis).

---

## 4. Rekomendasi Perbaikan

Rujuk **dokumen MASTG-TEST-0272 §4** untuk rekomendasi remediasi teknis dependency yang identik (upgrade versi, dependency locking, CI/CD gate).

Tambahan spesifik untuk alur kerja berbasis SBOM:

### 4.1 Integrasikan Generasi SBOM ke Pipeline Rilis

```yaml
# Contoh GitHub Actions
- name: Generate SBOM
  run: ./gradlew cyclonedxBom
- name: Upload SBOM to Dependency-Track
  run: |
    curl -X "PUT" "${DTRACK_URL}/api/v1/bom" \
      -H "X-API-Key: ${DTRACK_API_KEY}" \
      -d "{\"project\": \"${PROJECT_ID}\", \"bom\": \"$(base64 -w0 build/reports/bom.json)\"}"
```

### 4.2 Terbitkan SBOM sebagai Bagian dari Setiap Rilis

Simpan SBOM sebagai artefak rilis (mis. terlampir di GitHub Release) — memungkinkan audit historis dan memenuhi ekspektasi compliance (§1.3) tanpa perlu menghasilkan ulang SBOM lama secara retroaktif.

### 4.3 Manfaatkan Notifikasi Otomatis Dependency-Track

Konfigurasikan Dependency-Track untuk mengirim notifikasi (Slack/email/webhook) setiap kali kerentanan baru ditemukan pada komponen yang sudah diunggah — memanfaatkan sifat monitoring berkelanjutannya secara maksimal, bukan hanya diperiksa manual sesekali.

### 4.4 Checklist Remediasi

- [ ] SBOM dihasilkan (atau diterima dari tim developer) dan diverifikasi mencerminkan versi rilis yang diaudit
- [ ] SBOM diunggah dan dianalisis lewat Dependency-Track atau tool analisis SBOM setara
- [ ] Kerentanan yang ditemukan sudah diprioritaskan dan direncanakan remediasinya
- [ ] Proses generasi SBOM diintegrasikan ke pipeline rilis (bukan proses manual ad-hoc)
- [ ] Notifikasi otomatis untuk kerentanan baru sudah dikonfigurasi
- [ ] **Verifikasi ulang:** hasilkan dan analisis SBOM baru pada setiap rilis versi aplikasi

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0274: Dependencies with Known Vulnerabilities in the App's SBOM](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0274/)
- [MASTG-TEST-0272: Identify Dependencies with Known Vulnerabilities in the Android Project](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0272/)
- [MASWE-0044: Dependencies with Known Vulnerabilities](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0044/)
- [MASTG-TECH-0130: Software Composition Analysis of Android Dependencies by Creating a SBOM](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0130/)

### 5.2 Standar dan Regulasi

- [OWASP CycloneDX — Authoritative Guide to SBOM](https://cyclonedx.org/guides/sbom/introduction/)
- [Dependency-Track — U.S. Executive Order 14028](https://docs.dependencytrack.org/usage/executive-order-14028/)
- [NowSecure — Executive Order 14028 Updates & Why SBOMs Are Important](https://www.nowsecure.com/blog/2022/06/08/executive-order-14028-updates-why-sboms-are-important/)
- [NowSecure — 4 Things You Can Do with a Mobile SBOM](https://www.nowsecure.com/blog/2022/08/24/4-things-you-can-do-with-a-mobile-sbom/)
- [App Defense Alliance — Mobile Application Security Assessment (MASA)](https://appdefensealliance.dev/masa)
- [NTIA — Minimum Elements for a Software Bill of Materials](https://www.ntia.gov/report/2021/minimum-elements-software-bill-materials-sbom)
- [CWE-1104: Use of Unmaintained Third Party Components](https://cwe.mitre.org/data/definitions/1104.html)

### 5.3 Dokumentasi Tools

- [cdxgen — CycloneDX Generator](https://github.com/CycloneDX/cdxgen)
- [OWASP Dependency-Track](https://dependencytrack.org/)
- [CycloneDX Gradle Plugin](https://github.com/CycloneDX/cyclonedx-gradle-plugin)
- [Syft (Anchore)](https://github.com/anchore/syft)
- [Grype (Anchore)](https://github.com/anchore/grype)
- [Trivy — Aqua Security](https://trivy.dev/)
- [GUAC — Graph for Understanding Artifact Composition](https://github.com/guacsec/guac)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026), standar OWASP CycloneDX, serta konteks regulasi (Executive Order 14028, App Defense Alliance MASA) yang mendasari pentingnya adopsi SBOM di industri software modern. Berbeda dari MASTG-TEST-0272 yang bersifat pemindaian langsung sekali jalan, nilai unik test ini terletak pada **portabilitas artefak SBOM** — dapat dihasilkan sekali, dibagikan ke auditor/regulator, dan dipantau ulang secara berkelanjutan lewat platform seperti Dependency-Track — serta pengakuan eksplisit MASTG bahwa penguji dapat memperoleh SBOM lewat kerja sama tim developer, bukan hanya lewat analisis mandiri.*
