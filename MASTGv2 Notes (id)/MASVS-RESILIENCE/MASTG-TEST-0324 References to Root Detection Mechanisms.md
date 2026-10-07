# MASTG-TEST-0324 References to Root Detection Mechanisms

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0324 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-RESILIENCE |
| **Weakness** | MASWE-0051 |
| **Tipe Pengujian** | Static, Code |
| **Teknik terkait** | MASTG-TECH-0013 (Reverse Engineering), MASTG-TECH-0014 (Static Analysis for Relevant APIs) |
| **Best Practice terkait** | MASTG-BEST-0029 (Implementing Resilience and RASP Signals — `status: placeholder`), MASTG-BEST-0030 (Implementing Root Detection) |
| **Knowledge terkait** | MASTG-KNOW-0027 (Root Detection) |
| **Test terkait** | **MASTG-TEST-0325** — counterpart **dinamis** yang mengonfirmasi mekanisme root detection aktif saat runtime (hubungan dua arah, lihat §1.2) |
| **Rule resmi** | `mastg-android-root-detection.yaml` — 5 rule sekaligus (file checks, package check, test-keys, system properties, runtime exec), lihat §1.4 |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Kutipan overview resmi MASTG:

> *"This test checks whether the app implements root detection by statically analyzing the app binary for common root detection patterns. These may include checks for files and artifacts typically associated with rooted devices, as well as calls to known root detection APIs or libraries."*

Penting dicatat sejak awal: ini adalah test tentang **keberadaan (presence)** mekanisme root detection, **bukan** tentang **efektivitas/kekuatannya**. MASTG secara eksplisit membatasi scope ini:

> *"Out of Scope: This test does not cover robustness or effectiveness of root detection mechanisms, which can be very difficult to assess through static analysis alone and may require manual reverse engineering and custom instrumentation."*

Pembatasan scope ini penting secara metodologis — menemukan root detection di kode **bukan berarti** mekanisme tersebut sulit dibypass. Evaluasi kekuatan/robustness root detection (apakah mudah di-patch, di-hook, atau dihindari) adalah pertanyaan yang **berbeda** dan dibahas lebih lanjut di MASTG-BEST-0030 (§1.5).

### 1.2 Hubungan Dua Arah dengan MASTG-TEST-0325 (Statis ↔ Dinamis)

Berbeda dari banyak pasangan static/dynamic lain dalam seri riset ini yang arahnya satu jalur (statis dulu, lalu dinamis mengonfirmasi), overview test ini secara eksplisit menawarkan **dua urutan kerja yang sama validnya**:

> *"This way, you can use static analysis to surface potential root detection logic and then focus your dynamic testing on those specific checks to confirm they are triggered at runtime. Alternatively, you can perform dynamic testing first to identify any root detection mechanisms that are active at runtime, and then use static analysis to further investigate their implementation and coverage."*

Dengan kata lain:

- **Jalur A (Statis → Dinamis):** Temukan kandidat pola root detection di kode lewat semgrep/grep, lalu gunakan sebagai target hooking yang presisi di MASTG-TEST-0325.
- **Jalur B (Dinamis → Statis):** Hook API umum (`File.exists`, `Runtime.exec`, dsb.) di perangkat rooted dulu untuk melihat mekanisme mana yang **benar-benar aktif**, lalu lacak balik ke kode untuk memahami implementasi lengkap dan cakupannya.

Pemilihan jalur mana yang dipakai bergantung pada konteks — bila kode mudah didekompilasi dan dibaca, Jalur A lebih efisien; bila kode terobfuskasi berat, Jalur B (mengamati perilaku runtime dulu) seringkali lebih cepat memberi titik awal investigasi.

### 1.3 Mengapa Definisi "Root" Diperluas untuk Android: Custom ROM

Overview MASTG-KNOW-0027 memberi nuansa definisi yang sering terlewat:

> *"For Android, we define 'root detection' a bit more broadly, including custom ROMs detection, i.e., determining whether the device is a stock Android build or a custom build."*

Ini berarti indikator seperti **`Build.TAGS` mengandung `"test-keys"`** (menandakan image non-stock, ditandatangani dengan test key alih-alih release key resmi) termasuk dalam cakupan root detection meski secara teknis perangkat belum tentu memiliki akses `su`. Kategori deteksi ini relevan karena custom ROM sering (meski tidak selalu) berkorelasi dengan environment yang lebih mudah dimodifikasi/diinstrumentasi.

### 1.4 Analisis Rule Resmi: Lima Pola Terpisah, Severity INFO Semua

Rule resmi `mastg-android-root-detection.yaml` berisi **lima rule Semgrep terpisah**, masing-masing menyasar satu kategori teknik dari MASTG-KNOW-0027:

| Rule ID | Pola yang Dicocokkan | Kategori dari MASTG-KNOW-0027 |
|---|---|---|
| `mastg-android-root-detection-file-checks` | `new File($PATH).exists()` dengan `$PATH` mengandung `su`/`magisk`/`Superuser.apk` | File Existence Checks |
| `mastg-android-root-detection-package-check` | `$PM.getPackageInfo($PKG, ...)` | Checking Installed App Packages |
| `mastg-android-root-detection-test-keys` | `Build.TAGS.contains("test-keys")` (3 variasi pattern, termasuk bentuk Kotlin `StringsKt.contains$default`) | Checking for Custom Android Builds |
| `mastg-android-root-detection-system-properties` | `Runtime.getRuntime().exec("getprop " + $PROP)` | — (cek system property via shell) |
| `mastg-android-root-detection-runtime-exec` | `Runtime.getRuntime().exec($CMD)` **dengan pengecualian** pola `getprop` di atas | Executing Privileged Commands |

Catatan analitis penting: **seluruh lima rule memiliki severity `INFO`**, bukan `WARNING` atau `ERROR` — ini konsisten dengan sifat test (hanya mendeteksi **presence**, bukan menilai **efektivitas**), dan juga mengakui bahwa pemanggilan pola-pola ini (`Runtime.exec`, `getPackageInfo`) **tidak otomatis berarti root detection** — bisa saja dipakai untuk tujuan lain yang sama sekali tidak terkait keamanan. Severity INFO menandakan hasil ini murni informatif, perlu diverifikasi manual terhadap konteks pemanggilan.

Rule `-test-keys` juga menunjukkan kematangan desain — menangani **tiga variasi pola berbeda** untuk kasus yang sama, termasuk pola hasil kompilasi Kotlin (`StringsKt.contains$default`), menunjukkan bahwa rule telah disesuaikan untuk kode sumber campuran Java/Kotlin, bukan hanya mengasumsikan satu bahasa.

### 1.5 Dampak Nyata di Dunia: RootBeer sebagai Target Bypass Paling Umum

MASTG-KNOW-0027 secara eksplisit mereferensikan **RootBeer** (MASTG-TOOL-0146) sebagai salah satu library root detection yang umum dipakai. Riset komunitas keamanan menunjukkan bahwa justru karena popularitasnya, RootBeer menjadi **target bypass paling umum** dalam pengujian penetrasi aplikasi mobile:

> *"RootBeer is a widely used open-source root detection library that many apps rely on, making it a high-value target during assessments. RootBeer exposes an isRooted() method on the RootBeer class... Apps may call individual RootBeer check methods directly such as checkForSuBinary, checkForDangerousProps, checkForRWPaths, detectTestKeys, and checkSuExists."*

Ini memberi konteks nyata untuk evaluasi efektivitas (§1.1) — begitu penguji (atau penyerang) tahu aplikasi memakai RootBeer (ditemukan lewat test ini), script Frida bypass yang sudah tersedia publik di Frida CodeShare dapat langsung dipakai untuk menetralisir **seluruh metode check** sekaligus, tanpa perlu reverse-engineering mendalam. Ini menegaskan poin dari MASTG-BEST-0030 (§1.6) bahwa **mengandalkan satu library default tanpa kustomisasi** adalah praktik yang lemah.

### 1.6 Prinsip Desain dari MASTG-BEST-0030: Root Detection sebagai "Cost-Raising", Bukan Penghalang Absolut

Kutipan kunci yang membingkai cara menilai temuan test ini:

> *"Root detection is an environment risk signal that helps identify devices with elevated privilege or common rooting artifacts. It is a cost raising measure and it is bypassable, so it should be used only when rooted device risk materially impacts the app."*

MASTG-BEST-0030 memberikan tujuh praktik baik yang relevan untuk dinilai **bersamaan dengan** hasil test ini (tidak cukup hanya menemukan presence):

1. Layer defenses (gabung dengan integrity check, anti-debug, enforcement backend)
2. Distribute checks (sebar di banyak titik, bukan satu gate terpusat)
3. Use multiple methods (gabung filesystem, property, process, native level)
4. **Avoid well-known patterns only** — poin yang langsung relevan dengan temuan RootBeer-default di §1.5
5. Proportional responses (jangan langsung lockout total saat confidence rendah)
6. Validate server-side
7. Rotate and randomize checks antar sesi/rilis

Dan catatan realistis tentang keterbatasan:

> *"Root detection can flag legitimate scenarios such as custom ROMs, enterprise test devices, and security research environments. Aggressive blocking can push users to modified app builds, and can increase support costs."*

Ini relevan untuk rekomendasi perbaikan — root detection yang terlalu agresif punya efek samping bisnis nyata, bukan hanya pertimbangan keamanan murni.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **jadx** | Dekompilasi DEX → Java (MASTG-TECH-0013) |
| **Semgrep** + rule resmi `mastg-android-root-detection.yaml` | Pencocokan lima pola root detection (MASTG-TECH-0014) |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **MobSF** | Laporan otomatis yang sudah menyertakan deteksi pola root-check umum dalam pipeline statisnya |
| **mobsfscan** | CLI standalone berbasis rule-set MobSF + Semgrep, cocok untuk integrasi CI tanpa perlu menjalankan MobSF penuh |
| **Androguard** | Library Python untuk parsing DEX/APK/Manifest — fondasi banyak tool lain, berguna untuk query kustom terhadap string/method yang berkaitan root detection |
| **Quark-Engine** | Scoring perilaku aplikasi berdasarkan rule set bobot, dapat dikustomisasi untuk menandai kombinasi pola root detection sebagai satu "behavior" |
| **grep/ripgrep** | Pencarian cepat string literal seperti path `su`, `magisk`, nama package rooting (`com.topjohnwu.magisk`, dsb.) di luar lingkup pattern Semgrep yang baku |

### 2.3 Prasyarat Lingkungan

- Tidak butuh device/root untuk analisis statis.
- Siapkan daftar string/path acuan dari MASTG-KNOW-0027 (§1.3) untuk melengkapi pencarian manual di luar lima rule resmi.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0013** untuk reverse engineer aplikasi.
2. Gunakan **MASTG-TECH-0014** untuk mencari API yang relevan.

### 3.2 Metode A — Semgrep dengan Rule Resmi

```bash
semgrep --config mastg-android-root-detection.yaml ./decompiled/sources
```

### 3.3 Metode B — grep/ripgrep untuk Pola di Luar Cakupan Rule Resmi

```bash
D=./decompiled/sources

# Path/binary root yang tidak tercakup regex rule resmi (hanya su/magisk/Superuser.apk)
rg -n 'busybox|daemonsu|/system/xbin/|/system/app/Superuser' $D

# Package rooting selain yang sudah dicakup
rg -n 'eu\.chainfire\.supersu|com\.noshufou\.android\.su|com\.koushikdutta\.superuser' $D

# Pengecekan proses (checkRunningProcesses pattern)
rg -n 'getRunningServices|getRunningAppProcesses' $D
```

### 3.4 Metode C — mobsfscan untuk Integrasi CI

```bash
pip install mobsfscan
mobsfscan ./decompiled/sources --json -o root_detection_scan.json
```

Berguna bila tim ingin menjalankan pemeriksaan root detection (dan pola keamanan lain) secara otomatis di pipeline CI/CD, bukan hanya sesi audit manual satu kali.

### 3.5 Metode D — MobSF Laporan Otomatis

Unggah APK ke instance MobSF (self-hosted) — laporan statis otomatis akan menyertakan bagian temuan terkait root detection sebagai bagian dari ringkasan keamanan menyeluruh, berguna untuk triase awal sebelum audit manual mendalam.

### 3.6 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Kapan dipakai |
|---|---|---|
| **A** | Semgrep + rule resmi | Baseline wajib, mencakup 5 pola inti |
| **B** | grep/ripgrep manual | Melengkapi cakupan rule resmi yang terbatas (hanya su/magisk/Superuser.apk untuk file checks) |
| **C** | mobsfscan | Integrasi CI/CD berkelanjutan |
| **D** | MobSF | Triase cepat/laporan menyeluruh |

**Kombinasi minimum yang aku rekomendasikan:** **A (wajib) + B (menutup celah cakupan rule resmi)**, dilanjutkan ke **MASTG-TEST-0325** untuk konfirmasi runtime sesuai hubungan dua arah di §1.2.

---

### 3.7 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Evaluation:** *"The test case fails if the app does not implement any root detection checks. However, note that static analysis may not detect all root detection mechanisms, especially if they are proprietary, obfuscated, or implemented in native code."*
>
> *"If root detection checks are found, this is a positive sign, but you should still evaluate their effectiveness."*

Catatan penting: logika FAIL test ini **berbeda arah** dibanding kebanyakan test lain dalam seri riset ini — di sini **ketidakhadiran** mekanisme adalah FAIL, bukan **kehadiran** sebuah pola berbahaya.

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | **Tidak ditemukan** satu pun pola root detection (dari rule resmi maupun pencarian manual tambahan) di seluruh kode aplikasi |

**Contoh:** hasil scan Semgrep + grep manual kosong, tidak ada referensi ke `su`, `magisk`, `getPackageInfo` untuk package rooting, `test-keys`, atau `Runtime.exec` yang berkaitan root — mengindikasikan aplikasi tidak memiliki mekanisme deteksi lingkungan rooted sama sekali. **FAIL**.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Ditemukan minimal satu pola root detection yang valid (bukan false positive — lihat catatan severity INFO di §1.4) |
| P2 | Mekanisme yang ditemukan **tersebar di berbagai lapisan** (file check + package check + native, bukan hanya satu library default tanpa modifikasi) — sinyal kualitas tambahan di luar sekadar lulus/gagal biner |

**Contoh bukti:**

```java
// Ditemukan di com/example/targetapp/security/RootChecker.java
if (new File("/system/xbin/su").exists() || Build.TAGS.contains("test-keys")) {
    disableSensitiveFeatures();
}
```

Interpretasi: dua pola berbeda (file check + test-keys check) ditemukan dan dipakai bersamaan untuk mengurangi fitur sensitif. **PASS**, dengan catatan evaluasi lanjutan terhadap robustness (§1.6) tetap diperlukan.

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **PASS pada test ini TIDAK berarti aman** — ini murni menandakan presence. Rujuk MASTG-BEST-0030 untuk menilai apakah implementasi tersebut layak disebut efektif (berlayer, tersebar, pakai server-side validation, dsb.) — jangan berhenti di "ditemukan root check, selesai".

2. **FAIL pada test ini bisa jadi false negative akibat obfuskasi atau native code** — sesuai catatan resmi, mekanisme proprietary/obfuscated/native tidak selalu terdeteksi lewat pattern matching biasa. Pertimbangkan Metode D (MobSF, yang juga menganalisis native library) dan lanjutkan ke **MASTG-TEST-0325** (dinamis) sebelum menyimpulkan tidak ada root detection sama sekali.

3. **Severity INFO pada rule resmi bukan berarti temuan tidak penting** — itu mengakui ambiguitas interpretasi otomatis (pattern bisa dipakai untuk tujuan non-security), bukan mengecilkan pentingnya hasil akhir evaluasi manual.

4. **Ketergantungan pada library default (RootBeer tanpa kustomisasi) adalah temuan kualitas, bukan sekadar PASS/FAIL** — sesuai §1.5, ini target bypass paling umum di dunia nyata; catat sebagai rekomendasi perbaikan meski hasil test teknis tetap PASS.

5. **Dokumentasikan:** lokasi kode tiap pola yang ditemukan, kategori teknik (sesuai taksonomi MASTG-KNOW-0027), apakah memakai library pihak ketiga (RootBeer/RootBeer-like) atau implementasi kustom, dan rekomendasi untuk pengujian lanjutan di MASTG-TEST-0325.

---

## 4. Rekomendasi Perbaikan

### 4.1 Jangan Hanya Mengandalkan Library Default

```java
// LEMAH — hanya memanggil isRooted() default tanpa kustomisasi
RootBeer rootBeer = new RootBeer(context);
if (rootBeer.isRooted()) { ... }

// LEBIH BAIK — kombinasikan dengan pengecekan kustom tambahan
RootBeer rootBeer = new RootBeer(context);
boolean suspicious = rootBeer.isRooted()
    || customNativeCheck()
    || checkWritableSystemPartition();
```

### 4.2 Sebarkan Pengecekan, Jangan Satu Gate Terpusat

Tempatkan pengecekan di titik-titik sensitif (sebelum transaksi, saat inisialisasi sesi) alih-alih hanya sekali di `onCreate()` — sesuai praktik "Distribute checks" MASTG-BEST-0030.

### 4.3 Validasi Server-Side sebagai Lapisan Terakhir

Jangan jadikan client-side root detection satu-satunya garis pertahanan untuk operasi berisiko tinggi — korelasikan sinyal risiko dengan kebijakan server yang mempertimbangkan konteks pengguna secara menyeluruh.

### 4.4 Checklist Remediasi

- [ ] Root detection tersedia dan tersebar di beberapa lapisan (bukan satu library default saja)
- [ ] Kombinasi minimal: file check + package check + native-level check
- [ ] Respons proporsional (bukan lockout total langsung) untuk kasus confidence rendah
- [ ] Validasi tambahan di server-side untuk operasi sensitif
- [ ] Hasil dikonfirmasi lewat MASTG-TEST-0325 sebelum dianggap final

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0324 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0324.md)
- [MASTG-TEST-0325: Runtime Use of Root Detection Techniques (source)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0325.md)
- [MASTG-KNOW-0027: Root Detection](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0027/)
- [MASTG-BEST-0030: Implementing Root Detection](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0030.md)
- [MASTG-BEST-0029: Implementing Resilience and RASP Signals](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0029.md)

### 5.2 Riset dan Kasus Nyata

- [Secarma: Bypassing Android's RootBeer Library (Part 2)](https://secarma.com/bypassing-androids-rootbeer-library-part-2)
- [RedFoxSec: Android Root Detection Bypass Using Frida: Full Guide](https://www.redfoxsec.com/blog/android-root-detection-bypass-using-frida)
- [GitHub: rootbeer-bypass — Frida script untuk bypass RootBeer sample](https://github.com/0x4ngK4n/rootbeer-bypass)
- [Talsec: Simple Root Detection: Implementation and Verification](https://docs.talsec.app/appsec-articles/articles/simple-root-detection-implementation-and-verification)
- [NetSPI: Android Root Detection Techniques](https://www.netspi.com/blog/technical-blog/mobile-application-penetration-testing/android-root-detection-techniques/)

### 5.3 Dokumentasi Tools

- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
- [mobsfscan — Standalone Static Analysis CLI](https://github.com/MobSF/mobsfscan)
- [Androguard](https://github.com/androguard/androguard)
- [Quark-Engine](https://www.kali.org/tools/quark-engine/)
- [Frida CodeShare](https://codeshare.frida.re/)

---

*Dokumen ini disusun berdasarkan konten resmi OWASP MASTG (`tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0324.md`, `MASTG-KNOW-0027`, `MASTG-BEST-0030`, rule `mastg-android-root-detection.yaml`), serta riset komunitas keamanan tentang RootBeer sebagai target bypass paling umum di dunia nyata. Nuansa metodologis terpenting: test ini murni mengevaluasi **presence**, bukan **efektivitas** — PASS pada test ini hanya langkah pertama; evaluasi kualitas implementasi (layering, distribusi, validasi server-side) sesuai MASTG-BEST-0030 tetap wajib dilakukan secara terpisah, dan hubungan dengan MASTG-TEST-0325 bersifat dua arah (statis→dinamis atau dinamis→statis), tidak seperti kebanyakan pasangan test lain yang searah.*
