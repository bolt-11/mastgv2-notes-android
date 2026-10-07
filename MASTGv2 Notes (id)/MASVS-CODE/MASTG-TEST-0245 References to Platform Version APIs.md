# MASTG-TEST-0245 References to Platform Version APIs

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0245 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-CODE (Code Quality) — *catatan: pesan rule semgrep resmi menyebut `[MASVS-PLATFORM]`, sebuah inkonsistensi metadata, lihat §3.2* |
| **Weakness** | MASWE-0041 — *Running on a Recent Platform Version Not Ensured* |
| **API yang disorot** | `Build` (khususnya `Build.VERSION.SDK_INT`) |
| **Tipe Pengujian** | Static, Code |
| **Profile** | **L2 saja** |
| **Best Practice** | MASTG-BEST-0010 (Use Up-to-Date minSdkVersion) |
| **Teknik terkait** | MASTG-TECH-0013 (Reverse Engineering), MASTG-TECH-0014 (Static Analysis) |
| **Test terkait** | Sesama kelompok MASWE-0041/0042/0043 di MASVS-CODE (mis. test terkait `targetSdkVersion` dan enforced updating — lihat §1.4) |
| **Demo terkait** | — (tidak ada) |
| **Rule resmi** | `mastg-android-sdk-version.yml` (ada, tapi cakupannya sempit — lihat §3.2) |
| **CWE terkait** | CWE-1104 (Use of Unmaintained Third Party Components — analog konseptual), terkait erat dengan risiko dari platform version usang secara umum |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Kutipan overview resmi MASTG:

> *"This test verifies whether an app is running on a recent version of the Android operating system."*

Lebih presisi lagi, test ini memeriksa apakah aplikasi **memiliki kode** yang secara aktif memeriksa versi OS saat runtime — lewat `Build.VERSION.SDK_INT` — dan membandingkannya dengan konstanta versi tertentu (`Build.VERSION_CODES.*`) untuk **mengambil keputusan** (menjalankan fitur keamanan baru, membatasi fungsionalitas pada OS lawas, dsb.), bukan sekadar menjalankan aplikasi begitu saja tanpa mempedulikan versi OS yang mendasarinya.

```kotlin
if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
    // Android 14 (API 34) — bisa memakai fitur keamanan yang hanya tersedia di sini
} else {
    // fallback untuk versi lebih lama
}
```

### 1.2 Perbedaan Krusial: `minSdkVersion` (Build-Time) vs `Build.VERSION.SDK_INT` (Runtime) — Dua Lapisan yang Saling Melengkapi, Bukan Saling Menggantikan

Ini konsep paling penting untuk dipahami sebelum mengevaluasi test ini, dan dijelaskan mendalam di MASTG-BEST-0010:

> *"`minSdkVersion`: Defines the lowest API level the app is allowed to run on... If you set a low `minSdkVersion`, your app completely misses out on these protections on older devices."*
>
> *"While a high `minSdkVersion` reduces the need for runtime version checks, dynamically verifying the OS version using `Build.VERSION.SDK_INT` remains beneficial."*

Kedua mekanisme ini beroperasi di **lapisan yang berbeda** dan **keduanya diperlukan**, bukan salah satu menggantikan yang lain:

| Mekanisme | Kapan dievaluasi | Mengontrol apa |
|---|---|---|
| **`minSdkVersion`** (di `build.gradle`) | **Saat instalasi** (Play Store/package manager menolak instal di device dengan API di bawah nilai ini) | **Populasi device** yang bisa menjalankan aplikasi sama sekali |
| **`Build.VERSION.SDK_INT`** (di kode, runtime) | **Saat aplikasi berjalan**, pada device yang sudah lolos filter `minSdkVersion` | **Perilaku aplikasi** — fitur mana yang aktif pada device tersebut |

Implikasinya: **menaikkan `minSdkVersion` saja tidak cukup** bila kode aplikasi tidak memanfaatkan celah rentang API yang lebih tinggi tersebut untuk benar-benar mengaktifkan fitur keamanan baru. Sebaliknya, **memiliki banyak pengecekan `SDK_INT` di kode saja tidak cukup** bila `minSdkVersion` diset sangat rendah (mis. API 21/Android 5.0) — device dengan API tersebut akan **selamanya terjebak** di cabang kode `else` (fallback lawas) karena mereka tidak akan pernah memenuhi syarat pengecekan `if (SDK_INT >= ...)` yang lebih tinggi. Test ini secara spesifik memeriksa **keberadaan mekanisme kedua** (pengecekan runtime), sebagai bukti bahwa aplikasi memang **dirancang untuk memanfaatkan** perbedaan versi OS, bukan menerapkan satu perilaku seragam untuk semua versi.

### 1.3 Kesalahpahaman Umum: `targetSdkVersion` Bukan `minSdkVersion`

MASTG-BEST-0010 menyoroti kebingungan yang sangat sering terjadi antara dua atribut Gradle yang namanya mirip:

> *"`targetSdkVersion`: Defines the highest API level the app is designed to run on. The app can run on lower API levels, but it won't necessarily take advantage of all new security enforcements."*

Bahkan dokumentasi resmi Android sendiri diakui berkontribusi pada kebingungan ini — MASTG-BEST-0010 memberi contoh nyata:

> *"Even if an app targets API 28+ but is running on an older Android version (below API 28), cleartext traffic is still allowed unless explicitly disabled. Developers might assume that just increasing `targetSdkVersion` automatically blocks cleartext, which is incorrect."*

Ini **koneksi langsung** dengan nuansa `targetSdkVersion` yang sudah dibahas mendalam di dokumen **MASTG-TEST-0235** (§1.4 pada dokumen tersebut) — default `cleartextTrafficPermitted` ditentukan oleh `targetSdkVersion`, **bukan** oleh device Android yang sebenarnya dipakai. Test MASTG-TEST-0245 ini melengkapi pemahaman tersebut dari sisi lain: bahkan dengan `targetSdkVersion` tinggi, device dengan OS versi lama (di bawah `targetSdkVersion` tersebut) **tidak otomatis** mendapat proteksi versi baru — kecuali aplikasi secara eksplisit memeriksa `Build.VERSION.SDK_INT` dan menyesuaikan perilakunya, atau `minSdkVersion` dinaikkan untuk mengeksklusi device tersebut sepenuhnya dari populasi pengguna.

### 1.4 Efek Berlipat (Compounding) dengan Weakness Lain

MASWE-0041 secara eksplisit menyebut efek berlipat dari masalah ini:

> *"The weakness compounds when combined with deprecated APIs and removal of compiler-provided security features in older platforms, creating a compounding risk profile for affected users."*

Ini menghubungkan test ini dengan MASWE-0045 (*Compiler-Provided Security Features Not Used* — dibahas mendalam di dokumen **MASTG-TEST-0222/0223** tentang PIE dan stack canary) dan MASWE-0046 (*Use of Deprecated APIs*). Device dengan OS versi sangat lama tidak hanya kehilangan proteksi level-aplikasi, tapi juga **proteksi level-sistem operasi** (SELinux enforcement, ASLR yang lebih matang, model permission runtime, dsb.) — kombinasi ini menciptakan permukaan risiko yang jauh lebih besar dibanding masing-masing kelemahan berdiri sendiri.

### 1.5 Linimasa Peningkatan Keamanan Platform Android (Konteks untuk Menilai Dampak `minSdkVersion` Rendah)

MASTG-BEST-0010 menyediakan linimasa peningkatan keamanan Android per versi — berguna sebagai referensi cepat untuk menilai **seberapa signifikan** proteksi yang hilang bila `minSdkVersion` aplikasi diset di bawah versi tersebut:

| Versi Android (API) | Peningkatan Keamanan Signifikan |
|---|---|
| 4.2 (16) | Pengenalan SELinux |
| 4.3 (18) | SELinux diaktifkan default |
| 5.0 (21) | ART default, banyak fitur baru |
| 6.0 (23) | Model permission runtime granular (bukan all-or-nothing saat instalasi) |
| 8.0-8.1 (26-27) | Banyak peningkatan keamanan |
| 9 (28) | **Cleartext HTTP diblokir default**, restriksi mic/camera background |
| 10 (29) | **TLS 1.3 dipaksakan**, lokasi "only while using app" |
| 11 (30) | **Scoped storage dipaksakan**, permission auto-reset, APK Signature Scheme v4 |
| 13 (33) | Safer exporting context-registered receiver |

Tabel ini menegaskan bahwa `minSdkVersion` yang rendah (mis. di bawah API 28/Android 9) berarti aplikasi **secara struktural** kehilangan proteksi cleartext default, scoped storage paksa, dan berbagai hardening lain yang sudah dibahas di berbagai dokumen sebelumnya dalam seri riset ini (MASTG-TEST-0201, 0235, dsb).

### 1.6 Kasus Nyata: CVE-2012-6636 dan `addJavascriptInterface()`

Riset komunitas memberikan bukti konkret dampak nyata dari tidak adanya pengecekan versi platform:

> CVE-2012-6636 memungkinkan eksekusi kode lewat JavaScript bridge dan reflection pada API di bawah 17. Dalam pengujian praktis, ketika sebuah aplikasi dijalankan pada API 15, eksploitasi berhasil menghasilkan **remote shell**, sementara pada API 27 hanya menampilkan halaman error generik.

Studi empiris lebih lanjut menemukan **909 aplikasi** yang memanggil `addJavascriptInterface()`, dengan **413 di antaranya rentan** terhadap kebocoran informasi privat — karena aplikasi tersebut tidak memeriksa versi API sebelum mengekspos JavaScript interface yang berbahaya pada versi Android yang rentan (di bawah API 17). Ini contoh konkret bagaimana **ketiadaan pengecekan `Build.VERSION.SDK_INT`** sebelum mengaktifkan fitur tertentu dapat berujung pada eksekusi kode jarak jauh pada device dengan OS lawas.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **jadx** | Dekompilasi DEX → Java/Kotlin-like untuk pencarian pola `Build.VERSION.SDK_INT` |
| **grep / ripgrep** | Pencarian pola API — melengkapi cakupan rule resmi yang sempit |
| **semgrep** | Menjalankan rule resmi sebagai baseline |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **aapt2 / apkanalyzer** | Ekstraksi `minSdkVersion`/`targetSdkVersion` dari manifest untuk konteks evaluasi (§1.2) — nilai `minSdkVersion` yang rendah relevan untuk menilai signifikansi dampak temuan |
| **CodeQL** | Menelusuri pola pengecekan versi yang lebih kompleks, termasuk pemakaian `androidx.core.os.BuildCompat` atau reflection-based version checking |
| **MobSF** | Menampilkan `minSdkVersion`/`targetSdkVersion` di ringkasan Manifest Analysis sebagai konteks pendukung |
| **Android Lint** (`ObsoleteSdkInt`, `NewApi`) | Lint rule bawaan Android Studio yang justru mendekati masalah dari **arah sebaliknya** — mendeteksi kode yang memanggil API baru **tanpa** pengecekan versi yang memadai (`NewApi`), atau pengecekan versi yang sudah usang/tidak perlu lagi karena `minSdkVersion` sudah melampauinya (`ObsoleteSdkInt`) — pelengkap yang sangat relevan untuk menilai *kualitas* pengecekan versi yang ada, bukan sekadar keberadaannya |

### 2.3 Prasyarat Lingkungan

- **Tidak butuh device/root** — cukup APK atau source code.
- **Selalu ekstrak `minSdkVersion` dan `targetSdkVersion` di awal** sebagai konteks wajib (§1.2/§1.3) — angka pengecekan `SDK_INT` yang ditemukan harus dinilai relatif terhadap kedua nilai ini, bukan berdiri sendiri.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0013** untuk reverse engineer aplikasi.
2. Gunakan **MASTG-TECH-0014** untuk mencari API yang relevan.

### 3.2 Metode A — Rule Semgrep Resmi *(ada, tapi perlu diperluas)*

```yaml
rules:
  - id: mastg-android-sdk-version
    languages:
      - java
    severity: WARNING
    metadata:
      summary: This rule scans for API that checks the version of the operating system
    message: "[MASVS-PLATFORM] Make sure to verify that your app runs on a device with an up-to-date OS version to make sure it satisfy your security requirements"
    patterns:
      - pattern: Build.VERSION.SDK_INT
```

```bash
jadx -d ./decompiled ./target-app.apk
semgrep --config https://raw.githubusercontent.com/OWASP/mastg/master/rules/mastg-android-sdk-version.yml ./decompiled/sources/
```

**Catatan tentang rule ini:**

1. **Inkonsistensi metadata**: pesan rule menyebut `[MASVS-PLATFORM]`, sementara frontmatter test resmi (MASTG-TEST-0245) dan weakness terkait (MASWE-0041) sama-sama mengklasifikasikan test ini di bawah **MASVS-CODE**. Ini pola inkonsistensi metadata serupa yang sudah ditemukan sebelumnya di seri riset ini (mis. MASTG-KNOW-0007 pada dokumen MASTG-TEST-0226). Tidak mengubah cara pengujian, tapi perlu dicatat agar tidak membingungkan saat melaporkan hasil ke sistem tracking yang mengelompokkan berdasarkan kategori MASVS.
2. **`languages: [java]` saja** — sama seperti pola yang berulang ditemukan di beberapa rule resmi lain dalam seri ini, cakupan eksplisit hanya Java meski overview resmi justru memberi contoh dalam **Kotlin**. Karena `Build.VERSION.SDK_INT` adalah pola sintaks sederhana yang sama persis di kedua bahasa, risiko celah untuk kasus ini relatif rendah, tapi tetap perlu diverifikasi pada basis kode Kotlin murni yang kompleks.
3. **Rule hanya mendeteksi keberadaan pola `Build.VERSION.SDK_INT` secara literal** — tidak menangkap pendekatan alternatif seperti `androidx.core.os.BuildCompat` (API compatibility helper resmi Google), perbandingan `Build.VERSION.RELEASE` (string versi, pendekatan lama/kurang direkomendasikan), atau reflection-based version checking yang kadang dipakai untuk menghindari deteksi statis.
4. **Tidak menilai kualitas pengecekan** — rule ini semata mendeteksi keberadaan, bukan apakah pengecekan tersebut benar-benar melindungi fitur keamanan-kritis atau hanya dipakai untuk hal kosmetik (mis. menyesuaikan UI/tema).

### 3.3 Metode B — grep/ripgrep untuk Pola Alternatif *(menutup celah §3.2)*

```bash
D=./decompiled/sources

# Pola standar
rg -n 'Build\.VERSION\.SDK_INT' $D

# Pola alternatif — BuildCompat (AndroidX)
rg -n 'BuildCompat\.' $D

# Pola alternatif — perbandingan string versi (kurang direkomendasikan tapi masih ditemukan)
rg -n 'Build\.VERSION\.RELEASE' $D

# Cari konteks pemakaian — apakah dipakai untuk keputusan keamanan atau hanya UI
rg -n -B3 -A5 'Build\.VERSION\.SDK_INT' $D | grep -i "encrypt\|keystore\|permission\|biometric\|storage\|cert\|tls\|ssl"
```

### 3.4 Metode C — Android Lint (`NewApi`, `ObsoleteSdkInt`) — Menilai Kualitas, Bukan Hanya Keberadaan

```bash
cd android-project/
./gradlew lint
```

- **`NewApi`**: menandai pemanggilan API yang baru tersedia di level API tertentu **tanpa** pengecekan `SDK_INT` yang memadai — ini justru mendeteksi **ketiadaan** pengecekan versi pada titik yang seharusnya ada, melengkapi rule resmi MASTG yang hanya mendeteksi keberadaan.
- **`ObsoleteSdkInt`**: menandai pengecekan `SDK_INT` yang **sudah tidak relevan lagi** karena `minSdkVersion` proyek sudah melampaui nilai yang diperiksa — bermanfaat untuk membersihkan technical debt dan memastikan `minSdkVersion` benar-benar dinaikkan sesuai kemajuan basis kode.

### 3.5 Metode D — Ekstraksi Konteks `minSdkVersion`/`targetSdkVersion` (Wajib untuk Interpretasi Hasil)

```bash
jadx --no-src -d ./out target-app.apk
grep -o 'minSdkVersion="[0-9]*"\|targetSdkVersion="[0-9]*"' ./out/resources/AndroidManifest.xml
```

Hasil ini **wajib** disandingkan dengan temuan Metode A/B/C — sesuai §1.2/§1.5, sebuah aplikasi dengan `minSdkVersion` tinggi (mis. API 28+) secara struktural sudah mewarisi banyak proteksi default tanpa perlu terlalu banyak pengecekan `SDK_INT` manual, sementara `minSdkVersion` rendah menuntut pengecekan yang jauh lebih ekstensif untuk mengompensasi.

### 3.6 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Mendeteksi keberadaan? | Mendeteksi kualitas/celah? | Kapan dipakai |
|---|---|---|---|---|
| **A** | Rule semgrep resmi | ✅ | ❌ | Baseline cepat |
| **B** | grep pola alternatif | ✅ (+cakupan lebih luas) | ❌ | Melengkapi cakupan rule resmi |
| **C** | Android Lint `NewApi`/`ObsoleteSdkInt` | Tidak langsung | ✅ | **Paling bernilai** — menjawab pertanyaan sesungguhnya: apakah pengecekan yang ada memadai? |
| **D** | Ekstraksi manifest | N/A | N/A (konteks) | **Wajib** sebagai dasar interpretasi seluruh temuan lain |

**Kombinasi minimum yang aku rekomendasikan:** **D (konteks minSdkVersion/targetSdkVersion) → A+B (baseline+pelengkap) → C (Android Lint untuk menilai kualitas)**. Metode C memberi nilai tambah paling signifikan dibanding rule resmi MASTG karena ia menjawab pertanyaan yang lebih relevan secara keamanan: bukan "apakah ada pengecekan versi di suatu tempat", tapi "apakah API yang butuh pengecekan versi benar-benar sudah dijaga dengan pengecekan yang memadai".

---

### 3.7 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Observation:** *"The output should contain a list of locations where relevant APIs are used."*
>
> **Evaluation:** *"The test case fails if the app does not include any API calls to verify the operating system version."*

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | **Tidak ditemukan** satu pun referensi `Build.VERSION.SDK_INT` (atau alternatifnya) di seluruh codebase |
| F2 | `minSdkVersion` diset rendah (di bawah API 28, sesuai linimasa §1.5), **dan** tidak ada pengecekan versi untuk mengompensasi fitur keamanan yang hilang pada device lawas |
| F3 | Android Lint `NewApi` menemukan pemanggilan API level tinggi **tanpa** guard `SDK_INT` yang sesuai — indikasi bahwa meski *ada* pengecekan versi di tempat lain, cakupannya tidak menyeluruh |
| F4 | Fitur keamanan-kritis (enkripsi, biometrik, penyimpanan aman) diimplementasikan tanpa mempertimbangkan API level minimum yang dibutuhkan fitur tersebut, berpotensi menyebabkan crash atau fallback tak terduga pada device lawas |

**Contoh bukti (ilustratif — MASTG belum menyediakan demo resmi untuk test ini):**

```bash
$ grep -o 'minSdkVersion="[0-9]*"' AndroidManifest.xml
minSdkVersion="21"    # Android 5.0 — melewatkan SELinux enforcement penuh, permission runtime, dsb.

$ rg -c 'Build\.VERSION\.SDK_INT' ./decompiled/sources/
0   # TIDAK ADA satu pun pengecekan versi di seluruh aplikasi
```

Interpretasi: `minSdkVersion` yang rendah (API 21) dikombinasikan dengan **nol** pengecekan `SDK_INT` — aplikasi menjalankan perilaku identik di semua rentang device dari Android 5.0 hingga versi terbaru, kehilangan kesempatan mengaktifkan fitur keamanan yang tersedia di API lebih tinggi. **FAIL** sesuai klausul resmi.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Ditemukan pengecekan `Build.VERSION.SDK_INT` yang dipakai untuk mengondisikan fitur keamanan-kritis berdasarkan level API |
| P2 | `minSdkVersion` sudah cukup tinggi (mis. API 28+) sehingga proteksi platform utama sudah terjamin secara struktural, **dan** pengecekan versi tambahan tetap ada untuk memanfaatkan fitur yang lebih baru dari API tersebut |
| P3 | Android Lint tidak menemukan pelanggaran `NewApi` — seluruh pemanggilan API level tinggi sudah dijaga pengecekan versi yang sesuai |

**Contoh output yang menandakan PASS:**

```bash
$ rg -n 'Build\.VERSION\.SDK_INT' ./decompiled/sources/com/example/target/crypto/KeyManager.java
42:    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
43:        // Memakai Android Keystore StrongBox / fitur biometric yang lebih baru
```

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Selalu evaluasi bersama `minSdkVersion`, bukan berdiri sendiri.** Sesuai §1.2, keberadaan pengecekan `SDK_INT` yang minim mungkin **wajar** bila `minSdkVersion` aplikasi sudah tinggi (device di bawahnya sudah dieksklusi sepenuhnya) — sebaliknya, `minSdkVersion` rendah **menuntut** pengecekan yang jauh lebih ekstensif.

2. **Fokus pada pengecekan yang menjaga fitur keamanan-kritis**, bukan sekadar menghitung total kemunculan `SDK_INT` di kode. Pengecekan versi untuk menyesuaikan tema UI atau ikon status bar tidak sama nilainya dengan pengecekan versi untuk mengaktifkan enkripsi hardware-backed.

3. **Manfaatkan Android Lint sebagai pelengkap yang lebih presisi** dibanding rule resmi MASTG — `NewApi` menjawab pertanyaan yang lebih relevan secara keamanan dibanding sekadar "apakah `SDK_INT` disebut di suatu tempat".

4. **Ingat nuansa `targetSdkVersion` vs `minSdkVersion` vs OS aktual perangkat** (§1.3) — jangan campur aduk ketiganya saat menulis laporan. `targetSdkVersion` tinggi tidak menjamin proteksi otomatis pada device dengan OS lama, sesuai contoh cleartext yang sudah dibahas mendalam di dokumen MASTG-TEST-0235.

5. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | `minSdkVersion` sangat rendah (di bawah API 23) tanpa pengecekan versi sama sekali | **Tinggi** |
   | `minSdkVersion` rendah, ada beberapa pengecekan tapi tidak mencakup fitur keamanan-kritis | **Menengah** |
   | `minSdkVersion` sudah tinggi (28+), sedikit pengecekan versi | **Rendah/Informational** — risiko sudah dimitigasi lewat `minSdkVersion` |

6. **Dokumentasikan:** nilai `minSdkVersion`/`targetSdkVersion`, daftar lokasi pengecekan `SDK_INT` beserta fitur yang dijaganya, hasil Android Lint `NewApi`/`ObsoleteSdkInt`, dan penilaian apakah cakupan pengecekan memadai relatif terhadap `minSdkVersion` yang diset.

---

## 4. Rekomendasi Perbaikan

### 4.1 Naikkan `minSdkVersion` ke Nilai yang Wajar

```gradle
android {
    defaultConfig {
        minSdkVersion 28  // Android 9 — proteksi cleartext default, dsb.
        targetSdkVersion 34
    }
}
```

### 4.2 Terapkan Pengecekan Versi untuk Fitur Keamanan-Kritis

```kotlin
fun getSecureKeyGenSpec(alias: String): KeyGenParameterSpec.Builder {
    val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT)
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
        builder.setIsStrongBoxBacked(true)  // hanya tersedia API 28+
    }
    return builder
}
```

### 4.3 Aktifkan Android Lint `NewApi` sebagai Build-Blocking Check

```gradle
android {
    lintOptions {
        error 'NewApi'
    }
}
```

### 4.4 Checklist Remediasi

- [ ] `minSdkVersion` sudah dievaluasi dan dinaikkan ke nilai yang proporsional dengan kebutuhan keamanan aplikasi
- [ ] Fitur keamanan-kritis sudah dijaga pengecekan `Build.VERSION.SDK_INT` yang sesuai
- [ ] Android Lint `NewApi` diaktifkan sebagai build-blocking check
- [ ] `ObsoleteSdkInt` diperiksa untuk membersihkan pengecekan versi yang sudah tidak relevan
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0245 setelah setiap perubahan `minSdkVersion` atau penambahan fitur baru

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0245: References to Platform Version APIs](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0245/)
- [MASTG-TEST-0235: Android App Configurations Allowing Cleartext Traffic](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0235/)
- [MASWE-0041: Running on a Recent Platform Version Not Ensured](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0041/)
- [MASTG-BEST-0010: Use Up-to-Date minSdkVersion](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0010/)
- [MASTG-TECH-0013: Reverse Engineering Android Apps](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/)
- [MASTG-TECH-0014: Static Analysis on Android](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/)
- [Rule resmi: mastg-android-sdk-version.yml (GitHub)](https://github.com/OWASP/mastg/blob/master/rules/mastg-android-sdk-version.yml)

### 5.2 Dokumentasi Resmi Android

- [Android Developers — `Build.VERSION` reference](https://developer.android.com/reference/android/os/Build.VERSION)
- [Android Developers — Meet Google Play's target API level requirement](https://support.google.com/googleplay/android-developer/answer/11926878)
- [Android Security Bulletins](https://source.android.com/docs/security/bulletin)
- [Android Developers — `androidx.core.os.BuildCompat`](https://developer.android.com/reference/androidx/core/os/BuildCompat)

### 5.3 Riset dan Kasus Nyata

- [Digital Interruption Research — How Does The SDK Version Affect The Security of Android Applications?](https://research.digitalinterruption.com/2019/01/25/how-does-the-sdk-version-affect-the-security-of-android-applications/)
- [arXiv — Measuring the Declared SDK Versions and Their Consistency with API Calls in Android Apps](https://arxiv.org/pdf/1702.04872)
- [arXiv — An Empirical Study on Android-related Vulnerabilities](https://arxiv.org/pdf/1704.03356)
- [Valency Networks — Application Supports Insecure or Outdated Android Versions](https://valencynetworks.com/kb/android-app-vulnerability-supporting-insecure-or-outdated-android-versions.html)

### 5.4 Dokumentasi Tools

- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [Android Lint — Documentation](https://developer.android.com/studio/write/lint)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026), dokumentasi resmi Android Developers, serta riset akademik dan komunitas (termasuk kasus nyata CVE-2012-6636) mengenai dampak keamanan dari `minSdkVersion` yang rendah. Nuansa terpenting: pengecekan `Build.VERSION.SDK_INT` di runtime dan `minSdkVersion` di build-time adalah dua lapisan kontrol yang saling melengkapi, bukan saling menggantikan — evaluasi yang tepat menuntut keduanya dinilai bersama, tidak berdiri sendiri.*
