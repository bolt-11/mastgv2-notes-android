# MASTG-TEST-0399 SafeBrowsing Disabled

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0399 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-CODE |
| **Weakness** | MASWE-0035 |
| **Tipe Pengujian** | Static, Config, Code |
| **API terkait** | `WebView`, `WebSettings`, `EnableSafeBrowsing`, `setSafeBrowsingEnabled` |
| **Teknik terkait** | MASTG-TECH-0013, MASTG-TECH-0117 (Obtain Manifest), MASTG-TECH-0150, MASTG-TECH-0014 |
| **Knowledge terkait** | MASTG-KNOW-0018 (WebViews) |
| **Tersedia sejak** | API level 27 (Android 8.1) |
| **Test terkait** | **MASTG-TEST-0398** — dokumen terkait dalam seri riset ini; keduanya membahas kontrol navigasi WebView namun dari mekanisme berbeda (custom allowlist vs layanan reputasi Google) |
| **Rule resmi** | `mastg-android-webview-safebrowsing.yml` — dua pola bersih, lihat §1.4 |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian dan Mekanisme SafeBrowsing

Kutipan overview resmi MASTG:

> *"Since Android 8.1 (API level 27), WebViews include SafeBrowsing by default, which warns users about URLs that Google has classified as known threats such as phishing or malware sites."*

SafeBrowsing adalah **lapisan perlindungan reputasi berbasis layanan Google** — berbeda fundamental dari mekanisme yang dibahas di MASTG-TEST-0398 (allowlist/denylist kustom yang ditulis developer sendiri). SafeBrowsing memanfaatkan **basis data ancaman yang terus diperbarui secara global** oleh Google, mencakup URL yang diklasifikasikan berbahaya di seluruh web — sesuatu yang mustahil ditiru oleh allowlist kustom aplikasi mana pun.

### 1.2 Evolusi Teknis: Dari Local Blocklist ke Real-Time Checking

Konteks teknis tambahan yang relevan untuk memahami kekuatan mekanisme ini:

> *"For WebView versions prior to M126, Safe Browsing on WebView uses the 'Local Blocklist' or 'V4' protocol, with URLs checked for malware, phishing etc against an on-device blocklist that is periodically updated by Google's servers. From M126 onwards, WebView uses a 'Real-Time' or 'V5' protocol for Safe Browsing, with URLs checked in real-time against blocklists maintained by servers."*

Evolusi ini penting — versi WebView modern tidak lagi bergantung pada basis data lokal yang hanya diperbarui secara periodik (dengan jeda waktu antara ancaman baru muncul dan perangkat menerima update), melainkan memeriksa **secara real-time** terhadap server Google. Ini berarti menonaktifkan SafeBrowsing pada WebView modern berarti kehilangan perlindungan yang **lebih kuat** dibanding yang tersedia di versi-versi awal fitur ini.

### 1.3 Dua Titik Kontrol dengan Hierarki Prioritas yang Jelas

Overview menjelaskan dua cara menonaktifkan SafeBrowsing, dengan hierarki yang eksplisit:

> *"Apps can also disable SafeBrowsing at runtime by calling `WebSettings.setSafeBrowsingEnabled(false)` on a WebView instance. This takes precedence over the manifest setting, so even if the manifest enables SafeBrowsing, it can still be disabled in code."*

| Titik Kontrol | Lokasi | Prioritas |
|---|---|---|
| Manifest meta-data `EnableSafeBrowsing` | `AndroidManifest.xml` | Default/global untuk seluruh WebView aplikasi |
| `WebSettings.setSafeBrowsingEnabled(false)` | Kode Java/Kotlin, per instance WebView | **Menang** atas setting manifest |

Hierarki ini punya implikasi penting untuk metodologi pengujian (§3) — **memeriksa manifest saja tidak cukup**. Sebuah aplikasi bisa terlihat aman di manifest (tidak ada meta-data `false`, atau bahkan secara eksplisit `true`) namun tetap rentan bila di suatu tempat dalam kode, satu pemanggilan `setSafeBrowsingEnabled(false)` menonaktifkannya untuk instance WebView tertentu — ini konsisten dengan prinsip evaluasi resmi berikut:

> **Evaluation:** *"A WebView is protected only when SafeBrowsing is neither disabled in the manifest nor in code."*

Logika evaluasi ini adalah **AND** terhadap dua negasi — kedua titik kontrol harus **sama-sama** tidak menonaktifkan, bukan sekadar salah satu.

### 1.4 Analisis Rule Resmi: Dua Pola Bersih Tanpa Kompleksitas Berlebih

Berbeda dari beberapa rule lain dalam seri riset ini yang memiliki kesenjangan cakupan signifikan, rule `mastg-android-webview-safebrowsing.yml` untuk test ini cukup sederhana dan tepat sasaran — karena nilai yang berbahaya adalah **literal tunggal** (`false`), tidak ada ruang ambiguitas seperti pada rule-rule yang menangani kombinasi flag:

```yaml
# Pola manifest
pattern: <meta-data android:name="android.webkit.WebView.EnableSafeBrowsing" android:value="false" ... />

# Pola kode
pattern: $WEBSETTINGS.setSafeBrowsingEnabled(false)
```

Kedua pola ini secara langsung memetakan kedua titik kontrol yang disebut overview (§1.3) tanpa kesenjangan yang jelas — ini adalah salah satu rule paling "rapi" yang ditemukan dalam seri riset ini, kemungkinan karena sifat biner dari nilai yang diperiksa (`true`/`false`) tidak memberi banyak ruang untuk variasi ekspresi yang rumit seperti kombinasi flag bitwise pada test-test lain.

### 1.5 Catatan Penting: Rule Terkait Namun Berbeda Scope yang Ditemukan Bersebelahan di File TEST-0398

Dalam riset dokumen MASTG-TEST-0398 sebelumnya, ditemukan rule kedua `mastg-android-webviewclient-safebrowsing-whitelist` yang **dibundel dalam file YAML milik TEST-0398**, menyasar `setSafeBrowsingWhitelist()` dan override `onSafeBrowsingHit()`. Topik tersebut **lebih dekat secara tematik** dengan test ini (SafeBrowsing) dibanding dengan TEST-0398 (URL handler kustom), namun **tidak disebutkan** di `apis:` frontmatter test ini maupun TEST-0398. Ini mengindikasikan adanya **topik ketiga yang terkait** (penyesuaian/pelemahan SafeBrowsing lewat whitelist atau override callback) yang belum memiliki test MASTG resmi tersendiri, namun sudah memiliki rule Semgrep yang dibundel secara tidak konsisten secara organisasi file. Penguji yang ingin audit SafeBrowsing secara menyeluruh sebaiknya **juga** memeriksa pola ini sebagai pelengkap, meski secara ketat berada di luar scope deklaratif kedua test (TEST-0398 dan TEST-0399).

### 1.6 Bukti Nyata: Android Lint Rule Resmi sebagai Pengakuan Risiko di Tingkat Tooling Platform

Signifikansi risiko ini diakui bukan hanya oleh MASTG, tapi juga oleh **tooling resmi Android sendiri** — Google menyediakan custom lint check khusus untuk pola ini:

> *"Application has disabled safe browsing for all WebView objects is a warning"* — dari dokumentasi [Android Custom Lint Rules: DisabledAllSafeBrowsing](https://googlesamples.github.io/android-custom-lint-rules/checks/DisabledAllSafeBrowsing.md.html).

Keberadaan lint check resmi ini menegaskan bahwa Google sendiri menganggap pola menonaktifkan SafeBrowsing secara menyeluruh cukup berisiko untuk diperingatkan secara otomatis **saat compile-time**, sebelum aplikasi bahkan sempat dirilis — sebuah sinyal kuat tentang tingkat keseriusan temuan ini dari sudut pandang vendor platform itu sendiri, bukan hanya dari perspektif pengujian keamanan independen seperti MASTG.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **aapt / Androguard** | Ekstraksi manifest untuk memeriksa meta-data `EnableSafeBrowsing` (MASTG-TECH-0117, MASTG-TECH-0150) |
| **jadx** | Dekompilasi untuk pencarian `setSafeBrowsingEnabled` di kode (MASTG-TECH-0013, MASTG-TECH-0014) |
| **Semgrep** + rule resmi | Deteksi kedua pola secara otomatis |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **Android Lint** | `DisabledAllSafeBrowsing` check bawaan — bisa dijalankan langsung terhadap source project (bila tersedia) sebagai pelengkap analisis APK biner |
| **grep/ripgrep** | Verifikasi tambahan dan pencarian pola terkait (whitelist/callback, §1.5) |

### 2.3 Prasyarat Lingkungan

- Tidak butuh device/root — murni analisis statis konfigurasi.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0013** untuk reverse engineer aplikasi.
2. Gunakan **MASTG-TECH-0117** untuk memperoleh `AndroidManifest.xml`.
3. Gunakan **MASTG-TECH-0150** untuk memeriksa atribut yang relevan.
4. Gunakan **MASTG-TECH-0014** untuk mencari API yang relevan di kode.

### 3.2 Metode A — Semgrep dengan Rule Resmi (Cakupan Lengkap)

```bash
semgrep --config mastg-android-webview-safebrowsing.yml ./AndroidManifest.xml ./decompiled/sources
```

### 3.3 Metode B — grep/ripgrep untuk Verifikasi Manual

```bash
# Manifest
grep -A3 'EnableSafeBrowsing' AndroidManifest.xml

# Kode
rg -n 'setSafeBrowsingEnabled\(' ./decompiled/sources
```

### 3.4 Metode C — Pencarian Pola Terkait (Pelengkap, Sesuai §1.5)

```bash
rg -n 'setSafeBrowsingWhitelist\(|onSafeBrowsingHit\(' ./decompiled/sources
```

### 3.5 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Kapan dipakai |
|---|---|---|
| **A** | Semgrep + rule resmi | Baseline wajib — cakupan sudah memadai |
| **B** | grep/ripgrep manual | Verifikasi tambahan/konfirmasi |
| **C** | grep manual | Pelengkap opsional untuk topik terkait whitelist/callback |

**Kombinasi minimum yang aku rekomendasikan:** **A (sudah cukup sebagai baseline)**, dengan **C** sebagai pelengkap bila audit menyeluruh terhadap seluruh aspek SafeBrowsing diperlukan.

---

### 3.6 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Evaluation:** *"The test case fails if the `android.webkit.WebView.EnableSafeBrowsing` meta-data is present with `android:value='false'`, or if SafeBrowsing is disabled in code via `WebSettings.setSafeBrowsingEnabled(false)`."*

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila salah satu dari:

| No | Kondisi |
|---|---|
| F1 | Meta-data `android.webkit.WebView.EnableSafeBrowsing` di manifest bernilai `false` |
| F2 | `WebSettings.setSafeBrowsingEnabled(false)` dipanggil di kode untuk instance WebView manapun |

**Contoh bukti:**

```xml
<meta-data android:name="android.webkit.WebView.EnableSafeBrowsing" android:value="false" />
```

**FAIL** — perlindungan reputasi Google dinonaktifkan secara global untuk seluruh WebView aplikasi.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Tidak ada meta-data `EnableSafeBrowsing=false` di manifest, **dan** |
| P2 | Tidak ada pemanggilan `setSafeBrowsingEnabled(false)` di kode untuk WebView manapun |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Periksa KEDUA titik kontrol, bukan hanya manifest** — sesuai §1.3, `setSafeBrowsingEnabled(false)` di kode menang atas setting manifest; aplikasi yang terlihat aman di manifest tetap bisa FAIL bila ada pemanggilan ini di kode untuk instance WebView tertentu.

2. **Periksa setiap instance WebView secara terpisah** bila aplikasi memiliki banyak WebView — penonaktifan di kode bersifat per-instance, sehingga satu WebView bisa aman sementara WebView lain (mis. untuk iklan pihak ketiga) dinonaktifkan SafeBrowsing-nya.

3. **Tidak ada alasan bisnis yang umumnya valid untuk menonaktifkan ini** — berbeda dari beberapa test lain dalam seri riset ini yang punya nuansa "tidak selalu berbahaya", temuan di test ini jarang memiliki justifikasi sah; kemungkinan besar merupakan kelalaian atau konfigurasi warisan yang tidak disengaja.

4. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | SafeBrowsing dinonaktifkan pada WebView yang memuat konten dari sumber eksternal/pihak ketiga | **Tinggi** |
   | SafeBrowsing dinonaktifkan pada WebView yang hanya memuat konten first-party terkontrol penuh | **Rendah-Sedang** |
   | SafeBrowsing aktif di kedua titik kontrol | **Bukan temuan** |

5. **Dokumentasikan:** lokasi manifest/kode, nilai yang ditemukan, dan apakah ada pola terkait (whitelist/callback, §1.5) yang melemahkan perlindungan lebih lanjut.

---

## 4. Rekomendasi Perbaikan

### 4.1 Pastikan SafeBrowsing Tetap Aktif (Default, Jangan Diubah)

```xml
<!-- Hapus meta-data ini sepenuhnya, atau pastikan value="true" bila memang perlu dideklarasikan eksplisit -->
<!-- <meta-data android:name="android.webkit.WebView.EnableSafeBrowsing" android:value="false" /> -->
```

```java
// Hindari pemanggilan ini kecuali ada justifikasi kuat yang terdokumentasi
// webSettings.setSafeBrowsingEnabled(false);
```

### 4.2 Checklist Remediasi

- [ ] Meta-data `EnableSafeBrowsing` tidak diset `false` di manifest
- [ ] Tidak ada pemanggilan `setSafeBrowsingEnabled(false)` di kode untuk WebView manapun
- [ ] Bila ditemukan whitelist/callback SafeBrowsing (§1.5), diaudit terpisah untuk memastikan tidak melemahkan perlindungan secara tidak sengaja
- [ ] Dijalankan Android Lint (`DisabledAllSafeBrowsing`) sebagai pemeriksaan tambahan di pipeline CI bila memiliki akses ke source project

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0399 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-CODE/MASTG-TEST-0399.md)
- [MASTG-TEST-0398 (dokumen terkait dalam seri riset ini)](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0398/)
- [MASTG-KNOW-0018: WebViews](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0018/)

### 5.2 Dokumentasi Resmi dan Riset

- [Chromium: Android WebView Safe Browsing (Dokumentasi Teknis V4/V5 Protocol)](https://chromium.googlesource.com/chromium/src.git/+/master/android_webview/browser/safe_browsing/README.md)
- [Android Developers: Manage WebView Objects](https://developer.android.com/develop/ui/views/layout/webapps/managing-webview)
- [Android Custom Lint Rules: DisabledAllSafeBrowsing](https://googlesamples.github.io/android-custom-lint-rules/checks/DisabledAllSafeBrowsing.md.html)

### 5.3 Dokumentasi Tools

- [Semgrep Documentation](https://semgrep.dev/docs/)
- [Google Safe Browsing](https://developers.google.com/safe-browsing/)

---

*Dokumen ini disusun berdasarkan konten resmi OWASP MASTG (`tests-beta/android/MASVS-CODE/MASTG-TEST-0399.md`, `MASTG-KNOW-0018`), analisis rule `mastg-android-webview-safebrowsing.yml` yang menunjukkan desain bersih tanpa kesenjangan signifikan (berkat sifat biner nilai yang diperiksa), serta dokumentasi teknis Chromium tentang evolusi protokol SafeBrowsing dari local blocklist (V4) ke real-time checking (V5, sejak M126). Bukti nyata paling kuat untuk test ini datang dari pengakuan Google sendiri lewat custom lint rule resmi `DisabledAllSafeBrowsing` — menegaskan bahwa vendor platform pun menganggap pola ini cukup berisiko untuk diperingatkan otomatis saat compile-time. Nuansa metodologis terpenting: evaluasi bersifat AND terhadap dua titik kontrol independen (manifest dan kode), dengan kode selalu menang atas manifest — audit yang hanya memeriksa salah satu titik kontrol tidak memadai.*
