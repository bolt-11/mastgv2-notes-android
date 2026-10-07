# MASTG-TEST-0393 Use of Unverified App Links

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0393 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-PLATFORM |
| **Weakness** | MASWE-0029 |
| **Tipe Pengujian** | Static, Config |
| **Teknik terkait** | MASTG-TECH-0013, MASTG-TECH-0172 (Listing Deep Links), MASTG-TECH-0174 (Verifying App Link Website Association) |
| **Knowledge terkait** | MASTG-KNOW-0019 (Deep Links) |
| **Best Practice terkait** | MASTG-BEST-0070 (Verify Android App Links with autoVerify and Digital Asset Links) |
| **Rule resmi** | `mastg-android-deeplink-autoverify-missing.yml` — desain yang relatif solid, lihat §1.5 |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Kutipan overview resmi MASTG:

> *"Android App Links are http/https deep links that the OS verifies against a website's Digital Asset Links file before routing them to the app... When a deep link `<intent-filter>` declares an http/https `<data>` scheme... but is missing the `android:autoVerify="true"` attribute, Android cannot confirm the app's ownership of the declared domain. A malicious app can register the same intent filter and intercept the deep links, enabling phishing, credential theft, or hijacking of user actions."*

### 1.2 Dua Jenis Deep Link dan Mengapa Keduanya Perlu Dibedakan

MASTG-KNOW-0019 membedakan dua jenis deep link secara fundamental:

| Jenis | Skema | Verifikasi OS | Risiko Utama |
|---|---|---|---|
| **Custom URL Scheme** | `myapp://` (bebas) | **Tidak pernah** diverifikasi | Bisa diklaim aplikasi mana pun yang mendaftarkan skema sama |
| **Android App Links** | `http://`/`https://` dengan `autoVerify` | **Diverifikasi** terhadap Digital Asset Links domain | Aman **hanya jika** verifikasi berhasil |

Test ini secara spesifik menyasar kategori kedua yang **gagal dikonfigurasi dengan benar** — deep link yang memakai skema `http`/`https` (yang **seharusnya bisa** diverifikasi) namun developer **lupa atau sengaja tidak** mengaktifkan `android:autoVerify="true"`, sehingga kehilangan satu-satunya keunggulan keamanan yang membedakannya dari custom URL scheme yang rapuh.

### 1.3 Deep Link Collision: Mekanisme Serangan yang Mendasari

> *"Using unverified deep links can cause a significant issue — any other apps installed on a user's device can declare and try to handle the same intent, which is known as deep link collision... In recent versions of Android this results in a so-called disambiguation dialog shown to the user that asks them to select the application that should handle the deep link. The user could make the mistake of choosing a malicious application instead of the legitimate one."*

Ini menjelaskan mekanisme serangan secara teknis — tanpa verifikasi, Android **tidak memiliki cara** untuk mengetahui aplikasi mana yang "benar-benar" berhak atas sebuah domain; sistem hanya bisa menampilkan dialog pilihan dan **mempercayakan keputusan ke pengguna**, yang bisa dikelabui secara sosial (nama aplikasi palsu yang meniru, ikon serupa) untuk memilih aplikasi berbahaya.

### 1.4 Nuansa Historis Kritis: Kegagalan Satu Link Bisa Melumpuhkan Verifikasi Semua Link (Pra-Android 12)

Ini adalah detail arsitektural yang sangat penting dan berulang kali ditekankan di seluruh dokumentasi terkait:

> *"Before Android 12 (API level 31), if the app has any non-verifiable links (e.g., missing autoVerify, an invalid Digital Asset Links file, or custom URL schemes), the system may skip verification for all Android App Links declared by that app — leaving even correctly configured App Links unprotected."*

Implikasi ini sangat serius — pada aplikasi dengan `minSdkVersion`/pengujian di perangkat API < 31, **satu** `<intent-filter>` yang salah konfigurasi (atau bahkan custom URL scheme yang tidak terkait) bisa **melumpuhkan perlindungan untuk SELURUH App Link lain** yang sudah dikonfigurasi dengan benar di aplikasi yang sama. Ini berarti audit harus **komprehensif** — menemukan satu `<intent-filter>` yang benar tidak menjamin keseluruhan domain terlindungi bila ada `<intent-filter>` lain yang cacat di aplikasi yang sama.

Android 12+ memperbaiki sebagian masalah ini:

> *"Starting with Android 12, a generic web intent resolves to the user's default browser unless the target app is approved for the specific domain, reducing but not eliminating the attack surface."*

### 1.5 Analisis Rule Resmi: Desain yang Relatif Solid dengan Nested Pattern-Inside

Berbeda dari banyak rule lain dalam seri riset ini yang punya kesenjangan cakupan signifikan, rule `mastg-android-deeplink-autoverify-missing.yml` menunjukkan desain yang cukup matang — memakai **empat lapis `pattern-inside`** untuk memastikan konteks yang tepat:

```yaml
patterns:
  - pattern: <data ... android:scheme="$SCHEME" ... />
  - metavariable-regex: { metavariable: $SCHEME, regex: ^https?$ }
  - pattern-inside: <activity ...>...</activity>
  - pattern-inside: <intent-filter ...><action .../>...</intent-filter>  # harus VIEW
  - pattern-inside: <intent-filter ...><category .../>...</intent-filter>  # harus BROWSABLE
  - pattern-not-inside: <intent-filter ... android:autoVerify="true" ...>...</intent-filter>
```

Rule ini secara eksplisit memverifikasi **seluruh tiga komponen** yang disebut MASTG-KNOW-0019 sebagai syarat deep link web yang valid (action `VIEW`, category `BROWSABLE`, data scheme `http`/`https`) **sebelum** menandai ketidakhadiran `autoVerify` — ini mengurangi risiko false positive terhadap `<intent-filter>` yang bukan benar-benar web deep link (misalnya hanya menangani intent internal tanpa kategori BROWSABLE).

### 1.6 Keterbatasan Penting: Presence Attribute ≠ Verifikasi Berhasil

Catatan resmi di bagian evaluasi menegaskan batas kemampuan analisis statis murni:

> *"Note that the presence of `android:autoVerify="true"` is necessary but not sufficient: the website association must also succeed. Use MASTG-TECH-0174 to confirm the declared domains are actually verified, since a misconfigured Digital Asset Links file leaves the App Links unverified even when the attribute is set."*

Ini berarti test ini **hanya** mengidentifikasi kandidat berdasarkan atribut manifest — verifikasi **sesungguhnya** (apakah file `assetlinks.json` benar-benar valid dan dapat diakses) menuntut langkah tambahan dengan MASTG-TECH-0174, yang memeriksa status verifikasi aktual di device (`adb shell pm get-app-links`) atau lewat tool independen.

### 1.7 Bukti Nyata: Empat Laporan HackerOne yang Sudah Dicantumkan Langsung oleh MASTG

Ini adalah test yang unik karena **dokumentasi resminya sendiri** sudah mencantumkan empat bukti kerentanan nyata tanpa perlu riset eksternal tambahan:

> - *HackerOne #1372667 — Able to steal bearer token from deep link*
> - *HackerOne #401793 — Insecure deeplink leads to sensitive information disclosure*
> - *HackerOne #583987 — Android app deeplink leads to CSRF in follow action*
> - *HackerOne #341908 — XSS via Direct Message deeplinks*

Keempat kasus ini mencakup spektrum dampak yang luas — dari pencurian token autentikasi langsung, kebocoran informasi sensitif, CSRF (memaksa aksi atas nama pengguna tanpa persetujuan — misalnya "follow" paksa), hingga XSS yang disuntikkan lewat parameter deep link pesan langsung. Keragaman dampak ini menegaskan bahwa risiko deep link yang tidak terverifikasi **bukan kategori tunggal**, melainkan **vektor masuk** yang bisa bereskalasi ke berbagai jenis kerentanan lain tergantung bagaimana parameter deep link diproses lebih lanjut oleh aplikasi.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **aapt2 / xmlstarlet** | Ekstraksi manifest untuk enumerasi `<intent-filter>` deep link (MASTG-TECH-0172) |
| **Semgrep** + rule resmi | Deteksi `<data>` http/https tanpa `autoVerify` (cakupan relatif solid) |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **Android App Link Verification Tester** (`deeplink_analyser.py`) | Enumerasi deep link dan verifikasi status asosiasi langsung dari APK (MASTG-TECH-0172, MASTG-TECH-0174) |
| **adb shell pm get-app-links** | Verifikasi status asosiasi sesungguhnya di device (API 31+) — wajib untuk menutup celah §1.6 |
| **adb shell dumpsys package** | Melihat seluruh skema yang didaftarkan aplikasi |

### 2.3 Prasyarat Lingkungan

- Analisis manifest tidak butuh device/root.
- Verifikasi status asosiasi sesungguhnya (§1.6) butuh device/emulator dengan aplikasi terinstal, atau akses ke domain yang bersangkutan untuk memeriksa `assetlinks.json` secara independen.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0013** untuk reverse engineer aplikasi.
2. Gunakan **MASTG-TECH-0172** untuk mendaftar deep link yang dideklarasikan di manifest.

### 3.2 Metode A — Semgrep dengan Rule Resmi

```bash
semgrep --config mastg-android-deeplink-autoverify-missing.yml ./AndroidManifest.xml
```

### 3.3 Metode B — Android App Link Verification Tester

```bash
git clone https://github.com/inesmartins/Android-App-Link-Verification-Tester
python3 deeplink_analyser.py -op list-all -apk target.apk
python3 deeplink_analyser.py -op verify-applinks -apk target.apk
```

### 3.4 Metode C — Verifikasi Status Asosiasi Sesungguhnya (Wajib, Sesuai §1.6)

```bash
adb shell pm get-app-links com.example.app
```

Periksa output — status harus `verified` untuk setiap domain; nilai lain (`legacy_failure`, kode numerik error) berarti domain **tidak** terverifikasi meski `autoVerify="true"` sudah ada di manifest.

### 3.5 Metode D — Pemeriksaan Manual File Digital Asset Links

```bash
curl -s https://www.example.com/.well-known/assetlinks.json
```

Verifikasi: apakah file ada, disajikan via HTTPS tanpa redirect, JSON valid, dan mencantumkan package name + fingerprint sertifikat signing yang benar.

### 3.6 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Kapan dipakai |
|---|---|---|
| **A** | Semgrep + rule resmi | Baseline wajib — deteksi cepat ketidakhadiran `autoVerify` |
| **B** | deeplink_analyser.py | Alternatif terintegrasi untuk enumerasi + verifikasi |
| **C** | `adb shell pm get-app-links` | **Wajib** — konfirmasi verifikasi sesungguhnya |
| **D** | curl manual | Diagnosis akar penyebab bila verifikasi gagal |

**Kombinasi minimum yang aku rekomendasikan:** **A (triase) → C (wajib, konfirmasi nyata)**, dengan **D** untuk diagnosis bila C menunjukkan kegagalan.

---

### 3.7 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Evaluation:** *"The test case fails if you identify any deep link `<intent-filter>` element that declares an http/https `<data>` scheme without the `android:autoVerify="true"` attribute."*

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | `<intent-filter>` dengan action `VIEW` + category `BROWSABLE` + `<data>` scheme `http`/`https` **tanpa** `android:autoVerify="true"` |
| F2 | *(Validasi lanjutan)* `autoVerify="true"` ada namun verifikasi domain gagal saat diperiksa via `adb shell pm get-app-links` (§1.6) |

**Contoh bukti (merefleksikan pola nyata HackerOne #1372667 §1.7):**

```xml
<activity android:name=".DeepLinkActivity" android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="https" android:host="app.example.com" android:path="/auth/callback" />
    </intent-filter>
</activity>
```

Interpretasi: deep link `https://app.example.com/auth/callback` (kemungkinan membawa bearer token sebagai parameter) tanpa `autoVerify` — aplikasi berbahaya bisa mendaftarkan intent filter identik dan mencegat token autentikasi. **FAIL**.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | `android:autoVerify="true"` ada pada seluruh `<intent-filter>` http/https, **dan** |
| P2 | Verifikasi domain terkonfirmasi `verified` via `adb shell pm get-app-links`, **dan** |
| P3 | *(Pra-Android 12)* Tidak ada `<intent-filter>` lain yang non-verifiable di aplikasi yang sama yang bisa melumpuhkan verifikasi keseluruhan (§1.4) |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Jangan berhenti setelah menemukan `autoVerify="true"`** — sesuai §1.6, ini kondisi perlu namun tidak cukup; selalu verifikasi status sesungguhnya via Metode C.

2. **Audit seluruh `<intent-filter>` di aplikasi, bukan hanya satu per satu secara terisolasi** — sesuai §1.4, pada perangkat pra-Android 12, satu link yang cacat bisa melumpuhkan verifikasi seluruh App Link lain di aplikasi yang sama.

3. **Nilai parameter deep link untuk risiko lanjutan** — sesuai keragaman dampak di §1.7 (token theft, CSRF, XSS), periksa juga bagaimana parameter dari deep link diproses lebih lanjut, karena verifikasi App Links sendiri tidak menjamin penanganan parameter yang aman.

4. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | Deep link membawa token/kredensial/parameter sensitif tanpa `autoVerify` | **Tinggi** |
   | Deep link navigasi biasa tanpa data sensitif, tanpa `autoVerify` | **Sedang** |
   | `autoVerify` ada namun verifikasi domain gagal | **Tinggi** (secara efektif setara F1) |
   | Seluruh kriteria PASS terpenuhi, termasuk verifikasi nyata | **Bukan temuan** |

5. **Dokumentasikan:** daftar lengkap `<intent-filter>` deep link, status `autoVerify`, hasil `pm get-app-links` per domain, dan parameter sensitif yang dibawa deep link (bila ada).

---

## 4. Rekomendasi Perbaikan

### 4.1 Aktifkan autoVerify dan Pastikan Digital Asset Links Valid (Sesuai MASTG-BEST-0070)

```xml
<intent-filter android:autoVerify="true">
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />
    <data android:scheme="https" android:host="app.example.com" />
</intent-filter>
```

```json
// https://app.example.com/.well-known/assetlinks.json
[{
  "relation": ["delegate_permission/common.handle_all_urls"],
  "target": {
    "namespace": "android_app",
    "package_name": "com.example.app",
    "sha256_cert_fingerprints": ["AA:BB:CC:..."]
  }
}]
```

### 4.2 Hindari Custom URL Scheme untuk Flow Sensitif

Sesuai MASTG-BEST-0070, jangan pakai `myapp://` untuk flow yang membawa token/data sensitif — skema ini **tidak pernah** diverifikasi OS. Migrasikan seluruh flow sensitif ke App Links yang terverifikasi.

### 4.3 Checklist Remediasi

- [ ] Seluruh `<intent-filter>` http/https memiliki `android:autoVerify="true"`
- [ ] File `assetlinks.json` valid, HTTPS tanpa redirect, mencantumkan package + fingerprint yang benar, untuk setiap domain/subdomain
- [ ] Verifikasi dikonfirmasi `verified` via `adb shell pm get-app-links`
- [ ] Tidak ada `<intent-filter>` non-verifiable lain yang bisa melumpuhkan verifikasi keseluruhan (pra-Android 12)
- [ ] Flow sensitif (token, auth callback) dimigrasikan dari custom URL scheme ke App Links terverifikasi

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0393 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0393.md)
- [MASTG-KNOW-0019: Deep Links](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0019/)
- [MASTG-BEST-0070: Verify Android App Links with autoVerify and Digital Asset Links](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0070.md)
- [MASTG-TECH-0172: Listing Deep Links](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0172/)
- [MASTG-TECH-0174: Verifying App Link Website Association](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0174/)

### 5.2 Kasus Nyata (Dicantumkan Langsung oleh MASTG)

- [HackerOne #1372667: Able to Steal Bearer Token from Deep Link](https://hackerone.com/reports/1372667)
- [HackerOne #401793: Insecure Deeplink Leads to Sensitive Information Disclosure](https://hackerone.com/reports/401793)
- [HackerOne #583987: Android App Deeplink Leads to CSRF in Follow Action](https://hackerone.com/reports/583987)
- [HackerOne #341908: XSS via Direct Message Deeplinks](https://hackerone.com/reports/341908)
- [People VT: Measuring the Insecurity of Mobile Deep Links of Android (Riset Akademik)](https://people.cs.vt.edu/gangwang/deep17.pdf)

### 5.3 Dokumentasi Tools

- [Android App Link Verification Tester](https://github.com/inesmartins/Android-App-Link-Verification-Tester)
- [Semgrep Documentation](https://semgrep.dev/docs/)

---

*Dokumen ini disusun berdasarkan konten resmi OWASP MASTG (`tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0393.md`, `MASTG-KNOW-0019`, `MASTG-BEST-0070`), analisis rule `mastg-android-deeplink-autoverify-missing.yml` yang menunjukkan desain relatif matang dengan verifikasi konteks berlapis, serta empat laporan HackerOne nyata yang sudah dicantumkan langsung oleh dokumentasi resmi MASTG sendiri — mencakup pencurian bearer token, kebocoran informasi, CSRF, dan XSS via parameter deep link. Nuansa metodologis terpenting: keberadaan `android:autoVerify="true"` adalah kondisi **perlu namun tidak cukup** — verifikasi domain sesungguhnya (via `adb shell pm get-app-links` atau pemeriksaan langsung file `assetlinks.json`) adalah langkah wajib yang tidak bisa digantikan analisis manifest semata, dan pada perangkat pra-Android 12, satu `<intent-filter>` yang cacat di aplikasi manapun dapat melumpuhkan verifikasi seluruh App Link lain yang sudah dikonfigurasi dengan benar.*
