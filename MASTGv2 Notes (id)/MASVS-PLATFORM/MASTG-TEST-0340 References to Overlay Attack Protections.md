# MASTG-TEST-0340 References to Overlay Attack Protections

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0340 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-PLATFORM |
| **Weakness** | MASWE-0036 |
| **Tipe Pengujian** | Static, Code |
| **API terkait** | `onFilterTouchEventForSecurity`, `setFilterTouchesWhenObscured`, `FLAG_WINDOW_IS_OBSCURED`, `FLAG_WINDOW_IS_PARTIALLY_OBSCURED` |
| **Teknik terkait** | MASTG-TECH-0013, MASTG-TECH-0014, MASTG-TECH-0117 (Obtain Manifest), MASTG-TECH-0150 (Obtain targetSdkVersion), MASTG-TECH-0126 (Obtain Permissions) |
| **Knowledge terkait** | MASTG-KNOW-0022 (Overlay Attacks) |
| **Best Practice terkait** | MASTG-BEST-0040 (Preventing Overlay Attacks) |
| **Rule resmi** | `mastg-android-overlay-protection.yml` — 7 pola lengkap, semua severity INFO, lihat §1.4 |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Kutipan overview resmi MASTG:

> *"Overlay attacks (also known as tapjacking) allow malicious apps to place deceptive UI elements over a legitimate app's interface, potentially tricking users into performing unintended actions such as granting permissions, revealing credentials, or authorizing payments."*

Sama seperti MASTG-TEST-0324 (root detection), ini adalah test "presence-based" — fokusnya adalah **apakah mekanisme perlindungan ada**, bukan menyasar pola kode yang berbahaya.

### 1.2 Evolusi Historis Overlay Attack: Tiga Generasi Serangan Berbeda

MASTG-KNOW-0022 menjelaskan bahwa "overlay attack" bukan satu jenis serangan tunggal, melainkan **tiga generasi teknik berbeda** yang masing-masing menyasar kelemahan platform yang berbeda sepanjang sejarah Android:

| Generasi | Rentang API Level | Mekanisme |
|---|---|---|
| **Tapjacking klasik** | Android 6.0 (API 23) ke bawah | Memanfaatkan fitur screen overlay untuk mendengarkan tap dan mencegat informasi yang diteruskan ke activity di bawahnya |
| **Cloak & Dagger** | Android 5.0–7.1 (API 21-25) | Menyalahgunakan kombinasi `SYSTEM_ALERT_WINDOW` ("draw on top") **dan** `BIND_ACCESSIBILITY_SERVICE` — kedua izin ini **diberikan otomatis tanpa notifikasi** saat aplikasi diinstal dari Play Store pada rentang API tersebut |
| **Toast Overlay** | Hingga Android 8.0 (API 26) | Varian yang **sama sekali tidak memerlukan permission apa pun** dari pengguna, dipatch lewat CVE-2017-0752 |

Signifikansi poin Cloak & Dagger sangat penting untuk konteks ancaman: *"When apps were installed from the Play Store, users did not need to explicitly grant these permissions and were not even notified."* Ini berarti pada era tersebut, pengguna **tidak memiliki cara untuk menyadari** bahwa aplikasi berbahaya telah memperoleh kapabilitas untuk menggambar di atas aplikasi lain — tidak ada dialog izin yang muncul sama sekali.

### 1.3 Bukti Nyata: Malware Perbankan yang Secara Eksplisit Dikutip MASTG Sendiri

Berbeda dari banyak test lain yang saya perlu riset eksternal untuk menemukan bukti nyata, MASTG-KNOW-0022 **sendiri** sudah secara eksplisit mencantumkan nama-nama malware nyata yang mengeksploitasi kelas kerentanan ini, secara spesifik menyasar sektor perbankan:

> *"Over the years, malware such as MazorBot, BankBot, and MysteryBot have exploited screen overlays to target business-critical applications, particularly in the banking sector."*

Riset akademik berskala besar tentang deteksi malware overlay di tingkat market juga menguatkan skala masalah ini secara empiris, menunjukkan bahwa ini bukan ancaman niche yang hanya dibahas di paper penelitian tanpa dampak nyata, melainkan kategori malware yang cukup umum untuk dipelajari dalam skala besar di seluruh ekosistem aplikasi yang beredar.

### 1.4 Analisis Rule Resmi: Pemetaan Lengkap 1-ke-1, Seluruhnya Severity INFO

Berbeda dari banyak rule lain dalam seri riset ini yang punya kesenjangan cakupan signifikan, rule `mastg-android-overlay-protection.yml` menunjukkan **kelengkapan desain yang sangat baik** — setiap API/atribut yang disebut di overview resmi (§1.1 daftar lima mekanisme) memiliki pola Semgrep tersendiri yang terpisah:

| Pattern ID | Menyasar |
|---|---|
| `-setfiltertoucheswhenobscured` | `setFilterTouchesWhenObscured()` |
| `-onfiltertoucheventforsecurity` | Override `onFilterTouchEventForSecurity()` |
| `-flag-window-is-obscured` | Pengecekan `FLAG_WINDOW_IS_OBSCURED` (2 variasi ekspresi bitwise) |
| `-flag-window-is-partially-obscured` | Pengecekan `FLAG_WINDOW_IS_PARTIALLY_OBSCURED` (2 variasi) |
| `-xml-attribute` | Atribut XML `android:filterTouchesWhenObscured="true"` — **satu-satunya rule dalam set ini yang menyasar bahasa XML**, bukan Java |
| `-sethideoverlaywindows` | `setHideOverlayWindows()` |
| `-hide-overlay-windows-permission` | Deklarasi permission `HIDE_OVERLAY_WINDOWS` di manifest |

Catatan analitis: seluruh tujuh pola ini **konsisten diberi severity `INFO`**, sejalan dengan sifat test "presence-based" — kehadiran pola-pola ini bukan indikasi bahaya, melainkan **sinyal positif** yang harus dicatat sebagai bukti mitigasi, mirip pola severity pada rule root detection (TEST-0324). Satu kelebihan desain yang patut dicatat: pemisahan pola XML dari pola Java menunjukkan kesadaran bahwa `android:filterTouchesWhenObscured` bisa dikonfigurasi di **dua tempat berbeda** (layout XML statis atau kode Java dinamis) — mencerminkan pemahaman mendalam terhadap cara developer Android sungguhan menulis kode.

### 1.5 Nuansa `targetSdkVersion`: Mengapa Langkah 4 Resmi Secara Eksplisit Meminta Informasi Ini

Perhatikan bahwa langkah resmi (§ Steps) secara eksplisit meminta ekstraksi `targetSdkVersion` (MASTG-TECH-0150) sebagai bagian dari observasi — ini bukan kebetulan. Kriteria FAIL resmi memiliki klausa yang **bersyarat pada versi API**:

> *"The app targets API level 31 or higher but does not use `setHideOverlayWindows(true)` and declare the `HIDE_OVERLAY_WINDOWS` permission."*

Ini konsisten dengan pola berulang dalam seri riset ini (mis. TEST-0285, TEST-0315) di mana `targetSdkVersion`/`minSdkVersion` menjadi parameter penentu **apakah suatu mekanisme bahkan tersedia atau relevan secara teknis** — `setHideOverlayWindows()` **tidak ada** sebagai API sebelum API level 31, sehingga tidak masuk akal menuntut kehadirannya pada aplikasi yang targetnya di bawah itu. Namun bagi aplikasi yang **sudah** menargetkan API 31+, ketidakhadiran mekanisme paling kuat ini (prevention penuh, bukan sekadar filtering touch) menjadi temuan yang layak dicatat.

### 1.6 Hierarki Robustness: Prevention vs Detection, Bukan Semua Mekanisme Setara

MASTG-BEST-0040 secara eksplisit mengurutkan mekanisme dari **paling robust ke paling lemah** — nuansa penting yang membedakan evaluasi kualitas temuan PASS, bukan sekadar biner ada/tidak ada:

> *"The following approaches are listed from most robust to least robust: 1. HIDE_OVERLAY_WINDOWS + setHideOverlayWindows(true) — most robust, prevents overlays entirely. 2. filterTouchesWhenObscured — filters touch events when obscured. 3. onFilterTouchEventForSecurity — custom policy, granular."*

Dan secara terpisah, dua mekanisme **deteksi** (`FLAG_WINDOW_IS_OBSCURED`/`PARTIALLY_OBSCURED`) dicatat sebagai kategori berbeda — mereka **hanya mendeteksi**, tidak otomatis mencegah:

> *"These mechanisms detect when overlays are present but do not automatically prevent them. They allow the app to respond accordingly... Note that this approach requires custom implementation to decide how to handle detected overlays."*

Implikasi penting: aplikasi yang **hanya** memeriksa flag deteksi tanpa logika respons yang benar (mis. memeriksa flag namun tetap melanjutkan aksi sensitif apa pun hasilnya) secara teknis "memiliki referensi API" namun **tidak benar-benar terlindungi** — ini kembali menegaskan sifat `type: [static, code]` murni test ini yang **tidak memverifikasi efektivitas logika**, hanya keberadaan referensi.

### 1.7 Keterbatasan yang Diakui Jujur: Tidak Semua Serangan Bisa Dimitigasi di Level Aplikasi

MASTG-BEST-0040 memberi pengakuan penting tentang batas kemampuan kontrol level aplikasi:

> *"Some attacks, particularly those exploiting system-level vulnerabilities (for example, Toast Overlay on Android versions before 8.0), cannot be fully mitigated at the app level."*

Dan catatan tentang risiko over-engineering:

> *"Applying touch filtering too broadly may impact legitimate use cases where overlays are expected (for example, system dialogs, accessibility features)."*

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **jadx** | Dekompilasi DEX → Java dan ekstraksi layout XML (MASTG-TECH-0013) |
| **Semgrep** + rule resmi `mastg-android-overlay-protection.yml` | Mendeteksi seluruh 7 pola API/atribut (MASTG-TECH-0014) |
| **aapt / Androguard** | Ekstraksi `AndroidManifest.xml` untuk `targetSdkVersion` dan permission (MASTG-TECH-0117, MASTG-TECH-0150, MASTG-TECH-0126) |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **grep/ripgrep** | Verifikasi tambahan pola yang mungkin ditulis dengan variasi ekspresi di luar cakupan Semgrep |
| **MobSF** | Laporan otomatis yang kadang menyertakan ekstraksi `targetSdkVersion` dan permission sebagai bagian ringkasan |
| **Aplikasi simulasi overlay (untuk verifikasi dinamis manual)** | Membuat overlay sungguhan di device uji untuk mengonfirmasi secara empiris apakah UI sensitif benar-benar terlindungi |

### 2.3 Prasyarat Lingkungan

- Tidak butuh device/root untuk analisis statis.
- Untuk verifikasi dinamis (opsional), butuh device uji dengan kemampuan menjalankan aplikasi overlay sederhana (`SYSTEM_ALERT_WINDOW`) untuk menguji perilaku aplikasi target secara langsung.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0013** untuk reverse engineer aplikasi.
2. Gunakan **MASTG-TECH-0014** untuk mencari API yang relevan.
3. Gunakan **MASTG-TECH-0117** untuk memperoleh `AndroidManifest.xml`.
4. Gunakan **MASTG-TECH-0150** untuk memperoleh `targetSdkVersion`.
5. Gunakan **MASTG-TECH-0126** untuk memperoleh permission yang relevan.

### 3.2 Metode A — Semgrep dengan Rule Resmi (Cakupan Lengkap)

```bash
semgrep --config mastg-android-overlay-protection.yml ./decompiled/sources ./resources/layout
```

### 3.3 Metode B — Ekstraksi Manifest untuk targetSdkVersion dan Permission

```bash
aapt dump badging app.apk | grep -E 'targetSdkVersion|HIDE_OVERLAY_WINDOWS'
```

### 3.4 Metode C — grep/ripgrep untuk Verifikasi Tambahan

```bash
D=./decompiled/sources
L=./resources/layout

rg -n 'setFilterTouchesWhenObscured|onFilterTouchEventForSecurity|setHideOverlayWindows' $D
rg -n 'filterTouchesWhenObscured' $L
```

### 3.5 Metode D — Verifikasi Dinamis dengan Overlay Simulasi

```
Prosedur manual:
1. Buat/instal aplikasi sederhana yang meminta SYSTEM_ALERT_WINDOW dan menggambar overlay transparan
2. Jalankan aplikasi target, navigasi ke layar sensitif (login, konfirmasi pembayaran)
3. Aktifkan overlay dari aplikasi simulasi di atas layar target
4. Coba berinteraksi dengan elemen UI sensitif — amati apakah tap diblokir/difilter (PASS) atau diteruskan normal (FAIL)
```

Ini memberi bukti paling konklusif tentang efektivitas sesungguhnya, melengkapi kelemahan §1.6 bahwa analisis statis murni tidak memverifikasi logika respons.

### 3.6 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Kapan dipakai |
|---|---|---|
| **A** | Semgrep + rule resmi | Baseline — cakupannya sudah lengkap untuk test ini |
| **B** | aapt/manifest | Wajib — menentukan apakah kriteria API 31+ berlaku |
| **C** | grep/ripgrep | Pelengkap verifikasi |
| **D** | Simulasi dinamis | Bukti efektivitas sesungguhnya, menutup keterbatasan analisis statis murni |

**Kombinasi minimum yang aku rekomendasikan:** **A + B (wajib)**, dengan **D** sangat direkomendasikan untuk UI sensitif pada aplikasi kategori finansial mengingat riwayat malware perbankan nyata (§1.3).

---

### 3.7 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Evaluation:** *"The test fails if the app handles sensitive user interactions (such as login, payment confirmation, permission requests, or security settings) and does not implement any overlay attack protections on those sensitive UI elements."*

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Tidak ada `setFilterTouchesWhenObscured(true)`/`android:filterTouchesWhenObscured="true"` pada UI sensitif |
| F2 | Tidak ada override `onFilterTouchEventForSecurity` |
| F3 | Tidak ada pengecekan `FLAG_WINDOW_IS_OBSCURED`/`PARTIALLY_OBSCURED` pada handler sentuhan UI sensitif |
| F4 | `targetSdkVersion` ≥ 31 **namun** tidak memakai `setHideOverlayWindows(true)` + permission `HIDE_OVERLAY_WINDOWS` |

**Contoh bukti:**

```xml
<!-- layout/activity_payment_confirm.xml, tanpa filterTouchesWhenObscured -->
<Button
    android:id="@+id/btn_confirm_payment"
    android:text="Konfirmasi Pembayaran" />
```

```java
// Tidak ditemukan setFilterTouchesWhenObscured/onFilterTouchEventForSecurity di seluruh codebase
// targetSdkVersion = 33, tidak ada setHideOverlayWindows/HIDE_OVERLAY_WINDOWS
```

Interpretasi: tombol konfirmasi pembayaran (UI sangat sensitif) tidak memiliki perlindungan overlay apa pun, dan aplikasi menargetkan API 31+ tanpa memanfaatkan mekanisme prevention terkuat yang tersedia. **FAIL**.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | UI sensitif memakai minimal satu mekanisme dari §1.6, **dengan prioritas** mekanisme prevention (`setHideOverlayWindows` untuk API 31+) di atas sekadar deteksi |
| P2 | Bila hanya memakai mekanisme deteksi (`FLAG_WINDOW_IS_OBSCURED`), ada logika respons yang jelas (menolak input, menampilkan peringatan) — bukan sekadar membaca flag tanpa aksi |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Selalu periksa `targetSdkVersion` sebelum menilai kriteria F4** — tidak masuk akal menuntut `setHideOverlayWindows` pada aplikasi yang menargetkan API di bawah 31 (API tersebut belum ada).

2. **Nilai kualitas, bukan hanya keberadaan** — sesuai hierarki §1.6, PASS dengan `setHideOverlayWindows` jauh lebih kuat dibanding PASS yang hanya mengandalkan pengecekan flag deteksi tanpa logika respons yang jelas; catat perbedaan kualitas ini dalam laporan meski keduanya secara teknis "PASS".

3. **Pertimbangkan verifikasi dinamis untuk UI kategori finansial** — mengingat riwayat nyata malware perbankan (MazorBot, BankBot, MysteryBot) yang secara spesifik menyasar kategori ini (§1.3), simulasi overlay langsung (Metode D) memberi keyakinan jauh lebih tinggi dibanding sekadar menemukan referensi API di kode.

4. **Jangan terlalu agresif merekomendasikan filtering di semua tempat** — sesuai peringatan MASTG-BEST-0040, terapkan hanya pada UI yang benar-benar sensitif; penerapan berlebihan bisa mengganggu skenario legitimate (dialog sistem, fitur aksesibilitas).

5. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | Tidak ada perlindungan apa pun pada UI finansial/kredensial/permission kritis | **Tinggi** |
   | Hanya mekanisme deteksi tanpa logika respons jelas | **Sedang** |
   | Mekanisme prevention kuat (`setHideOverlayWindows`) diterapkan dengan benar | **Bukan temuan** |

6. **Dokumentasikan:** lokasi UI sensitif yang diperiksa, mekanisme yang ditemukan (atau tidak ditemukan), `targetSdkVersion`, dan hasil verifikasi dinamis bila dilakukan.

---

## 4. Rekomendasi Perbaikan

### 4.1 Prioritaskan Prevention untuk API 31+

```kotlin
// Pada Activity dengan UI sensitif, targetSdkVersion >= 31
override fun onResume() {
    super.onResume()
    window.setHideOverlayWindows(true)
}
```

```xml
<uses-permission android:name="android.permission.HIDE_OVERLAY_WINDOWS" />
```

### 4.2 Terapkan Filtering Touch untuk Kompatibilitas Mundur

```xml
<Button
    android:id="@+id/btn_confirm_payment"
    android:filterTouchesWhenObscured="true"
    android:text="Konfirmasi Pembayaran" />
```

### 4.3 Checklist Remediasi

- [ ] Seluruh UI sensitif (login, pembayaran, permission, security settings) memiliki minimal satu mekanisme perlindungan overlay
- [ ] Aplikasi dengan `targetSdkVersion` ≥ 31 memanfaatkan `setHideOverlayWindows` + permission terkait
- [ ] Mekanisme deteksi (bila dipakai) disertai logika respons yang jelas, bukan sekadar membaca flag
- [ ] Diverifikasi secara dinamis dengan simulasi overlay nyata untuk UI kategori finansial
- [ ] Filtering tidak diterapkan berlebihan sehingga mengganggu skenario legitimate

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0340 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0340.md)
- [MASTG-KNOW-0022: Overlay Attacks](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0022/)
- [MASTG-BEST-0040: Preventing Overlay Attacks](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0040.md)

### 5.2 Dokumentasi Resmi Android

- [Android Developers: Tapjacking](https://developer.android.com/privacy-and-security/risks/tapjacking)
- [Window#setHideOverlayWindows](https://developer.android.com/reference/android/view/Window#setHideOverlayWindows(boolean))

### 5.3 Riset dan Kasus Nyata

- [Cloak & Dagger — Official Research Site](https://cloak-and-dagger.org/)
- [Black Hat US-17: Cloak and Dagger — From Two Permissions to Complete Control of the UI Feedback Loop](https://www.blackhat.com/docs/us-17/thursday/us-17-Fratantonio-Cloak-And-Dagger-From-Two-Permissions-To-Complete-Control-Of-The-UI-Feedback-Loop-wp.pdf)
- [Unit 42: Android Toast Overlay Attack — Cloak and Dagger with No Permissions (CVE-2017-0752)](https://unit42.paloaltonetworks.com/unit42-android-toast-overlay-attack-cloak-and-dagger-with-no-permissions/)
- [Understanding and Detecting Overlay-based Android Malware at Market Scales](https://tianyin.github.io/pub/overlay.pdf)

### 5.4 Dokumentasi Tools

- [Semgrep Documentation](https://semgrep.dev/docs/)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)

---

*Dokumen ini disusun berdasarkan konten resmi OWASP MASTG (`tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0340.md`, `MASTG-KNOW-0022`, `MASTG-BEST-0040`), analisis rule `mastg-android-overlay-protection.yml` yang menunjukkan kelengkapan desain 1-ke-1 terhadap seluruh API yang disebut overview, serta riset Black Hat/akademik tentang Cloak & Dagger dan Toast Overlay. MASTG-KNOW-0022 sendiri secara eksplisit mengutip malware perbankan nyata (MazorBot, BankBot, MysteryBot) yang mengeksploitasi kelas kerentanan ini. Nuansa metodologis terpenting: test ini bersifat "presence-based" seperti root detection (TEST-0324) — seluruh pola rule diberi severity INFO, dan evaluasi kualitas PASS harus mempertimbangkan hierarki robustness (prevention > detection) serta ketergantungan kriteria FAIL pada `targetSdkVersion` untuk mekanisme `setHideOverlayWindows` yang hanya tersedia sejak API 31.*
