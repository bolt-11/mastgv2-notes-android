# MASTG-TEST-0329 References to APIs Enforcing Authentication without Explicit User Action

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0329 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-AUTH |
| **Weakness** | MASWE-0020 |
| **Tipe Pengujian** | Static, Code |
| **API terkait** | `BiometricPrompt.PromptInfo.Builder`, `setConfirmationRequired` |
| **Teknik terkait** | MASTG-TECH-0013 (Reverse Engineering), MASTG-TECH-0014 (Static Analysis for Relevant APIs) |
| **Knowledge terkait** | MASTG-KNOW-0001 (Biometric Authentication) |
| **Best Practice terkait** | MASTG-BEST-0038 (Require Explicit User Confirmation for Biometric Authentication) |
| **Test terkait** | MASTG-TEST-0326, MASTG-TEST-0327, MASTG-TEST-0328 — satu rangkaian penuh pemeriksaan konfigurasi `BiometricPrompt` dari sudut berbeda |
| **Rule resmi** | `mastg-android-biometric-no-confirmation-required.yml` — pola tunggal sederhana, serupa struktur dengan rule TEST-0328 |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Kutipan overview resmi MASTG:

> *"This test checks if the app enforces biometric authentication without requiring explicit user action. When using BiometricPrompt API... the `setConfirmationRequired()` method in `BiometricPrompt.Builder` controls whether the user must explicitly confirm their authentication, which is enforced by default."*

Sama seperti MASTG-TEST-0328, ini adalah test di mana **default API sudah aman** — `setConfirmationRequired()` secara default bernilai `true`, dan risiko muncul hanya ketika developer **secara eksplisit** mengatur `false`.

### 1.2 Mengapa Konfirmasi Eksplisit Penting: Biometrik Pasif vs Aktif

MASTG-BEST-0038 menjelaskan mekanisme teknis di balik risiko ini:

> *"When `setConfirmationRequired(false)` is used, passive biometrics such as face recognition can authenticate the user implicitly as soon as the device detects their biometric data. This means authentication can complete without the user actively acknowledging the operation."*

Perbedaan modalitas biometrik di sini krusial:

| Modalitas | Sifat | Implikasi tanpa Confirmation |
|---|---|---|
| **Sidik jari (fingerprint)** | Aktif — pengguna harus **sengaja** menyentuh sensor | Risiko lebih rendah; sentuhan jari tetap memerlukan niat fisik langsung |
| **Wajah/iris (face/iris)** | Pasif — cukup **mengarahkan** kamera ke wajah, tanpa aksi sadar dari pengguna | Risiko tinggi — autentikasi bisa selesai **tanpa pengguna menyadari atau menyetujui** sedang terjadi apa pun |

Dokumentasi resmi Android menjelaskan tujuan desain fitur ini sebagai trade-off kenyamanan vs keamanan:

> *"If your app shows a biometric authentication dialog for a lower-risk action, you can provide a hint to the system that the user doesn't need to confirm authentication. This hint can allow the user to view content in your app more quickly after re-authenticating using a passive modality."*

Namun dokumentasi yang sama secara eksplisit membalik rekomendasi untuk kasus berisiko tinggi:

> *"This configuration is preferable if your app is showing the dialog to confirm a sensitive or high-risk action, such as making a purchase"* — merujuk pada **`setConfirmationRequired(true)`**, bukan `false`.

### 1.3 Skenario Serangan Konkret: Memanfaatkan Modalitas Pasif Tanpa Persetujuan

Risiko nyata dari konfigurasi `false` pada modalitas pasif adalah skenario di mana **pengguna tidak secara aktif memilih untuk mengautentikasi**, namun sistem tetap menerima biometrik yang "terlihat" oleh sensor:

- **Serangan "flash" kamera tanpa sadar** — penyerang mengarahkan perangkat korban yang sudah dalam keadaan terbuka/dipegang ke wajah korban secara singkat (misalnya saat korban lengah, tertidur, atau tidak sadar), memicu autentikasi wajah pasif tanpa korban pernah berniat melakukan transaksi apa pun.
- **Kurangnya "jendela sadar"** bagi pengguna untuk membatalkan — pada mode aktif (confirmation required), pengguna masih memiliki kesempatan terakhir untuk menekan tombol konfirmasi/batal setelah biometrik terverifikasi; pada mode pasif, proses selesai **seketika** begitu wajah terdeteksi cocok.

### 1.4 Bukti Nyata Cross-Platform: Kasus Face ID dan Penyalahgunaan untuk Transfer Dana

Meski platform berbeda (iOS, bukan Android), kasus berikut mengilustrasikan secara persis **kelas risiko yang sama** yang coba dicegah `setConfirmationRequired(true)` — penyalahgunaan biometrik wajah pasif terhadap korban yang tidak sadar untuk mengotorisasi transaksi finansial:

> *"Researchers demonstrated at the Black Hat USA 2019 conference that they could bypass Face ID using specially modified glasses with tape, and when placing the glasses over a sleeping victim's face, they were able to access the iPhone and send themselves money through a mobile payment app."*

Kasus nyata lain (dilaporkan media, bukan riset terkontrol) menunjukkan dugaan modus serupa di lapangan:

> *"Approximately $25,000 had been transferred out of a victim's checking accounts using Zelle, Venmo, CashApp, and investment accounts, and the victim suspected his assailants might have used his unconscious face to unlock his iPhone."*

Meski kasus-kasus ini melibatkan Face ID iOS (bukan `BiometricPrompt` Android) dan melibatkan bypass unlock layar secara umum (bukan secara spesifik API `setConfirmationRequired`), **prinsip ancamannya identik** — wajah yang terdeteksi secara pasif (tanpa pengguna secara sadar memilih untuk mengautentikasi) dapat dimanfaatkan untuk mengotorisasi aksi finansial bernilai tinggi tanpa persetujuan sesungguhnya. Inilah justifikasi nyata mengapa MASTG-BEST-0038 secara spesifik menyebut "payments" sebagai contoh utama operasi yang **wajib** memakai `setConfirmationRequired(true)`.

### 1.5 Nuansa Penting: Ini Hanyalah "Hint", Sistem Bisa Mengabaikannya

Catatan dari dokumentasi resmi Android yang jarang disorot namun penting untuk interpretasi hasil pengujian:

> *"Caution: Because this flag is passed as a hint to the system, the system might ignore the value if the user has changed their system settings for biometric authentication."*

Ini berarti `setConfirmationRequired(false)` **tidak menjamin** perilaku pasif akan benar-benar terjadi di semua kondisi — ini adalah **permintaan**, bukan **perintah mutlak**, dan sistem Android (atau preferensi pengguna di level OS) dapat mengambil keputusan akhir yang berbeda. Implikasinya untuk pengujian: temuan FAIL dari analisis statis **tetap valid sebagai indikasi niat/konfigurasi developer yang keliru**, namun perilaku aktual di perangkat tertentu bisa bervariasi tergantung versi Android dan setting pengguna — relevan dicatat sebagai keterbatasan interpretasi, bukan alasan untuk mengabaikan temuan.

### 1.6 Klasifikasi Severity: Sama Seperti TEST-0326, Bukan Vulnerability Kritis Otomatis

Catatan resmi memakai pola bahasa yang serupa dengan TEST-0326 (fallback device credential):

> *"Using setConfirmationRequired(false) is not inherently a vulnerability. It may be appropriate for low-risk operations, but for sensitive operations like payments or data access, the app should use setConfirmationRequired(true)."*

Ini menegaskan bahwa test ini, seperti TEST-0326, lebih tepat dikategorikan sebagai **hardening/konteks-dependent issue** — severity akhirnya bergantung penuh pada apakah operasi yang dilindungi benar-benar tergolong sensitif (pembayaran, akses data kesehatan) atau sekadar kenyamanan (login cepat ke konten non-sensitif).

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **jadx** | Dekompilasi DEX → Java (MASTG-TECH-0013) |
| **Semgrep** + rule resmi `mastg-android-biometric-no-confirmation-required.yml` | Pencocokan pola `setConfirmationRequired(false)` (MASTG-TECH-0014) |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **grep/ripgrep** | Verifikasi konteks pemanggilan — apakah builder yang sama dipakai untuk operasi sensitif (pembayaran) atau operasi ringan (login konten) |
| **MobSF** | Laporan otomatis yang kadang menyertakan pemeriksaan konfigurasi biometrik |
| **Verifikasi device fisik (face unlock device)** | Observasi langsung perilaku sesungguhnya — relevan mengingat nuansa "hint, bisa diabaikan sistem" di §1.5 |

### 2.3 Prasyarat Lingkungan

- Tidak butuh device/root untuk analisis statis.
- Untuk verifikasi perilaku aktual (opsional), diperlukan device dengan sensor wajah/iris yang mendukung mode pasif.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0013** untuk reverse engineer aplikasi.
2. Gunakan **MASTG-TECH-0014** untuk mencari API yang relevan.

### 3.2 Metode A — Semgrep dengan Rule Resmi

```bash
semgrep --config mastg-android-biometric-no-confirmation-required.yml ./decompiled/sources
```

### 3.3 Metode B — grep/ripgrep untuk Verifikasi Konteks Operasi

```bash
D=./decompiled/sources

# Cari pola berbahaya langsung
rg -n 'setConfirmationRequired\(\s*false\s*\)' $D

# Verifikasi konteks di sekitar pemanggilan — cari indikasi nama method/kelas terkait pembayaran/data sensitif
rg -n -B10 'setConfirmationRequired(false)' $D | grep -iE 'payment|transfer|checkout|health|medical|sensitive'
```

### 3.4 Metode C — Verifikasi Dinamis di Device Fisik dengan Face Unlock

```
Prosedur manual:
1. Jalankan aplikasi di device dengan sensor wajah/iris yang mendukung
2. Picu dialog BiometricPrompt pada titik yang ditandai `setConfirmationRequired(false)` dari Metode A/B
3. Amati: apakah operasi selesai SEKETIKA begitu wajah terdeteksi, tanpa tombol konfirmasi tambahan?
4. Bandingkan dengan titik lain yang memakai default/true — apakah ada tombol konfirmasi eksplisit yang muncul?
```

Berguna untuk mengonfirmasi secara langsung bahwa hint `false` benar-benar berlaku di device uji (mengingat catatan §1.5 bahwa sistem bisa mengabaikannya).

### 3.5 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Kapan dipakai |
|---|---|---|
| **A** | Semgrep + rule resmi | Baseline wajib |
| **B** | grep/ripgrep manual | Menilai relevansi konteks sensitif/non-sensitif di sekitar pemanggilan |
| **C** | Verifikasi device fisik | Konfirmasi perilaku aktual, mengingat sifat "hint" dari flag ini |

**Kombinasi minimum yang aku rekomendasikan:** **A + B (wajib)**, dengan **C** sebagai pelengkap bila device dengan sensor wajah/iris tersedia untuk operasi kategori high-risk yang ditemukan.

---

### 3.6 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Evaluation:** *"The test case fails if the app sets `setConfirmationRequired()` to `false` for sensitive operations that require explicit user authorization."*

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | `setConfirmationRequired(false)` dipanggil untuk operasi sensitif yang memerlukan otorisasi eksplisit pengguna (pembayaran, akses data kesehatan, dsb.) |

**Contoh bukti:**

```java
// Ditemukan di com/example/wallet/payment/PaymentConfirmActivity.java
BiometricPrompt.PromptInfo promptInfo = new BiometricPrompt.PromptInfo.Builder()
    .setTitle("Konfirmasi Pembayaran")
    .setSubtitle("Rp 5.000.000 ke John Doe")
    .setConfirmationRequired(false) // berisiko untuk operasi pembayaran
    .build();
```

Interpretasi: operasi pembayaran bernilai tinggi dikonfigurasi memakai mode pasif tanpa konfirmasi eksplisit — persis skenario risiko yang diperingatkan MASTG-BEST-0038 dan diilustrasikan kasus nyata §1.4. **FAIL**.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | `setConfirmationRequired(true)` diset eksplisit untuk operasi sensitif, **atau** |
| P2 | Method ini **tidak dipanggil sama sekali** (default `true`) untuk operasi sensitif |
| P3 | `setConfirmationRequired(false)` **hanya** dipakai untuk operasi berisiko rendah (mis. login cepat ke tampilan konten non-sensitif), sesuai rekomendasi resmi Android |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Ketidakhadiran pemanggilan API adalah PASS, bukan FAIL** — sama seperti TEST-0328, default sudah aman; fokus evaluasi pada kasus `false` yang **eksplisit** ditulis developer.

2. **Konteks operasi adalah penentu utama severity, bukan sekadar keberadaan pola** — temuan `setConfirmationRequired(false)` pada fitur non-sensitif **bukan temuan** sama sekali; selalu telusuri konteks pemanggilan (nama Activity/method, parameter yang ditampilkan di dialog) sebelum menyimpulkan FAIL.

3. **Ingat sifat "hint" dari flag ini (§1.5)** — jangan klaim kepastian absolut bahwa perilaku pasif akan selalu terjadi persis sesuai kode; bila memungkinkan, verifikasi dengan Metode C di device nyata untuk klaim yang lebih kuat dalam laporan.

4. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | `setConfirmationRequired(false)` pada operasi pembayaran/finansial bernilai tinggi atau akses data kesehatan | **Sedang-Tinggi** |
   | `false` pada operasi sensitif namun bernilai lebih rendah (mis. ubah profil) | **Rendah-Sedang** |
   | `false` pada operasi non-sensitif (login konten, personalisasi) | **Bukan temuan** |

5. **Dokumentasikan:** lokasi kode, konteks operasi yang dilindungi (nama fitur/Activity), nilai yang dikonfigurasi, dan hasil verifikasi device fisik bila dilakukan.

---

## 4. Rekomendasi Perbaikan

### 4.1 Gunakan Confirmation Required untuk Operasi Bernilai Tinggi

```java
// SEBELUM — pembayaran dengan mode pasif tanpa konfirmasi
new BiometricPrompt.PromptInfo.Builder()
    .setTitle("Konfirmasi Pembayaran")
    .setConfirmationRequired(false)
    .build();

// SESUDAH — sesuai MASTG-BEST-0038
new BiometricPrompt.PromptInfo.Builder()
    .setTitle("Konfirmasi Pembayaran")
    .setConfirmationRequired(true)
    .build();
```

### 4.2 Pisahkan Jalur Konfigurasi Berdasarkan Sensitivitas Operasi

Pertimbangkan membuat helper/factory method terpisah untuk "biometric prompt operasi sensitif" (selalu `true`) versus "biometric prompt operasi ringan" (`false` diperbolehkan), agar developer baru tidak secara tidak sengaja memakai konfigurasi pasif untuk fitur baru yang sensitif di kemudian hari.

### 4.3 Checklist Remediasi

- [ ] Seluruh operasi pembayaran/finansial/data sensitif memakai `setConfirmationRequired(true)` atau default
- [ ] `setConfirmationRequired(false)` hanya dipakai untuk operasi berisiko rendah yang terdokumentasi jelas alasannya
- [ ] Diverifikasi di device fisik dengan sensor wajah/iris untuk kasus high-risk yang ditemukan
- [ ] Dikorelasikan dengan hasil MASTG-TEST-0326/0327/0328 untuk audit menyeluruh konfigurasi `BiometricPrompt`

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0329 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-AUTH/MASTG-TEST-0329.md)
- [MASTG-KNOW-0001: Biometric Authentication](https://mas.owasp.org/MASTG/knowledge/android/MASVS-AUTH/MASTG-KNOW-0001/)
- [MASTG-BEST-0038: Require Explicit User Confirmation for Biometric Authentication](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0038.md)

### 5.2 Dokumentasi Resmi Android

- [Android Developers: Implement a Custom Biometric Authentication Flow — No Explicit User Action](https://developer.android.com/identity/sign-in/biometric-auth#no-explicit-user-action)
- [BiometricPrompt.Builder#setConfirmationRequired](https://developer.android.com/reference/android/hardware/biometrics/BiometricPrompt.Builder#setConfirmationRequired(boolean))

### 5.3 Riset dan Kasus Nyata

- [MacRumors: Researchers Demonstrated Method for Bypassing Face ID on an 'Unconscious' Victim's iPhone Using Glasses and Tape](https://www.macrumors.com/2019/08/08/face-id-bypassed-glasses-tape/amp)
- [Neowin: Tape and Glasses Are All You Need to Break Apple's FaceID — Alongside a Sleeping Person](https://www.neowin.net/news/tape-and-glasses-are-all-you-need-to-break-apples-faceid---alongside-a-sleeping-person/)

### 5.4 Dokumentasi Tools

- [Semgrep Documentation](https://semgrep.dev/docs/)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)

---

*Dokumen ini disusun berdasarkan konten resmi OWASP MASTG (`tests-beta/android/MASVS-AUTH/MASTG-TEST-0329.md`, `MASTG-KNOW-0001`, `MASTG-BEST-0038`), dokumentasi resmi Android tentang biometric auth tanpa aksi eksplisit, serta kasus nyata (meski cross-platform, iOS Face ID) dari riset Black Hat 2019 dan laporan media tentang penyalahgunaan biometrik wajah pasif terhadap korban tidak sadar untuk mengotorisasi transfer dana — bukti konkret mengapa MASTG-BEST-0038 secara spesifik menyoroti "payments" sebagai contoh utama operasi yang wajib memakai konfirmasi eksplisit. Nuansa metodologis terpenting: sama seperti TEST-0328, default API sudah aman (ketidakhadiran pemanggilan = PASS), dan flag ini bersifat "hint" yang bisa diabaikan sistem berdasarkan setting pengguna — klaim kepastian absolut dari analisis statis semata perlu dilunakkan dengan catatan ini.*
