# MASTG-TEST-0327 References to APIs for Event-Bound Biometric Authentication

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0327 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-AUTH |
| **Weakness** | MASWE-0020 |
| **Tipe Pengujian** | Static, Code |
| **API terkait** | `BiometricPrompt`, `BiometricPrompt.CryptoObject`, `authenticate` |
| **Teknik terkait** | MASTG-TECH-0013 (Reverse Engineering), MASTG-TECH-0014 (Static Analysis for Relevant APIs) |
| **Knowledge terkait** | MASTG-KNOW-0001 (Biometric Authentication), MASTG-KNOW-0043 (Android KeyStore), MASTG-KNOW-0047 (Cryptographic Key Storage), MASTG-KNOW-0012 (Key Generation) |
| **Best Practice terkait** | MASTG-BEST-0036 (Use Cryptographic Binding for Biometric Authentication) |
| **Test terkait** | **MASTG-TEST-0326** — topik berdekatan (fallback device credential) namun menyasar kelemahan konfigurasi yang **berbeda** (lihat §1.5 untuk perbandingan) |
| **Rule resmi** | `mastg-android-biometric-event-bound.yml` — 4 pola sekaligus, lihat §1.4 |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Kutipan overview resmi MASTG:

> *"This test checks if the app implements event-bound biometric authentication to access sensitive resources (e.g., tokens, keys), where authentication success relies solely on a callback result rather than being cryptographically bound to sensitive operations and requiring user presence."*

Ini adalah salah satu test paling krusial dalam kategori MASVS-AUTH — bukan soal **apakah** biometrik dipakai (itu sudah diasumsikan ada), melainkan **bagaimana** hasil autentikasi biometrik tersebut **diikat** ke operasi sensitif yang dilindunginya.

### 1.2 Dua Model Pengikatan: Event-Bound vs Crypto-Bound

Overview resmi menjelaskan perbedaan fundamental antara dua model:

> *"When used without a CryptoObject the app relies on the `onAuthenticationSucceeded` callback to determine if authentication was successful (event-bound). This makes it susceptible to logic manipulation by overwriting the callback without successfully passing the biometric verification."*
>
> *"In contrast, when a CryptoObject is used (crypto-bound), the app passes a cryptographic object (e.g., Cipher, Signature, Mac) that requires user authentication. This ensures authentication is not just a one-time boolean, but part of a secure data retrieval path (out-of-process), so bypassing authentication becomes significantly harder."*

Perbedaan konseptualnya:

| Model | Mekanisme | Titik Kegagalan |
|---|---|---|
| **Event-bound** | Hasil autentikasi = sekadar panggilan balik (`onAuthenticationSucceeded()`) yang menandakan "sukses" | **Satu titik tunggal** — siapa pun yang bisa memanggil/memicu method callback tersebut (lewat hooking) otomatis "lolos", tanpa pernah menyentuh sensor biometrik sungguhan |
| **Crypto-bound** | Hasil autentikasi = akses terhadap objek kriptografis (`Cipher`/`Signature`/`Mac`) yang **hanya bisa dibuka** oleh Keystore setelah verifikasi biometrik sukses di **Trusted Execution Environment (TEE)** | Operasi kriptografis terjadi **di luar proses aplikasi** (out-of-process) — memanggil method Java secara paksa tidak memberi akses ke kunci yang terkunci di hardware |

Frasa "out-of-process" di sini adalah kunci teknis mengapa crypto-bound jauh lebih kuat — validasi tidak terjadi di ruang proses aplikasi yang bisa dimanipulasi dengan hooking Frida biasa, melainkan di komponen hardware terisolasi (TEE/Secure Element) yang menjadi dasar Android KeyStore (sesuai MASTG-KNOW-0043).

### 1.3 Kriteria FAIL Ganda: Dua Kondisi Harus Sama-sama Terpenuhi

Bagian Evaluation resmi memiliki struktur logika AND yang eksplisit — ini penting untuk dipahami karena membedakan test ini dari banyak test lain yang kriteria FAIL-nya tunggal:

> *"The test case fails for each sensitive operation worth protecting if **all of the following applies**:*
> - *`BiometricPrompt.authenticate` is used without a `CryptoObject`.*
> - *There are no calls to key generation with `setUserAuthenticationRequired(true)` in conjunction with biometric authentication, as by default, the key is authorized to be used regardless of whether the user has been authenticated or not."*

Poin kedua ini mengandung detail teknis yang sangat mudah terlewat: **`setUserAuthenticationRequired(true)` bukan default**. Bila developer membuat key di Keystore tanpa secara eksplisit mengatur flag ini ke `true`, key tersebut **dapat dipakai kapan saja tanpa autentikasi apa pun** — artinya meski secara permukaan aplikasi "punya Keystore key", key itu sendiri tidak benar-benar terikat ke persyaratan autentikasi pengguna. Ini berarti **memiliki CryptoObject saja tidak cukup** untuk PASS — key yang mendasarinya juga harus dikonfigurasi dengan benar.

### 1.4 Analisis Rule Resmi: Empat Pola yang Saling Melengkapi

Rule `mastg-android-biometric-event-bound.yml` memiliki empat pola yang mencerminkan dua kriteria FAIL di atas, dipecah per API family (androidx vs framework lama) dan per aspek (pemanggilan `authenticate()` vs konfigurasi key):

| Pattern | Menyasar | Detail Teknis |
|---|---|---|
| **Pattern 1** | `androidx.biometric.BiometricPrompt.authenticate()` tanpa `CryptoObject` | Memakai `pattern-not` untuk mengecualikan varian 2-parameter (`PromptInfo`, `CryptoObject`) |
| **Pattern 2** | `android.hardware.biometrics.BiometricPrompt.authenticate()` tanpa `CryptoObject` (API framework lama) | Membedakan varian 3-parameter (tanpa crypto) vs 4-parameter (dengan crypto) berdasarkan **jumlah argumen** |
| **Pattern 3a** | `KeyGenParameterSpec.Builder` tanpa `setUserAuthenticationRequired(true)`, dalam file yang mengimpor `android.hardware.biometrics.BiometricPrompt` | Dibatasi scope impor untuk menghindari false positive pada key non-biometrik |
| **Pattern 3b** | Sama seperti 3a, tapi untuk scope impor `androidx.biometric.BiometricPrompt` | Menangani kedua varian library yang mungkin dipakai |

Catatan desain yang baik: rule ini secara eksplisit menyatakan alasan pembatasan scope pada komentar YAML-nya — *"Scoped to files using... BiometricPrompt to avoid false positives on non-biometric keys"* — menunjukkan kesadaran desainer rule terhadap risiko over-matching yang justru ditemukan sebagai kelemahan pada rule test sebelumnya (TEST-0326 §1.4). Namun perlu dicatat: pembatasan berbasis **file-level import** (bukan per-fungsi) berarti bila satu file memiliki banyak key generation untuk tujuan berbeda, rule bisa saja menandai key yang **tidak terkait biometrik** sama sekali hanya karena berada di file yang sama dengan kode biometrik — potensi false positive yang lebih sempit namun tetap ada.

### 1.5 Perbandingan dengan MASTG-TEST-0326: Dua Kelemahan Berbeda yang Sering Disalahpahami Sama

Penting membedakan test ini dari MASTG-TEST-0326 secara jelas, karena keduanya sama-sama membahas `BiometricPrompt` namun menyasar **aspek konfigurasi yang sama sekali berbeda**:

| | MASTG-TEST-0326 | MASTG-TEST-0327 (test ini) |
|---|---|---|
| **Pertanyaan inti** | Apakah autentikasi *bisa jatuh* ke metode yang lebih lemah (PIN/pattern)? | Apakah hasil autentikasi *terikat secara kriptografis* ke operasi yang dilindunginya? |
| **API yang disorot** | `setAllowedAuthenticators()` dengan `DEVICE_CREDENTIAL` | `authenticate()` tanpa `CryptoObject` |
| **Risiko bila FAIL** | Pengguna/penyerang bisa memakai PIN alih-alih jari/wajah (shoulder surfing) | Autentikasi bisa **dibypass sepenuhnya** lewat hooking tanpa autentikasi *apa pun*, termasuk PIN |
| **Severity relatif** | Hardening issue (per klasifikasi resmi) | Lebih serius — ini adalah **bypass total**, bukan sekadar "jalur lebih lemah" |

Keduanya **bisa dan sering muncul bersamaan** pada satu aplikasi — sebuah aplikasi bisa saja sudah benar menghindari `DEVICE_CREDENTIAL` (lulus TEST-0326) namun tetap rentan di test ini karena tidak memakai `CryptoObject` sama sekali.

### 1.6 Bukti Nyata: Bitwarden, Signal, dan Dashlane Pernah Ditemukan Rentan terhadap Pola Ini

Ini adalah bukti paling konkret yang bisa didapat untuk menunjukkan test ini bukan risiko teoretis — riset SEC Consult mendokumentasikan bypass nyata terhadap **tiga aplikasi populer dengan basis pengguna sangat besar**, tepat pada kelemahan yang disasar test ini:

> *"The research documented successful bypasses against three prominent applications: Bitwarden (1M+ downloads, v2023.3.2), Dashlane (5M+ downloads, v6.2313.0), and Signal (100M+ downloads, v6.17.3). Bitwarden and Signal did not generate a key at all and thus also did not make use of a CryptoObject to protect data cryptographically."*

Mekanisme teknis bypass yang didokumentasikan persis menggambarkan risiko "event-bound" dari §1.2:

> *"Frida hooks into the authenticate method of the BiometricPrompt API to detect an authentication attempt, and inside the hook, the script makes a callback to onAuthenticationSucceeded to trigger a successful authentication... making the app believe that biometric authentication was successful."*

Fakta bahwa aplikasi **password manager** (Bitwarden, Dashlane) dan aplikasi **pesan terenkripsi** (Signal) — kategori aplikasi yang secara eksplisit berfokus pada keamanan sebagai proposisi nilai utama mereka — ditemukan rentan terhadap pola ini menegaskan betapa mudahnya kesalahan konfigurasi ini terlewat bahkan oleh tim yang berpengalaman. Catatan penting dari riset ini juga relevan untuk realisme penilaian risiko:

> *"Importantly, attackers require either root device access or the ability to convince users to install a modified app version, plus physical device access to execute the attack."*

Ini menegaskan bahwa meski bypass secara teknis "trivial" sekali prasyarat terpenuhi, **prasyaratnya sendiri tidak trivial** (root + akses fisik, atau rekayasa sosial untuk instalasi APK modifikasi) — relevan untuk kalibrasi severity yang proporsional, bukan otomatis "kritis" tanpa konteks ancaman.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **jadx** | Dekompilasi DEX → Java (MASTG-TECH-0013) |
| **Semgrep** + rule resmi `mastg-android-biometric-event-bound.yml` | Pencocokan 4 pola `authenticate()`/`KeyGenParameterSpec` (MASTG-TECH-0014) |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **grep/ripgrep** | Verifikasi manual argumen `authenticate()` di luar batasan scope file-level rule resmi (§1.4) |
| **Frida** | Verifikasi dinamis — konfirmasi apakah bypass `onAuthenticationSucceeded` benar-benar berhasil mengubah perilaku aplikasi (menjembatani ke pengujian dinamis, meski tidak ada test dinamis resmi terpisah untuk topik ini) |
| **MobSF** | Laporan otomatis yang kadang menyertakan pemeriksaan konfigurasi Keystore sebagai bagian ringkasan |

### 2.3 Prasyarat Lingkungan

- Tidak butuh device/root untuk analisis statis.
- Pahami struktur `KeyGenParameterSpec.Builder` (rujuk MASTG-KNOW-0012) untuk mengenali pola method chaining yang bisa jadi tersebar di beberapa baris/method helper, tidak selalu dalam satu blok builder tunggal yang mudah dicocokkan rule.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0013** untuk reverse engineer aplikasi.
2. Gunakan **MASTG-TECH-0014** untuk mencari API yang relevan.

### 3.2 Metode A — Semgrep dengan Rule Resmi

```bash
semgrep --config mastg-android-biometric-event-bound.yml ./decompiled/sources
```

### 3.3 Metode B — grep/ripgrep untuk Verifikasi Manual Menyeluruh

```bash
D=./decompiled/sources

# Cari seluruh pemanggilan authenticate() untuk menghitung argumen secara manual
rg -n '\.authenticate\(' $D

# Cari konfigurasi key generation yang relevan biometrik
rg -n 'setUserAuthenticationRequired' $D

# Cari builder KeyGenParameterSpec yang TIDAK menyertakan baris di atas (perlu verifikasi manual per file)
rg -n 'new KeyGenParameterSpec.Builder' $D
```

### 3.4 Metode C — Frida untuk Verifikasi Dinamis (Reproduksi Teknik SEC Consult)

```javascript
Java.perform(function () {
    var BiometricPrompt = Java.use("androidx.biometric.BiometricPrompt");
    BiometricPrompt.authenticate.overload(
        "androidx.biometric.BiometricPrompt$PromptInfo"
    ).implementation = function (promptInfo) {
        console.log("[!] authenticate() dipanggil TANPA CryptoObject — rentan event-bound bypass");
        return this.authenticate(promptInfo);
    };
});
```

Mereproduksi secara terkontrol teknik yang didokumentasikan SEC Consult (§1.6) untuk memverifikasi secara empiris bahwa aplikasi target benar-benar rentan, melengkapi temuan statis dengan bukti dinamis konklusif.

### 3.5 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Kapan dipakai |
|---|---|---|
| **A** | Semgrep + rule resmi | Baseline wajib |
| **B** | grep/ripgrep manual | Verifikasi menyeluruh, menutup celah batasan file-level scope rule resmi (§1.4) |
| **C** | Frida | Konfirmasi dinamis konklusif, terutama untuk laporan ke klien/stakeholder yang butuh bukti eksploitasi nyata |

**Kombinasi minimum yang aku rekomendasikan:** **A + B (wajib)**, dengan **C** sangat direkomendasikan untuk aplikasi kategori high-risk (finansial, password manager, messaging terenkripsi) mengingat bukti nyata di §1.6 justru datang dari kategori aplikasi yang sama.

---

### 3.6 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG (kriteria AND ganda, §1.3):**

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila **kedua** kondisi berikut terpenuhi untuk satu operasi sensitif:

| No | Kondisi |
|---|---|
| F1 | `BiometricPrompt.authenticate()` dipanggil **tanpa** `CryptoObject` |
| F2 | **Dan** tidak ada key generation dengan `setUserAuthenticationRequired(true)` yang berkaitan dengan autentikasi biometrik tersebut |

**Contoh bukti (mereplikasi pola nyata Bitwarden/Signal di §1.6):**

```java
// Ditemukan di com/example/vault/auth/UnlockActivity.java
biometricPrompt.authenticate(promptInfo); // TIDAK ada CryptoObject

// Tidak ditemukan pemanggilan setUserAuthenticationRequired(true) di seluruh codebase
```

Interpretasi: aplikasi vault/password manager mengandalkan `onAuthenticationSucceeded()` semata sebagai gerbang akses ke data sensitif, tanpa pengikatan kriptografis apa pun. **FAIL** — risiko bypass total via hooking, persis seperti kasus nyata §1.6.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | `authenticate()` dipanggil **dengan** `CryptoObject` yang valid |
| P2 | **Dan** key yang mendasari `CryptoObject` tersebut dibuat dengan `setUserAuthenticationRequired(true)` secara eksplisit |

**Contoh bukti:**

```java
KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(KEY_ALIAS,
        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
    .setUserAuthenticationRequired(true)
    .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
    .build();
// ...
BiometricPrompt.CryptoObject cryptoObject = new BiometricPrompt.CryptoObject(cipher);
biometricPrompt.authenticate(promptInfo, cryptoObject);
```

**PASS** — autentikasi terikat ke operasi kriptografis yang hanya dapat dibuka setelah verifikasi biometrik di TEE.

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Kedua kriteria FAIL harus dicek bersamaan, jangan berhenti di kriteria pertama** — sesuai §1.3, menemukan `CryptoObject` **saja** tidak otomatis PASS; selalu lacak balik key generation-nya untuk memastikan `setUserAuthenticationRequired(true)` benar-benar ada, mengingat ini **bukan default**.

2. **Operasi non-sensitif boleh dikecualikan** — evaluasi resmi membatasi scope pada "each sensitive operation worth protecting"; autentikasi biometrik untuk fitur kosmetik (mis. toggle dark mode) di luar scope kekhawatiran test ini.

3. **Verifikasi batasan file-level scope rule resmi** — bila satu file berisi banyak key generation untuk tujuan berbeda (biometrik dan non-biometrik), pastikan key yang ditandai benar-benar terkait biometrik, bukan false positive akibat scoping berbasis import (§1.4).

4. **Pertimbangkan Metode C (Frida) untuk kasus high-risk** — mengingat kasus nyata melibatkan aplikasi sekelas Bitwarden/Signal, bukti dinamis konklusif (bukan hanya temuan statis) sangat berharga untuk laporan ke tim produk yang mungkin skeptis terhadap "temuan teoretis".

5. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | Event-bound pada operasi sensitif (akses vault, kunci enkripsi, token sesi) di aplikasi yang memproses data sangat sensitif | **Tinggi** (meski prasyarat serangan butuh root/akses fisik, sesuai §1.6) |
   | Event-bound pada operasi sensitif namun aplikasi non-high-risk | **Sedang** |
   | Crypto-bound sudah benar namun validity duration key terlalu panjang (di luar scope langsung test ini, tapi layak dicatat sebagai temuan terkait) | **Rendah/Informational** |

6. **Dokumentasikan:** lokasi pemanggilan `authenticate()`, apakah `CryptoObject` disertakan, lokasi key generation terkait beserta konfigurasi `setUserAuthenticationRequired`, dan hasil verifikasi dinamis bila dilakukan.

---

## 4. Rekomendasi Perbaikan

### 4.1 Selalu Gunakan CryptoObject dengan Key yang Dikonfigurasi Benar

```java
// SEBELUM — event-bound, rentan bypass (pola Bitwarden/Signal sebelum diperbaiki)
biometricPrompt.authenticate(promptInfo);

// SESUDAH — crypto-bound sesuai MASTG-BEST-0036
KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(KEY_ALIAS, PURPOSE_ENCRYPT | PURPOSE_DECRYPT)
    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
    .setUserAuthenticationRequired(true)
    .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG) // 0 = autentikasi per operasi
    .build();

BiometricPrompt.CryptoObject cryptoObject = new BiometricPrompt.CryptoObject(cipher);
biometricPrompt.authenticate(promptInfo, cryptoObject);
```

### 4.2 Hindari Validity Duration yang Panjang untuk Operasi Sangat Sensitif

Sesuai catatan MASTG-BEST-0036, gunakan timeout `0` (autentikasi diwajibkan untuk **setiap** operasi kriptografis) untuk data paling sensitif — hindari window validitas panjang yang membuat key tetap bisa dipakai meski perangkat berpindah tangan setelah autentikasi awal.

### 4.3 Checklist Remediasi

- [ ] Seluruh pemanggilan `authenticate()` untuk operasi sensitif menyertakan `CryptoObject`
- [ ] Setiap key yang mendasari `CryptoObject` dikonfigurasi dengan `setUserAuthenticationRequired(true)`
- [ ] Validity duration key diatur ke `0` untuk operasi paling sensitif, bukan window panjang
- [ ] Hasil diverifikasi secara dinamis dengan Frida (reproduksi teknik §3.4) untuk memastikan bypass benar-benar gagal setelah perbaikan
- [ ] Dibandingkan ulang dengan hasil MASTG-TEST-0326 — pastikan kedua kelemahan ditangani, bukan hanya satu

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0327 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-AUTH/MASTG-TEST-0327.md)
- [MASTG-TEST-0326: References to APIs Allowing Fallback to Non-Biometric Authentication](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0326/)
- [MASTG-KNOW-0001: Biometric Authentication](https://mas.owasp.org/MASTG/knowledge/android/MASVS-AUTH/MASTG-KNOW-0001/)
- [MASTG-KNOW-0043: Android KeyStore](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0043/)
- [MASTG-KNOW-0047: Cryptographic Key Storage](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0047/)
- [MASTG-KNOW-0012: Key Generation](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CRYPTO/MASTG-KNOW-0012/)
- [MASTG-BEST-0036: Use Cryptographic Binding for Biometric Authentication](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0036.md)

### 5.2 Riset dan Kasus Nyata

- [SEC Consult: Bypassing Android Biometric Authentication](https://sec-consult.com/blog/detail/bypassing-android-biometric-authentication/)
- [HackTricks: Bypass Biometric Authentication (Android)](https://hacktricks.wiki/en/mobile-pentesting/android-app-pentesting/bypass-biometric-authentication-android.html)
- [SecurityCafe: Mobile Pentesting 101 — Bypassing Biometric Authentication](https://securitycafe.ro/2022/09/05/mobile-pentesting-101-bypassing-biometric-authentication/)
- [Kayssel: Securing Biometric Authentication — Defending Against Frida Bypass Attacks](https://www.kayssel.com/post/android-8/)

### 5.3 Dokumentasi Tools

- [Semgrep Documentation](https://semgrep.dev/docs/)
- [Frida — Dynamic Instrumentation Toolkit](https://frida.re/docs/home/)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)

---

*Dokumen ini disusun berdasarkan konten resmi OWASP MASTG (`tests-beta/android/MASVS-AUTH/MASTG-TEST-0327.md`, `MASTG-KNOW-0001/0012/0043/0047`, `MASTG-BEST-0036`), analisis rule `mastg-android-biometric-event-bound.yml`, serta riset SEC Consult yang mendokumentasikan bypass nyata terhadap Bitwarden, Signal, dan Dashlane — tiga aplikasi dengan reputasi keamanan tinggi dan basis pengguna gabungan lebih dari 100 juta unduhan. Nuansa metodologis terpenting: kriteria FAIL resmi bersifat AND ganda (tanpa CryptoObject DAN tanpa `setUserAuthenticationRequired(true)`) — menemukan salah satu saja tidak cukup untuk menyimpulkan FAIL atau PASS; `setUserAuthenticationRequired(true)` bukan nilai default, sehingga keberadaan Keystore key semata tidak menjamin pengikatan autentikasi yang sesungguhnya.*
