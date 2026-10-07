# MASTG-TEST-0328 References to APIs Detecting Biometric Enrollment Changes

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0328 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-AUTH |
| **Weakness** | MASWE-0022 |
| **Tipe Pengujian** | Static, Code |
| **API terkait** | `KeyGenParameterSpec.Builder`, `setInvalidatedByBiometricEnrollment` |
| **Teknik terkait** | MASTG-TECH-0013 (Reverse Engineering), MASTG-TECH-0014 (Static Analysis for Relevant APIs) |
| **Knowledge terkait** | MASTG-KNOW-0001 (Biometric Authentication) |
| **Best Practice terkait** | MASTG-BEST-0037 (Invalidate Biometric Keys on Enrollment Changes) |
| **Test terkait** | **MASTG-TEST-0327** — topik berdekatan (konfigurasi key biometrik), menyasar aspek konfigurasi yang berbeda (lihat §1.4) |
| **Rule resmi** | `mastg-android-biometric-invalidated-enrollment.yml` — satu pola tunggal, lihat §1.3 |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian dan Model Ancaman

Kutipan overview resmi MASTG:

> *"This test checks whether the app fails to protect sensitive operations against unauthorized access following biometric enrollment changes. An attacker who obtains the device passcode could add a new fingerprint or facial representation via system settings and use it to authenticate in the app."*

Model ancaman di sini sangat spesifik dan berbeda dari test biometrik lain dalam seri riset ini (TEST-0326, TEST-0327) — bukan soal kelemahan API biometrik itu sendiri, melainkan skenario **dua langkah**: (1) penyerang berhasil memperoleh **passcode layar kunci** perangkat (lewat shoulder surfing, social engineering, atau bahkan prasyarat fisik lain), lalu (2) memanfaatkan akses tersebut untuk **mendaftarkan sidik jari/wajah mereka sendiri** lewat menu Settings sistem Android — sebuah aksi yang **tidak memerlukan otorisasi tambahan** selain passcode yang sudah dimiliki. Setelah terdaftar, biometrik baru milik penyerang tersebut secara default dapat dipakai untuk membuka **key Keystore apa pun** yang sudah ada di perangkat, kecuali key tersebut secara eksplisit dikonfigurasi untuk menolak biometrik yang didaftarkan setelah key dibuat.

### 1.2 Mekanisme Teknis: `setInvalidatedByBiometricEnrollment`

> *"This behaviour occurs when `setInvalidatedByBiometricEnrollment` is set to `false` when keys are generated. By default and when set to `true`, a key becomes permanently invalidated if a new biometric is enrolled. As a result, only users whose biometric data was enrolled when the item was created can unlock it."*

Poin penting yang membedakan test ini dari TEST-0327: **`true` adalah behaviour default** di sini (berbeda dari `setUserAuthenticationRequired` di TEST-0327 yang defaultnya `false`/tidak wajib autentikasi). MASTG-BEST-0037 menegaskan nuansa relasi default ini:

> *"Either configure `setInvalidatedByBiometricEnrollment(true)` explicitly, or rely on the default behavior, which invalidates keys when `setUserAuthenticationRequired(true)` is set."*

Artinya: **invalidasi otomatis hanya berlaku bila key juga memakai `setUserAuthenticationRequired(true)`** (syarat dari TEST-0327). Ini menciptakan ketergantungan silang antara kedua test — bila sebuah key gagal pada TEST-0327 (tidak mewajibkan autentikasi pengguna sama sekali), pertanyaan tentang invalidasi enrollment di test ini menjadi **tidak relevan secara teknis**, karena key tersebut sudah bisa dipakai tanpa autentikasi apa pun sejak awal — kerentanannya sudah "lebih parah" dari yang disasar test ini.

### 1.3 Analisis Rule Resmi: Pola Tunggal yang Sederhana dan Tepat Sasaran

Berbeda dari rule-rule biometrik lain dalam seri riset ini yang punya banyak pola dan beberapa kelemahan cakupan (TEST-0326 §1.4, TEST-0327 §1.4), rule untuk test ini sangat sederhana:

```yaml
pattern: $BUILDER.setInvalidatedByBiometricEnrollment(false)
```

Rule ini **tidak rentan false positive** seperti rule TEST-0326 — karena satu-satunya nilai yang secara eksplisit berbahaya adalah literal `false`, dan rule hanya mencocokkan persis itu, tanpa ambiguitas nilai lain yang bisa disalahartikan. Namun ini juga berarti rule **tidak menangkap kasus "tidak dipanggil sama sekali"** — mengingat `true` adalah default, aplikasi yang **tidak pernah memanggil method ini sama sekali** justru otomatis aman (asalkan `setUserAuthenticationRequired(true)` juga dipanggil, sesuai §1.2). Ini adalah salah satu dari sedikit kasus dalam seri riset ini di mana **ketidakhadiran pemanggilan API lebih aman daripada memanggilnya dengan nilai yang salah** — pola evaluasi yang terbalik dari kebanyakan test resilience/root-detection yang menuntut kehadiran mekanisme.

### 1.4 Perbandingan dengan MASTG-TEST-0327: Dua Aspek Konfigurasi Key yang Independen

| | MASTG-TEST-0327 | MASTG-TEST-0328 (test ini) |
|---|---|---|
| **Pertanyaan inti** | Apakah autentikasi *terikat secara kriptografis* ke operasi (CryptoObject + `setUserAuthenticationRequired`)? | Apakah key tetap valid setelah **biometrik baru** didaftarkan di sistem? |
| **Nilai default yang aman** | **Tidak aman secara default** — developer harus eksplisit mengatur `true` | **Aman secara default** — `true` adalah default, risiko muncul hanya bila eksplisit diset `false` |
| **Prasyarat serangan** | Akses fisik + root/APK modifikasi (hooking) | Mengetahui **passcode layar kunci** korban + akses fisik sesaat ke perangkat (tanpa perlu root) |
| **Hubungan** | Invalidasi enrollment (test ini) **hanya efektif** bila `setUserAuthenticationRequired(true)` juga diset (lihat §1.2) | — |

Perbedaan prasyarat serangan ini penting dicatat — skenario test ini **tidak memerlukan root atau APK modifikasi** sama sekali, hanya memerlukan **pengetahuan terhadap passcode layar kunci** korban (yang bisa diperoleh lewat cara non-teknis seperti shoulder surfing atau rekayasa sosial) plus akses fisik singkat ke perangkat untuk mendaftarkan biometrik baru lewat Settings. Ini membuat skenario ancaman test ini secara realistis **lebih mudah dieksekusi** oleh penyerang non-teknis dibanding skenario TEST-0327 yang menuntut kemampuan hooking Frida.

### 1.5 Konteks Nyata: Rangkaian Serangan terhadap Passcode sebagai Titik Awal

Riset keamanan terbaru pada chipset Samsung (CVE-2025-20987, CVE-2025-20988, CVE-2025-20989) menggambarkan mengapa "memperoleh passcode" bukan sekadar skenario hipotetis belaka:

> *"Recent critical vulnerabilities affecting Samsung and other devices enable PIN cracking and credential encryption bypass. The PIN controls unlocking the screen, authorizing payments, enrolling or changing biometrics, and decrypting user data."*

Kutipan ini secara eksplisit mengonfirmasi rangkaian ancaman yang persis dibahas overview resmi — PIN/passcode bukan hanya mengontrol unlock layar, tapi juga **mengontrol pendaftaran biometrik baru**, yang pada akhirnya mengontrol akses ke key kriptografis terenkripsi. Ini menunjukkan bahwa kerentanan brute-force/crack PIN di tingkat OS/chipset dan kelemahan konfigurasi `setInvalidatedByBiometricEnrollment` di tingkat aplikasi adalah **dua lapis dari rantai serangan yang sama** — melemahkan salah satu titik memperbesar dampak kelemahan di titik lain.

### 1.6 Peringatan Keseimbangan: Mengatasi `KeyPermanentlyInvalidatedException` dengan Benar

MASTG-BEST-0037 memberi catatan penting yang sering jadi sumber bug developer di sisi lain spektrum — bila developer sudah benar mengatur `true` (sesuai rekomendasi), mereka **wajib menangani konsekuensinya** dengan baik:

> *"Key invalidation is immediate and permanent when a new biometric is enrolled. The app must handle `KeyPermanentlyInvalidatedException` and guide the user to re-authenticate to create a new key."*

Kasus nyata dari laporan bug publik menunjukkan ini bukan kekhawatiran teoretis — sebuah dompet kripto open-source melaporkan masalah persis ini:

> *"Adding a fingerprint on Android may permanently invalidate the vault's hardware key"* — dari laporan isu GitHub `0xMiden/wallet#1307`.

Dan laporan lain menunjukkan konsekuensi yang lebih parah bila penanganan error tidak tepat — bukan sekadar re-enrollment yang diminta ke pengguna, tapi **crash berulang tanpa henti**:

> *"resetOnError recurses until the process dies when the fresh key also fails (Samsung, after biometric enrollment)"* — dari laporan isu GitHub `flutter_secure_storage#1282`.

Ini menegaskan bahwa remediasi untuk test ini **bukan sekadar mengubah satu baris boolean** — developer harus memastikan alur penanganan exception setelah invalidasi berjalan mulus (regenerasi key baru + permintaan re-autentikasi), bukan menyebabkan vault terkunci permanen atau aplikasi crash berulang. Trade-off keamanan-vs-usability ini relevan dimasukkan ke rekomendasi perbaikan (§4).

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **jadx** | Dekompilasi DEX → Java (MASTG-TECH-0013) |
| **Semgrep** + rule resmi `mastg-android-biometric-invalidated-enrollment.yml` | Pencocokan pola `setInvalidatedByBiometricEnrollment(false)` (MASTG-TECH-0014) |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **grep/ripgrep** | Verifikasi silang dengan `setUserAuthenticationRequired` pada file/builder yang sama, untuk menilai relevansi temuan sesuai ketergantungan di §1.2 |
| **MobSF** | Laporan otomatis yang kadang menyertakan pemeriksaan konfigurasi Keystore |
| **adb (manual device testing)** | Verifikasi dinamis nyata — daftarkan biometrik baru di Settings device uji, lalu amati apakah aplikasi benar-benar menolak key lama (lihat Metode C) |

### 2.3 Prasyarat Lingkungan

- Tidak butuh device/root untuk analisis statis.
- Untuk verifikasi dinamis (Metode C), butuh device fisik/emulator dengan kemampuan mendaftarkan biometrik tambahan (emulator biasanya memerlukan dukungan sensor biometrik virtual).

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0013** untuk reverse engineer aplikasi.
2. Gunakan **MASTG-TECH-0014** untuk mencari API yang relevan.

### 3.2 Metode A — Semgrep dengan Rule Resmi

```bash
semgrep --config mastg-android-biometric-invalidated-enrollment.yml ./decompiled/sources
```

### 3.3 Metode B — grep/ripgrep untuk Verifikasi Ketergantungan Silang

```bash
D=./decompiled/sources

# Cari pola berbahaya langsung
rg -n 'setInvalidatedByBiometricEnrollment\(\s*false\s*\)' $D

# Verifikasi apakah setUserAuthenticationRequired juga dipakai pada builder yang sama (relevansi, §1.2)
rg -n -B5 -A5 'setInvalidatedByBiometricEnrollment' $D | grep -B10 -A10 'setUserAuthenticationRequired'

# Cari juga penanganan KeyPermanentlyInvalidatedException untuk menilai kualitas remediasi (§1.6)
rg -n 'KeyPermanentlyInvalidatedException' $D
```

### 3.4 Metode C — Verifikasi Dinamis Nyata di Device Fisik/Emulator

```
Prosedur manual:
1. Pastikan aplikasi sudah login dan memiliki key Keystore terkait operasi sensitif (mis. buka vault/dompet)
2. Daftarkan sidik jari/wajah BARU di menu Settings > Security > Biometrics perangkat uji
3. Kembali ke aplikasi, coba akses ulang operasi sensitif dengan biometrik BARU tersebut
4. Amati: apakah aplikasi menolak (key terinvalidasi, PASS) atau tetap menerima (key masih valid, FAIL)?
5. Amati juga: apakah aplikasi menangani penolakan tersebut dengan baik (minta re-enrollment) atau crash (lihat §1.6)?
```

Ini adalah bentuk pengujian paling konklusif untuk test ini — secara langsung mereproduksi skenario ancaman resmi tanpa perlu membaca kode sama sekali, meski membutuhkan akses device fisik/emulator yang mendukung.

### 3.5 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Kapan dipakai |
|---|---|---|
| **A** | Semgrep + rule resmi | Baseline wajib, cakupan pola sudah tepat sasaran (§1.3) |
| **B** | grep/ripgrep manual | Verifikasi relevansi sesuai ketergantungan `setUserAuthenticationRequired` (§1.2) dan kualitas exception handling (§1.6) |
| **C** | Verifikasi dinamis manual | Bukti konklusif paling kuat, mereproduksi skenario ancaman asli secara langsung |

**Kombinasi minimum yang aku rekomendasikan:** **A + B (wajib)**, dengan **C** sangat direkomendasikan bila device uji tersedia — ini salah satu test di mana verifikasi dinamis manual relatif murah dan cepat dilakukan, tidak memerlukan tooling khusus seperti Frida.

---

### 3.6 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Evaluation:** *"The test case fails if the app uses `setInvalidatedByBiometricEnrollment(false)` for keys used to protect sensitive data resources."*

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Ditemukan `setInvalidatedByBiometricEnrollment(false)` pada key yang melindungi resource/operasi sensitif |

**Contoh bukti:**

```java
// Ditemukan di com/example/wallet/crypto/KeyManager.java
KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(KEY_ALIAS, PURPOSE_DECRYPT)
    .setUserAuthenticationRequired(true)
    .setInvalidatedByBiometricEnrollment(false) // SENGAJA diset false
    .build();
```

Interpretasi: key tetap valid meski biometrik baru didaftarkan setelahnya — persis skenario ancaman di §1.1. **FAIL**.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | `setInvalidatedByBiometricEnrollment(true)` dipanggil secara eksplisit, **atau** |
| P2 | Method ini **tidak dipanggil sama sekali** (mengandalkan default `true`) — tetap PASS asalkan `setUserAuthenticationRequired(true)` juga ada (§1.2) |

**Contoh bukti:**

```java
KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(KEY_ALIAS, PURPOSE_DECRYPT)
    .setUserAuthenticationRequired(true)
    // tidak memanggil setInvalidatedByBiometricEnrollment() -> default true
    .build();
```

**PASS**.

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Ketidakhadiran pemanggilan API adalah PASS, bukan FAIL** — berbeda dari kebanyakan test lain dalam kategori resilience/biometrik yang menuntut kehadiran mekanisme eksplisit, test ini unik karena **default sudah aman**; jangan salah menandai "tidak ditemukan referensi API" sebagai temuan negatif di sini.

2. **Selalu verifikasi ketergantungan dengan `setUserAuthenticationRequired`** — bila key yang diperiksa **tidak** memakai `setUserAuthenticationRequired(true)` sama sekali, invalidasi enrollment menjadi tidak relevan secara teknis (§1.2); dalam kasus ini, fokuskan temuan ke MASTG-TEST-0327 yang menyasar masalah yang lebih mendasar.

3. **Pertimbangkan verifikasi dinamis (Metode C) sebagai bukti paling kuat** — khususnya untuk aplikasi kategori high-risk (dompet kripto, perbankan), reproduksi langsung skenario ancaman (daftarkan biometrik baru, coba akses) memberi bukti tak terbantahkan dibanding sekadar menemukan baris kode.

4. **Jangan lupa menilai kualitas exception handling sebagai temuan terpisah** — bila `setInvalidatedByBiometricEnrollment(true)` sudah benar diatur namun `KeyPermanentlyInvalidatedException` tidak ditangani dengan baik (§1.6), ini adalah **temuan usability/stability terpisah** yang layak dilaporkan meski secara teknis test keamanan ini tetap PASS.

5. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | `setInvalidatedByBiometricEnrollment(false)` eksplisit pada operasi finansial/dompet kripto, dikombinasikan dengan `setUserAuthenticationRequired(true)` | **Sedang-Tinggi** |
   | Sama seperti di atas namun pada aplikasi kategori risiko rendah | **Rendah-Sedang** |
   | `false` ditemukan namun key tidak memakai `setUserAuthenticationRequired` sama sekali | **Tidak relevan untuk test ini** — rujuk ke TEST-0327 sebagai temuan utama |

6. **Dokumentasikan:** lokasi kode, nilai yang dikonfigurasi, keberadaan `setUserAuthenticationRequired` pada builder yang sama, dan hasil verifikasi dinamis bila dilakukan.

---

## 4. Rekomendasi Perbaikan

### 4.1 Hindari Mengeset False Secara Eksplisit Tanpa Alasan Kuat

```java
// SEBELUM — rentan terhadap skenario "attacker mendaftarkan biometrik baru"
KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(KEY_ALIAS, PURPOSE_DECRYPT)
    .setUserAuthenticationRequired(true)
    .setInvalidatedByBiometricEnrollment(false)
    .build();

// SESUDAH — eksplisit true, atau cukup hilangkan baris ini (default sudah true)
KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(KEY_ALIAS, PURPOSE_DECRYPT)
    .setUserAuthenticationRequired(true)
    .setInvalidatedByBiometricEnrollment(true)
    .build();
```

### 4.2 Tangani KeyPermanentlyInvalidatedException dengan Baik (Sesuai §1.6)

```java
try {
    cipher.init(Cipher.DECRYPT_MODE, secretKey);
} catch (KeyPermanentlyInvalidatedException e) {
    // JANGAN retry berulang tanpa henti (lihat kasus nyata flutter_secure_storage#1282)
    notifyUserKeyInvalidated();
    regenerateKeyAndPromptReEnrollment();
}
```

### 4.3 Checklist Remediasi

- [ ] Tidak ada `setInvalidatedByBiometricEnrollment(false)` pada key yang melindungi operasi sensitif
- [ ] `setUserAuthenticationRequired(true)` dipasangkan secara konsisten (prasyarat agar invalidasi enrollment relevan)
- [ ] `KeyPermanentlyInvalidatedException` ditangani dengan regenerasi key + permintaan re-enrollment, bukan crash/retry tanpa henti
- [ ] Diverifikasi secara dinamis dengan mendaftarkan biometrik baru di device uji (Metode C)
- [ ] Dikorelasikan dengan hasil MASTG-TEST-0327 untuk gambaran lengkap konfigurasi key biometrik

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0328 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-AUTH/MASTG-TEST-0328.md)
- [MASTG-TEST-0327: References to APIs for Event-Bound Biometric Authentication](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0327/)
- [MASTG-KNOW-0001: Biometric Authentication](https://mas.owasp.org/MASTG/knowledge/android/MASVS-AUTH/MASTG-KNOW-0001/)
- [MASTG-BEST-0037: Invalidate Biometric Keys on Enrollment Changes](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0037.md)

### 5.2 Dokumentasi Resmi Android

- [KeyGenParameterSpec.Builder#setInvalidatedByBiometricEnrollment](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setInvalidatedByBiometricEnrollment(boolean))
- [KeyPermanentlyInvalidatedException](https://developer.android.com/reference/android/security/keystore/KeyPermanentlyInvalidatedException)

### 5.3 Riset dan Kasus Nyata

- [Blackduck: Understanding CVE-2020-7958 — Biometric Data Extraction in Android](https://www.blackduck.com/blog/cve-2020-7958-trustlet-tee-attack.html)
- [arXiv: "Please Enter Your PIN" — On the Risk of Bypass Attacks on Biometric Authentication on Mobile Devices](https://arxiv.org/pdf/1911.07692)
- [GitHub Issue: 0xMiden/wallet#1307 — Adding a Fingerprint on Android May Permanently Invalidate the Vault's Hardware Key](https://github.com/0xMiden/wallet/issues/1307)
- [GitHub Issue: flutter_secure_storage#1282 — resetOnError Recurses Until the Process Dies](https://github.com/juliansteenbakker/flutter_secure_storage/issues/1282)

### 5.4 Dokumentasi Tools

- [Semgrep Documentation](https://semgrep.dev/docs/)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)

---

*Dokumen ini disusun berdasarkan konten resmi OWASP MASTG (`tests-beta/android/MASVS-AUTH/MASTG-TEST-0328.md`, `MASTG-KNOW-0001`, `MASTG-BEST-0037`), analisis rule `mastg-android-biometric-invalidated-enrollment.yml`, serta riset CVE Samsung terbaru (CVE-2025-20987/20988/20989) tentang rantai serangan PIN-cracking-ke-enrollment-biometrik, dan laporan bug publik nyata (0xMiden/wallet, flutter_secure_storage) tentang tantangan penanganan `KeyPermanentlyInvalidatedException`. Nuansa metodologis terpenting: ini adalah salah satu test di mana **default API sudah aman** — ketidakhadiran pemanggilan `setInvalidatedByBiometricEnrollment()` di kode berarti PASS, bukan FAIL, berbeda dari pola evaluasi kebanyakan test resilience lain; dan relevansi temuan FAIL sepenuhnya bergantung pada keberadaan `setUserAuthenticationRequired(true)` pada key yang sama, menghubungkan test ini erat dengan MASTG-TEST-0327.*
