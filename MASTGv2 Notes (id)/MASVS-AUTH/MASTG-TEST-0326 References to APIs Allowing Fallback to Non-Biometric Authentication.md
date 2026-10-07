# MASTG-TEST-0326 References to APIs Allowing Fallback to Non-Biometric Authentication

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0326 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-AUTH |
| **Weakness** | MASWE-0021 |
| **Tipe Pengujian** | Static, Code |
| **API terkait** | `BiometricPrompt`, `BiometricManager.Authenticators`, `setAllowedAuthenticators` |
| **Teknik terkait** | MASTG-TECH-0013 (Reverse Engineering), MASTG-TECH-0014 (Static Analysis for Relevant APIs) |
| **Knowledge terkait** | MASTG-KNOW-0001 (Biometric Authentication) |
| **Best Practice terkait** | MASTG-BEST-0031 (Enforce Strong Biometrics for Sensitive Operations) |
| **Rule resmi** | `mastg-android-biometric-device-credential-fallback.yml` — ditemukan **kelemahan cakupan pola**, lihat §1.4 |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Kutipan overview resmi MASTG:

> *"This test checks if the app uses biometric authentication mechanisms that allow fallback to device credentials (PIN, pattern, or password) for sensitive operations."*

Mekanisme konfigurasi yang dicek:

> *"When the authenticator constant `DEVICE_CREDENTIAL` is included (either alone or combined with biometric authenticators using the OR operator "|"), the authentication allows fallback to device credentials, which is considered weaker than requiring biometrics alone because passcodes are more susceptible to compromise (e.g., through shoulder surfing)."*

Serta API lama yang setara secara fungsional:

> *"Similarly, using `setDeviceCredentialAllowed(true)` (deprecated since API 30) also enables fallback to device credentials."*

### 1.2 Tiga Kelas Autentikator dan Mengapa Kombinasinya Penting

MASTG-KNOW-0001 mendefinisikan tiga konstanta `BiometricManager.Authenticators` yang menjadi inti evaluasi test ini:

| Konstanta | Nilai Integer | Deskripsi |
|---|---|---|
| `BIOMETRIC_STRONG` | 15 (0x000F) | Autentikasi biometrik Class 3 — tingkat keamanan tertinggi |
| `BIOMETRIC_WEAK` | 255 (0x00FF) | Autentikasi biometrik Class 2 — lebih rentan spoofing |
| `DEVICE_CREDENTIAL` | 32768 (0x8000) | PIN, pattern, atau password layar kunci perangkat |

Nilai-nilai ini dapat dikombinasikan secara bitwise OR, misalnya `BIOMETRIC_STRONG | DEVICE_CREDENTIAL`. Poin krusial yang ditekankan overview: **kombinasi apa pun yang menyertakan bit `DEVICE_CREDENTIAL`** — baik sendirian maupun digabung dengan autentikator biometrik manapun — tetap dianggap FAIL, karena pada akhirnya pengguna (atau penyerang yang mengamati/memaksa) dapat **memilih** jalur PIN/pattern/password yang lebih lemah alih-alih biometrik.

### 1.3 Mengapa Fallback ke Device Credential Dianggap Lebih Lemah: Risiko Shoulder Surfing

Alasan teknis yang diberikan overview secara spesifik merujuk pada **shoulder surfing** — serangan observasi di mana pihak lain dapat melihat PIN/pattern yang dimasukkan pengguna secara visual. Riset akademik tentang dampak nyata shoulder surfing terhadap pengguna smartphone menguatkan mengapa ini bukan risiko teoretis:

> *"Shoulder surfing is an observation attack where an attacker attempts to observe the authenticator of a victim while being entered on the device. When banking apps fall back to PIN/pattern/password entry, users are vulnerable to this physical attack where observers can see the credentials being entered."*

Berbeda dari biometrik (sidik jari/wajah) yang secara inheren tidak dapat "diamati" dan direplikasi semudah mengingat kombinasi angka yang terlihat, PIN/pattern yang dimasukkan secara visual di tempat umum (transportasi, kafe) menciptakan jendela eksposur yang nyata — terutama untuk aplikasi finansial yang dipakai di berbagai situasi publik.

### 1.4 Temuan Analitis: Rule Resmi Memiliki Cakupan Pola yang Lebih Luas dari yang Diklaim

Ini adalah bagian paling penting dari analisis rule — pola `mastg-android-biometric-device-credential-fallback.yml` **tidak hanya** menangkap kasus `DEVICE_CREDENTIAL` seperti yang diklaim deskripsinya, tapi secara teknis menangkap **jauh lebih banyak** dari itu:

```yaml
- patterns:
    - pattern: $BUILDER.setAllowedAuthenticators($VALUE)
    - metavariable-pattern:
        metavariable: $VALUE
        patterns:
          - pattern-not: BiometricManager.Authenticators.BIOMETRIC_STRONG
          - pattern-not: 15
```

Logika rule ini adalah: **flag APAPUN** nilai yang diteruskan ke `setAllowedAuthenticators()` **KECUALI** secara eksplisit sama dengan literal `BiometricManager.Authenticators.BIOMETRIC_STRONG` atau literal integer `15`. Konsekuensinya:

1. **`BIOMETRIC_WEAK` sendirian (255) akan ditandai sebagai "allows fallback to device credentials"** — padahal `BIOMETRIC_WEAK` **sama sekali tidak menyertakan bit `DEVICE_CREDENTIAL` (32768)**. Ini adalah kelemahan biometrik Class 2 (rentan spoofing), bukan fallback ke kredensial perangkat — kategori masalah yang **berbeda** dari yang diklaim message rule.
2. **Kombinasi apa pun yang ditulis dalam bentuk ekspresi** (mis. `BIOMETRIC_STRONG | BIOMETRIC_WEAK`, tanpa `DEVICE_CREDENTIAL` sama sekali) **juga akan ditandai** sebagai false positif, karena `pattern-not` Semgrep melakukan pencocokan sintaksis terhadap literal yang ditentukan, bukan evaluasi semantik bitwise terhadap nilai akhir ekspresi.

Ini mengulangi pola "rule description vs implementation mismatch" yang sudah ditemukan pada beberapa test lain dalam seri riset ini — rule **secara teknis terlalu luas (over-broad)** dibanding klaim pesannya, meski di sisi lain tetap **cukup aman untuk tujuan triase awal** (false positive lebih dapat ditoleransi di sini dibanding false negative, karena arah evaluasi test condong konservatif terhadap keamanan). Penguji harus memverifikasi secara manual setiap hasil match untuk memastikan benar `DEVICE_CREDENTIAL` yang menjadi penyebab, bukan sekadar `BIOMETRIC_WEAK` atau kombinasi biometrik murni yang ditulis dalam bentuk ekspresi.

Pola kedua dari rule ini (untuk `canAuthenticate()`) memiliki keterbatasan logika yang identik, dan pattern ketiga (`setDeviceCredentialAllowed(true)`) sudah tepat sasaran tanpa ambiguitas.

### 1.5 Nuansa Klasifikasi Severity: "Hardening Issue", Bukan "Vulnerability Kritis"

Catatan resmi MASTG memberikan panduan klasifikasi yang eksplisit dan tidak lazim ditemukan selengkap ini di test lain:

> *"Using `DEVICE_CREDENTIAL` is not inherently a vulnerability, but in high-security applications (e.g., finance, government, health), their use can represent a weakness or misconfiguration that reduces the intended security posture. This issue is therefore better categorized as a security weakness or hardening issue, not a critical vulnerability."*

Ini penting untuk laporan — temuan dari test ini **jangan dilabeli sebagai "vulnerability kritis"** secara default. Severity-nya bergantung sepenuhnya pada **konteks domain aplikasi** (lihat §3.8 poin severity).

### 1.6 Konteks Terkait: Risiko Lebih Besar Muncul Bila Tidak Dipasangkan dengan CryptoObject

Riset independen (SEC Consult) tentang bypass biometrik Android menunjukkan bahwa risiko `DEVICE_CREDENTIAL` fallback ini sering **bertumpuk** dengan kelemahan implementasi lain yang berhubungan namun berbeda secara teknis:

> *"One bypass method involves the app using the authenticate overload that does NOT require a CryptoObject... When apps use BiometricPrompt with device credential fallback without binding biometric authentication to a CryptoObject, this creates an insecure configuration. This means that once a user authenticates (either biometrically or via PIN/password), the app may treat that single authentication as sufficient for all subsequent sensitive operations."*

Ini relevan sebagai konteks tambahan saat triase temuan test ini — bila ditemukan `DEVICE_CREDENTIAL` fallback **dan** tidak ada pengikatan `CryptoObject` (sesuai konsep Keystore-Backed Authentication di MASTG-KNOW-0001 §1.2), risiko gabungannya lebih tinggi daripada masing-masing kelemahan dinilai terpisah — autentikasi tidak hanya bisa jatuh ke kredensial yang lebih lemah, tapi hasil autentikasi itu sendiri tidak terikat kriptografis ke operasi sensitif yang dilindunginya.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **jadx** | Dekompilasi DEX → Java (MASTG-TECH-0013) |
| **Semgrep** + rule resmi `mastg-android-biometric-device-credential-fallback.yml` | Pencocokan pola `setAllowedAuthenticators`/`canAuthenticate`/`setDeviceCredentialAllowed` (MASTG-TECH-0014) |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **grep/ripgrep** | Verifikasi manual nilai integer mentah di bytecode terdekompilasi (`15`, `255`, `32768`, atau kombinasi OR-nya) untuk menutup celah false positive rule resmi (§1.4) |
| **MobSF** | Laporan otomatis yang kadang menyertakan pemeriksaan konfigurasi biometrik sebagai bagian ringkasan keamanan |
| **Frida** | Verifikasi dinamis nilai `$VALUE` sesungguhnya yang diteruskan ke `setAllowedAuthenticators()` saat runtime — melengkapi analisis statis untuk kasus nilai yang dihasilkan secara dinamis/tidak hardcoded |

### 2.3 Prasyarat Lingkungan

- Tidak butuh device/root untuk analisis statis.
- Pahami tabel nilai integer autentikator (§1.2) untuk verifikasi manual hasil match rule, mengingat kode terdekompilasi sering menampilkan **nilai integer mentah** alih-alih nama konstanta simbolik.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0013** untuk reverse engineer aplikasi.
2. Gunakan **MASTG-TECH-0014** untuk mencari API yang relevan.

### 3.2 Metode A — Semgrep dengan Rule Resmi (dengan Verifikasi Manual Wajib)

```bash
semgrep --config mastg-android-biometric-device-credential-fallback.yml ./decompiled/sources
```

**Wajib ditindaklanjuti manual** sesuai §1.4 — untuk setiap match, periksa apakah nilai `$VALUE` benar-benar menyertakan bit `DEVICE_CREDENTIAL`, bukan sekadar `BIOMETRIC_WEAK` saja atau kombinasi biometrik murni.

### 3.3 Metode B — grep/ripgrep untuk Verifikasi Nilai Integer Mentah

```bash
D=./decompiled/sources

# Cari pemanggilan setAllowedAuthenticators dengan nilai integer eksplisit
rg -n 'setAllowedAuthenticators\(' $D -A 0

# Verifikasi manual: apakah nilai 32768 (0x8000) muncul sendirian atau di-OR-kan?
rg -n 'setAllowedAuthenticators\(\s*(32768|0x8000|.*\|.*32768)' $D

# Cari pola deprecated setDeviceCredentialAllowed
rg -n 'setDeviceCredentialAllowed\(\s*true\s*\)' $D
```

### 3.4 Metode C — Frida untuk Verifikasi Nilai Dinamis Saat Runtime

```javascript
Java.perform(function () {
    var Builder = Java.use("androidx.biometric.BiometricPrompt$PromptInfo$Builder");
    Builder.setAllowedAuthenticators.implementation = function (value) {
        console.log("[setAllowedAuthenticators] value: " + value +
            " (biner: " + value.toString(2) + ")");
        return this.setAllowedAuthenticators(value);
    };
});
```

Berguna untuk kasus di mana nilai `$VALUE` tidak hardcoded di kode (mis. berasal dari remote config/feature flag), sehingga analisis statis saja tidak dapat memastikan nilai final yang benar-benar dipakai.

### 3.5 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Kapan dipakai |
|---|---|---|
| **A** | Semgrep + rule resmi | Baseline wajib, triase awal cepat |
| **B** | grep/ripgrep manual | Verifikasi wajib untuk menyingkirkan false positive rule resmi (§1.4) |
| **C** | Frida | Nilai autentikator ditentukan dinamis/tidak hardcoded |

**Kombinasi minimum yang aku rekomendasikan:** **A + B (wajib dipasangkan)**, dengan **C** sebagai pelengkap bila ditemukan indikasi nilai dikonfigurasi secara dinamis.

---

### 3.6 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Evaluation:** *"The test case fails if the app uses BiometricPrompt with authenticators that include DEVICE_CREDENTIAL for any sensitive data resource that needs protection."*

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | `setAllowedAuthenticators()` dipanggil dengan nilai yang menyertakan bit `DEVICE_CREDENTIAL` (baik sendirian maupun OR dengan autentikator biometrik), untuk melindungi resource/operasi sensitif |
| F2 | `setDeviceCredentialAllowed(true)` dipanggil (API deprecated, tapi secara fungsional setara F1) |

**Contoh bukti:**

```java
// Ditemukan di com/example/targetapp/auth/BiometricHelper.java
BiometricPrompt.PromptInfo promptInfo = new BiometricPrompt.PromptInfo.Builder()
    .setTitle("Konfirmasi Transaksi")
    .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG
        | BiometricManager.Authenticators.DEVICE_CREDENTIAL)
    .build();
```

Interpretasi: autentikasi untuk konfirmasi transaksi (operasi sensitif) mengizinkan fallback ke PIN/pattern/password perangkat. **FAIL** — namun klasifikasikan sebagai *hardening issue*, bukan *critical vulnerability* (§1.5).

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | `setAllowedAuthenticators()` hanya memakai `BIOMETRIC_STRONG` (nilai `15`) tanpa `DEVICE_CREDENTIAL`, untuk seluruh operasi sensitif |
| P2 | **Setelah verifikasi manual** (§1.4), match rule yang awalnya ditandai ternyata hanya `BIOMETRIC_WEAK` sendirian atau kombinasi biometrik murni tanpa bit `DEVICE_CREDENTIAL` — ini **bukan temuan untuk test ini** (meski `BIOMETRIC_WEAK` sendiri bisa jadi temuan terpisah terkait kekuatan kelas biometrik, bukan topik test ini) |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Verifikasi manual bukan opsional** — berdasarkan §1.4, rule resmi akan menghasilkan false positive untuk `BIOMETRIC_WEAK` sendirian dan kombinasi ekspresi biometrik murni. Jangan melaporkan match mentah dari Semgrep sebagai temuan final tanpa konfirmasi bit `DEVICE_CREDENTIAL` benar-benar ada.

2. **Severity bergantung penuh pada domain aplikasi (§1.5)** — jangan default ke severity tinggi; evaluasi apakah aplikasi target termasuk kategori high-security (finansial, pemerintahan, kesehatan) sebelum menetapkan tingkat urgensi remediasi.

3. **"Sensitive operation" perlu didefinisikan dengan jelas di awal** — evaluasi resmi membatasi FAIL hanya untuk "resource yang memerlukan perlindungan"; fallback device credential untuk fitur non-sensitif (mis. membuka tampilan preferensi tema) secara logis di luar scope kekhawatiran test ini meski secara teknis match pola yang sama.

4. **Periksa juga pengikatan `CryptoObject`** sebagai konteks tambahan (§1.6) — temuan `DEVICE_CREDENTIAL` fallback **tanpa** `CryptoObject` punya implikasi risiko gabungan yang lebih serius dibanding ditemukan sendirian.

5. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | `DEVICE_CREDENTIAL` fallback pada operasi sensitif di aplikasi finansial/kesehatan/pemerintahan, tanpa `CryptoObject` | **Sedang-Tinggi** (hardening issue serius) |
   | `DEVICE_CREDENTIAL` fallback pada operasi sensitif di aplikasi kategori umum/non-high-security | **Rendah-Sedang** |
   | Fallback hanya untuk operasi non-sensitif | **Bukan temuan** |

6. **Dokumentasikan:** lokasi kode pemanggilan, nilai autentikator yang dikonfigurasi (hasil verifikasi manual, bukan mentah dari tool), apakah dipasangkan dengan `CryptoObject`, dan klasifikasi domain aplikasi (high-security atau tidak) untuk menentukan severity akhir.

---

## 4. Rekomendasi Perbaikan

### 4.1 Batasi ke BIOMETRIC_STRONG Saja untuk Operasi Sensitif

```java
// SEBELUM — mengizinkan fallback ke PIN/pattern/password
new BiometricPrompt.PromptInfo.Builder()
    .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG
        | BiometricManager.Authenticators.DEVICE_CREDENTIAL)
    .build();

// SESUDAH — hanya biometrik Class 3, sesuai MASTG-BEST-0031
new BiometricPrompt.PromptInfo.Builder()
    .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
    .build();
```

### 4.2 Pasangkan dengan CryptoObject untuk Pengikatan Kriptografis

```java
BiometricPrompt.CryptoObject cryptoObject = new BiometricPrompt.CryptoObject(cipher);
biometricPrompt.authenticate(promptInfo, cryptoObject);
```

Mengurangi risiko gabungan yang dijelaskan di §1.6 — hasil autentikasi terikat langsung ke operasi kriptografis spesifik, bukan sekadar sinyal boolean "sudah terotentikasi" yang bisa disalahgunakan untuk operasi lain.

### 4.3 Checklist Remediasi

- [ ] Seluruh operasi sensitif dikonfirmasi hanya memakai `BIOMETRIC_STRONG`, tidak ada `DEVICE_CREDENTIAL`
- [ ] Tidak ada pemanggilan `setDeviceCredentialAllowed(true)` yang tersisa (API deprecated)
- [ ] Autentikasi biometrik dipasangkan dengan `CryptoObject` untuk operasi kriptografis sensitif
- [ ] Klasifikasi domain aplikasi (high-security atau tidak) didokumentasikan untuk menentukan urgensi remediasi
- [ ] Hasil Semgrep diverifikasi manual untuk menyingkirkan false positive `BIOMETRIC_WEAK`

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0326 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-AUTH/MASTG-TEST-0326.md)
- [MASTG-KNOW-0001: Biometric Authentication](https://mas.owasp.org/MASTG/knowledge/android/MASVS-AUTH/MASTG-KNOW-0001/)
- [MASTG-BEST-0031: Enforce Strong Biometrics for Sensitive Operations](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0031.md)
- [GitHub Issue #3748: Update Android Biometrics MASTG-KNOW-0001 and MASTG-BEST-0031](https://github.com/OWASP/mastg/issues/3748)

### 5.2 Dokumentasi Resmi Android

- [BiometricPrompt.Builder#setAllowedAuthenticators](https://developer.android.com/reference/android/hardware/biometrics/BiometricPrompt.Builder#setAllowedAuthenticators(int))
- [BiometricManager.Authenticators](https://developer.android.com/reference/android/hardware/biometrics/BiometricManager.Authenticators#constants_1)
- [Android Developers — Secure User Authentication](https://developer.android.com/security/fraud-prevention/authentication)

### 5.3 Riset dan Kasus Nyata

- [SEC Consult: Bypassing Android Biometric Authentication](https://sec-consult.com/blog/detail/bypassing-android-biometric-authentication/)
- [Oversecured: Vulnerabilities That Lead to Account Takeover in Banking and Fintech Mobile Apps](https://oversecured.com/blog/mobile-banking-security-account-takeover-vulnerabilities)
- [arXiv: Towards Baselines for Shoulder Surfing on Mobile Authentication](https://arxiv.org/pdf/1709.04959)
- [Wikipedia: Shoulder Surfing (Computer Security)](https://en.wikipedia.org/wiki/Shoulder_surfing_%28computer_security%29)

### 5.4 Dokumentasi Tools

- [Semgrep Documentation](https://semgrep.dev/docs/)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
- [Frida — Dynamic Instrumentation Toolkit](https://frida.re/docs/home/)

---

*Dokumen ini disusun berdasarkan konten resmi OWASP MASTG (`tests-beta/android/MASVS-AUTH/MASTG-TEST-0326.md`, `MASTG-KNOW-0001`, `MASTG-BEST-0031`), analisis langsung terhadap rule `mastg-android-biometric-device-credential-fallback.yml`, serta riset industri (SEC Consult, Oversecured) tentang bypass biometrik dunia nyata. Nuansa metodologis terpenting: rule Semgrep resmi memiliki cakupan pola yang lebih luas dari klaim deskripsinya — `pattern-not` hanya mengecualikan literal eksak `BIOMETRIC_STRONG`/`15`, sehingga `BIOMETRIC_WEAK` sendirian atau kombinasi ekspresi biometrik murni (tanpa `DEVICE_CREDENTIAL` sama sekali) akan ikut ditandai sebagai false positive — verifikasi manual terhadap nilai bit `DEVICE_CREDENTIAL` (32768/0x8000) adalah langkah wajib, bukan opsional, sebelum melaporkan temuan final.*
