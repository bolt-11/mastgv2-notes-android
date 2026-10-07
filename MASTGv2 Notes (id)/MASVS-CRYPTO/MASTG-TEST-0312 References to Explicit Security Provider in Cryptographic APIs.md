# MASTG-TEST-0312 References to Explicit Security Provider in Cryptographic APIs

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0312 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-CRYPTO (MASVS-CRYPTO-1) |
| **Weakness** | MASWE-0007 — *Improper Encryption* |
| **Tipe Pengujian** | Static, Code |
| **Knowledge** | MASTG-KNOW-0011 (Security Provider) |
| **Best Practice** | MASTG-BEST-0020 (Update the GMS Security Provider — dibahas mendalam di dokumen MASTG-TEST-0295) |
| **Teknik terkait** | MASTG-TECH-0013, MASTG-TECH-0014 |
| **Test terkait** | **MASTG-TEST-0295** (GMS Security Provider Not Updated) — test yang berbeda namun berbagi tema "security provider"; **klarifikasi penting**: rule semgrep resmi untuk test ini (lihat §3.2) sebelumnya **salah diasosiasikan** dengan MASTG-TEST-0295 dalam riset pendahuluan seri dokumen ini — rule tersebut sebenarnya **milik test ini** |
| **Demo terkait** | — (tidak ada) |
| **Rule resmi** | `mastg-android-hardcoded-security-provider.yaml` — **rule yang tepat sasaran untuk test ini** |
| **CWE terkait** | CWE-327 (Use of a Broken or Risky Cryptographic Algorithm), CWE-1104 (Use of Unmaintained Third Party Components) |

---

## 1. Penjelasan

### 1.1 Klarifikasi Penting: Koreksi atas Analisis Sebelumnya di Dokumen MASTG-TEST-0295

Sebelum membahas substansi test ini, perlu dicatat klarifikasi metodologis yang penting: pada dokumen **MASTG-TEST-0295** (GMS Security Provider Not Updated) dalam seri riset ini, rule semgrep `mastg-android-hardcoded-security-provider.yaml` **ditemukan dan dengan tepat ditandai sebagai tidak relevan** untuk topik `ProviderInstaller`/pembaruan provider via Google Play Services yang menjadi fokus test tersebut. Riset lanjutan untuk test ini (MASTG-TEST-0312) **mengonfirmasi** bahwa rule tersebut memang **bukan** rule yang salah sasaran secara keseluruhan — ia **benar-benar relevan**, hanya **untuk test yang berbeda**, yaitu **test ini**. Ini contoh baik tentang bagaimana sebuah rule tunggal di repositori MASTG dapat melayani test ID yang spesifik, dan pentingnya memverifikasi asosiasi rule-ke-test secara presisi alih-alih berasumsi dari kesamaan topik permukaan ("security provider").

### 1.2 Tujuan Pengujian: Ketika "Menentukan Provider Secara Eksplisit" Justru Berisiko

Kutipan overview resmi MASTG:

> *"Android cryptography APIs based on the Java Cryptography Architecture (JCA) allow developers to specify a security provider when calling `getInstance` methods. However, **explicitly specifying a provider can cause security issues and break compatibility** because several providers have been deprecated or removed in recent versions."*

Ini test yang secara konseptual **menarik** karena menggabungkan **dua dimensi masalah yang biasanya dipisahkan** dalam seri riset ini: **keamanan** (provider lawas membawa implementasi kriptografi yang mungkin usang/rentan) **dan** **stabilitas/kompatibilitas** (provider yang di-hardcode secara eksplisit berisiko membuat aplikasi **crash** pada versi Android yang lebih baru). Di JCA (Java Cryptography Architecture), method `getInstance()` pada berbagai kelas kriptografi (`Cipher`, `KeyStore`, `Signature`, dll.) menerima **parameter provider opsional** — nama string yang menentukan **implementasi spesifik** mana yang harus dipakai, alih-alih membiarkan sistem memilih provider default secara otomatis berdasarkan urutan prioritas yang sudah dikonfigurasi platform.

### 1.3 Linimasa Deprecation yang Menjadi Akar Risiko Nyata

Overview resmi memberi **linimasa konkret** yang menjadi dasar mengapa hardcoding nama provider adalah praktik berbahaya pada ekosistem Android yang terus berevolusi:

| Provider | Status |
|---|---|
| **_Crypto_** | Deprecated di Android 7.0 (API 24), **dihapus sepenuhnya** di Android 9 (API 28) |
| **_BouncyCastle_ (`BC`)** | Deprecated di Android 9 (API 28), **dihapus sepenuhnya** di Android 12 (API 31) |
| **Provider apa pun (secara umum)** | *"Apps targeting Android 9 (API level 28) or above fail when a provider is specified"* — pernyataan yang lebih luas dari overview resmi, mengindikasikan risiko kegagalan tidak terbatas hanya pada kedua provider di atas |

Pola ini **berulang secara historis** — Android secara konsisten menghapus/mendeprecate provider lawas demi konsolidasi ke implementasi yang lebih modern dan terpelihara (**Conscrypt**, dibahas di §1.4). Developer yang **menuliskan nama provider secara eksplisit** di kode mereka **mengikat** aplikasi pada provider spesifik tersebut — begitu provider itu dihapus dari platform, pemanggilan `getInstance(algo, "NamaProvider")` akan **melempar** `NoSuchProviderException` saat runtime, menyebabkan **crash** yang sepenuhnya dapat dihindari seandainya developer **tidak** menentukan provider secara eksplisit sejak awal (membiarkan sistem memilih provider default yang sesuai secara otomatis).

### 1.4 Kasus Nyata: Crash Produksi pada Aplikasi F-Droid

Riset komunitas mendokumentasikan contoh konkret dari konsekuensi nyata pola ini pada aplikasi **F-Droid** (toko aplikasi open-source populer) setelah pembaruan ke Android 12:

> Pengguna mengalami **crash** saat mengetuk fitur *"Nearby"* kemudian *"Find people nearby"*, dengan error: **`no such algorithm: SHA1WITHRSA for provider BC`**.

Kasus ini menggambarkan dengan sangat jelas bagaimana penghapusan implementasi BouncyCastle di Android 12 (yang mencakup **seluruh algoritma AES** dan berbagai algoritma lain yang sebelumnya disediakan provider `BC`) secara langsung menyebabkan kegagalan fungsional pada aplikasi produksi nyata yang masih menyandikan asumsi bahwa provider `BC` akan selalu tersedia — bukan skenario hipotetis, melainkan **insiden yang benar-benar dialami pengguna** pada aplikasi yang luas dipakai.

### 1.5 Provider yang Direkomendasikan: `AndroidOpenSSL` (Conscrypt)

Overview resmi menyebut solusi yang jelas:

> *"This test identifies cases where an app explicitly specifies a security provider... that is not the default provider, `AndroidOpenSSL` (Conscrypt), which is actively maintained and should generally be used."*

**Conscrypt** (nama internal provider: `AndroidOpenSSL`) adalah provider JCA berbasis OpenSSL/BoringSSL yang dikembangkan dan **secara aktif dipelihara oleh Google** sebagai bagian dari platform Android itu sendiri. Berbeda dari provider pihak ketiga seperti BouncyCastle yang siklus integrasinya ke Android bergantung pada keputusan platform yang bisa berubah (dan pada akhirnya dihapus), Conscrypt **menjadi provider default** pada Android modern dan terus menerima pembaruan keamanan seiring rilis platform — inilah mengapa overview resmi menyimpulkan: **cara teraman** untuk menghindari seluruh kelas masalah ini adalah **tidak menentukan provider sama sekali**, membiarkan sistem secara otomatis memilih Conscrypt (atau provider default lain yang sesuai) tanpa perlu developer melakukan apa pun secara eksplisit.

### 1.6 Pengecualian Legitimate yang Secara Eksplisit Diakui: `AndroidKeyStore`

Ini nuansa evaluasi paling penting yang membedakan test ini dari larangan absolut "jangan pernah menentukan provider apa pun". Overview resmi secara eksplisit mengakui **satu pengecualian yang sah**:

> *"It examines `getInstance` calls and flags any use of a named provider other than legitimate exceptions such as `KeyStore.getInstance("AndroidKeyStore")`."*

Pemanggilan `KeyStore.getInstance("AndroidKeyStore")` — serta pola terkait seperti `KeyPairGenerator.getInstance("RSA", "AndroidKeyStore")` yang dibahas di MASTG-KNOW-0012 (rujuk dokumen MASTG-TEST-0307 dalam seri riset ini) — **BUKAN** kesalahan, karena `AndroidKeyStore` **bukan sembarang provider JCA biasa**; ia adalah **mekanisme integrasi khusus** dengan hardware-backed keystore Android yang **memang harus** dipanggil secara eksplisit by design (tidak ada cara lain untuk mengakses kunci yang disimpan di Keystore selain memanggil provider ini secara spesifik). Klausul Evaluation resmi menegaskan pengecualian ini secara presisi dengan membatasi kondisi FAIL **khusus** untuk operasi `KeyStore`:

> *"The test case fails if any `getInstance` call explicitly specifies a security provider other than `AndroidKeyStore` **for `KeyStore` operations**."*

Perhatikan **formulasi spesifik** ini — klausul resmi secara literal membatasi kondisi FAIL pada pemanggilan `KeyStore.getInstance()` yang memakai provider selain `AndroidKeyStore`, bukan pada **seluruh** kelas JCA (`Cipher`, `Signature`, `MessageDigest`, dll.) secara umum — meski substansi dan rationale dari overview (linimasa deprecation, risiko crash) jelas berlaku luas ke seluruh API JCA. Ini nuansa presisi bahasa yang **layak diperhatikan** penguji saat menafsirkan cakupan evaluasi literal vs semangat keseluruhan test ini.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **jadx** | Dekompilasi DEX → Java untuk pencarian pola `getInstance()` dengan parameter provider |
| **grep / ripgrep** | Pencarian pola API dan ekstraksi nama provider yang dipakai |
| **semgrep** | Menjalankan rule resmi |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **CodeQL** | Menelusuri seluruh pemanggilan `getInstance()` dua-argumen di seluruh kelas JCA yang relevan (`Cipher`, `KeyGenerator`, `KeyPairGenerator`, `MessageDigest`, `Signature`, `Mac`, `SecretKeyFactory`, `KeyFactory`, `SecureRandom`, dll.), mengklasifikasikan nama provider yang ditemukan terhadap daftar provider yang sudah deprecated/dihapus |
| **MobSF** | Kadang menampilkan pola ini di laporan Code Analysis kategori kriptografi |
| **Target multi-versi Android (emulator)** | Verifikasi dinamis — menjalankan aplikasi pada emulator Android 12+ untuk mengonfirmasi secara empiris apakah pemanggilan provider yang ditemukan benar-benar menyebabkan crash `NoSuchProviderException`/`NoSuchAlgorithmException` |

### 2.3 Prasyarat Lingkungan

- **Tidak butuh device/root** untuk analisis statis inti.
- **Untuk verifikasi dinamis**, idealnya tersedia emulator dengan **beberapa versi API berbeda** (khususnya API 28+ dan API 31+) untuk mengonfirmasi secara empiris dampak crash sesuai linimasa deprecation (§1.3).

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0013** untuk reverse engineer aplikasi.
2. Gunakan **MASTG-TECH-0014** untuk mencari API yang relevan.

### 3.2 Metode A — Rule Semgrep Resmi *(rule yang tepat sasaran, lihat §1.1)*

```yaml
rules:
  - id: mastg-android-hardcoded-security-provider
    languages: [java]
    severity: WARNING
    metadata:
      summary: This rule looks for explicitly specified security providers in getInstance calls.
    message: "[MASVS-CRYPTO-1] Explicitly specified security provider found. Do not hardcode a provider unless using AndroidKeyStore."
    patterns:
      - pattern-either:
          - pattern: $X.getInstance($ALGO, $PROVIDER)
          - pattern: $X.getInstance($ALGO, (String $PROVIDER))
          - pattern: $X.getInstance($ALGO, (java.security.Provider $PROVIDER))
      - pattern-not: KeyStore.getInstance("AndroidKeyStore")
      - metavariable-regex:
          metavariable: $X
          regex: (Cipher|KeyGenerator|KeyPairGenerator|MessageDigest|Signature|Mac|SecretKeyFactory|KeyFactory|SecureRandom|KeyAgreement|AlgorithmParameters|AlgorithmParameterGenerator|CertificateFactory|CertPathBuilder|CertPathValidator|CertStore|KeyStore)
```

```bash
semgrep --config https://raw.githubusercontent.com/OWASP/mastg/master/rules/mastg-android-hardcoded-security-provider.yaml ./decompiled/sources/
```

**Analisis cakupan rule ini**: rule ini secara efektif mencakup **seluruh kelas JCA relevan** (lihat daftar lengkap di `metavariable-regex`) — jauh lebih luas dibanding klausul Evaluation literal resmi yang hanya menyebut `KeyStore` secara spesifik (§1.6). Rule ini sudah menyertakan `pattern-not` untuk mengecualikan `KeyStore.getInstance("AndroidKeyStore")` secara eksplisit sebagai pengecualian legitimate — konsisten dengan overview resmi. **Berbeda dari beberapa rule lain yang dianalisis dalam seri riset ini**, rule ini **cukup komprehensif dan berfungsi sebagaimana diklaim** — layak dipakai sebagai metode utama tanpa banyak catatan celah signifikan.

### 3.3 Metode B — grep/ripgrep sebagai Pelengkap Verifikasi Manual

```bash
D=./decompiled/sources

# Temukan seluruh pemanggilan getInstance dengan 2 argumen (algoritma + provider)
rg -n '\.getInstance\([^,]+,\s*"[A-Za-z]+"\)' $D

# Soroti khusus provider yang DIKETAHUI sudah deprecated/dihapus
rg -n '\.getInstance\([^,]+,\s*"(BC|Crypto)"\)' $D
```

### 3.4 Metode C — CodeQL untuk Klasifikasi Sistematis

```ql
import java

class ExplicitProviderCall extends MethodAccess {
  ExplicitProviderCall() {
    this.getMethod().hasName("getInstance") and
    this.getNumArgument() = 2 and
    this.getArgument(1).getType().hasName("String") and
    not (this.getQualifier().getType().hasName("KeyStore") and
         this.getArgument(1).(StringLiteral).getValue() = "AndroidKeyStore")
  }
}

from ExplicitProviderCall call
select call, call.getArgument(1).toString(), "Provider dispesifikasikan secara eksplisit — verifikasi apakah ini AndroidOpenSSL/Conscrypt atau provider berisiko (BC/Crypto)"
```

### 3.5 Metode D — Verifikasi Dinamis Multi-Versi (Konfirmasi Dampak Crash Nyata)

```bash
# Jalankan pada emulator Android 12+ (API 31+) untuk konfirmasi BouncyCastle sudah dihapus
emulator -avd api31-test &
adb install target-app.apk
adb logcat | grep -i "NoSuchProviderException\|NoSuchAlgorithmException"
# Picu alur kode yang memakai provider eksplisit, amati crash
```

### 3.6 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Cakupan | Kapan dipakai |
|---|---|---|---|
| **A** | Rule semgrep resmi | Luas, mencakup seluruh kelas JCA relevan | **Baseline utama yang andal** |
| **B** | grep | Pelengkap verifikasi manual cepat | Cross-check cepat |
| **C** | CodeQL | Klasifikasi terstruktur untuk codebase besar | Audit skala besar |
| **D** | Verifikasi dinamis multi-versi | Bukti definitif dampak crash nyata | Konfirmasi akhir, terutama untuk laporan ke tim developer |

**Kombinasi minimum yang aku rekomendasikan:** **A (baseline andal) → D (konfirmasi dampak nyata pada versi Android yang relevan)** untuk laporan yang paling persuasif bagi tim developer.

---

### 3.7 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Evaluation:** *"The test case fails if any `getInstance` call explicitly specifies a security provider other than `AndroidKeyStore` for `KeyStore` operations."*

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Ditemukan pemanggilan `getInstance(algo, "BC")` atau `getInstance(algo, "Crypto")` — provider yang **sudah dikonfirmasi** dihapus pada versi Android yang relevan |
| F2 | Ditemukan pemanggilan `getInstance()` dengan provider eksplisit **apa pun** selain `AndroidOpenSSL`/default sistem, pada kelas JCA selain `KeyStore` (mengikuti semangat luas overview, §1.6) |
| F3 | Verifikasi dinamis (Metode D) mengonfirmasi crash `NoSuchProviderException`/`NoSuchAlgorithmException` nyata pada versi Android target |

**Contoh bukti (ilustratif — MASTG belum menyediakan demo resmi untuk test ini):**

```java
// Ditemukan di com/example/target/crypto/LegacyCryptoHelper.java
Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");  // BouncyCastle eksplisit
```

```bash
$ emulator -avd api31-test &
$ adb logcat | grep NoSuchProviderException
E/AndroidRuntime: java.security.NoSuchProviderException: no such provider: BC
    at com.example.target.crypto.LegacyCryptoHelper.encrypt(LegacyCryptoHelper.java:22)
```

Interpretasi: provider `BC` di-hardcode secara eksplisit, dan verifikasi dinamis pada Android 12+ mengonfirmasi **crash nyata** sesuai linimasa deprecation (§1.3) — persis pola yang dialami aplikasi F-Droid (§1.4). **FAIL kritis**, menggabungkan dimensi keamanan dan stabilitas sekaligus.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Seluruh pemanggilan `getInstance()` **tidak** menentukan provider secara eksplisit — membiarkan sistem memilih provider default (Conscrypt/`AndroidOpenSSL`) secara otomatis |
| P2 | Satu-satunya pemanggilan dengan provider eksplisit adalah `KeyStore.getInstance("AndroidKeyStore")` — pengecualian legitimate |
| P3 | Verifikasi dinamis multi-versi tidak menunjukkan crash terkait provider pada versi Android manapun yang didukung aplikasi |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Ini test langka di mana "perbaikan keamanan" dan "perbaikan stabilitas" sepenuhnya selaras** — komunikasikan kedua manfaat ini ke tim developer untuk meningkatkan urgensi remediasi, karena dampak crash yang nyata (bukan hanya risiko keamanan abstrak) seringkali lebih efektif memotivasi perbaikan cepat.

2. **Perhatikan nuansa formulasi literal klausul Evaluation vs semangat luas overview** (§1.6) — meski klausul resmi secara literal hanya menyebut `KeyStore`, rule resmi dan rationale keseluruhan overview jelas mencakup seluruh kelas JCA; laporkan temuan pada kelas JCA lain sebagai bagian dari semangat test ini, bukan diabaikan karena formulasi literal yang lebih sempit.

3. **Rule resmi untuk test ini cukup diandalkan** — berbeda dari beberapa rule lain yang dianalisis dalam seri riset ini yang menunjukkan celah signifikan, rule ini layak dipakai sebagai metode utama dengan keyakinan lebih tinggi.

4. **Verifikasi dinamis pada versi Android yang relevan memberi bukti paling persuasif** — crash nyata jauh lebih meyakinkan tim developer dibanding argumen risiko keamanan teoretis semata.

5. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | Provider yang **sudah dikonfirmasi dihapus** (`BC` pada API 31+, `Crypto` pada API 28+) ditemukan di jalur kode aktif | **Tinggi** (risiko crash produksi nyata) |
   | Provider yang masih ada tapi dihardcode (mengikat aplikasi pada implementasi yang mungkin dihapus di masa depan) | **Menengah** |
   | `KeyStore.getInstance("AndroidKeyStore")` | **Bukan temuan** |

6. **Dokumentasikan:** lokasi kode, nama provider yang di-hardcode, status deprecation/removal provider tersebut sesuai linimasa (§1.3), dan hasil verifikasi dinamis bila dilakukan.

---

## 4. Rekomendasi Perbaikan

### 4.1 Hapus Parameter Provider, Biarkan Sistem Memilih Default

```java
// SEBELUM — mengikat ke provider yang berisiko dihapus
Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");

// SESUDAH — sistem otomatis memilih provider default (Conscrypt/AndroidOpenSSL)
Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
```

### 4.2 Bila Perlu Menjamin Konsistensi Lintas Versi Android Lawas, Bundle Conscrypt Secara Eksplisit

```groovy
dependencies {
    implementation 'org.conscrypt:conscrypt-android:2.5.2'
}
```

```kotlin
Security.addProvider(Conscrypt.newProvider())
```

### 4.3 Checklist Remediasi

- [ ] Seluruh pemanggilan `getInstance()` dengan provider eksplisit diinventarisasi
- [ ] Parameter provider dihapus kecuali untuk `KeyStore.getInstance("AndroidKeyStore")`
- [ ] Verifikasi dinamis pada emulator multi-versi mengonfirmasi tidak ada crash terkait provider
- [ ] Bila dibutuhkan konsistensi lintas versi lawas, Conscrypt di-bundle secara eksplisit sebagai pengganti BouncyCastle
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0312 setelah setiap penambahan kode kriptografi baru

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0312: References to Explicit Security Provider in Cryptographic APIs](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0312/)
- [MASTG-TEST-0295: GMS Security Provider Not Updated](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0295/)
- [MASWE-0007: Improper Encryption](https://mas.owasp.org/MASWE/MASVS-CRYPTO/MASWE-0007/)
- [MASTG-KNOW-0011: Security Provider](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CRYPTO/MASTG-KNOW-0011/)
- [MASTG-BEST-0020: Update the GMS Security Provider](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0020/)
- [Rule resmi: mastg-android-hardcoded-security-provider.yaml (GitHub)](https://github.com/OWASP/mastg/blob/master/rules/mastg-android-hardcoded-security-provider.yaml)

### 5.2 Dokumentasi Resmi Android

- [Android Developers Blog — Cryptography Changes in Android P](https://android-developers.googleblog.com/2018/03/cryptography-changes-in-android-p.html)
- [Android Developers — Android 9 Changes: Conscrypt Implementations](https://developer.android.com/about/versions/pie/android-9.0-changes-all#conscrypt_implementations_of_parameters_and_algorithms)
- [Android Developers — Android 12 Behavior Changes: Bouncy Castle](https://developer.android.com/about/versions/12/behavior-changes-all#bouncy-castle)
- [Conscrypt — A Java Security Provider for Android](https://github.com/google/conscrypt)

### 5.3 Riset dan Kasus Nyata

- [GitLab F-Droid — Issue #2338 (crash akibat penghapusan BouncyCastle)](https://gitlab.com/fdroid/fdroidclient/-/issues/2338)
- [GitHub google/conscrypt#1119 — NoSuchProviderException: no such provider: BC on Android 7](https://github.com/google/conscrypt/issues/1119)
- [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
- [CWE-1104: Use of Unmaintained Third Party Components](https://cwe.mitre.org/data/definitions/1104.html)

### 5.4 Dokumentasi Tools

- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026), dokumentasi resmi Android Developers seputar perubahan security provider lintas versi, dan kasus nyata kerusakan aplikasi F-Droid akibat penghapusan BouncyCastle di Android 12. Test ini unik karena menggabungkan dimensi keamanan dan stabilitas/kompatibilitas yang sepenuhnya selaras — menghardcode nama provider bukan hanya mengikat aplikasi pada implementasi kriptografi yang mungkin usang secara keamanan, tapi juga menciptakan risiko crash produksi nyata seiring Android menghapus provider lawas. Dokumen ini juga mengoreksi temuan sebelumnya pada dokumen MASTG-TEST-0295 — rule semgrep yang di sana ditandai tidak relevan ternyata memang milik test ini (MASTG-TEST-0312), bukan rule yang sepenuhnya tanpa pasangan test yang jelas.*
