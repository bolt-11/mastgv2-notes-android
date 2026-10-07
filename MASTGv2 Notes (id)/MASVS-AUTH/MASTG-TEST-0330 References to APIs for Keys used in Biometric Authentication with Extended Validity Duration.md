# MASTG-TEST-0330 References to APIs for Keys used in Biometric Authentication with Extended Validity Duration

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0330 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-AUTH |
| **Weakness** | MASWE-0020 |
| **Tipe Pengujian** | Static, Code |
| **API terkait** | `KeyGenParameterSpec.Builder`, `setUserAuthenticationParameters`, `setUserAuthenticationValidityDurationSeconds` |
| **Teknik terkait** | MASTG-TECH-0013 (Reverse Engineering), MASTG-TECH-0014 (Static Analysis for Relevant APIs) |
| **Knowledge terkait** | MASTG-KNOW-0001, MASTG-KNOW-0043, MASTG-KNOW-0047, MASTG-KNOW-0012 |
| **Best Practice terkait** | MASTG-BEST-0036 (Use Cryptographic Binding for Biometric Authentication) |
| **Test terkait** | Rangkaian penuh MASTG-TEST-0326 s/d 0330 — lima test yang bersama-sama mengaudit konfigurasi `BiometricPrompt`/`KeyGenParameterSpec` dari sudut berbeda |
| **Rule resmi** | `mastg-android-biometric-validity-duration.yml` — 2 pola dengan `metavariable-comparison` numerik, lihat §1.4 |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Kutipan overview resmi MASTG:

> *"This test checks if the app configures cryptographic keys with an extended validity duration that allows keys to remain unlocked beyond the immediate operation. When using biometric authentication with CryptoObject, the authentication validity duration determines how long a key remains usable after successful authentication."*

Ini adalah test kelima dan terakhir dalam rangkaian audit konfigurasi `BiometricPrompt`/Keystore dalam seri riset ini. Berbeda dari TEST-0327 (apakah autentikasi terikat kriptografis sama sekali) dan TEST-0328 (apakah key bertahan setelah enrollment baru), test ini menyasar dimensi **waktu** — bahkan dengan `CryptoObject` yang sudah benar dan invalidasi enrollment yang sudah benar, key tetap bisa menjadi titik lemah bila **jendela waktu validitasnya** dikonfigurasi terlalu panjang.

### 1.2 Mekanisme Teknis: Duration 0 vs Duration > 0

Overview memberi definisi yang jelas dan terukur:

> *"Duration = 0: The key requires authentication for every cryptographic operation. This is the most secure configuration as each use of the key requires biometric verification."*
>
> *"Duration > 0: The key remains unlocked for the specified duration (in seconds) after successful authentication. When the duration is set to a high value in the range of minutes or hours an attacker with physical access to the phone could trigger sensitive operations without biometric verification."*

Ilustrasi skenario risiko konkret: bila sebuah aplikasi dompet digital mengatur durasi 1 jam, maka begitu pengguna melakukan satu kali autentikasi wajah/sidik jari di pagi hari, **siapa pun yang memegang perangkat tersebut** dalam jendela satu jam berikutnya dapat memicu transaksi sensitif **tanpa perlu melewati sensor biometrik sama sekali** — baik itu orang yang meminjam ponsel secara sah, maupun penyerang yang berhasil mendapatkan akses fisik singkat (dicuri, dipinjam paksa, atau ditinggal tanpa pengawasan di meja kerja).

### 1.3 Nuansa Penting dari API Lama: Nilai `-1` sebagai Kasus Khusus yang Mudah Terlewat

Riset komunitas mengungkap detail teknis penting pada API `setUserAuthenticationValidityDurationSeconds` (deprecated) yang **tidak disebutkan secara eksplisit** di overview resmi namun relevan untuk audit menyeluruh:

> *"When setUserAuthenticationValidityDurationSeconds is set to -1, the key can only be unlocked using a biometric identity. If it is set to a different value, the key can be unlocked using a device screenlock too... When this parameter is not set within the range [-1, 0], authentication requirements have no effect, and the device only needs to be unlocked. This represents a critical configuration error."*

Ini berarti ada **tiga kategori nilai**, bukan hanya dua (0 vs >0) yang eksplisit disebut overview:

| Nilai | Perilaku |
|---|---|
| `-1` | Hanya biometrik murni yang bisa membuka key (tanpa jatuh ke layar kunci umum) |
| `0` | Autentikasi diwajibkan setiap operasi — namun bisa lewat biometrik ATAU layar kunci |
| `> 0` | Key tetap terbuka selama durasi tersebut setelah satu kali autentikasi |

Nilai `-1` ini adalah detail yang mudah terlewat dari pembacaan overview resmi semata — penguji harus memasukkannya ke dalam pencarian pola, bukan hanya mencari nilai positif sesuai bunyi literal overview.

### 1.4 Analisis Rule Resmi: Pendekatan `metavariable-comparison` yang Lebih Presisi

Berbeda dari beberapa rule biometrik lain dalam seri riset ini yang mengandalkan `pattern-not` terhadap literal tertentu (rentan false positive, lihat TEST-0326 §1.4), rule untuk test ini memakai pendekatan yang secara teknis lebih kuat — `metavariable-comparison` untuk evaluasi numerik sesungguhnya:

```yaml
- patterns:
    - pattern: $BUILDER.setUserAuthenticationParameters($DURATION, ...)
    - metavariable-comparison:
        metavariable: $DURATION
        comparison: $DURATION > 0
```

Pendekatan ini **mengevaluasi nilai literal secara matematis** (`$DURATION > 0`), bukan sekadar mencocokkan pola teks — ini jauh lebih tepat sasaran dibanding pendekatan `pattern-not` yang rentan terhadap variasi penulisan ekspresi. Namun keterbatasan yang tetap melekat pada pendekatan ini: `metavariable-comparison` Semgrep hanya dapat mengevaluasi **nilai literal** yang tertulis langsung di kode (`3600`, `300`, dsb.) — bila durasi diteruskan lewat **variabel atau konstanta bernama** (`AUTH_VALIDITY_SECONDS`) yang didefinisikan di tempat lain, rule tidak dapat melakukan evaluasi nilai lintas-definisi tersebut, dan match akan gagal (false negative). Ini konsisten dengan keterbatasan umum analisis statis berbasis pattern-matching yang telah dibahas pada beberapa test lain dalam seri ini.

### 1.5 Bukti Empiris Skala Besar: Riset KeyDroid tentang Praktik Nyata Developer

Ini adalah bukti paling kuat yang tersedia untuk test ini — riset akademik **KeyDroid** (analisis skala besar terhadap penyimpanan key aman di aplikasi Android nyata) memberikan data empiris konkret tentang seberapa umum konfigurasi durasi panjang dipraktikkan di lapangan:

> *"The Android Keystore API allows developers to set a validity duration period in seconds during which the key can be reused without any need to reauthenticate. The most popular durations were 5 seconds (set by 38.53% of keys which set a duration) and 1 hour (set by 4.45% of keys)."*

Data ini mengungkap dua insight penting:

1. **5 detik adalah pilihan paling populer** (38.53% dari key yang mengatur durasi) — ini relatif wajar untuk kasus "beberapa operasi terkait berurutan" yang disebut catatan evaluasi resmi (§1.6), namun tetap bukan `0`.
2. **4.45% key mengatur durasi 1 jam** — ini adalah temuan paling mengkhawatirkan; riset yang sama mencatat variasi durasi yang jauh lebih singkat juga umum:

> *"13.2% of calls that set a duration set it to 3 seconds or less, meaning that the user can only reuse the key within the next few seconds. For some use cases, unless the user proceeds very quickly this is effectively the same as requiring authentication each time."*

Data ini memberi konteks kalibrasi realistis untuk severity (§3.6) — durasi dalam hitungan detik tunggal secara praktis mendekati keamanan `duration = 0`, sementara durasi dalam hitungan jam (yang nyatanya dipraktikkan hampir 1 dari 20 key menurut riset ini) adalah risiko nyata yang patut mendapat perhatian serius saat ditemukan.

### 1.6 Klasifikasi Severity: Bergantung pada Skala Durasi, Bukan Biner

Catatan resmi memberi panduan yang lebih bernuansa dibanding test fallback/confirmation sebelumnya — bukan sekadar "ada vs tidak ada", tapi **skala durasi itu sendiri** yang menentukan tingkat risiko:

> *"A non-zero authentication validity duration is not inherently a vulnerability. Short durations in the range of seconds may be acceptable for certain use cases where multiple related operations need to be performed in quick succession. However, for high-security applications and sensitive operations, requiring authentication per use (duration = 0) provides the strongest protection."*

Ini konsisten dengan data KeyDroid di §1.5 — durasi beberapa detik (kategori 13.2% dan sebagian dari 38.53%) punya profil risiko yang jauh berbeda dari durasi dalam skala jam (kategori 4.45%).

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **jadx** | Dekompilasi DEX → Java (MASTG-TECH-0013) |
| **Semgrep** + rule resmi `mastg-android-biometric-validity-duration.yml` | Pencocokan numerik `setUserAuthenticationParameters`/`setUserAuthenticationValidityDurationSeconds` dengan durasi > 0 (MASTG-TECH-0014) |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **grep/ripgrep** | Mencari pemanggilan dengan **variabel/konstanta bernama** (bukan literal) untuk menutup celah false negative rule resmi (§1.4), termasuk mencari nilai `-1` (§1.3) |
| **Frida** | Verifikasi dinamis nilai durasi sesungguhnya yang dipakai saat runtime, bila nilai berasal dari remote config |
| **MobSF** | Laporan otomatis yang kadang menyertakan pemeriksaan konfigurasi Keystore |

### 2.3 Prasyarat Lingkungan

- Tidak butuh device/root untuk analisis statis.
- Siapkan daftar konstanta/variabel umum yang mungkin dipakai untuk durasi (`AUTH_TIMEOUT`, `VALIDITY_SECONDS`, dsb.) untuk pencarian manual tambahan.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0013** untuk reverse engineer aplikasi.
2. Gunakan **MASTG-TECH-0014** untuk mencari API yang relevan.

### 3.2 Metode A — Semgrep dengan Rule Resmi

```bash
semgrep --config mastg-android-biometric-validity-duration.yml ./decompiled/sources
```

### 3.3 Metode B — grep/ripgrep untuk Menutup Celah Nilai Non-Literal dan Nilai -1

```bash
D=./decompiled/sources

# Cari seluruh pemanggilan, termasuk yang memakai variabel (tidak tertangkap rule resmi)
rg -n 'setUserAuthenticationParameters\(|setUserAuthenticationValidityDurationSeconds\(' $D

# Cari khusus nilai -1 (kasus khusus dari §1.3 yang sering terlewat)
rg -n 'setUserAuthenticationValidityDurationSeconds\(\s*-1\s*\)' $D

# Untuk hasil yang memakai variabel, lacak balik definisinya
rg -n 'AUTH_VALIDITY|AUTHENTICATION_TIMEOUT|VALIDITY_DURATION' $D
```

### 3.4 Metode C — Frida untuk Verifikasi Nilai Dinamis

```javascript
Java.perform(function () {
    var Builder = Java.use("android.security.keystore.KeyGenParameterSpec$Builder");
    Builder.setUserAuthenticationParameters.implementation = function (timeout, type) {
        console.log("[setUserAuthenticationParameters] timeout=" + timeout + " type=" + type);
        return this.setUserAuthenticationParameters(timeout, type);
    };
});
```

Berguna untuk kasus di mana nilai durasi ditentukan dinamis (mis. dari feature flag/remote config) sehingga tidak dapat dipastikan dari analisis statis saja.

### 3.5 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Kapan dipakai |
|---|---|---|
| **A** | Semgrep + rule resmi | Baseline wajib — menangkap nilai literal positif |
| **B** | grep/ripgrep manual | Wajib dipasangkan — menutup celah nilai via variabel dan kasus khusus `-1` |
| **C** | Frida | Nilai durasi ditentukan dinamis/remote config |

**Kombinasi minimum yang aku rekomendasikan:** **A + B (wajib dipasangkan)**, dengan **C** sebagai pelengkap untuk kasus nilai dinamis.

---

### 3.6 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Evaluation:** *"The test case fails if the app configures keys used for sensitive operations with: `setUserAuthenticationParameters(duration, type)` where duration > 0, OR `setUserAuthenticationValidityDurationSeconds(duration)` where duration > 0."*

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Key yang melindungi operasi sensitif dikonfigurasi dengan durasi > 0 (baik via API baru atau deprecated) |

**Contoh bukti (merefleksikan pola nyata dari data KeyDroid §1.5):**

```java
// Ditemukan di com/example/wallet/crypto/KeyManager.java
KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(KEY_ALIAS, PURPOSE_DECRYPT)
    .setUserAuthenticationRequired(true)
    .setUserAuthenticationParameters(3600, KeyProperties.AUTH_BIOMETRIC_STRONG) // 1 jam
    .build();
```

Interpretasi: key dompet digital tetap terbuka selama 1 jam setelah satu kali autentikasi — persis kategori risiko tertinggi yang ditemukan pada 4.45% key di riset KeyDroid. **FAIL**.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Durasi diset ke `0` secara eksplisit, **atau** |
| P2 | Durasi (deprecated API) diset ke `-1` untuk kasus yang menuntut biometrik murni (§1.3), **atau** |
| P3 | Method ini tidak dipanggil sama sekali, mengandalkan default yang mewajibkan autentikasi per operasi |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Ini test dengan skala risiko gradasi, bukan biner murni** — sesuai §1.6, durasi beberapa detik untuk kasus operasi berurutan punya profil risiko yang jauh berbeda dari durasi dalam skala jam; jangan perlakukan semua nilai > 0 dengan severity yang sama.

2. **Jangan lewatkan nilai via variabel/konstanta** — rule resmi hanya mengevaluasi literal numerik langsung (§1.4); audit manual (Metode B) wajib untuk kode yang memakai konstanta bernama.

3. **Periksa juga kasus khusus nilai `-1`** pada API deprecated — nilai ini punya semantik berbeda dari `0` (§1.3) dan tidak disebutkan secara eksplisit di evaluasi resmi; pastikan tidak salah menandainya sebagai FAIL.

4. **Rujuk data empiris KeyDroid untuk kalibrasi ekspektasi** — temuan durasi pendek (≤5 detik) relatif umum dan dapat diterima tergantung use case; durasi dalam skala menit-jam lebih layak mendapat perhatian serius dan severity lebih tinggi.

5. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | Durasi dalam skala jam pada operasi finansial/data sangat sensitif | **Tinggi** |
   | Durasi dalam skala menit pada operasi sensitif | **Sedang** |
   | Durasi beberapa detik (≤5 detik) untuk kasus operasi berurutan yang terdokumentasi jelas | **Rendah/dapat diterima** |
   | Durasi `0` atau `-1` (biometrik murni) | **Bukan temuan** |

6. **Dokumentasikan:** lokasi kode, nilai durasi yang dikonfigurasi (literal atau nama variabel), jenis operasi yang dilindungi, dan justifikasi bisnis bila durasi > 0 dipakai secara sengaja.

---

## 4. Rekomendasi Perbaikan

### 4.1 Gunakan Duration 0 untuk Operasi Sangat Sensitif

```java
// SEBELUM — key tetap terbuka 1 jam setelah autentikasi
KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(KEY_ALIAS, PURPOSE_DECRYPT)
    .setUserAuthenticationRequired(true)
    .setUserAuthenticationParameters(3600, KeyProperties.AUTH_BIOMETRIC_STRONG)
    .build();

// SESUDAH — autentikasi diwajibkan setiap operasi, sesuai MASTG-BEST-0036
KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(KEY_ALIAS, PURPOSE_DECRYPT)
    .setUserAuthenticationRequired(true)
    .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
    .build();
```

### 4.2 Bila Durasi > 0 Diperlukan, Batasi ke Skala Detik Tunggal dan Dokumentasikan Alasannya

Sesuai konteks "multiple related operations in quick succession" dari catatan resmi — bila benar-benar diperlukan, pakai nilai serendah mungkin (mis. 3-5 detik, sejalan dengan praktik paling umum di data KeyDroid) dan catat justifikasi bisnisnya secara eksplisit dalam dokumentasi kode.

### 4.3 Checklist Remediasi

- [ ] Seluruh key yang melindungi operasi sensitif memakai durasi `0`
- [ ] Bila durasi > 0 dipakai, dibatasi ke skala detik tunggal dengan justifikasi terdokumentasi
- [ ] Tidak ada nilai durasi yang ditentukan lewat variabel/remote config tanpa audit nilai aktualnya
- [ ] Diverifikasi dengan Frida bila nilai durasi bersifat dinamis
- [ ] Dikorelasikan dengan hasil MASTG-TEST-0327/0328/0329 untuk audit menyeluruh konfigurasi Keystore biometrik

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0330 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-AUTH/MASTG-TEST-0330.md)
- [MASTG-KNOW-0001: Biometric Authentication](https://mas.owasp.org/MASTG/knowledge/android/MASVS-AUTH/MASTG-KNOW-0001/)
- [MASTG-KNOW-0012: Key Generation](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CRYPTO/MASTG-KNOW-0012/)
- [MASTG-BEST-0036: Use Cryptographic Binding for Biometric Authentication](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0036.md)

### 5.2 Dokumentasi Resmi Android

- [KeyGenParameterSpec.Builder#setUserAuthenticationParameters](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setUserAuthenticationParameters(int,%20int))
- [KeyGenParameterSpec.Builder#setUserAuthenticationValidityDurationSeconds (deprecated)](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setUserAuthenticationValidityDurationSeconds(int))

### 5.3 Riset dan Kasus Nyata

- [arXiv: KeyDroid — A Large-Scale Analysis of Secure Key Storage in Android Apps](https://arxiv.org/pdf/2507.07927)
- [CodeQL Query Help: Insecurely Generated Keys for Local Authentication](https://codeql.github.com/codeql-query-help/java/java-android-insecure-local-key-gen/)
- [Minded Security: Implementing Secure Biometric Authentication on Mobile Applications](https://blog.mindedsecurity.com/2020/07/implementing-secure-biometric.html)

### 5.4 Dokumentasi Tools

- [Semgrep Documentation — metavariable-comparison](https://semgrep.dev/docs/writing-rules/rule-syntax/#metavariable-comparison)
- [Frida — Dynamic Instrumentation Toolkit](https://frida.re/docs/home/)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)

---

*Dokumen ini disusun berdasarkan konten resmi OWASP MASTG (`tests-beta/android/MASVS-AUTH/MASTG-TEST-0330.md`, `MASTG-KNOW-0001/0012/0043/0047`, `MASTG-BEST-0036`), analisis rule `mastg-android-biometric-validity-duration.yml`, serta data empiris skala besar dari riset akademik KeyDroid yang menganalisis praktik nyata konfigurasi durasi validitas biometrik di ekosistem aplikasi Android — menemukan 38.53% key yang mengatur durasi memilih 5 detik, namun 4.45% justru memilih durasi 1 jam penuh. Nuansa metodologis terpenting: test ini memiliki skala risiko gradasi (bukan biner) berdasarkan besaran durasi, rule resmi memakai `metavariable-comparison` yang lebih presisi dari rule biometrik lain namun tetap terbatas pada nilai literal (tidak menangkap variabel), dan API deprecated memiliki nilai khusus `-1` dengan semantik berbeda dari `0` yang mudah terlewat dari pembacaan overview resmi semata.*
