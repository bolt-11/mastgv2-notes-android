# MASTG-TEST-0338 References to Storage Integrity Check APIs

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0338 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-RESILIENCE |
| **Weakness** | MASWE-0057 |
| **Tipe Pengujian** | Static, Code, **Manual** |
| **API terkait** | `javax.crypto.Mac`, `java.security.Signature`, `java.security.MessageDigest` |
| **Flag khusus** | `false_negative_prone: true` — ditandai eksplisit di frontmatter |
| **Teknik terkait** | MASTG-TECH-0013 (Reverse Engineering), MASTG-TECH-0014 (Static Analysis for Relevant APIs), MASTG-TECH-0008 (Accessing App Data Directories), MASTG-TECH-0023 (Reviewing Decompiled Java Code) |
| **Knowledge terkait** | MASTG-KNOW-0036 (Shared Preferences) |
| **Best Practice terkait** | MASTG-BEST-0066 (Implementing Storage Integrity Checks on Android) |
| **Rule resmi** | `mastg-android-local-storage-input-validation.yml` — ditemukan **cacat desain signifikan**, lihat §1.4 |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Kutipan overview resmi MASTG:

> *"Android apps can protect the integrity and authenticity of data they store on the device (e.g., in SharedPreferences, files, or databases) by computing an HMAC or a digital signature over the data and verifying it before use. If the app does not implement such checks, an attacker who modifies the stored data can go undetected and the app may trust the tampered input in a security-relevant decision."*

Nuansa penting yang ditekankan overview — ancaman ini **tidak bergantung pada kebocoran data ke aplikasi lain**. Bahkan data yang sudah tersimpan dengan benar di sandbox privat aplikasi (`MODE_PRIVATE`, tidak bisa dibaca aplikasi lain secara normal) tetap rentan terhadap tampering dari **pemilik perangkat sendiri** atau penyerang yang berhasil memperoleh akses privileged lokal:

> *"Even data stored in the app's private sandbox (such as SharedPreferences) normally cannot be modified by other apps, but it can still be tampered with in local attack scenarios, such as on rooted devices, during dynamic analysis, through backups, or by directly manipulating the app's data directory after obtaining privileged access."*

### 1.2 Skenario Ancaman Konkret: Manipulasi Trial Counter / Flag Premium

Overview memberi skenario langkah-demi-langkah yang sangat spesifik dan mudah dipahami:

> *"Suppose an app stores a usage counter or entitlement flag in SharedPreferences and trusts it without verifying its integrity. 1. An attacker uses MASTG-TECH-0008 to locate the app's data directories on a rooted device. 2. The attacker modifies the stored value (for example, resets a trial counter or flips a 'premium' flag). 3. Because the app never verifies an HMAC or signature over the stored data, it loads the tampered value as authentic. 4. The attacker bypasses the intended restriction."*

Skenario ini bukan risiko teoretis — ia adalah **model bisnis utuh** dari tools populer yang sudah lama beredar di ekosistem Android:

> *"Lucky Patcher's In-App Purchase Obstruction feature provides users with a way to bypass in-app purchases and access premium features without spending any money by modifying the app code and tricking the in-app purchase system into thinking that a legitimate purchase has been made... Lucky Patcher can bypass license verification for paid apps and unlock in-app purchases without payment."*

Keberadaan tools seperti ini — yang memerlukan root namun sudah sangat matang dan mudah diakses publik — menegaskan bahwa risiko yang disasar test ini **secara aktif dieksploitasi di lapangan** terhadap aplikasi yang tidak menerapkan integrity check, bukan sekadar skenario akademik.

### 1.3 Tiga API Inti dan Perannya Masing-Masing

| API | Mekanisme | Kapan Dipakai |
|---|---|---|
| `javax.crypto.Mac` | HMAC — kunci simetris yang sama dipakai untuk membuat dan memverifikasi tag | Paling umum, cocok bila aplikasi sendiri yang menulis dan membaca data |
| `java.security.Signature` | Tanda tangan digital asimetris (public/private key) | Cocok bila verifikasi perlu dilakukan pihak yang tidak memiliki private key (mis. server memverifikasi data yang ditandatangani aplikasi) |
| `java.security.MessageDigest` | Checksum/hash murni (tanpa kunci) | **Tidak memberikan autentisitas** — hanya mendeteksi perubahan tidak sengaja, bukan tampering yang disengaja (penyerang bisa menghitung ulang hash baru setelah modifikasi) |

Poin kritis yang perlu digarisbawahi: kehadiran `MessageDigest` **saja** (tanpa HMAC/signature) **tidak cukup** untuk melindungi dari tampering yang disengaja — checksum murni tanpa kunci rahasia bisa dihitung ulang oleh siapa pun, termasuk penyerang yang baru saja mengubah datanya. Ini relevan untuk evaluasi §3.7 — ditemukannya `MessageDigest` semata bukan indikasi kuat adanya integrity protection yang efektif.

### 1.4 Temuan Analitis Kritis: Rule Resmi Mengandung Pola Spesifik-Demo yang Tidak Generik

Ini adalah temuan paling signifikan dari analisis rule untuk test ini. Rule `mastg-android-local-storage-input-validation.yml` memiliki struktur sebagai berikut:

```yaml
- patterns:
    - pattern-inside: |
        ...
        private final String loadPlain(...) {
          ...
        }
    - pattern-either:
        - pattern: prefs().getString(...)
        - ...
```

Perhatikan `pattern-inside` yang **mewajibkan** kecocokan berada di dalam method yang secara **literal** bernama `loadPlain` atau `loadProtected`. Ini adalah masalah desain yang serius — **rule ini hanya akan berfungsi bila kode target aplikasi memiliki method yang benar-benar dinamai persis "loadPlain"/"loadProtected"**. Ini sangat mustahil terjadi secara kebetulan pada aplikasi produksi nyata di luar aplikasi contoh/demo resmi MASTG sendiri (seperti Crackmes/MASTG-APP yang dipakai untuk mendemonstrasikan teknik di dokumentasi). Dengan kata lain, rule ini kemungkinan besar **ditulis sebagai template yang disalin dari kode demo internal MASTG** dan belum digeneralisasi menjadi pola yang benar-benar dapat mendeteksi kode arbitrer di aplikasi nyata manapun.

Pola kedua (`mastg-android-hmac-validation-present`) lebih longgar dan generik — ia mencari kehadiran `Mac.getInstance()`, `SecretKeySpec`, `$MAC.init()`, `$MAC.doFinal()` di mana pun tanpa batasan nama method. Pola ini **jauh lebih berguna secara praktis**, meski tetap tidak mencakup `Signature`/`MessageDigest` yang disebut di frontmatter `apis:` test ini. Juga perhatikan ketidakcocokan tag kategori pada rule ini — pesan rule menggunakan tag `[MASVS-CODE-4]`, bukan `[MASVS-RESILIENCE-...]` seperti kategori test ini — indikasi lain bahwa rule ini kemungkinan ditulis/diadaptasi dari konteks berbeda tanpa disesuaikan penuh ke kategori MASVS-RESILIENCE.

### 1.5 Mengapa Test Ini Diberi Tipe "Manual" dan Flag `false_negative_prone`

Bagian "Further Validation Required" menjelaskan mengapa kehadiran API semata tidak cukup:

> *"These APIs are commonly used for unrelated purposes (for example, networking, analytics, or generic checksums), so their mere presence does not confirm a storage integrity mechanism."*

`Mac`/`Signature`/`MessageDigest` adalah API kriptografi **generik** yang dipakai di mana-mana — autentikasi API jaringan (HMAC untuk request signing), verifikasi lisensi, bahkan deduplikasi cache. Menemukan API ini di kode **tidak otomatis berarti** API tersebut dipakai untuk melindungi data `SharedPreferences`/file/database spesifik yang relevan untuk test ini — penguji harus **melacak secara manual** apakah hasil HMAC/signature tersebut benar-benar dibandingkan dengan nilai yang dibaca ulang dari local storage.

Bagian "Expected False Negatives" resmi juga mengakui keterbatasan sebaliknya:

> *"This test may produce false negatives if the integrity check relies on a third-party library, a custom implementation, or APIs not covered by the analysis."*

Flag `false_negative_prone: true` di frontmatter adalah pengakuan metadata eksplisit dari MASTG sendiri — jarang ditemukan test lain dengan flag ini secara terbuka di luar catatan prosa.

### 1.6 Kriteria Tambahan: Bukan Hanya "Apakah Ada", Tapi "Apakah Efektif untuk Attacker Model yang Relevan"

Pertanyaan validasi ketiga dari "Further Validation Required" memberi standar yang lebih tinggi dari sekadar "ditemukan HMAC":

> *"Determine whether that validation is effective for the attacker model in scope."*

Ini terhubung langsung ke catatan peringatan MASTG-BEST-0066:

> *"Storage integrity checks are bypassable if the attacker can extract the HMAC key (for example, if it is hardcoded in the app or recoverable on a rooted device) or intercept the verification logic at runtime. Treat these as a defense-in-depth control rather than a standalone guarantee."*

Artinya, bahkan temuan PASS (HMAC ditemukan dan dipakai dengan benar) perlu **penilaian lanjutan** — di mana kunci HMAC tersebut disimpan? Bila kunci hanya hardcoded di kode (bisa diekstrak lewat reverse engineering) atau tidak memakai Android Keystore, perlindungan tersebut secara efektif **hanya menaikkan biaya serangan**, bukan benar-benar mencegahnya terhadap penyerang yang cukup termotivasi (root + reverse engineering).

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **jadx** | Dekompilasi DEX → Java (MASTG-TECH-0013, MASTG-TECH-0023) |
| **Semgrep** + rule resmi `mastg-android-local-storage-input-validation.yml` | Triase awal — namun cakupannya terbatas (§1.4) |
| **objection** | Akses direktori data aplikasi (MASTG-TECH-0008) untuk verifikasi langsung isi `SharedPreferences`/file/database |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **grep/ripgrep** | Mencari seluruh pemanggilan `Mac`/`Signature`/`MessageDigest` tanpa batasan nama method, menutup celah rule resmi (§1.4) |
| **Frida** | Verifikasi dinamis — hook fungsi pembacaan `SharedPreferences` dan fungsi verifikasi HMAC/signature untuk mengamati apakah keduanya benar-benar terhubung saat runtime |
| **Lucky Patcher (dalam environment uji terkontrol)** | Mereplikasi skenario serangan nyata (§1.2) — mencoba memodifikasi nilai `SharedPreferences` secara langsung dan mengamati apakah aplikasi mendeteksinya |

### 2.3 Prasyarat Lingkungan

- Analisis statis awal tidak butuh device/root.
- **Verifikasi dinamis sangat direkomendasikan** mengingat sifat "manual" dan `false_negative_prone` test ini — butuh device rooted/emulator untuk mengakses dan memodifikasi data aplikasi secara langsung (MASTG-TECH-0008).

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0013** untuk reverse engineer aplikasi.
2. Gunakan **MASTG-TECH-0014** untuk mencari API yang relevan.

### 3.2 Metode A — Semgrep dengan Rule Resmi (Cakupan Terbatas)

```bash
semgrep --config mastg-android-local-storage-input-validation.yml ./decompiled/sources
```

**Catatan wajib:** pola `mastg-android-local-storage-input-validation` hanya berfungsi bila ada method bernama literal `loadPlain`/`loadProtected` (§1.4) — kemungkinan besar tidak akan menghasilkan match pada aplikasi nyata. Andalkan pola kedua (`mastg-android-hmac-validation-present`) sebagai sinyal yang lebih berguna, namun tetap perlu verifikasi manual.

### 3.3 Metode B — grep/ripgrep untuk Cakupan Penuh Tiga API

```bash
D=./decompiled/sources

# Cari seluruh pemanggilan HMAC tanpa batasan nama method
rg -n 'Mac\.getInstance\(|SecretKeySpec\(' $D

# Cari pemanggilan Signature (tidak tercakup rule resmi sama sekali)
rg -n 'Signature\.getInstance\(' $D

# Cari pemanggilan MessageDigest (perlu verifikasi apakah dipasangkan dengan kunci rahasia, §1.3)
rg -n 'MessageDigest\.getInstance\(' $D

# Cari pembacaan SharedPreferences/file/database di sekitar hasil di atas
rg -n -B5 -A5 'Mac\.getInstance|Signature\.getInstance' $D | grep -E 'SharedPreferences|getString\(|getInt\(|openFileInput|query\('
```

### 3.4 Metode C — Review Manual (Wajib, Sesuai MASTG-TECH-0023)

Untuk setiap lokasi dari Metode A/B:

1. Identifikasi apakah nilai yang dibaca dari local storage memengaruhi keputusan keamanan (autentikasi, otorisasi, akses fitur premium, flag konfigurasi).
2. Lacak apakah ada HMAC/signature yang dihitung **atas data yang sama** dan dibandingkan **sebelum** nilai tersebut dipakai.
3. Periksa reaksi aplikasi bila verifikasi gagal — apakah benar-benar menolak nilai tersebut, atau tetap melanjutkan meski verifikasi gagal (kegagalan silent)?
4. Lacak sumber kunci HMAC — apakah hardcoded di kode, atau disimpan di Android Keystore (§1.6)?

### 3.5 Metode D — Verifikasi Dinamis dengan Replikasi Skenario Serangan Nyata

```bash
# Via objection, akses direktori data aplikasi
objection -g com.example.app explore
# di dalam REPL:
cd /data/data/com.example.app/shared_prefs
cat app_prefs.xml
```

```
Prosedur manual:
1. Identifikasi nilai yang diduga entitlement/counter (mis. <boolean name="is_premium" value="false" />)
2. Modifikasi langsung nilai tersebut via editor teks di device rooted
3. Jalankan ulang aplikasi, amati apakah perubahan diterima (FAIL) atau ditolak/terdeteksi (PASS)
```

Ini secara langsung mereplikasi skenario ancaman resmi (§1.2) dan teknik yang dipakai tools seperti Lucky Patcher secara nyata.

### 3.6 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Kapan dipakai |
|---|---|---|
| **A** | Semgrep + rule resmi | Triase awal, namun pola pertama hampir tidak berguna (§1.4) |
| **B** | grep/ripgrep manual | Cakupan yang jauh lebih memadai untuk tiga API resmi |
| **C** | Review manual (wajib) | Inti pengujian — menilai relevansi keamanan dan efektivitas |
| **D** | Verifikasi dinamis | Bukti paling konklusif, mereplikasi skenario serangan nyata langsung |

**Kombinasi minimum yang aku rekomendasikan:** **B (baseline yang sesungguhnya) → C (wajib) → D (bukti final)**, dengan Metode A hanya sebagai pelengkap kecil mengingat keterbatasan signifikan pada pola pertamanya.

---

### 3.7 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Evaluation:** *"The test case fails if the app uses data loaded from local storage in a security-relevant decision without verifying its integrity and authenticity beforehand."*

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Nilai dari `SharedPreferences`/file/database memengaruhi keputusan keamanan **dan** tidak ada HMAC/signature yang diverifikasi sebelum nilai tersebut dipakai |

**Contoh bukti (merefleksikan skenario resmi §1.2):**

```java
// Ditemukan di com/example/app/billing/PremiumChecker.java
SharedPreferences prefs = getSharedPreferences("billing", MODE_PRIVATE);
boolean isPremium = prefs.getBoolean("is_premium", false); // tidak ada verifikasi integritas
if (isPremium) {
    unlockPremiumFeatures();
}
```

Interpretasi: flag premium dibaca langsung tanpa HMAC/signature apa pun — dapat dimodifikasi langsung di device rooted (via Lucky Patcher atau edit manual) untuk membuka fitur premium secara gratis. **FAIL**.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Nilai sensitif disimpan **beserta** HMAC/signature yang dihitung atasnya, dan diverifikasi **sebelum** dipakai dalam keputusan keamanan, **dan** |
| P2 | Aplikasi bereaksi secara benar (menolak nilai) bila verifikasi gagal, **dan** |
| P3 | Kunci HMAC/signature tersimpan di Android Keystore (bukan hardcoded) — sesuai MASTG-BEST-0066 untuk efektivitas penuh terhadap attacker model root (§1.6) |

**Contoh bukti:**

```java
boolean isPremium = prefs.getBoolean("is_premium", false);
byte[] expectedTag = Base64.decode(prefs.getString("is_premium_hmac", ""), Base64.DEFAULT);
byte[] actualTag = hmac(String.valueOf(isPremium).getBytes(), keystoreKey);
if (MessageDigest.isEqual(expectedTag, actualTag) && isPremium) {
    unlockPremiumFeatures();
} else {
    // tolak, log sebagai indikasi tampering
}
```

**PASS**.

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Jangan andalkan rule resmi Pola 1 sebagai sinyal berarti** — kemungkinan besar tidak akan menghasilkan match pada kode aplikasi nyata manapun (§1.4); gunakan grep manual sebagai baseline yang sesungguhnya.

2. **`MessageDigest` murni bukan bukti integrity protection yang efektif** — selalu verifikasi apakah checksum dipasangkan dengan kunci rahasia (menjadikannya HMAC) atau hanya hash polos yang bisa dihitung ulang penyerang (§1.3).

3. **PASS teknis tidak selalu berarti aman penuh** — selalu periksa lokasi penyimpanan kunci HMAC/signature (§1.6); HMAC dengan kunci hardcoded hanya memberi perlindungan "defense-in-depth" minimal, bukan garansi nyata terhadap penyerang dengan akses root.

4. **Reaksi aplikasi terhadap kegagalan verifikasi sama pentingnya dengan keberadaan verifikasi itu sendiri** — aplikasi yang menghitung HMAC namun tetap melanjutkan meski verifikasi gagal (silent failure) secara efektif setara dengan tidak memiliki perlindungan sama sekali.

5. **Manfaatkan verifikasi dinamis untuk bukti paling kuat** — mereplikasi langsung skenario Lucky Patcher-style (modifikasi manual nilai di device rooted) memberi bukti paling konklusif dan mudah dipahami stakeholder non-teknis.

6. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | Flag entitlement/finansial (premium, pembayaran) tanpa integrity check apa pun | **Tinggi** |
   | Flag konfigurasi non-finansial tanpa integrity check | **Sedang** |
   | Integrity check ada namun kunci hardcoded/tidak di Keystore | **Rendah-Sedang** (defense-in-depth lemah) |
   | Integrity check ada, kunci di Keystore, reaksi kegagalan tepat | **Bukan temuan** |

7. **Dokumentasikan:** lokasi kode, jenis data yang dilindungi, mekanisme integrity check yang dipakai (HMAC/signature/tidak ada), lokasi penyimpanan kunci, dan hasil verifikasi dinamis (replikasi tampering).

---

## 4. Rekomendasi Perbaikan

### 4.1 Implementasikan HMAC dengan Kunci dari Android Keystore

```kotlin
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

fun hmac(data: ByteArray, key: ByteArray): ByteArray {
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(SecretKeySpec(key, "HmacSHA256"))
    return mac.doFinal(data)
}

fun verify(data: ByteArray, tag: ByteArray, key: ByteArray): Boolean {
    return hmac(data, key).contentEquals(tag)
}
```

### 4.2 Pastikan Reaksi yang Benar Saat Verifikasi Gagal

```java
if (!verify(storedValue, storedTag, keystoreKey)) {
    Log.w(TAG, "Integritas data SharedPreferences gagal diverifikasi — kemungkinan tampering");
    resetToSecureDefault(); // JANGAN lanjutkan dengan nilai yang tidak terverifikasi
    return;
}
```

### 4.3 Checklist Remediasi

- [ ] Seluruh data keamanan-relevan di local storage (entitlement, counter, flag konfigurasi) dilindungi HMAC/signature
- [ ] Kunci HMAC/signature disimpan di Android Keystore, bukan hardcoded
- [ ] Aplikasi menolak dan merespons dengan benar saat verifikasi integritas gagal
- [ ] Diverifikasi secara dinamis dengan mencoba modifikasi langsung nilai di device rooted
- [ ] Dipahami sebagai kontrol defense-in-depth, dikombinasikan dengan validasi server-side untuk keputusan bisnis kritis (pembayaran, lisensi)

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0338 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0338.md)
- [MASTG-KNOW-0036: Shared Preferences](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0036/)
- [MASTG-BEST-0066: Implementing Storage Integrity Checks on Android](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0066.md)
- [MASTG-TECH-0008: Accessing App Data Directories](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0008/)

### 5.2 Riset dan Kasus Nyata

- [Doverunner: How to Block Lucky Patcher Usage on Android Apps?](https://doverunner.com/blogs/how-to-block-lucky-patcher-usage-on-android-apps/)
- [OWASP Cheat Sheet: Encrypt-then-MAC Pattern](https://web.archive.org/web/20210804035343/https://cseweb.ucsd.edu/~mihir/papers/oem.html)

### 5.3 Dokumentasi Tools

- [Semgrep Documentation](https://semgrep.dev/docs/)
- [Objection — Runtime Mobile Exploration](https://github.com/sensepost/objection)
- [Frida — Dynamic Instrumentation Toolkit](https://frida.re/docs/home/)

---

*Dokumen ini disusun berdasarkan konten resmi OWASP MASTG (`tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0338.md`, `MASTG-KNOW-0036`, `MASTG-BEST-0066`), analisis rule `mastg-android-local-storage-input-validation.yml`, serta konteks nyata tools populer (Lucky Patcher) yang secara aktif dipakai untuk mengeksploitasi kelemahan storage integrity di ekosistem Android. Nuansa metodologis terpenting: rule resmi Pola 1 (`mastg-android-local-storage-input-validation`) mengandung ketergantungan pada nama method literal (`loadPlain`/`loadProtected`) yang kemungkinan besar merupakan sisa template dari kode demo internal dan **tidak akan cocok dengan kode aplikasi nyata manapun** — Pola 2 (`mastg-android-hmac-validation-present`) jauh lebih berguna namun juga memiliki tag kategori yang tidak konsisten (`MASVS-CODE-4` pada test berkategori MASVS-RESILIENCE). Test ini secara eksplisit ditandai `false_negative_prone` dan bertipe manual — kehadiran API semata tidak pernah cukup; penilaian relevansi keamanan, pemasangan verifikasi yang benar, dan reaksi terhadap kegagalan verifikasi semuanya menuntut review manusia.*
