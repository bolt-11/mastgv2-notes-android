# MASTG-TEST-0305 Sensitive Data Stored Unencrypted via DataStore

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0305 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-STORAGE (MASVS-STORAGE-1) |
| **Weakness** | MASWE-0001 — *Sensitive Data Stored Unencrypted in Private Storage* |
| **Tipe Pengujian** | **Static, Dynamic** |
| **Status resmi MASTG** | **`placeholder`** — belum ada Overview/Steps/Evaluation lengkap |
| **Catatan resmi (satu-satunya konten yang tersedia)** | *"This test checks if the app uses the modern Jetpack DataStore API (Preferences DataStore or Proto DataStore) to store sensitive data (e.g., tokens, PII) without encryption. It confirms the absence of secure serializers or mechanisms to protect data integrity and confidentiality."* |
| **Test terkait** | **MASTG-TEST-0287** (SharedPreferences) — DataStore adalah **pengganti resmi** yang direkomendasikan Android untuk SharedPreferences, namun membawa **celah enkripsi yang berbeda** (lihat §1.2); **MASTG-TEST-0304** (Room Database) — pola analisis serupa (dua jalur API dengan kebutuhan deteksi berbeda) |
| **Demo terkait** | — (tidak ada) |
| **Rule resmi** | — (tidak ada) |
| **CWE terkait** | CWE-312, CWE-311 |

---

## 1. Penjelasan

### 1.1 Status Test Ini dan Posisinya sebagai "Generasi Berikutnya" dari MASTG-TEST-0287

Test ini berstatus **`placeholder`**, namun posisinya dalam rangkaian evaluasi penyimpanan data Android sangat jelas: **Jetpack DataStore** adalah pengganti resmi yang direkomendasikan Google untuk **`SharedPreferences`** (dibahas mendalam di dokumen **MASTG-TEST-0287** dalam seri riset ini) — fakta ini bahkan secara eksplisit dicatat di **MASTG-KNOW-0036** yang menjadi rujukan dokumen tersebut: *"Android recommends `DataStore` as a modern replacement for `SharedPreferences`."* Mengikuti tren migrasi industri menuju DataStore, test ini hadir sebagai **evaluasi setara** untuk mekanisme penyimpanan generasi baru tersebut.

### 1.2 Temuan Paling Kritis: DataStore Tidak Memiliki Padanan `EncryptedSharedPreferences` Sama Sekali

Ini adalah **nuansa paling penting** dalam dokumen ini, dan menciptakan sebuah **paradoks migrasi** yang signifikan bagi tim developer. Riset komunitas secara eksplisit menegaskan:

> *"DataStore has a lack of built-in encryption, which `EncryptedSharedPreferences` previously provided. By default, when persisting data to device storage the DataStore library does not encrypt it."*

Ini menciptakan situasi yang **ironis** bila disandingkan dengan nuansa yang sudah dibahas mendalam di dokumen MASTG-TEST-0287 — di sana dijelaskan bahwa `EncryptedSharedPreferences` kini **deprecated**, dan panduan resmi menyarankan migrasi ke pendekatan yang lebih modern. Namun **DataStore — tujuan migrasi resmi untuk `SharedPreferences` secara umum — sama sekali tidak menyediakan mekanisme enkripsi bawaan apa pun**, baik untuk varian **Preferences DataStore** maupun **Proto DataStore**. Developer yang **mengikuti rekomendasi resmi Android** untuk bermigrasi dari `SharedPreferences`/`EncryptedSharedPreferences` ke DataStore, **tanpa menyadari celah ini**, berisiko **tanpa sengaja menurunkan tingkat keamanan** penyimpanan data sensitif mereka — dari "terenkripsi" (meski lewat library yang sudah deprecated) menjadi "sama sekali tidak terenkripsi" (API modern yang direkomendasikan, namun polos tanpa enkripsi apa pun secara default).

### 1.3 Dua Varian DataStore dan Implikasinya terhadap Kemungkinan Enkripsi

Riset komunitas menjelaskan perbedaan mendasar antara dua varian DataStore yang relevan untuk strategi enkripsi:

> *"Preferences DataStore stores and accesses data using keys without a predefined schema and without type safety, while Proto DataStore stores data as instances of a custom data type and requires you to define a schema using protocol buffers but provides type safety."*

| Varian | Skema Data | Kemungkinan Integrasi Enkripsi |
|---|---|---|
| **Preferences DataStore** | Key-value tanpa skema tetap (mirip `SharedPreferences`) | **Terbatas** — API serializer-nya tidak dirancang fleksibel untuk injeksi logika enkripsi kustom |
| **Proto DataStore** | Skema Protocol Buffers yang ditentukan developer, type-safe | **Memungkinkan** — via custom `Serializer<T>` yang dapat disisipi logika enkripsi/dekripsi secara manual |

Poin krusial ini berarti: **pilihan varian DataStore yang dipakai developer secara langsung membatasi opsi mitigasi yang tersedia**. Aplikasi yang sudah memakai Preferences DataStore untuk data sensitif memiliki jalur mitigasi yang jauh lebih sulit dibanding yang memakai Proto DataStore — sebuah pertimbangan arsitektural yang idealnya sudah dipikirkan **sejak awal pemilihan varian**, bukan ditambal belakangan.

### 1.4 Mekanisme Mitigasi: Custom `Serializer` pada Proto DataStore

Untuk Proto DataStore, mekanisme enkripsi **harus diimplementasikan secara manual** oleh developer lewat interface `Serializer<T>` — Proto DataStore memanggil method `readFrom()`/`writeTo()` milik serializer ini setiap kali membaca/menulis data ke disk, sehingga developer dapat **menyisipkan langkah enkripsi/dekripsi** tepat di titik tersebut:

```kotlin
object EncryptedUserPrefsSerializer : Serializer<UserPrefs> {
    override val defaultValue: UserPrefs = UserPrefs.getDefaultInstance()

    override suspend fun readFrom(input: InputStream): UserPrefs {
        val decryptedBytes = decryptWithKeystore(input.readBytes())  // Dekripsi SEBELUM parsing
        return UserPrefs.parseFrom(decryptedBytes)
    }

    override suspend fun writeTo(t: UserPrefs, output: OutputStream) {
        val encryptedBytes = encryptWithKeystore(t.toByteArray())  // Enkripsi SEBELUM menulis ke disk
        output.write(encryptedBytes)
    }
}
```

**Tidak ada mekanisme serupa** yang tersedia secara native untuk Preferences DataStore — inilah mengapa Proto DataStore menjadi **satu-satunya jalur realistis** untuk mengamankan data sensitif dalam ekosistem DataStore.

### 1.5 Rekomendasi Resmi Terkini: Google Tink, Bukan Jetpack Security Crypto

Riset komunitas memberi arah mitigasi resmi terbaru yang relevan, melengkapi nuansa deprecation yang sudah dibahas di dokumen MASTG-TEST-0287:

> *"Google deprecated Jetpack Security's cryptography APIs (`EncryptedSharedPreferences`/`EncryptedFile`) and now recommends moving to **Tink**, which offers a consistent, secure, and upgradeable cryptography layer that is independent from device-specific Android behavior."*

**Google Tink** adalah pustaka kriptografi multi-platform (dikembangkan oleh tim keamanan Google) yang kini menjadi **rekomendasi utama** untuk kebutuhan enkripsi data lokal di Android — dipakai sebagai lapisan enkripsi di dalam custom `Serializer` Proto DataStore sesuai pola §1.4. Terdapat juga **implementasi referensi resmi** untuk migrasi dari `EncryptedSharedPreferences` (deprecated) langsung ke Proto DataStore yang diamankan Tink — menunjukkan bahwa **jalur migrasi yang benar** memang sudah dipetakan Google, meski membutuhkan lebih banyak kerja implementasi manual dibanding solusi drop-in seperti `EncryptedSharedPreferences` di masa lalu.

### 1.6 Mengapa Tipe Pengujian Ini Static DAN Dynamic

Berbeda dari banyak test lain yang murni statis atau murni dinamis, frontmatter test ini secara eksplisit menandai **kedua** tipe (`[static, dynamic]`). Ini masuk akal mengingat sifat DataStore:

- **Statis**: memeriksa kode untuk keberadaan custom `Serializer` yang mengimplementasikan enkripsi (atau ketiadaannya) — mirip pola analisis di MASTG-TEST-0304.
- **Dinamis**: DataStore pada akhirnya menyimpan data di file (Preferences DataStore sebagai XML di `datastore/`, Proto DataStore sebagai binary protobuf) — verifikasi **isi file sesungguhnya** di device tetap diperlukan sebagai bukti definitif, sama seperti pola di MASTG-TEST-0287/0304, karena kode yang "tampak" mengenkripsi tetap bisa gagal secara implementasi.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **jadx** | Dekompilasi DEX → Java/Kotlin-like untuk pencarian pola DataStore dan `Serializer` kustom |
| **grep / ripgrep** | Pencarian pola API |
| **adb** | Ekstraksi file DataStore dari device untuk verifikasi langsung |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **CodeQL** | Menelusuri implementasi `Serializer<T>` kustom dan memverifikasi apakah `readFrom()`/`writeTo()` benar-benar memanggil operasi kriptografi (`Cipher`, Tink `Aead`) |
| **protoc / Proto DataStore tooling** | Untuk memeriksa skema `.proto` yang dipakai dan menilai apakah field sensitif teridentifikasi dari nama field skema |
| **strings / hexdump** | Memeriksa isi file DataStore mentah untuk mendeteksi string plaintext yang terbaca langsung |
| **TruffleHog/gitleaks** | Pemindaian pola secret pada hasil ekstraksi file DataStore |

### 2.3 Prasyarat Lingkungan

- **Tidak butuh device/root** untuk analisis statis inti.
- **Root/`run-as` diperlukan** untuk ekstraksi langsung file DataStore dari `/data/data/<package>/datastore/` atau `/data/data/<package>/files/datastore/` (lokasi dapat bervariasi tergantung konfigurasi).
- **Identifikasi varian DataStore yang dipakai** (Preferences vs Proto) sebagai langkah pertama wajib, karena menentukan jalur mitigasi yang realistis (§1.3).

---

## 3. Cara Pengujian

Karena tidak ada langkah resmi rinci (status placeholder), metodologi berikut disusun dari elaborasi catatan resmi dan pemahaman arsitektur DataStore.

### 3.1 Langkah Umum

1. Identifikasi seluruh penggunaan DataStore (Preferences atau Proto) dalam basis kode.
2. Untuk Proto DataStore: periksa apakah `Serializer` kustom yang dipakai benar-benar mengimplementasikan enkripsi.
3. Untuk Preferences DataStore: catat sebagai **otomatis berisiko tinggi** bila menyimpan data sensitif, karena tidak ada jalur mitigasi native yang tersedia (§1.3).
4. Ekstrak dan verifikasi file DataStore langsung dari device.

### 3.2 Metode A — grep/ripgrep

```bash
D=./decompiled/sources

# Temukan penggunaan Preferences DataStore
rg -n 'preferencesDataStore\(|PreferenceDataStoreFactory' $D

# Temukan penggunaan Proto DataStore dan Serializer kustom
rg -n 'DataStoreFactory\.create\(|: Serializer<' $D

# Verifikasi apakah Serializer kustom memanggil operasi kriptografi
rg -n -A15 'object \w+Serializer\s*:\s*Serializer<' $D | grep -c "Cipher\|Aead\|encrypt\|decrypt"
```

### 3.3 Metode B — CodeQL untuk Verifikasi Isi Serializer

```ql
import java

class CustomSerializer extends Class {
  CustomSerializer() {
    this.getAnInterface().hasQualifiedName("androidx.datastore.core", "Serializer")
  }
}

class CryptoOperation extends MethodAccess {
  CryptoOperation() {
    this.getMethod().getDeclaringType().hasQualifiedName("javax.crypto", "Cipher") or
    this.getMethod().getDeclaringType().getName().matches("%Aead%")  // Google Tink
  }
}

from CustomSerializer serializer
where not exists(CryptoOperation op | op.getEnclosingCallable().getDeclaringType() = serializer)
select serializer, "Serializer DataStore kustom ditemukan TANPA operasi kriptografi apa pun — data kemungkinan tidak terenkripsi"
```

### 3.4 Metode C — Verifikasi Langsung File DataStore (Bukti Definitif)

```bash
adb shell run-as com.target.app find /data/data/com.target.app -path "*datastore*"
adb shell run-as com.target.app cat /data/data/com.target.app/files/datastore/user_prefs.preferences_pb > ./dump.bin

# Periksa apakah isinya dapat dibaca sebagai teks biasa
strings ./dump.bin | grep -iE "token|password|email"
hexdump -C ./dump.bin | head -30
```

Bila `strings`/`hexdump` menunjukkan nilai yang **terbaca jelas sebagai teks manusia** (bukan data biner acak yang konsisten dengan output enkripsi), ini bukti kuat bahwa data tersimpan tanpa enkripsi.

### 3.5 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Kapan dipakai |
|---|---|---|
| **A** | grep | Baseline, identifikasi varian DataStore dan keberadaan Serializer kustom |
| **B** | CodeQL | Verifikasi sistematis apakah Serializer benar-benar mengenkripsi |
| **C** | Verifikasi file langsung | **Bukti definitif**, terutama untuk kasus implementasi yang "tampak" benar namun gagal secara praktik |

**Kombinasi minimum yang aku rekomendasikan:** **A (identifikasi varian + Serializer) → B (verifikasi isi Serializer) → C (bukti definitif dari file mentah)**.

---

### 3.6 Kriteria Evaluasi: Positive Case & Negative Case

Karena tidak ada klausul Evaluation resmi (status placeholder), kriteria berikut disusun berdasarkan catatan resmi dan prinsip dasar MASWE-0001.

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Aplikasi memakai **Preferences DataStore** untuk menyimpan data sensitif (kredensial, token, PII) — otomatis berisiko tinggi karena tidak ada jalur mitigasi native (§1.3) |
| F2 | Aplikasi memakai **Proto DataStore** dengan `Serializer` kustom yang **tidak** mengimplementasikan enkripsi apa pun |
| F3 | Verifikasi langsung file DataStore (Metode C) mengonfirmasi data tersimpan sebagai teks yang dapat dibaca langsung |

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Aplikasi memakai **Proto DataStore** dengan `Serializer` kustom yang terverifikasi mengimplementasikan enkripsi (Tink/Android Keystore) dengan benar |
| P2 | Verifikasi langsung file DataStore mengonfirmasi data tersimpan sebagai ciphertext biner, tidak dapat dibaca sebagai teks |
| P3 | Aplikasi tidak menyimpan data sensitif via DataStore sama sekali |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Preferences DataStore yang menyimpan data sensitif adalah sinyal FAIL yang kuat secara default** — karena tidak ada jalur mitigasi native yang realistis, berbeda dari Proto DataStore yang setidaknya **memungkinkan** mitigasi lewat `Serializer` kustom.

2. **Jangan simpulkan PASS hanya karena ditemukan `Serializer` kustom** — banyak `Serializer` kustom dibuat semata untuk serialisasi format data (bukan untuk keamanan); verifikasi isi method `readFrom()`/`writeTo()` benar-benar memanggil operasi kriptografi (Metode B/C).

3. **Korelasikan dengan dokumen MASTG-TEST-0287** untuk konteks lengkap — ironi migrasi SharedPreferences → DataStore (§1.2) adalah temuan penting yang layak disoroti dalam laporan audit bila organisasi sedang/baru menyelesaikan migrasi semacam ini.

4. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | Preferences DataStore menyimpan kredensial/token plaintext | **Kritis** |
   | Proto DataStore tanpa enkripsi menyimpan data sensitif | **Tinggi** |
   | Proto DataStore dengan enkripsi yang diverifikasi benar | **Bukan temuan** |

5. **Dokumentasikan:** varian DataStore yang dipakai, status implementasi `Serializer` (bila Proto), hasil verifikasi file mentah, dan korelasi dengan hasil audit MASTG-TEST-0287.

---

## 4. Rekomendasi Perbaikan

### 4.1 Migrasi ke Proto DataStore dengan Tink (Bila Masih Memakai Preferences DataStore untuk Data Sensitif)

```kotlin
// build.gradle
implementation "com.google.crypto.tink:tink-android:1.13.0"
```

```kotlin
object EncryptedSerializer : Serializer<SensitiveData> {
    private val aead: Aead by lazy { /* inisialisasi Tink Aead via Android Keystore */ }

    override val defaultValue: SensitiveData = SensitiveData.getDefaultInstance()

    override suspend fun readFrom(input: InputStream): SensitiveData {
        val ciphertext = input.readBytes()
        val plaintext = aead.decrypt(ciphertext, null)
        return SensitiveData.parseFrom(plaintext)
    }

    override suspend fun writeTo(t: SensitiveData, output: OutputStream) {
        val plaintext = t.toByteArray()
        val ciphertext = aead.encrypt(plaintext, null)
        output.write(ciphertext)
    }
}
```

### 4.2 Pertimbangkan Tetap Memakai Android Keystore Langsung untuk Data Sangat Sensitif

Untuk kredensial/kunci kriptografi paling kritis, pertimbangkan tidak memakai DataStore sama sekali — simpan langsung di Android Keystore (rujuk pola di dokumen MASTG-TEST-0212/0287).

### 4.3 Checklist Remediasi

- [ ] Varian DataStore yang dipakai aplikasi diidentifikasi (Preferences/Proto)
- [ ] Data sensitif yang disimpan via Preferences DataStore dimigrasikan ke Proto DataStore + Tink, atau ke Android Keystore langsung
- [ ] `Serializer` kustom diverifikasi benar-benar mengenkripsi, bukan hanya melakukan serialisasi format
- [ ] Verifikasi langsung file DataStore mengonfirmasi tidak ada data plaintext yang terbaca
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0305 setiap penambahan penyimpanan data sensitif baru via DataStore

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0305: Sensitive Data Stored Unencrypted via DataStore](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0305/)
- [MASTG-TEST-0287: Runtime Storage of Unencrypted Data via the SharedPreferences API](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0287/)
- [MASTG-TEST-0304: References to Sensitive Data Unencrypted via Android Room Database](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0304/)
- [MASWE-0001: Sensitive Data Stored Unencrypted in Private Storage](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0001/)
- [MASTG-KNOW-0036: Shared Preferences](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0036/)

### 5.2 Dokumentasi Resmi Android

- [Android Developers — DataStore](https://developer.android.com/topic/libraries/architecture/datastore)
- [Android Developers — DataStore Releases](https://developer.android.com/jetpack/androidx/releases/datastore)
- [Android Developers — Cryptography (Jetpack Security Crypto deprecation, Tink)](https://developer.android.com/privacy-and-security/cryptography)
- [Google Tink](https://developers.google.com/tink)

### 5.3 Riset dan Artikel Komunitas

- [Medium — Goodbye SharedPreferences: The Future of Android Data Storage with DataStore & Keystore](https://medium.com/@mahesh31.ambekar/the-modern-android-storage-stack-datastore-and-keystore-29f54572aa08)
- [DEV Community — Beyond Preferences](https://dev.to/tkuenneth/beyond-preferences-1fh2)
- [Styling Android — DataStore: Security](https://blog.stylingandroid.com/datastore-security/)
- [Medium ne-digital — Jetpack DataStore Evaluation: Journey to Find an Alternative Secure Storage](https://medium.com/ne-digital/jetpack-datastore-evaluation-aefb65260a30)
- [droidcon — Unpacking Android Security Part 2: Insecure Data Storage](https://www.droidcon.com/2022/06/15/unpacking-android-security-part-2-insecure-data-storage/)
- [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)

### 5.4 Dokumentasi Tools

- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [TruffleHog](https://docs.trufflesecurity.com/)

---

*Dokumen ini disusun sepenuhnya dari riset independen karena MASTG-TEST-0305 berstatus **placeholder**. Temuan paling signifikan: **Jetpack DataStore — pengganti resmi yang direkomendasikan Android untuk `SharedPreferences` — sama sekali tidak menyediakan mekanisme enkripsi bawaan**, menciptakan paradoks migrasi di mana developer yang mengikuti rekomendasi resmi untuk berpindah dari `SharedPreferences`/`EncryptedSharedPreferences` (kini deprecated) ke DataStore berisiko tanpa sadar menurunkan tingkat keamanan penyimpanan data sensitif mereka. Mitigasi hanya realistis dilakukan lewat Proto DataStore (bukan Preferences DataStore) dengan custom `Serializer` yang mengintegrasikan Google Tink — jalur yang jauh lebih kompleks dibanding solusi drop-in yang pernah disediakan `EncryptedSharedPreferences`.*
