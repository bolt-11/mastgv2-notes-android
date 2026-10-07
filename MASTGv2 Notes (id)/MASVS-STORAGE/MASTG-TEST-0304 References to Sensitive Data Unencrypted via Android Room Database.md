# MASTG-TEST-0304 References to Sensitive Data Unencrypted via Android Room Database

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0304 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-STORAGE (MASVS-STORAGE-1) |
| **Weakness** | MASWE-0001 — *Sensitive Data Stored Unencrypted in Private Storage* |
| **Tipe Pengujian** | Static, Code |
| **Status resmi MASTG** | **`placeholder`** — belum ada Overview/Steps/Evaluation lengkap |
| **Catatan resmi (satu-satunya konten yang tersedia)** | *"This test checks if the app uses the default SQLite API (e.g., `SQLiteOpenHelper`, `context.openOrCreateDatabase`) to store sensitive data (e.g., tokens, PII) in an unencrypted database file within the app's sandbox. It confirms the absence of secure alternatives like SQLCipher or encrypted databases."* |
| **Knowledge** | MASTG-KNOW-0037 (SQLite Database) |
| **Test terkait** | Berkaitan erat dengan rangkaian MASTG-TEST-0200-an (eksternal storage) dan MASTG-TEST-0287 (SharedPreferences) — sama-sama menyasar MASWE-0001 untuk mekanisme penyimpanan berbeda |
| **Demo terkait** | — (tidak ada) |
| **Rule resmi** | — (tidak ada) |
| **CWE terkait** | CWE-312 (Cleartext Storage of Sensitive Information), CWE-311 |

---

## 1. Penjelasan

### 1.1 Status Test Ini dan Klarifikasi Judul vs Mekanisme yang Sesungguhnya Diuji

Test ini berstatus **`placeholder`**, namun ada nuansa penting yang perlu diklarifikasi sejak awal: **judul resmi test menyebut "Android Room Database"**, sementara **catatan resminya** justru menjelaskan mekanisme deteksi lewat API **`SQLiteOpenHelper`** dan **`context.openOrCreateDatabase`** — API SQLite mentah tingkat-rendah, bukan API Room (`@Entity`, `@Dao`, `@Database`, `Room.databaseBuilder()`) secara langsung. Ini **bukan kesalahan atau inkonsistensi metadata** (berbeda dari beberapa kasus lain yang sudah ditemukan dalam seri riset ini) — ini justru mencerminkan **hubungan arsitektural yang benar**: **Room dibangun di atas `SQLiteOpenHelper`**. Pustaka Room adalah **lapisan abstraksi (ORM)** yang pada akhirnya **menghasilkan kode `SQLiteOpenHelper`** di balik layar lewat annotation processing saat kompilasi — ia **tidak** menciptakan format penyimpanan baru yang berbeda. Sebuah database yang dibuat lewat Room, tanpa konfigurasi enkripsi tambahan, pada akhirnya **tetap tersimpan sebagai file `.db` SQLite biasa** yang sepenuhnya identik secara format dengan yang dibuat manual lewat `openOrCreateDatabase()` — keduanya **sama-sama rentan** terhadap masalah yang sama bila tidak dienkripsi.

### 1.2 Implikasi Penting bagi Metodologi Deteksi: Pola Pencarian Berbeda untuk Room vs SQLite Mentah

Ini adalah **nuansa teknis paling penting** dari dokumen ini. Karena Room **menyembunyikan** pemanggilan `SQLiteOpenHelper` di balik lapisan abstraksinya (kode tersebut **dihasilkan otomatis** oleh annotation processor Room saat kompilasi, bukan ditulis langsung oleh developer), **mencari literal teks `SQLiteOpenHelper` di kode aplikasi tidak akan menemukan apa pun** pada aplikasi yang memakai Room — meski database yang dihasilkannya pada akhirnya tetap tidak terenkripsi dengan cara yang persis sama.

Ini menciptakan **dua pola pencarian yang sama sekali berbeda** untuk dua skenario penggunaan database SQLite di Android:

| Skenario | Pola yang Harus Dicari | Lokasi Kemunculan |
|---|---|---|
| **SQLite API mentah** (sesuai yang disebut catatan resmi) | `SQLiteOpenHelper`, `context.openOrCreateDatabase()` | Kode aplikasi yang ditulis developer secara langsung |
| **Room** (sesuai judul resmi test) | `@Database`, `@Entity`, `Room.databaseBuilder(...).build()` **TANPA** parameter `SupportFactory`/`SupportOpenHelperFactory` (SQLCipher) | Kelas abstrak yang di-extend dari `RoomDatabase`, pemanggilan builder Room |

Penguji yang **hanya** mengikuti pola pencarian literal dari catatan resmi (`SQLiteOpenHelper`/`openOrCreateDatabase`) akan **melewatkan seluruh kelas aplikasi berbasis Room** yang sebenarnya menjadi fokus utama sesuai **judul** test ini — inilah mengapa dokumen ini memperluas metodologi pencarian untuk mencakup **kedua** jalur secara eksplisit, bukan hanya mengikuti catatan resmi secara literal.

### 1.3 Mekanisme Enkripsi Room: Pluggable SQLite via SQLCipher

Kabar baiknya, Room dirancang dengan **arsitektur pluggable** yang memudahkan integrasi enkripsi tanpa perlu menulis ulang seluruh lapisan akses data. Riset komunitas menjelaskan:

> *"Room supports a pluggable SQLite implementation, and so developers can plug in a SQLite edition that supports encryption, such as SQLCipher for Android. Integration is accomplished by configuring Room's database builder to use SQLCipher's `SupportOpenHelperFactory` or `SupportFactory`, which requires minimal modifications beyond specifying the factory."*

Contoh perbedaan konfigurasi antara database Room yang **tidak terenkripsi** dan yang **terenkripsi**:

```kotlin
// TIDAK TERENKRIPSI — pola paling umum ditemukan, dan menjadi target FAIL test ini
val db = Room.databaseBuilder(context, AppDatabase::class.java, "app_database")
    .build()
```

```kotlin
// TERENKRIPSI — dengan SQLCipher SupportFactory
val passphrase: ByteArray = SQLiteDatabase.getBytes("passphrase_rahasia".toCharArray())
val factory = SupportFactory(passphrase)
val db = Room.databaseBuilder(context, AppDatabase::class.java, "app_database")
    .openHelperFactory(factory)   // <-- INI yang membedakan aman vs tidak aman
    .build()
```

Perbedaan antara kedua kode di atas **sangat tipis secara tekstual** (satu baris `.openHelperFactory(factory)`) namun **sangat signifikan** secara keamanan — penguji perlu secara spesifik mencari **ketiadaan** baris `openHelperFactory()` pada setiap pemanggilan `Room.databaseBuilder()`, bukan sekadar mencari keberadaan Room itu sendiri (yang hampir pasti **selalu** ditemukan pada aplikasi modern, karena Room adalah pustaka database resmi Android Jetpack yang sangat umum dipakai).

### 1.4 Bukti Konkret Risiko: Lokasi dan Format File yang Dihasilkan

MASTG-KNOW-0037 memberi contoh konkret yang menggambarkan dampak nyata ketiadaan enkripsi, menggunakan API SQLite mentah sebagai ilustrasi (namun konsekuensinya **identik** untuk database Room tanpa SQLCipher):

```kotlin
var notSoSecure = openOrCreateDatabase("privateNotSoSecure", Context.MODE_PRIVATE, null)
notSoSecure.execSQL("CREATE TABLE IF NOT EXISTS Accounts(Username VARCHAR, Password VARCHAR);")
notSoSecure.execSQL("INSERT INTO Accounts VALUES('admin','AdminPass');")
```

Hasilnya: file database tersimpan di `/data/data/<package-name>/databases/privateNotSoSecure` sebagai **file SQLite biasa yang dapat dibuka dan dibaca sepenuhnya** oleh siapa pun yang memiliki akses ke direktori tersebut (root, forensik device, backup ekstraksi — rujuk pembahasan MASTG-TEST-0262 dalam seri riset ini) menggunakan tool SQLite standar apa pun (`sqlite3`, DB Browser for SQLite) tanpa hambatan kriptografi sama sekali. **Tidak ada perbedaan** dalam konsekuensi ini antara database yang dibuat via `openOrCreateDatabase()` langsung atau via `Room.databaseBuilder()` tanpa `SupportFactory` — keduanya menghasilkan file `.db` yang **sama-sama dapat dibuka langsung** dengan tool SQLite generik.

### 1.5 Berkas Pendukung yang Juga Perlu Diperiksa: Journal dan Lock Files

MASTG-KNOW-0037 memberi catatan tambahan yang relevan untuk kelengkapan audit:

> *"The database's directory may contain several files besides the SQLite database: Journal files... Lock files..."*

File jurnal SQLite (`-journal`, `-wal` untuk Write-Ahead Logging) **dapat menyimpan salinan sementara data** yang sedang ditulis/diubah — termasuk data sensitif yang sedang diproses — sebelum transaksi final di-commit ke file database utama. Audit yang lengkap idealnya **turut memeriksa** keberadaan dan isi file-file pendukung ini, bukan hanya file `.db` utama, karena mereka bisa menjadi **jendela kebocoran tambahan** yang jarang diperiksa auditor yang hanya fokus pada file database utama.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **jadx** | Dekompilasi DEX → Java/Kotlin-like untuk pencarian pola Room dan SQLite mentah |
| **grep / ripgrep** | Pencarian pola API — mencakup KEDUA jalur (Room dan SQLite mentah) sesuai §1.2 |
| **sqlite3 (CLI)** / **DB Browser for SQLite** | Membuka langsung file `.db` yang diekstrak dari device untuk memverifikasi apakah isinya benar-benar dapat dibaca tanpa password/kunci |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **CodeQL** | Menelusuri seluruh kelas yang extend `RoomDatabase` dan memverifikasi apakah pemanggilan `Room.databaseBuilder()` terkait menyertakan `.openHelperFactory()` dengan `SupportFactory` SQLCipher |
| **MobSF** | Kadang menandai penggunaan database SQLite/Room di laporan Code Analysis |
| **adb** | Ekstraksi file `.db` langsung dari `/data/data/<package>/databases/` (butuh root/run-as) untuk verifikasi langsung |
| **TruffleHog/gitleaks** | Pemindaian pola secret pada hasil dump isi tabel database, sama seperti dibahas di dokumen MASTG-TEST-0287/0212 dalam seri riset ini |

### 2.3 Prasyarat Lingkungan

- **Tidak butuh device/root** untuk analisis statis inti.
- **Root/`run-as` diperlukan** untuk ekstraksi dan verifikasi langsung file `.db` dari device.
- **Identifikasi data sensitif terlebih dahulu** (prasyarat tersirat, konsisten dengan test-test MASVS-STORAGE lain dalam seri riset ini) untuk menentukan tabel/kolom mana yang relevan diperiksa isinya.

---

## 3. Cara Pengujian

Karena tidak ada langkah resmi rinci (status placeholder), metodologi berikut disusun dari elaborasi catatan resmi plus perluasan untuk mencakup Room sesuai judul test.

### 3.1 Langkah Umum

1. Identifikasi seluruh mekanisme database yang dipakai aplikasi (Room **dan/atau** SQLite mentah).
2. Untuk SQLite mentah: cari `SQLiteOpenHelper`/`openOrCreateDatabase()`.
3. Untuk Room: cari kelas `@Database`/extend `RoomDatabase`, lalu verifikasi keberadaan `SupportFactory`.
4. Ekstrak file `.db` dari device dan verifikasi langsung apakah dapat dibuka tanpa kunci.

### 3.2 Metode A — grep/ripgrep untuk Kedua Jalur

```bash
D=./decompiled/sources

# Jalur 1: SQLite mentah (sesuai catatan resmi)
rg -n 'extends SQLiteOpenHelper|openOrCreateDatabase\(' $D

# Jalur 2: Room — temukan definisi database
rg -n '@Database\(|extends RoomDatabase' $D

# Jalur 2: Room — periksa SETIAP pemanggilan databaseBuilder dan verifikasi SupportFactory
rg -n -A10 'Room\.databaseBuilder\(' $D | grep -B10 '\.build()' | grep -c "SupportFactory\|openHelperFactory"
```

Bila hasil terakhir menunjukkan **0** untuk suatu blok `databaseBuilder()`, ini kandidat FAIL — database Room tersebut dibangun tanpa enkripsi.

### 3.3 Metode B — CodeQL untuk Verifikasi Sistematis Seluruh Instance Room

```ql
import java

class RoomDatabaseBuilderCall extends MethodAccess {
  RoomDatabaseBuilderCall() {
    this.getMethod().hasName("databaseBuilder") and
    this.getMethod().getDeclaringType().hasQualifiedName("androidx.room", "Room")
  }
}

class OpenHelperFactoryCall extends MethodAccess {
  OpenHelperFactoryCall() {
    this.getMethod().hasName("openHelperFactory")
  }
}

from RoomDatabaseBuilderCall builder
where not exists(OpenHelperFactoryCall factory |
  factory.getQualifier().toString() = builder.toString() or
  factory.getEnclosingCallable() = builder.getEnclosingCallable())
select builder, "Room.databaseBuilder() ditemukan TANPA openHelperFactory (SQLCipher) — database kemungkinan tidak terenkripsi"
```

### 3.4 Metode C — Verifikasi Langsung File `.db` (Bukti Definitif)

```bash
adb shell run-as com.target.app ls /data/data/com.target.app/databases/
adb shell run-as com.target.app cat /data/data/com.target.app/databases/app_database > ./app_database_dump.db

# Coba buka LANGSUNG tanpa password apa pun
sqlite3 ./app_database_dump.db ".tables"
sqlite3 ./app_database_dump.db "SELECT * FROM users LIMIT 5;"
```

Bila perintah ini **berhasil** menampilkan struktur tabel dan isi data tanpa error/password, ini bukti definitif bahwa database **tidak terenkripsi** — terlepas dari apakah dibuat via Room atau SQLite mentah. Bila database terenkripsi SQLCipher dengan benar, `sqlite3` standar akan menampilkan error (`file is not a database`) karena formatnya tidak lagi sesuai spesifikasi SQLite polos.

### 3.5 Metode D — Periksa File Jurnal/Lock Pendukung (§1.5)

```bash
adb shell run-as com.target.app ls -la /data/data/com.target.app/databases/
# Perhatikan file dengan suffix -journal, -wal, -shm
adb shell run-as com.target.app cat /data/data/com.target.app/databases/app_database-wal > ./wal_dump.bin
strings ./wal_dump.bin | grep -iE "password|token|email"
```

### 3.6 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Mencakup Room? | Mencakup SQLite mentah? | Bukti definitif? | Kapan dipakai |
|---|---|---|---|---|---|
| **A** | grep | ✅ | ✅ | ❌ | Baseline, **wajib mencakup kedua jalur** |
| **B** | CodeQL | ✅ (presisi) | Sebagian | ❌ | Codebase besar dengan banyak definisi Room |
| **C** | Verifikasi file `.db` | N/A | N/A | ✅ | **Wajib** sebagai pembuktian akhir |
| **D** | File jurnal/lock | N/A | N/A | ✅ (tambahan) | Kelengkapan audit (§1.5) |

**Kombinasi minimum yang aku rekomendasikan:** **A (mencakup kedua jalur Room DAN SQLite mentah) → C (verifikasi langsung file .db sebagai bukti tak terbantahkan)**, dilengkapi **D** untuk audit yang lebih menyeluruh.

---

### 3.7 Kriteria Evaluasi: Positive Case & Negative Case

Karena tidak ada klausul Evaluation resmi (status placeholder), kriteria berikut disusun berdasarkan catatan resmi dan prinsip dasar MASWE-0001.

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Aplikasi memakai `SQLiteOpenHelper`/`openOrCreateDatabase()` untuk menyimpan data sensitif tanpa enkripsi tambahan |
| F2 | Aplikasi memakai Room (`Room.databaseBuilder()`) **tanpa** `.openHelperFactory()` SQLCipher untuk tabel yang menyimpan data sensitif |
| F3 | Verifikasi langsung (Metode C) mengonfirmasi file `.db` dapat dibuka dan dibaca sepenuhnya oleh `sqlite3` standar tanpa password |
| F4 | File jurnal/WAL pendukung (Metode D) ditemukan mengandung data sensitif dalam bentuk plaintext yang dapat dibaca |

**Contoh bukti (ilustratif — MASTG belum menyediakan demo resmi untuk test ini):**

```kotlin
// AppDatabase.kt
@Database(entities = [User::class], version = 1)
abstract class AppDatabase : RoomDatabase() {
    abstract fun userDao(): UserDao
}

// DatabaseModule.kt
val db = Room.databaseBuilder(context, AppDatabase::class.java, "user_database")
    .build()  // TIDAK ADA openHelperFactory
```

```bash
$ adb shell run-as com.example.target cat /data/data/com.example.target/databases/user_database > dump.db
$ sqlite3 dump.db "SELECT * FROM User;"
1|admin@example.com|5f4dcc3b5aa765d61d8327deb882cf99
```

Interpretasi: database Room dibangun tanpa `SupportFactory`, dan verifikasi langsung mengonfirmasi tabel `User` (termasuk email dan hash password) dapat dibaca sepenuhnya tanpa hambatan apa pun. **FAIL**.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Seluruh database (Room/SQLite mentah) yang menyimpan data sensitif memakai SQLCipher (`SupportFactory`) atau mekanisme enkripsi setara |
| P2 | Verifikasi langsung (Metode C) mengonfirmasi `sqlite3` standar **gagal** membuka file (`file is not a database`) |
| P3 | File jurnal/WAL pendukung tidak mengandung data sensitif plaintext yang dapat dibaca |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Jangan hanya mengikuti catatan resmi secara literal** — sesuai §1.2, pencarian murni untuk `SQLiteOpenHelper` akan melewatkan seluruh database berbasis Room yang menjadi fokus utama sesuai judul test ini. Selalu cakup kedua jalur.

2. **Perbedaan kode antara aman dan tidak aman sangat tipis secara tekstual** (§1.3) — satu baris `.openHelperFactory()` yang hilang adalah satu-satunya pembeda. Jangan menyimpulkan FAIL/PASS hanya dari keberadaan Room secara umum (yang hampir selalu ada di aplikasi modern); periksa spesifik setiap pemanggilan `databaseBuilder()`.

3. **Verifikasi langsung file `.db` adalah bukti paling definitif dan paling mudah diinterpretasikan** — bila `sqlite3` berhasil membuka dan menampilkan data, tidak ada ambiguitas sama sekali tentang status enkripsi.

4. **Jangan lupakan file jurnal/WAL** — audit yang hanya memeriksa file `.db` utama bisa melewatkan data sensitif yang masih tersisa di file pendukung sementara.

5. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | Tabel berisi kredensial/token/PII tanpa enkripsi, terverifikasi dapat dibaca langsung | **Kritis** |
   | Tabel berisi data non-sensitif tanpa enkripsi | **Bukan temuan** |
   | Enkripsi SQLCipher diterapkan tapi passphrase di-hardcode (rujuk MASTG-TEST-0212) | **Tinggi** — enkripsi ada tapi kuncinya sendiri bocor |

6. **Dokumentasikan:** mekanisme database yang dipakai (Room/SQLite mentah), status `SupportFactory`/enkripsi per instance database, hasil verifikasi langsung file `.db`, dan hasil pemeriksaan file jurnal/WAL.

---

## 4. Rekomendasi Perbaikan

### 4.1 Integrasikan SQLCipher ke Room

```kotlin
dependencies {
    implementation "net.zetetic:android-database-sqlcipher:4.5.4"
}
```

```kotlin
val passphrase = SQLiteDatabase.getBytes(getSecurePassphraseFromKeystore())  // JANGAN hardcode
val factory = SupportFactory(passphrase)
val db = Room.databaseBuilder(context, AppDatabase::class.java, "user_database")
    .openHelperFactory(factory)
    .build()
```

**Penting**: simpan passphrase lewat **Android Keystore** (rujuk pola di dokumen MASTG-TEST-0212), jangan hardcode di kode — enkripsi database tidak bernilai bila kuncinya sendiri bocor.

### 4.2 Untuk Migrasi Database Lama yang Belum Terenkripsi

```kotlin
// Cek apakah database sudah terenkripsi, bila belum, enkripsi secara in-place
if (!isDatabaseEncrypted(oldDbPath)) {
    SQLiteDatabase.loadLibs(context)
    val db = SQLiteDatabase.openDatabase(oldDbPath, "", null, SQLiteDatabase.OPEN_READWRITE)
    db.rawExecSQL("ATTACH DATABASE '$newEncryptedDbPath' AS encrypted KEY '$passphrase'")
    db.rawExecSQL("SELECT sqlcipher_export('encrypted')")
    db.rawExecSQL("DETACH DATABASE encrypted")
}
```

### 4.3 Checklist Remediasi

- [ ] Seluruh instance Room/SQLite mentah yang menyimpan data sensitif diinventarisasi
- [ ] SQLCipher (`SupportFactory`) diterapkan pada seluruh database yang relevan
- [ ] Passphrase disimpan lewat Android Keystore, bukan hardcoded
- [ ] Verifikasi langsung file `.db` mengonfirmasi tidak dapat dibuka tanpa kunci
- [ ] File jurnal/WAL diperiksa tidak mengandung data sensitif plaintext
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0304 setiap penambahan tabel/entity baru

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0304: References to Sensitive Data Unencrypted via Android Room Database](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0304/)
- [MASTG-TEST-0287: Runtime Storage of Unencrypted Data via the SharedPreferences API](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0287/)
- [MASTG-TEST-0212: Use of Hardcoded Cryptographic Keys in Code](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0212/)
- [MASWE-0001: Sensitive Data Stored Unencrypted in Private Storage](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0001/)
- [MASTG-KNOW-0037: SQLite Database](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0037/)

### 5.2 Dokumentasi Resmi Android

- [Android Developers — Save data in a local database using Room](https://developer.android.com/training/data-storage/room)
- [Android Developers — SQLite Documentation](https://developer.android.com/training/data-storage/sqlite)
- [SQLite — Temporary Files (Journal)](https://www.sqlite.org/tempfiles.html)
- [SQLite — Lock Files](https://www.sqlite.org/lockingv3.html)

### 5.3 Riset dan Artikel Komunitas

- [CommonsWare — Introducing SQLCipher for Android](https://commonsware.com/Room/pages/chap-sqlcipher-001.html)
- [sonique6784 — Protect your Room database with SQLCipher on Android](https://sonique6784.medium.com/protect-your-room-database-with-sqlcipher-on-android-78e0681be687)
- [Medium — Encrypting an Existing Room Database with SQLCipher](https://medium.com/@khambhaytajaydip/encrypting-an-existing-room-database-with-sqlcipher-in-android-50cdc98fe6c)
- [GitHub — android-database-sqlcipher](https://github.com/OutSystems/android-database-sqlcipher)
- [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)

### 5.4 Dokumentasi Tools

- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [DB Browser for SQLite](https://sqlitebrowser.org/)
- [TruffleHog](https://docs.trufflesecurity.com/)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026), dokumentasi resmi Android Developers, dan riset komunitas tentang integrasi SQLCipher dengan Room. Nuansa terpenting: judul test menyebut "Room Database", namun catatan resmi menjelaskan deteksi lewat API SQLite mentah (`SQLiteOpenHelper`) — ini bukan inkonsistensi, melainkan mencerminkan fakta arsitektural bahwa Room dibangun di atas SQLiteOpenHelper dan menghasilkan format penyimpanan yang identik tanpa konfigurasi enkripsi tambahan. Evaluasi yang lengkap menuntut pencarian pola untuk **kedua** jalur (Room dan SQLite mentah) secara eksplisit, karena mencari literal `SQLiteOpenHelper` saja akan melewatkan seluruh database berbasis Room yang justru menjadi fokus utama test ini.*
