# MASTG-TEST-0306 References to Sensitive Data Stored Unencrypted via Android Room DB

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0306 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-STORAGE (MASVS-STORAGE-1) |
| **Weakness** | MASWE-0001 — *Sensitive Data Stored Unencrypted in Private Storage* |
| **Tipe Pengujian** | Static, Code |
| **Status resmi MASTG** | **`placeholder`** — belum ada Overview/Steps/Evaluation lengkap |
| **Catatan resmi (satu-satunya konten yang tersedia)** | *"This test checks if the app uses the Android Room Persistence Library to store sensitive data (e.g., tokens, PII) without integrating an encryption layer (e.g., SQLCipher). It confirms the database file is stored in plaintext within the app's private sandbox."* |
| **Test terkait** | **MASTG-TEST-0304** (References to Sensitive Data Unencrypted via Android Room Database) — **lihat §1.1 untuk klarifikasi penting tentang hubungan dan kemungkinan tumpang tindih antara kedua test ini** |
| **Demo terkait** | — (tidak ada) |
| **Rule resmi** | — (tidak ada) |
| **CWE terkait** | CWE-312, CWE-311 |

---

## 1. Penjelasan

### 1.1 Klarifikasi Penting: Hubungan dan Tumpang Tindih dengan MASTG-TEST-0304

Ini adalah catatan metodologis yang **wajib** disampaikan sejak awal dokumen ini, karena riset menemukan bahwa **MASTG-TEST-0306 dan MASTG-TEST-0304** — keduanya berstatus `placeholder`, keduanya menyasar MASWE-0001 yang identik, keduanya bertipe `static, code` — memiliki **judul dan cakupan yang sangat tumpang tindih**:

| | MASTG-TEST-0304 | MASTG-TEST-0306 *(dokumen ini)* |
|---|---|---|
| **Judul** | *"...via Android Room **Database**"* | *"...via Android Room **DB**"* |
| **Fokus catatan resmi** | API **SQLite mentah** (`SQLiteOpenHelper`, `openOrCreateDatabase`) — meski judul menyebut "Room" | **Android Room Persistence Library** secara eksplisit dan spesifik |
| **Kriteria konfirmasi** | "Absence of secure alternatives like SQLCipher or encrypted databases" | "Without integrating an encryption layer (e.g., SQLCipher)... database file is stored in plaintext" |

Perbedaan substansial yang bisa diidentifikasi: **MASTG-TEST-0304** (sesuai analisis mendalam di dokumen tersebut) sebenarnya berfokus pada **deteksi API SQLite mentah** (`SQLiteOpenHelper`/`openOrCreateDatabase`) meski judulnya menyebut "Room" — sedangkan **MASTG-TEST-0306** secara **jauh lebih eksplisit dan konsisten** menyasar **Room Persistence Library** itu sendiri (`@Database`, `Room.databaseBuilder()`) sebagai objek pengujian utamanya, tanpa ambiguitas rujukan ke API SQLite mentah.

**Kemungkinan penjelasan**: ini berpotensi mencerminkan **tahap restrukturisasi konten** yang sedang berlangsung dalam katalog test-beta MASTG — di mana MASTG-TEST-0304 mungkin awalnya dimaksudkan mencakup seluruh spektrum (SQLite mentah **dan** Room), sementara MASTG-TEST-0306 kemudian ditambahkan sebagai **versi yang lebih presisi dan terfokus khusus pada Room**, menyisakan tumpang tindih sementara sebelum kedua test ini kemungkinan diselaraskan/digabungkan pada rilis final MASTG mendatang. Terlepas dari penjelasan pastinya, **bagi penguji saat ini**, implikasi praktisnya adalah: **kedua test ini pada dasarnya menuntut metodologi pengujian yang sama** untuk komponen Room — sehingga dokumen ini akan **merujuk secara ekstensif** ke metodologi yang sudah dibangun mendalam di dokumen MASTG-TEST-0304, sambil menegaskan ulang fokus spesifik pada Room Persistence Library sesuai catatan resmi test ini.

### 1.2 Inti Permasalahan: Room Tidak Mengenkripsi Apa pun Secara Default

Rujuk **dokumen MASTG-TEST-0304 §1.1** untuk penjelasan arsitektural lengkap tentang mengapa Room — sebagai lapisan ORM yang dibangun di atas `SQLiteOpenHelper` — **mewarisi karakteristik penyimpanan tidak terenkripsi** dari SQLite yang mendasarinya, kecuali developer secara eksplisit mengintegrasikan lapisan enkripsi tambahan. Catatan resmi test ini menegaskan ulang poin yang sama secara lebih eksplisit:

> *"It confirms the database file is stored in plaintext within the app's private sandbox."*

Tanpa integrasi SQLCipher (atau mekanisme enkripsi setara), setiap `@Entity` yang didefinisikan dalam skema Room — termasuk kolom yang menyimpan token, kata sandi, atau PII — pada akhirnya tersimpan sebagai baris data **plaintext murni** dalam file `.db` SQLite standar di `/data/data/<package>/databases/`, dapat dibuka langsung dengan tool SQLite generik apa pun oleh siapa pun yang memperoleh akses ke sandbox aplikasi tersebut (root, forensik device, ekstraksi backup).

### 1.3 Perbedaan Penekanan: "Integrasi Lapisan Enkripsi" sebagai Kriteria Eksplisit

Meski secara substansi serupa dengan MASTG-TEST-0304, catatan resmi test ini merumuskan kriteria dengan kata yang sedikit berbeda dan **layak disoroti**: *"without integrating an **encryption layer**"*. Frasa ini menekankan bahwa yang dicari bukan sekadar "apakah ada kata SQLCipher di dependency", melainkan **apakah lapisan enkripsi tersebut benar-benar terintegrasi secara fungsional** ke dalam konfigurasi Room yang dipakai — persis sesuai pembeda teknis yang sudah dibahas mendalam di dokumen MASTG-TEST-0304 §1.3 soal perbedaan tipis namun krusial antara `Room.databaseBuilder().build()` (tanpa enkripsi) versus `.openHelperFactory(SupportFactory(passphrase)).build()` (dengan enkripsi).

---

## 2. Tools yang Dipakai untuk Pengujian

Metodologi tools untuk test ini **identik** dengan yang sudah dibangun di **dokumen MASTG-TEST-0304 §2**, khusus bagian yang menyasar Room (bukan bagian SQLite mentah, yang di luar cakupan spesifik test ini). Ringkasan:

| Tool | Fungsi |
|---|---|
| **jadx** | Dekompilasi untuk pencarian kelas `@Database`/`RoomDatabase` |
| **grep / ripgrep** | Pencarian `Room.databaseBuilder()` dan verifikasi `.openHelperFactory()` |
| **CodeQL** | Verifikasi sistematis seluruh instance `Room.databaseBuilder()` terhadap keberadaan `SupportFactory` |
| **adb + sqlite3** | Ekstraksi dan verifikasi langsung file `.db` dari device — bukti definitif |
| **DB Browser for SQLite** | Alternatif GUI untuk membuka file `.db` yang diekstrak |

Rujuk dokumen MASTG-TEST-0304 §2 untuk detail prasyarat lingkungan yang berlaku sama.

---

## 3. Cara Pengujian

Karena tidak ada langkah resmi rinci (status placeholder) dan metodologinya identik dengan MASTG-TEST-0304, bagian ini merujuk metode yang sama dengan penyesuaian fokus murni pada Room.

### 3.1 Langkah Umum

1. Identifikasi seluruh kelas yang extend `RoomDatabase` dan diberi anotasi `@Database`.
2. Untuk setiap kelas database Room yang ditemukan, telusuri **lokasi pemanggilan** `Room.databaseBuilder(...).build()` yang menginstansiasinya.
3. Verifikasi apakah pemanggilan tersebut menyertakan `.openHelperFactory()` dengan `SupportFactory` (SQLCipher) sebelum `.build()`.
4. Konfirmasi langsung dengan ekstraksi file `.db` dari device.

### 3.2 Metode A — grep/ripgrep (Rujuk MASTG-TEST-0304 §3.2, Metode A Bagian Room)

```bash
D=./decompiled/sources

# Temukan definisi database Room
rg -n '@Database\(' $D

# Temukan instansiasi dan verifikasi keberadaan SupportFactory
rg -n -A10 'Room\.databaseBuilder\(' $D | grep -B10 '\.build()' | grep -c "SupportFactory\|openHelperFactory"
```

### 3.3 Metode B — CodeQL (Identik dengan MASTG-TEST-0304 §3.3)

Rujuk query CodeQL lengkap di dokumen MASTG-TEST-0304 — query tersebut secara spesifik sudah menyasar `Room.databaseBuilder()` dan `openHelperFactory()`, sehingga berlaku sama persis untuk test ini.

### 3.4 Metode C — Verifikasi Langsung File `.db` (Identik dengan MASTG-TEST-0304 §3.4)

```bash
adb shell run-as com.target.app ls /data/data/com.target.app/databases/
adb shell run-as com.target.app cat /data/data/com.target.app/databases/app_database > ./app_database_dump.db
sqlite3 ./app_database_dump.db ".tables"
sqlite3 ./app_database_dump.db "SELECT * FROM users LIMIT 5;"
```

Rujuk dokumen MASTG-TEST-0304 §3.4 untuk interpretasi hasil secara lengkap.

### 3.5 Perbandingan Metode

Rujuk tabel perbandingan lengkap di dokumen MASTG-TEST-0304 §3.6 — sepenuhnya berlaku untuk test ini tanpa modifikasi, karena cakupan Room di kedua dokumen identik.

**Kombinasi minimum yang aku rekomendasikan:** **grep/CodeQL untuk identifikasi seluruh instance Room tanpa SupportFactory → verifikasi langsung file `.db` sebagai bukti tak terbantahkan.**

---

### 3.6 Kriteria Evaluasi: Positive Case & Negative Case

Karena tidak ada klausul Evaluation resmi (status placeholder) dan kriterianya identik secara substansi dengan bagian Room pada MASTG-TEST-0304, kriteria berikut adalah versi yang difokuskan murni pada Room Persistence Library.

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Kelas `@Database`/`RoomDatabase` yang menyimpan entity dengan kolom sensitif (token, PII, kredensial) diinstansiasi via `Room.databaseBuilder()` **tanpa** `.openHelperFactory()` SQLCipher |
| F2 | Verifikasi langsung file `.db` (Metode C) mengonfirmasi `sqlite3` standar **berhasil** membuka dan menampilkan isi tabel tanpa password |

**Contoh bukti (ilustratif — MASTG belum menyediakan demo resmi untuk test ini; rujuk juga contoh identik di dokumen MASTG-TEST-0304 §3.7):**

```kotlin
@Database(entities = [AuthToken::class], version = 1)
abstract class AppDatabase : RoomDatabase() {
    abstract fun authTokenDao(): AuthTokenDao
}

val db = Room.databaseBuilder(context, AppDatabase::class.java, "secure_session_db")
    .build()  // TIDAK ADA openHelperFactory — database Room ini TIDAK terenkripsi
```

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Seluruh database Room yang menyimpan entity sensitif memakai `.openHelperFactory()` dengan `SupportFactory` SQLCipher yang terkonfigurasi benar |
| P2 | Verifikasi langsung file `.db` mengonfirmasi `sqlite3` standar **gagal** membuka file (`file is not a database`) |
| P3 | Aplikasi tidak memakai Room Persistence Library untuk menyimpan data sensitif sama sekali |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Bila sudah menjalankan MASTG-TEST-0304 secara lengkap (mencakup bagian Room-nya), hasil pengujian untuk test ini kemungkinan besar sudah terjawab** — mengingat tumpang tindih cakupan yang dijelaskan di §1.1. Dokumentasikan secara eksplisit di laporan audit bahwa kedua ID test ini dievaluasi bersamaan dengan metodologi yang sama, untuk transparansi kepada pembaca laporan.

2. **Jangan duplikasi usaha pengujian tanpa perlu** — bila organisasi/tim audit menjalankan kedua test ini secara terpisah tanpa menyadari tumpang tindihnya, ini berisiko membuang waktu dan menghasilkan laporan yang membingungkan (dua temuan "berbeda" untuk akar masalah yang identik). Rekomendasikan mengevaluasi keduanya dalam satu sesi analisis Room yang sama.

3. **Severity dan rekomendasi perbaikan identik dengan MASTG-TEST-0304** — rujuk dokumen tersebut §3.7 (catatan evaluasi) dan §4 (rekomendasi) secara lengkap, karena tidak ada perbedaan substansial dalam penanganan kedua test ini.

4. **Dokumentasikan:** status integrasi SQLCipher pada setiap instance Room, hasil verifikasi file `.db`, dan catatan eksplisit bahwa temuan ini dievaluasi bersamaan dengan MASTG-TEST-0304.

---

## 4. Rekomendasi Perbaikan

Rujuk **dokumen MASTG-TEST-0304 §4** untuk rekomendasi lengkap — integrasi SQLCipher via `SupportFactory`, penyimpanan passphrase lewat Android Keystore (bukan hardcoded), dan strategi migrasi database Room lama yang belum terenkripsi. Seluruh rekomendasi tersebut berlaku identik untuk test ini tanpa modifikasi, karena akar masalah dan solusi teknisnya sepenuhnya sama.

### 4.1 Checklist Remediasi

- [ ] Seluruh kelas `@Database`/`RoomDatabase` yang menyimpan entity sensitif diinventarisasi
- [ ] `SupportFactory` (SQLCipher) diterapkan pada seluruh instance yang relevan
- [ ] Passphrase disimpan lewat Android Keystore
- [ ] Verifikasi langsung file `.db` mengonfirmasi tidak dapat dibuka tanpa kunci
- [ ] Hasil pengujian dikorelasikan secara eksplisit dengan MASTG-TEST-0304 untuk menghindari duplikasi laporan
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0306 setiap penambahan entity/tabel Room baru

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0306: References to Sensitive Data Stored Unencrypted via Android Room DB](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0306/)
- [MASTG-TEST-0304: References to Sensitive Data Unencrypted via Android Room Database](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0304/) — **rujukan utama metodologi lengkap**
- [MASTG-TEST-0305: Sensitive Data Stored Unencrypted via DataStore](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0305/)
- [MASWE-0001: Sensitive Data Stored Unencrypted in Private Storage](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0001/)

### 5.2 Dokumentasi Resmi Android

- [Android Developers — Save data in a local database using Room](https://developer.android.com/training/data-storage/room)

### 5.3 Riset dan Artikel Komunitas

Rujuk daftar lengkap riset SQLCipher/Room di dokumen MASTG-TEST-0304 §5.3 — seluruh sumber tersebut relevan identik untuk test ini.

### 5.4 Dokumentasi Tools

Rujuk daftar lengkap di dokumen MASTG-TEST-0304 §5.4.

---

*Dokumen ini disusun sepenuhnya dari riset independen karena MASTG-TEST-0306 berstatus **placeholder**. Temuan metodologis terpenting: test ini memiliki **tumpang tindih substansial** dengan MASTG-TEST-0304 yang sudah dibahas sebelumnya dalam seri riset ini — keduanya menyasar MASWE-0001 untuk konteks Room Persistence Library, dengan MASTG-TEST-0304 historisnya lebih condong ke deteksi API SQLite mentah (meski judulnya menyebut Room) sementara MASTG-TEST-0306 secara eksplisit dan konsisten berfokus pada Room Persistence Library itu sendiri. Penguji disarankan mengevaluasi kedua ID test ini dalam satu sesi analisis yang sama untuk efisiensi, dan mendokumentasikan secara transparan bahwa keduanya merujuk pada metodologi serta temuan yang identik hingga MASTG merilis klarifikasi/konsolidasi resmi atas kedua test beta ini.*
