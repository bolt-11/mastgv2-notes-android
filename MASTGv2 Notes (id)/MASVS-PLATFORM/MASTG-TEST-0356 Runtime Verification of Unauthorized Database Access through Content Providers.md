# MASTG-TEST-0356 Runtime Verification of Unauthorized Database Access through Content Providers

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0356 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-PLATFORM |
| **Weakness** | MASWE-0018 |
| **Tipe Pengujian** | Dynamic, Filesystem, **Manual** |
| **Teknik terkait** | MASTG-TECH-0005 (Installing Apps), MASTG-TECH-0148 (Interacting with Android ContentProviders) |
| **Knowledge terkait** | MASTG-KNOW-0020, MASTG-KNOW-0117 |
| **Best Practice terkait** | MASTG-BEST-0049 |
| **Test terkait** | **MASTG-TEST-0355** — counterpart statis yang memeriksa konfigurasi manifest; test ini adalah **konfirmasi runtime langsung** (lihat §1.2 untuk nilai tambah spesifiknya) |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Kutipan overview resmi MASTG:

> *"If an app exports a content provider without requiring permissions, any app on the device can directly query its underlying database using ContentResolver or using the adb shell content command. Even when a permission is declared, a misconfigured protection level (for example, android:protectionLevel="normal") allows any requesting app to obtain it automatically, effectively bypassing the restriction. This test verifies at runtime whether the app's exported content providers are accessible without the required permissions."*

### 1.2 Nilai Tambah Dibanding Analisis Statis: Bukti Langsung, Tanpa Ambiguitas Interpretasi Manifest

Ini adalah pasangan dinamis dari **MASTG-TEST-0355** yang sudah dibahas sebelumnya dalam seri riset ini. Perbedaan nilai tambahnya sangat jelas dan praktis: analisis statis (TEST-0355) menuntut penguji **menginterpretasikan** kombinasi atribut manifest yang kompleks (`exported`, `readPermission`, `writePermission`, `permission`, `protectionLevel` dari permission yang dirujuk) — proses yang, seperti sudah dibahas di dokumen TEST-0355 §1.4, rawan kesalahan interpretasi (mis. rule resmi yang tidak bisa membedakan kasus read-protected-tapi-write-terbuka).

Test dinamis ini **menghilangkan seluruh ambiguitas tersebut** — alih-alih menduga dari konfigurasi manifest apakah provider dapat diakses, penguji **langsung mencoba mengaksesnya** dari luar konteks aplikasi (lewat `adb shell content`, yang berjalan sebagai shell user, bukan sebagai aplikasi target) dan mengamati **hasil sesungguhnya**. Bila query berhasil mengembalikan data, itu adalah **bukti definitif** bahwa provider benar-benar dapat diakses tanpa izin yang memadai — tidak peduli seberapa rumit kombinasi atribut manifestnya.

### 1.3 Cakupan Empat Operasi: Query, Insert, Update, Delete

MASTG-TECH-0148 menyediakan command `adb shell content` untuk keempat operasi CRUD, bukan hanya baca:

```bash
adb shell content query --uri content://org.owasp.mastestapp.provider/students
adb shell content insert --uri content://org.owasp.mastestapp.provider/students --bind name:s:Eve
adb shell content update --uri content://org.owasp.mastestapp.provider/students --where "id=1" --bind name:s:"Alice Jr"
adb shell content delete --uri content://org.owasp.mastestapp.provider/students --where "id=3"
```

Ini secara langsung menjembatani celah metodologis yang sudah diidentifikasi di dokumen TEST-0355 §1.4 — di sana saya merekomendasikan verifikasi dinamis terpisah untuk read dan write karena rule statis tidak dapat membedakan keduanya. Test ini **secara resmi menyediakan jalan untuk itu**: coba `query` untuk menguji perlindungan baca, lalu coba `insert`/`update`/`delete` secara terpisah untuk menguji perlindungan tulis — dua hasil yang bisa sangat berbeda pada provider yang sama (persis skenario kesalahan OEM nyata yang sudah dibahas di TEST-0355 §1.4: `readPermission` ada, `writePermission` tidak).

### 1.4 Catatan Teknis Penting dari MASTG-TECH-0148: Konteks Eksekusi sebagai Shell User

> *"The command executes in the context of the shell user, so access depends on whether the provider is exported and what permissions are enforced."*

Ini relevan untuk interpretasi hasil — `adb shell content` **bukan** aplikasi pihak ketiga biasa, melainkan berjalan dengan UID shell (`com.android.shell` pada beberapa versi Android memiliki privilese tertentu). Meski demikian, prinsip pengujiannya tetap valid: bila shell (yang tidak memiliki permission custom aplikasi target) berhasil mengakses provider, ini adalah indikasi kuat bahwa **aplikasi pihak ketiga mana pun** juga akan berhasil melakukan hal yang sama, karena keduanya sama-sama tidak memiliki permission khusus yang didefinisikan aplikasi target (kecuali permission tersebut adalah permission sistem bawaan yang secara khusus diberikan ke shell).

### 1.5 Validasi Lanjutan: Isi Data, Bukan Sekadar Keberhasilan Query

> **Further Validation Required:** *"Inspect the content of each row returned by the query to determine whether the data is sensitive: Determine whether the records contain sensitive information (e.g., personal data, credentials, tokens, or health data). Determine whether the accessible data represents a security risk given the app's data classification."*

Ini konsisten dengan prinsip evaluasi kontekstual yang berulang di seri riset ini — keberhasilan teknis mengakses provider (query berhasil, mengembalikan baris data) **belum tentu** berarti temuan keamanan serius bila data yang terekspos memang tidak sensitif (misalnya tabel konfigurasi UI publik). Nilai akhir temuan selalu bergantung pada **isi data sesungguhnya**, bukan sekadar status keberhasilan akses.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **ADB** | Instalasi app (MASTG-TECH-0005), eksekusi `content query/insert/update/delete` (MASTG-TECH-0148) |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **Drozer** | Alternatif dengan modul siap pakai (`app.provider.query`, `scanner.provider.injection`), berguna untuk otomasi triase terhadap banyak provider sekaligus |
| **Aplikasi exploit sederhana (custom)** | Untuk mensimulasikan skenario paling realistis — aplikasi pihak ketiga benar-benar terinstal yang memanggil `ContentResolver.query()` tanpa permission apa pun, melengkapi hasil dari `adb shell content` yang berjalan sebagai shell user (§1.4) |

### 2.3 Prasyarat Lingkungan

- Device/emulator dengan `adb` terhubung dan aplikasi target terinstal.
- Tidak perlu root untuk pengujian dasar — `adb shell content` cukup untuk menguji sebagian besar skenario.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0005** untuk instalasi aplikasi.
2. Exercise aplikasi secara ekstensif untuk memicu sebanyak mungkin alur dan mengisi data sensitif.
3. Gunakan **MASTG-TECH-0148** untuk query provider exported aplikasi.

### 3.2 Metode A — Query Langsung via ADB Shell Content

```bash
# Identifikasi authority provider dari manifest (hasil TEST-0355)
adb shell content query --uri content://com.example.app.provider/users
```

### 3.3 Metode B — Uji Operasi Write Secara Terpisah (Menutup Celah TEST-0355 §1.4)

```bash
adb shell content insert --uri content://com.example.app.provider/users --bind name:s:"attacker_test"
adb shell content update --uri content://com.example.app.provider/users --where "id=1" --bind is_premium:i:1
adb shell content delete --uri content://com.example.app.provider/users --where "id=99"
```

Jalankan **keempat** operasi secara terpisah dan catat hasil masing-masing — provider yang menolak `query` namun menerima `insert` (atau sebaliknya) adalah temuan penting yang menegaskan perlunya pengujian granular per operasi.

### 3.4 Metode C — Drozer untuk Triase Otomatis Banyak Provider

```bash
dz> run app.provider.finduri -a com.example.app
dz> run app.provider.query content://com.example.app.provider/users --vertical
dz> run app.provider.insert content://com.example.app.provider/users --string name "test"
```

### 3.5 Metode D — Verifikasi dari Aplikasi Pihak Ketiga Sungguhan

```java
// Dalam aplikasi uji terpisah (bukan shell), tanpa permission apa pun
Cursor cursor = getContentResolver().query(
    Uri.parse("content://com.example.app.provider/users"),
    null, null, null, null
);
```

Menguatkan hasil Metode A dengan mensimulasikan skenario yang lebih realistis daripada `adb shell` (§1.4).

### 3.6 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Kapan dipakai |
|---|---|---|
| **A** | adb shell content query | Baseline wajib — uji baca |
| **B** | adb shell content insert/update/delete | **Wajib** — uji tulis secara terpisah, menutup celah TEST-0355 §1.4 |
| **C** | Drozer | Triase otomatis banyak provider sekaligus |
| **D** | Aplikasi pihak ketiga sungguhan | Verifikasi paling realistis, menghindari ambiguitas konteks shell user |

**Kombinasi minimum yang aku rekomendasikan:** **A + B (wajib, keempat operasi)**, dengan **D** sebagai penguat bukti untuk laporan final bila diperlukan tingkat keyakinan maksimal.

---

### 3.7 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Evaluation:** *"The test case fails if sensitive data can be accessed through content providers."*

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Query/insert/update/delete berhasil dieksekusi tanpa permission apa pun **dan** data/operasi yang terlibat bersifat sensitif |

**Contoh bukti:**

```
$ adb shell content query --uri content://com.example.app.provider/users
Row: 0 _id=1, username=budi_santoso, email=budi@example.com, auth_token=eyJhbGciOiJIUzI1NiJ9...
```

Interpretasi: token autentikasi dan email pengguna berhasil diekstrak tanpa permission apa pun dari shell. **FAIL**.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Seluruh keempat operasi (query/insert/update/delete) ditolak dengan `SecurityException`/permission error, **atau** |
| P2 | Operasi berhasil namun data yang terekspos terverifikasi tidak sensitif |

**Contoh bukti:**

```
$ adb shell content query --uri content://com.example.app.provider/users
java.lang.SecurityException: Permission Denial: opening provider ... requires com.example.app.permission.READ_USER_DATA
```

**PASS** (untuk operasi read; ulangi verifikasi yang sama untuk insert/update/delete).

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Uji keempat operasi secara terpisah, jangan berhenti di query saja** — sesuai §1.3, PASS pada `query` tidak menjamin PASS pada `insert`/`update`/`delete`; pola kesalahan OEM nyata yang dibahas di TEST-0355 justru terjadi persis pada asimetri ini.

2. **Hasil dari shell user adalah indikator kuat, bukan bukti absolut final** — untuk laporan dengan tingkat keyakinan maksimal, pertimbangkan Metode D (aplikasi pihak ketiga sungguhan) untuk menghindari ambiguitas tentang privilese khusus shell user (§1.4).

3. **Selalu nilai isi data, bukan sekadar status HTTP/berhasil-tidaknya command** — sesuai §1.5, FAIL hanya valid bila data yang terekspos benar-benar sensitif sesuai klasifikasi data aplikasi.

4. **Korelasikan dengan hasil MASTG-TEST-0355** — temuan dinamis ini adalah konfirmasi definitif terhadap kandidat yang ditemukan analisis statis; bila statis menunjukkan konfigurasi yang terlihat aman namun dinamis tetap berhasil mengakses, ini mengindikasikan kesalahan interpretasi konfigurasi (mis. `protectionLevel` yang lebih lemah dari yang terlihat) yang layak diinvestigasi lebih lanjut.

5. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | Data sangat sensitif (kredensial, token, data personal) berhasil diakses/dimodifikasi tanpa izin | **Tinggi** |
   | Operasi berhasil namun data tidak sensitif | **Bukan temuan** |
   | Hanya satu dari empat operasi yang gagal diblokir (asimetri read/write) | **Tinggi** — tetap dianggap serius karena menunjukkan kegagalan desain kontrol akses yang nyata |

6. **Dokumentasikan:** URI provider yang diuji, hasil keempat operasi (berhasil/ditolak beserta pesan error), contoh data yang berhasil diekstrak (redaksi bila perlu), dan metode verifikasi yang dipakai (shell vs aplikasi sungguhan).

---

## 4. Rekomendasi Perbaikan

Rekomendasi identik dengan pasangan statisnya (MASTG-TEST-0355) — lihat dokumen tersebut untuk detail lengkap (non-exported bila tidak perlu, permission read DAN write terpisah dengan `protectionLevel="signature"`). Poin tambahan spesifik hasil verifikasi dinamis:

### Checklist Remediasi

- [ ] Keempat operasi (query/insert/update/delete) terverifikasi ditolak tanpa permission yang sesuai
- [ ] Hasil diverifikasi baik dari `adb shell content` maupun dari aplikasi pihak ketiga sungguhan
- [ ] Setelah perbaikan manifest (sesuai rekomendasi TEST-0355), pengujian dinamis diulang untuk memastikan perbaikan benar-benar efektif, bukan hanya terlihat benar di manifest

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0356 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0356.md)
- [MASTG-TEST-0355: References to Unauthorized Database Access through Content Providers (dokumen pasangan statis dalam seri riset ini)](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0355/)
- [MASTG-TECH-0148: Interacting with Android ContentProviders](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0148/)
- [MASTG-BEST-0049: Restrict and Validate Access to Exported Content Providers](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0049.md)

### 5.2 Dokumentasi Tools

- [Android Developers: ContentResolver](https://developer.android.com/reference/android/content/ContentResolver)
- [Drozer — Android Security Assessment Framework](https://github.com/WithSecureLabs/drozer)

---

*Dokumen ini disusun berdasarkan konten resmi OWASP MASTG (`tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0356.md`, `MASTG-TECH-0148`), dilengkapi cross-reference mendalam dengan dokumen MASTG-TEST-0355 (pasangan statisnya) dalam seri riset ini. Nuansa metodologis terpenting: test ini menyediakan jalan konkret (`adb shell content insert/update/delete`) untuk menutup celah metodologis yang sudah diidentifikasi di TEST-0355 — yaitu kebutuhan menguji perlindungan read dan write secara terpisah, karena rule analisis statis resmi tidak dapat membedakan provider yang hanya melindungi satu dari dua jenis operasi tersebut. Keberhasilan query/insert/update/delete dari `adb shell content` (konteks shell user) adalah indikator kuat namun bukan bukti absolut final — verifikasi dari aplikasi pihak ketiga sungguhan memberi tingkat keyakinan tertinggi untuk laporan yang membutuhkan presisi maksimal.*
