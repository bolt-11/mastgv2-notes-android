# MASTG-TEST-0339 SQL Injection in Content Providers

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0339 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-CODE |
| **Weakness** | MASWE-0050 |
| **Tipe Pengujian** | Static, Code |
| **Teknik terkait** | MASTG-TECH-0013 (Reverse Engineering), MASTG-TECH-0014 (Static Analysis for Relevant APIs) |
| **Knowledge terkait** | MASTG-KNOW-0117 (Android ContentProvider) |
| **Best Practice terkait** | MASTG-BEST-0039 (Prevent SQL Injection in ContentProviders) |
| **Demo terkait** | MASTG-DEMO-0102 (dirujuk MASTG-KNOW-0117 sebagai contoh konkret) |
| **Rule resmi** | `mastg-android-sql-injection-contentprovider.yml` — satu pola, cakupan sempit, lihat §1.4 |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Kutipan overview resmi MASTG:

> *"Android applications can share structured data via ContentProvider components. However, if these providers create SQL queries using untrusted input from URIs without adequate validation or parameterization, they risk becoming susceptible to SQL injection attacks."*

`ContentProvider` adalah mekanisme Android untuk **berbagi data terstruktur antar aplikasi** melalui antarmuka berbasis URI (`content://<authority>/<path>`). Karena backend-nya umumnya SQLite, risiko klasik SQL injection yang biasa dikenal dari aplikasi web ternyata **relevan juga** di konteks Android — namun dengan vektor masuk yang berbeda: bukan form HTTP, melainkan **segmen URI** dan **parameter query** yang diteruskan lewat `ContentResolver`.

### 1.2 Dua Titik Masuk Utama: Path Segment dan Selection/SelectionArgs

MASTG-KNOW-0117 menjelaskan mekanisme URI parsing yang relevan:

> *"`Uri.getPathSegments()` returns a decoded list of path segments after the authority... These values are often user-controlled when the provider is exported."*

Dan perbedaan krusial antara dua cara membangun query `SELECT`:

> *"`appendWhere(CharSequence)` appends a condition to the WHERE clause. The provided string is inserted verbatim into the SQL query and is not parameterized."*
>
> *"The query() method accepts a selection string and a selectionArgs array. Each `?` placeholder in selection is replaced with the corresponding value from selectionArgs, and those values are treated strictly as data... This prevents SQL injection because values are bound, not interpreted as SQL."*

Tabel ringkas perbandingan dua pendekatan:

| Pendekatan | Keamanan |
|---|---|
| `qb.appendWhere(userInput)` | **Tidak aman** — string diselipkan verbatim ke SQL, diparse sebagai bagian dari statement |
| `qb.query(db, projection, "id = ?", new String[]{userInput}, ...)` | **Aman** — nilai di-bind sebagai data, tidak pernah diinterpretasi sebagai SQL |
| `selection = "id = '" + userInput + "'"` (string concatenation manual) | **Tidak aman** — secara fungsional identik dengan `appendWhere` tanpa parameterisasi |

### 1.3 Kriteria FAIL: Dua Pola Konkret

> **Evaluation:** *"The test case fails if: Untrusted user input (e.g., from getPathSegments()) is directly concatenated into SQL statements. The app uses appendWhere() or builds queries unsafely without sanitization or parameterization."*

### 1.4 Analisis Rule Resmi: Cakupan Sempit yang Melewatkan Kasus `selection` String Concatenation

Rule `mastg-android-sql-injection-contentprovider.yml` memakai dua varian pola yang keduanya **berfokus eksklusif pada `appendWhere()`**:

```yaml
patterns:
  - pattern-either:
      - pattern: |
          $QB.appendWhere("..." + $VAR);
      - pattern: |
          $QB.appendWhere($VAR);
  - pattern-inside: |
      $VAR = $URI.getPathSegments().get(...);
      ...
```

Catatan analitis penting di sini: varian kedua (`$QB.appendWhere($VAR)`, tanpa concatenation string) adalah desain yang **tepat dan cerdas** — rule ini benar menyadari bahwa **meneruskan variabel secara langsung tanpa concatenation apa pun** tetap berbahaya, karena `$VAR` yang berasal dari `getPathSegments()` bisa saja **sudah berisi string SQL berbahaya secara utuh** (mis. `"1 OR 1=1"`), tidak perlu digabung dengan string literal lain untuk menjadi exploit yang valid.

Namun, kesenjangan cakupan yang signifikan: rule ini **sama sekali tidak mencakup** pola kedua dari kriteria FAIL resmi (§1.3) — yaitu **concatenation manual ke parameter `selection`** sebelum diteruskan ke `query()`, bukan lewat `appendWhere()`:

```java
// Pola ini TIDAK tercakup rule resmi, meski secara fungsional sama bahayanya
String id = uri.getPathSegments().get(1);
String selection = "id = '" + id + "'"; // concatenation manual ke selection
Cursor c = db.query(table, projection, selection, null, null, null, null);
```

Ini karena rule secara eksklusif mencari pemanggilan method `appendWhere` — pola di atas memakai `query()` langsung dengan string `selection` yang sudah tercemar sebelum pemanggilan, tanpa menyentuh `SQLiteQueryBuilder.appendWhere` sama sekali. Penguji harus melengkapi pencarian otomatis dengan pola manual untuk menutup celah ini.

### 1.5 Bukti Nyata: Dari Framework Android Itu Sendiri hingga Aplikasi Produksi Populer

Kerentanan class ini memiliki riwayat yang luas dan berkelanjutan, baik di level framework Android maupun aplikasi pihak ketiga:

**Di level framework (komponen bawaan AOSP):**

> *"CVE-2020-0060: A local SQL injection vulnerability was found in a Content Provider provided by the 'com.android.providers.telephony' package (version 10), allowing injection and execution of arbitrary SQL statements within the context of the target package."*
>
> *"CVE-2018-9493: SQL injection in Android's DownloadProvider requires no permission if the provider is exported without permission protection."*

**Di level aplikasi produksi nyata (ownCloud Android app, bukan AOSP):**

> *"CVE-2023-24804, CVE-2023-23948: The ownCloud Android app's FileContentProvider has SQL injection vulnerabilities that allow malicious applications or users on the same device to obtain internal information of the app."*

Detail teknis kerentanan ownCloud ini sangat relevan sebagai ilustrasi konkret:

> *"The FileContentProvider exported user-controlled parameters directly into SQL queries without parameterization. In the delete method, the where parameter was concatenated directly: 'AND ($where)' allowed injection when building deletion statements. Attackers leveraged the exported content provider through two techniques: direct injection to exfiltrate data from any table, and blind SQL injection in owncloud_database using conditional LIKE queries that measured response differences to extract information from restricted tables."*

Fakta bahwa **dua kerentanan terpisah** ditemukan pada aplikasi populer yang sama (ownCloud) — satu di database file list, satu lagi lewat **blind SQL injection** yang jauh lebih canggih (mengekstrak data lewat perbedaan waktu/respons tanpa pesan error langsung) — menunjukkan bahwa kerentanan class ini tidak selalu sesederhana "injeksi langsung terlihat", dan audit harus mempertimbangkan skenario blind injection juga.

### 1.6 Peran Kritis Status `exported` sebagai Prasyarat Eksploitasi

MASTG-KNOW-0117 menegaskan bahwa risiko ini **sepenuhnya bergantung** pada konfigurasi akses:

> *"A ContentProvider's availability to other apps is governed by attributes in the Android manifest... Since Android 4.2, the default is false if no `<intent-filter>` is defined... Exported providers that process user-controlled input without validation are a common attack surface."*

Ini berarti **urutan investigasi yang logis** adalah: pertama identifikasi provider mana yang `exported="true"` (atau memiliki `<intent-filter>` tanpa deklarasi eksplisit pada API level lama, yang otomatis membuatnya exported), **baru kemudian** fokuskan analisis pola SQL injection pada provider-provider tersebut — provider yang tidak exported memiliki permukaan serangan yang jauh lebih kecil (hanya dapat diakses dari dalam aplikasi sendiri atau aplikasi dengan UID yang sama).

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **jadx** | Dekompilasi DEX → Java (MASTG-TECH-0013) |
| **Semgrep** + rule resmi `mastg-android-sql-injection-contentprovider.yml` | Mendeteksi pola `appendWhere()` dengan input dari `getPathSegments()` (MASTG-TECH-0014) |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **grep/ripgrep** | Menutup celah cakupan rule resmi — mencari concatenation manual ke parameter `selection` (§1.4) |
| **aapt / Androguard** | Ekstraksi manifest untuk memetakan provider `exported="true"` (prasyarat investigasi, §1.6) |
| **adb shell content** | Verifikasi dinamis langsung — mengirim query berbahaya ke provider via command line tanpa perlu menulis aplikasi exploit |
| **Drozer** | Framework pentest Android khusus untuk eksplorasi dan eksploitasi komponen IPC termasuk ContentProvider, menyediakan modul siap pakai untuk uji SQL injection |

### 2.3 Prasyarat Lingkungan

- Analisis statis tidak butuh device/root.
- Untuk verifikasi dinamis (Metode D), butuh device/emulator dengan aplikasi target terinstal dan `adb` terhubung.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0013** untuk reverse engineer aplikasi.
2. Gunakan **MASTG-TECH-0014** untuk mencari API yang relevan.

### 3.2 Metode A — Semgrep dengan Rule Resmi

```bash
semgrep --config mastg-android-sql-injection-contentprovider.yml ./decompiled/sources
```

### 3.3 Metode B — grep/ripgrep untuk Menutup Celah Selection Concatenation

```bash
D=./decompiled/sources

# Cari seluruh pemanggilan appendWhere (termasuk variasi yang mungkin terlewat rule resmi)
rg -n 'appendWhere\(' $D

# Cari concatenation manual ke variabel bernama 'selection'/'where' (TIDAK tercakup rule resmi)
rg -n 'selection\s*=\s*".*"\s*\+|where\s*=\s*".*"\s*\+' $D

# Lacak balik variabel yang berasal dari getPathSegments/getLastPathSegment
rg -n 'getPathSegments\(\)|getLastPathSegment\(\)' $D
```

### 3.4 Metode C — Pemetaan Provider Exported (Prasyarat Wajib, §1.6)

```bash
aapt dump xmltree app.apk AndroidManifest.xml | grep -B10 '<provider' | grep -E 'exported|authorities'
```

Fokuskan seluruh analisis Metode A/B hanya pada provider yang hasilnya `exported="true"` (atau tanpa atribut eksplisit namun memiliki `<intent-filter>`).

### 3.5 Metode D — Verifikasi Dinamis via ADB Shell Content

```bash
# Uji pemicu injeksi langsung ke provider exported yang teridentifikasi
adb shell content query --uri "content://com.example.app.provider/students/1' OR '1'='1"

# Uji blind SQL injection (replikasi teknik ownCloud di §1.5)
adb shell content query --uri "content://com.example.app.provider/students/1' AND (SELECT 1 FROM restricted_table LIMIT 1)='1"
```

### 3.6 Metode E — Drozer untuk Eksplorasi dan Eksploitasi Terstruktur

```bash
dz> run app.provider.info -a com.example.app
dz> run app.provider.query content://com.example.app.provider/students --selection "1=1"
dz> run scanner.provider.injection -a com.example.app
```

Modul `scanner.provider.injection` Drozer secara otomatis mencoba berbagai payload injeksi terhadap seluruh provider exported yang terdeteksi — mempercepat triase awal sebelum verifikasi manual mendalam.

### 3.7 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Kapan dipakai |
|---|---|---|
| **A** | Semgrep + rule resmi | Baseline, cakupan terbatas pada `appendWhere` |
| **B** | grep/ripgrep manual | Wajib — menutup celah pola `selection` concatenation |
| **C** | Pemetaan exported | Prasyarat wajib untuk mempersempit fokus investigasi |
| **D** | ADB shell content | Verifikasi dinamis langsung, replikasi skenario blind injection nyata |
| **E** | Drozer | Triase otomatis cepat terhadap seluruh provider exported |

**Kombinasi minimum yang aku rekomendasikan:** **C (wajib pertama) → A + B (triase statis) → D/E (verifikasi dinamis)**.

---

### 3.8 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG (dua pola FAIL, §1.3):**

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Input tidak terpercaya dari `getPathSegments()`/sumber URI lain dikonkatenasi langsung ke statement SQL |
| F2 | `appendWhere()` dipakai dengan input yang tidak disanitasi/diparameterisasi, **atau** query dibangun secara tidak aman dengan cara lain (concatenation manual ke `selection`) |

**Contoh bukti (merefleksikan pola nyata ownCloud di §1.5):**

```java
// Ditemukan di com/example/app/provider/FileContentProvider.java
@Override
public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
    String id = uri.getPathSegments().get(1); // dari URI, tidak tepercaya
    SQLiteQueryBuilder qb = new SQLiteQueryBuilder();
    qb.setTables("files");
    qb.appendWhere("_id = " + id); // concatenation langsung, TIDAK aman
    return qb.query(db, projection, selection, selectionArgs, null, null, sortOrder);
}
```

**AndroidManifest.xml:**
```xml
<provider android:name=".FileContentProvider" android:exported="true" />
```

Interpretasi: provider exported, menerima segmen URI tidak tepercaya, dan mengkonkatenasinya langsung ke `appendWhere()`. **FAIL** — persis pola kerentanan nyata ownCloud.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Seluruh query memakai `selection`/`selectionArgs` dengan placeholder `?`, **atau** |
| P2 | `appendWhereEscapeString()` dipakai sebagai pengganti `appendWhere()` mentah untuk kasus yang memang memerlukannya |

**Contoh bukti:**

```java
public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
    String id = uri.getPathSegments().get(1);
    SQLiteQueryBuilder qb = new SQLiteQueryBuilder();
    qb.setTables("files");
    return qb.query(db, projection, "_id = ?", new String[]{id}, null, null, sortOrder); // parameterized
}
```

**PASS**.

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Selalu mulai dari pemetaan provider exported** — sesuai §1.6, provider yang tidak exported memiliki permukaan serangan jauh lebih kecil; prioritaskan audit mendalam untuk provider exported terlebih dahulu.

2. **Jangan hanya mengandalkan rule resmi** — cakupannya terbatas pada `appendWhere()` saja (§1.4); pola concatenation manual ke `selection` string sama berbahayanya namun tidak tercakup rule.

3. **Pertimbangkan skenario blind SQL injection, bukan hanya error-based** — sesuai kasus nyata ownCloud (§1.5), penyerang dapat mengekstrak data dari tabel terbatas lewat teknik conditional query tanpa pesan error yang terlihat; pengujian dinamis (Metode D) sebaiknya mencoba kedua jenis payload.

4. **Perhatikan juga operasi selain `query()`** — sesuai temuan ownCloud, method `delete()`/`update()`/`insert()` pada `ContentProvider` juga rentan bila memakai pola concatenation serupa untuk parameter `where`.

5. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | Provider exported, SQL injection dikonfirmasi (statis + dinamis), memungkinkan akses data dari tabel yang seharusnya dibatasi | **Tinggi** |
   | Pola berbahaya ditemukan namun provider tidak exported (risiko hanya dari dalam aplikasi sendiri/app dengan UID sama) | **Rendah-Sedang** |
   | Seluruh query memakai parameterisasi yang benar | **Bukan temuan** |

6. **Dokumentasikan:** lokasi kode, status exported provider terkait, method yang rentan (`query`/`delete`/`update`/`insert`), dan hasil verifikasi dinamis (payload yang berhasil, data yang berhasil diekstrak).

---

## 4. Rekomendasi Perbaikan

### 4.1 Gunakan Parameterized Query Secara Konsisten (Sesuai MASTG-BEST-0039)

```kotlin
// SEBELUM — concatenation langsung
qb.appendWhere("_id = " + idSegment)

// SESUDAH — parameterized, sesuai MASTG-BEST-0039
val selection = "id = ?"
val selectionArgs = arrayOf(idSegment)
val cursor = qb.query(db, projection, selection, selectionArgs, null, null, sortOrder)
```

### 4.2 Terapkan Pola yang Sama untuk delete/update/insert

```java
// SEBELUM
db.execSQL("DELETE FROM files WHERE id = " + where);

// SESUDAH — prepared statement dengan argument binding
db.delete("files", "id = ?", new String[]{where});
```

### 4.3 Batasi `exported` Hanya Bila Benar-Benar Diperlukan

```xml
<provider
    android:name=".FileContentProvider"
    android:exported="false" />
```

Bila provider hanya dipakai secara internal, nonaktifkan `exported` sepenuhnya untuk menghilangkan permukaan serangan dari aplikasi pihak ketiga sama sekali.

### 4.4 Checklist Remediasi

- [ ] Seluruh operasi `query`/`delete`/`update`/`insert` pada ContentProvider memakai parameterisasi, tidak ada concatenation string langsung
- [ ] `appendWhere()` diganti dengan `selection`/`selectionArgs` atau `appendWhereEscapeString()` bila memang diperlukan
- [ ] Provider yang tidak perlu diakses aplikasi lain diset `exported="false"`
- [ ] Diverifikasi secara dinamis dengan payload injeksi langsung dan blind (ADB/Drozer)
- [ ] Permission (`readPermission`/`writePermission`) diterapkan untuk provider exported yang memang perlu diakses terbatas

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0339 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-CODE/MASTG-TEST-0339.md)
- [MASTG-KNOW-0117: Android ContentProvider](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CODE/MASTG-KNOW-0117/)
- [MASTG-BEST-0039: Prevent SQL Injection in ContentProviders](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0039.md)

### 5.2 Dokumentasi Resmi Android

- [Android Developers: Content Provider Basics — Protect Against Malicious Input](https://developer.android.com/guide/topics/providers/content-provider-basics#Injection)

### 5.3 Riset dan Kasus Nyata (CVE)

- [GitHub Security Lab: GHSL-2022-059/060 — SQL Injection in ownCloud Android App (CVE-2023-24804, CVE-2023-23948)](https://securitylab.github.com/advisories/GHSL-2022-059_GHSL-2022-060_Owncloud_Android_app/)
- [Advania: Local SQL Injection in com.android.providers.telephony (CVE-2020-0060)](https://www.advania.co.uk/insights/blog/android-telephony-vulnerability/)
- [RedFox Security: Exploiting Content Providers in Android Applications](https://redfoxsecurity.medium.com/exploiting-content-providers-in-android-applications-a75cbda2a5c7)
- [arXiv: SecComp — Towards Practically Defending Against Component Hijacking in Android Applications](https://arxiv.org/pdf/1609.03322)

### 5.4 Dokumentasi Tools

- [Semgrep Documentation](https://semgrep.dev/docs/)
- [Drozer — Android Security Assessment Framework](https://github.com/WithSecureLabs/drozer)
- [Androguard](https://github.com/androguard/androguard)

---

*Dokumen ini disusun berdasarkan konten resmi OWASP MASTG (`tests-beta/android/MASVS-CODE/MASTG-TEST-0339.md`, `MASTG-KNOW-0117`, `MASTG-BEST-0039`), analisis rule `mastg-android-sql-injection-contentprovider.yml`, serta riwayat CVE nyata baik di level framework Android (`CVE-2020-0060` telephony, `CVE-2018-9493` DownloadProvider) maupun aplikasi produksi populer (`CVE-2023-24804`/`CVE-2023-23948` pada ownCloud Android App) yang mencakup kedua jenis SQL injection: langsung dan blind. Nuansa metodologis terpenting: rule resmi hanya mencakup pola `appendWhere()`, sementara kriteria FAIL resmi test ini juga mencakup concatenation manual ke parameter `selection` yang sama sekali tidak tercakup rule — penguji wajib melengkapi dengan pencarian manual, dan investigasi harus selalu dimulai dari pemetaan status `exported` provider sebagai prasyarat eksploitasi.*
