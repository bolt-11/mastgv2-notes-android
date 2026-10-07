# MASTG-TEST-0375 Missing Validation of Data Returned from Implicit Intents

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0375 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-CODE |
| **Weakness** | MASWE-0050 |
| **Tipe Pengujian** | Dynamic, Hooks, **Manual** |
| **Teknik terkait** | MASTG-TECH-0005, MASTG-TECH-0043, MASTG-TECH-0023 |
| **Knowledge terkait** | MASTG-KNOW-0025 (Explicit vs Implicit Intents), MASTG-KNOW-0138 (URI Schemes in Android Intent Results) |
| **Best Practice terkait** | MASTG-BEST-0057 (Sanitize Data Coming from External Components) |
| **Test terkait** | MASTG-TEST-0372/0374 — dokumen terkait dalam seri riset ini; ketiganya membahas implicit intent dari sudut berbeda (lihat §1.1) |
| **Rule resmi** | — (tidak ada; test murni dinamis dengan validasi manual, konsisten dengan arah berlawanan dari dua test sebelumnya) |

---

## 1. Penjelasan

### 1.1 Arah Risiko yang Terbalik Dibanding MASTG-TEST-0372/0374

Kutipan overview resmi MASTG:

> *"Apps commonly use implicit intents and activity result APIs to request data from another app, such as selecting a file, opening a document, or importing content. The selected responder controls the result returned to the caller... The issue appears when the app treats the returned data as trusted."*

Ini adalah **arah berlawanan** dari dua test sebelumnya dalam seri riset ini:

| | MASTG-TEST-0372/0374 | MASTG-TEST-0375 (test ini) |
|---|---|---|
| **Arah aliran data** | Aplikasi **mengirim** data keluar lewat implicit intent | Aplikasi **menerima** data masuk dari hasil implicit intent |
| **Siapa yang dicurigai** | Aplikasi berbahaya yang **mencegat** intent (intent hijacking) | Aplikasi berbahaya yang **menjawab** permintaan (**malicious responder**) |
| **Risiko utama** | Kebocoran data sensitif ke pihak tak tepercaya | Aplikasi korban **mempercayai** data yang dikendalikan penyerang |

Ini adalah pola klasik **"confused deputy"** — aplikasi meminta file/dokumen lewat `ACTION_GET_CONTENT`/chooser, mengasumsikan hanya aplikasi "baik" (Google Drive, File Manager, dsb.) yang akan merespons, namun **sistem tidak dapat menjamin itu** — aplikasi berbahaya mana pun yang mendaftarkan `<intent-filter>` yang cocok juga bisa menjadi responder terpilih dan mengembalikan data apa pun yang mereka inginkan.

### 1.2 Dua Skema URI dan Perbedaan Kritis Model Kontrol Aksesnya

MASTG-KNOW-0138 menjelaskan perbedaan fundamental yang menjadi inti risiko test ini:

> *"`content://`: Routes through a ContentProvider. Access control: Governed by provider permissions, URI grants, and provider export state."*
>
> *"`file://`: Accesses the filesystem path directly. Access control: Governed by filesystem permissions for the calling process."*

Perbedaan ini krusial: URI `content://` **masih melewati lapisan kontrol akses** provider. Namun URI `file://` **benar-benar langsung** menjadi path filesystem yang dibuka **menggunakan identitas proses aplikasi pemanggil (korban)**, bukan identitas responder. Ini berarti:

> *"A responding app controls the URI value it returns in the result intent. If that value uses the `file://` scheme, the path is interpreted from the caller's process context. For example, `file:///data/data/com.example.app/shared_prefs/session.xml` denotes a filesystem path under the app-private data directory of `com.example.app`."*

Skenario ini sangat berbahaya — **responder berbahaya bisa "menipu" korban untuk membuka file pribadinya sendiri** (misalnya `shared_prefs/session.xml` milik korban sendiri) hanya dengan mengembalikan URI `file://` yang menunjuk ke path tersebut, lalu korban (yang mempercayai hasil secara membuta) membaca dan memproses "konten yang dipilih pengguna" — padahal sesungguhnya itu adalah file internal korban sendiri yang kini terekspos lewat jalur pemrosesan yang tidak dimaksudkan.

### 1.3 Vektor Kedua: Path Traversal via Metadata DISPLAY_NAME

Vektor kedua yang dijelaskan secara rinci dengan contoh kode konkret:

> *"When the responding app returns a content:// URI, the calling app can query `OpenableColumns.DISPLAY_NAME` to get a human-readable filename... The provider controls the value returned for that column. If the value contains path separators, constructing a path with `File(dir, name)` resolves it according to normal filesystem path rules."*

```kotlin
val name = getDisplayName(uri) ?: "download"
val target = File(context.filesDir, name) // resolves to ../lib-main/lib.so
```

Ini adalah **path traversal klasik** — `DISPLAY_NAME` yang seharusnya hanya nama file biasa (`"dokumen.pdf"`) bisa saja dikembalikan responder berbahaya sebagai `"../../../lib/malicious.so"`, dan bila aplikasi korban membangun path tujuan secara naif dengan `File(dir, name)`, hasil akhirnya bisa **menulis file di luar direktori yang dimaksudkan** — bahkan menimpa file library aplikasi sendiri.

### 1.4 Bukti Nyata yang Sangat Tepat Sasaran: CVE-2026-38093 pada Plugin file_picker Flutter

Ini adalah bukti nyata yang **persis** mereplikasi skenario path traversal `DISPLAY_NAME` yang dijelaskan MASTG-BEST-0057 (§1.3) — ditemukan pada plugin populer `file_picker` (dipakai luas di ekosistem Flutter, termasuk untuk membangun aplikasi Android):

> *"file_picker (aka flutter_file_picker) for Flutter, all versions through 10.3.10, is vulnerable to path traversal (CWE-22) in its Android implementation. The `openFileStream()` method uses the DISPLAY_NAME from `ContentResolver.query()` directly in file path construction without sanitization. A malicious Android app can supply a crafted ContentProvider that returns a filename containing '../' sequences, enabling the plugin to create files and directories outside the intended cache directory inside the victim app's internal storage."*

Catatan penting tentang keterbatasan dampak dalam kasus spesifik ini (relevan untuk kalibrasi severity yang realistis, bukan berlebihan):

> *"Existing files are not overwritten because an existence check is performed, but the flaw still allows placement of arbitrary files outside the allowed location... if the created files are later processed by the app, it could be used to modify data, elevate privileges, or facilitate other attacks."*

Ini menunjukkan nuansa penting — dampak langsung dari satu kerentanan path traversal **tergantung konteks lanjutan**: menulis file baru di lokasi tak terduga mungkin "hanya" information disclosure/clutter bila tidak ada logika lain yang memproses file tersebut secara otomatis, namun **bereskalasi signifikan** bila aplikasi kemudian memuat/mengeksekusi/mempercayai file di lokasi tersebut tanpa verifikasi lanjutan.

### 1.5 Mengapa Test Ini Dinamis, Bukan Statis

Berbeda dari TEST-0372/0374 yang murni statis, test ini secara eksplisit **dinamis** — alasannya logis: menilai "apakah data yang dikembalikan divalidasi sebelum dipakai di operasi sensitif" menuntut **mengamati aliran data sesungguhnya saat runtime**, mengingat responder yang benar-benar dipanggil, nilai yang benar-benar dikembalikan, dan jalur kode yang benar-benar dieksekusi sesudahnya seringkali tidak dapat dipastikan hanya dari membaca kode statis (terutama bila ada banyak kemungkinan responder/cabang kondisional).

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **Frida** | Hooking `onActivityResult`/`ActivityResultCallback`, `Intent.getData()`, `ContentResolver.query/openInputStream` (MASTG-TECH-0043) |
| **ADB** | Instalasi app, instalasi aplikasi responder uji kustom (MASTG-TECH-0005) |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **Aplikasi responder berbahaya kustom** | Mendaftarkan `<intent-filter>` yang cocok dengan permintaan aplikasi target, lalu mengembalikan URI `file://`/`content://` dengan `DISPLAY_NAME` berisi path traversal — mereplikasi langsung skenario CVE-2026-38093 (§1.4) |
| **jadx** | Review kode untuk melacak pemrosesan hasil setelah hook (MASTG-TECH-0023) |

### 2.3 Prasyarat Lingkungan

- Device rooted/emulator dengan `frida-server`.
- **Aplikasi responder uji kustom** yang bisa dikonfigurasi mengembalikan payload berbeda (URI `file://` ke path internal korban, `DISPLAY_NAME` dengan `../`, dsb.) — ini adalah komponen pengujian paling penting untuk test ini.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0005** untuk instalasi aplikasi.
2. Gunakan **MASTG-TECH-0043** untuk hook API yang relevan.
3. Exercise aplikasi secara ekstensif untuk memicu flow yang meminta data dari aplikasi lain lewat implicit intent.

### 3.2 Metode A — Frida: Hook Rantai Lengkap Request-Result-Processing

```javascript
Java.perform(function () {
    var Intent = Java.use("android.content.Intent");
    Intent.getData.implementation = function () {
        var uri = this.getData();
        console.log("[Intent.getData] " + (uri ? uri.toString() : "null"));
        console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
        return uri;
    };

    var ContentResolver = Java.use("android.content.ContentResolver");
    ContentResolver.openInputStream.overload('android.net.Uri').implementation = function (uri) {
        console.log("[ContentResolver.openInputStream] uri=" + uri.toString());
        return this.openInputStream(uri);
    };
});
```

### 3.3 Metode B — Replikasi Skenario Path Traversal dengan Responder Kustom (Wajib, Sesuai §1.4)

```xml
<!-- Manifest aplikasi responder uji -->
<provider android:name=".MaliciousProvider" android:authorities="com.attacker.evil.provider" android:exported="true" />
```

```java
// Implementasi query() di MaliciousProvider — kembalikan DISPLAY_NAME berisi path traversal
cursor.addRow(new Object[]{"../../../../lib-main/libnative.so"});
```

Picu flow file-picker di aplikasi target, pilih "responder" uji ini sebagai penjawab, amati apakah file benar-benar tertulis di luar direktori yang dimaksud.

### 3.4 Metode C — Review Manual Pasca-Hook (Wajib, Sesuai MASTG-TECH-0023)

Untuk setiap data yang tertangkap hook:

1. Apakah nilai langsung dipakai untuk membangun path file (`File(dir, name)`) tanpa sanitasi?
2. Apakah skema URI (`file://` vs `content://`) diperiksa sebelum dipakai?
3. Apakah hasil akhirnya memengaruhi operasi sensitif (penulisan file, parsing konten, keputusan otorisasi)?

### 3.5 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Kapan dipakai |
|---|---|---|
| **A** | Frida | Baseline wajib — observasi aliran data hasil intent |
| **B** | Responder kustom | **Wajib** — bukti konklusif replikasi serangan nyata |
| **C** | Review manual | **Wajib** — menilai validasi sesungguhnya |

**Kombinasi minimum yang aku rekomendasikan:** **A + B (wajib) → C (wajib)**.

---

### 3.6 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Evaluation:** *"The test case fails if data returned from an external intent result reaches a security-relevant operation without validation or sanitization."*

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Data dari hasil intent eksternal (`getData()`/`ClipData`/extras/metadata provider) mencapai operasi sensitif tanpa validasi |

**Contoh bukti (merefleksikan pola nyata CVE-2026-38093 §1.4):**

```java
override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
    val uri = data?.data ?: return
    val name = getDisplayName(uri) ?: "download" // dari responder, bisa jadi "../lib/evil.so"
    val target = File(context.filesDir, name) // TIDAK disanitasi
    contentResolver.openInputStream(uri)?.copyTo(target.outputStream())
}
```

**FAIL** — path traversal terbuka, file bisa ditulis di luar direktori yang dimaksud.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Skema URI diverifikasi (`content://` diprioritaskan, `file://` ditolak/ditangani khusus), **dan** |
| P2 | `DISPLAY_NAME`/filename disanitasi dengan `File(name).name` sebelum dipakai membangun path, **dan** |
| P3 | Path tujuan selalu dianchor ke direktori terkontrol (`filesDir`/`cacheDir`), bukan dibangun langsung dari nilai eksternal |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Selalu uji dengan responder berbahaya kustom** — mengandalkan responder "normal" (Google Files, dsb.) tidak akan pernah memicu kondisi berbahaya; replikasi aktif (Metode B) adalah satu-satunya cara memverifikasi secara konklusif.

2. **Periksa kedua vektor secara terpisah** — skema URI `file://` (§1.2) dan metadata `DISPLAY_NAME` (§1.3) adalah dua vektor independen; aplikasi bisa aman dari satu namun rentan dari yang lain.

3. **Nilai dampak lanjutan, bukan hanya keberhasilan penulisan file** — sesuai catatan realistis CVE-2026-38093 (§1.4), dampak penuh bergantung pada apakah file yang ditulis di lokasi tak terduga kemudian diproses/dieksekusi oleh logika lain.

4. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | Path traversal memungkinkan menimpa/menulis file yang kemudian dieksekusi/dipercaya (native lib, config kritis) | **Tinggi** |
   | Path traversal menulis file baru tanpa eskalasi lanjutan yang jelas | **Sedang** |
   | Skema URI dan filename divalidasi dengan benar | **Bukan temuan** |

5. **Dokumentasikan:** jenis URI yang diterima, nilai `DISPLAY_NAME`/metadata yang dicoba, path yang dihasilkan, dan apakah file berhasil ditulis di luar direktori yang dimaksud.

---

## 4. Rekomendasi Perbaikan

### 4.1 Validasi Skema URI dan Sanitasi Filename (Sesuai MASTG-BEST-0057)

```kotlin
fun sanitizeFileName(name: String): String = File(name).name // strip path traversal

override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
    val uri = data?.data ?: return
    if (uri.scheme != "content") return // tolak file:// dari responder eksternal

    val rawName = getDisplayName(uri) ?: "default.bin"
    val safeName = sanitizeFileName(rawName)
    val output = File(context.filesDir, safeName) // selalu anchor ke direktori terkontrol
    contentResolver.openInputStream(uri)?.use { input ->
        output.outputStream().use { out -> input.copyTo(out) }
    }
}
```

### 4.2 Checklist Remediasi

- [ ] Skema URI hasil intent diverifikasi — `file://` dari responder eksternal ditolak/ditangani khusus
- [ ] `DISPLAY_NAME`/metadata filename disanitasi dengan `File(name).name` sebelum dipakai
- [ ] Path tujuan selalu dianchor ke direktori terkontrol (`filesDir`/`cacheDir`)
- [ ] Diverifikasi dengan responder berbahaya kustom yang mencoba path traversal dan `file://` ke path internal

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0375 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-CODE/MASTG-TEST-0375.md)
- [MASTG-TEST-0372/0374 (dokumen terkait dalam seri riset ini)](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0372/)
- [MASTG-KNOW-0138: URI Schemes in Android Intent Results](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CODE/MASTG-KNOW-0138/)
- [MASTG-BEST-0057: Sanitize Data Coming from External Components](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0057.md)

### 5.2 Riset dan Kasus Nyata

- [GitHub Advisory: CVE-2026-38093 — file_picker (Flutter) Android Path Traversal via DISPLAY_NAME](https://github.com/advisories/ghsa-r2rg-pm28-j8gw)
- [SentinelOne: CVE-2025-48609 — Google Android Path Traversal Vulnerability](https://www.sentinelone.com/vulnerability-database/cve-2025-48609/)
- [Oversecured: Android Security Checklist — Theft of Arbitrary Files](https://blog.oversecured.com/Android-security-checklist-theft-of-arbitrary-files/)
- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)](https://cwe.mitre.org/data/definitions/22.html)

### 5.3 Dokumentasi Tools

- [Frida — Dynamic Instrumentation Toolkit](https://frida.re/docs/home/)

---

*Dokumen ini disusun berdasarkan konten resmi OWASP MASTG (`tests-beta/android/MASVS-CODE/MASTG-TEST-0375.md`, `MASTG-KNOW-0138`, `MASTG-BEST-0057`), serta bukti nyata yang sangat tepat sasaran: CVE-2026-38093 pada plugin populer `file_picker` Flutter, yang mereplikasi persis pola path traversal via `DISPLAY_NAME` yang dijelaskan dalam dokumentasi resmi MASTG. Nuansa metodologis terpenting: test ini menyasar arah risiko yang **berlawanan** dari MASTG-TEST-0372/0374 — bukan kebocoran data keluar, melainkan aplikasi yang **mempercayai secara membuta** data yang dikendalikan "responder" implicit intent eksternal (pola confused deputy), dengan dua vektor independen yang harus diperiksa terpisah: skema URI `file://` yang dibuka dengan identitas proses korban, dan metadata `DISPLAY_NAME` yang bisa disusupi sekuens path traversal.*
