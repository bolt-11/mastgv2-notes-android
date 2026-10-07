# MASTG-TEST-0357 References to Oversharing of File-Based Content Providers

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0357 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-PLATFORM |
| **Weakness** | MASWE-0018 |
| **Tipe Pengujian** | Static, Config, Code, **Manual** |
| **Teknik terkait** | MASTG-TECH-0013, MASTG-TECH-0159 (Verify Usage of File-Based Content Providers), MASTG-TECH-0014, MASTG-TECH-0023 |
| **Knowledge terkait** | MASTG-KNOW-0020, MASTG-KNOW-0117 |
| **Best Practice terkait** | MASTG-BEST-0049 (Restrict and Validate Access to Exported Content Providers) |
| **Test terkait** | MASTG-TEST-0355/0356 — dokumen terkait dalam seri riset ini; test-test tersebut menyasar provider **database-backed**, test ini secara spesifik menyasar provider **file-backed** (`FileProvider`) |
| **Rule resmi** | `mastg-android-fileprovider-broad-scope.yml` — 2 pola, ditemukan **kesenjangan cakupan**, lihat §1.4 |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Kutipan overview resmi MASTG:

> *"If the app exports an Android content provider without enforcing access restrictions, external callers may open private files through content:// URIs. This test checks whether exported providers expose sensitive stored data to callers that don't hold the required permissions."*

Test ini adalah pelengkap spesifik untuk `FileProvider` dari rangkaian test content provider dalam seri riset ini. Sudah dibahas di dokumen **MASTG-TEST-0355 §4.3** bahwa `FileProvider` direkomendasikan sebagai **mekanisme yang lebih aman** untuk berbagi file dibanding provider database kustom — namun keamanannya **sepenuhnya bergantung** pada seberapa sempit konfigurasi path yang didefinisikan di `res/xml/file_paths.xml`. Test ini secara khusus menyasar kesalahan konfigurasi tersebut.

### 1.2 Empat Pola Konfigurasi Berbahaya yang Eksplisit Disebut Evaluasi Resmi

> **Evaluation:** *"The test case fails if the app exports a FileProvider and if the provider's path configuration allows access outside the intended shared directory (for example, via `<root-path>`, `path="/"`, `path="."`, or `path=""`)."*

| Pola | Dampak |
|---|---|
| `<root-path>` | Memetakan **seluruh root filesystem** (`/`) ke namespace provider |
| `path="/"` | Setara secara fungsional dengan `<root-path>` pada elemen path manapun |
| `path="."` | Memetakan **seluruh direktori dasar** (mis. seluruh `filesDir`) — termasuk file yang ditambahkan nanti seperti token autentikasi, database, log |
| `path=""` | String kosong — secara fungsional setara dengan memetakan direktori dasar itu sendiri tanpa pembatasan subdirektori |

MASTG-BEST-0049 memberi penjelasan paling tajam tentang mengapa `path="."` berbahaya bahkan lebih dari yang terlihat sekilas:

> *"Setting path="." on any path element exposes the entire corresponding directory, including files added later such as authentication tokens, databases, or logs."*

Frasa *"files added later"* ini krusial — risiko konfigurasi ini **tidak statis**. Bahkan bila developer memverifikasi hari ini bahwa direktori yang dipetakan hanya berisi file non-sensitif, **risiko ini tetap laten** dan akan terwujud secara otomatis begitu developer lain di masa depan menyimpan file sensitif apa pun ke direktori yang sama tanpa menyadari bahwa direktori tersebut sudah "terhubung" ke FileProvider yang exported.

### 1.3 Dua Vektor Risiko yang Berbeda: Konfigurasi Path vs Input Attacker-Controlled

Overview dan MASTG-TECH-0159 mengidentifikasi **dua jenis analisis yang berbeda**, keduanya perlu dilakukan:

> *"Determine whether `FileProvider.getUriForFile()` is called with attacker-controlled input (for example, values derived from URI query parameters or user input)."*

Ini adalah vektor risiko **kedua** yang terpisah dari masalah konfigurasi path (§1.2) — bahkan bila `file_paths.xml` dikonfigurasi dengan benar secara sempit (mis. hanya `files-path name="reports" path="reports/"`), aplikasi **masih bisa rentan** bila argumen `File` yang diteruskan ke `FileProvider.getUriForFile()` berasal dari **input yang bisa dikontrol penyerang** — misalnya nama file yang diterima dari parameter URI deep link, lalu dipakai langsung tanpa validasi untuk membangun path `File` yang mungkin mengandung sekuens `../` untuk keluar dari subdirektori yang dimaksud (meski `FileProvider` secara native menolak path traversal yang mencoba keluar dari subtree yang dideklarasikan, kombinasi kelemahan lain di sekitarnya tetap bisa membuka celah).

### 1.4 Temuan Analitis: Rule Resmi Tidak Mencakup `path=""` dan `path="/"` Secara Eksplisit

Perhatikan pola yang dicakup rule `mastg-android-fileprovider-broad-scope.yml`:

```yaml
pattern-either:
  - pattern: <files-path ... path="." ... />
  - pattern: <cache-path ... path="." ... />
  - pattern: <external-path ... path="." ... />
  - pattern: <external-files-path ... path="." ... />
  - pattern: <external-cache-path ... path="." ... />
```

Dan rule kedua hanya menyasar `<root-path>`. **Kedua rule ini secara eksplisit hanya mencocokkan literal `path="."` dan elemen `<root-path>`** — **tidak ada pola** yang menyasar `path="/"` atau `path=""` secara terpisah, meski **keduanya disebut secara eksplisit** di bagian Evaluation resmi test ini sendiri (§1.2) sebagai pola yang sama berbahayanya. Ini adalah kesenjangan cakupan yang konsisten dengan pola yang berulang kali ditemukan dalam seri riset ini — rule resmi sering tidak mencakup **seluruh** varian yang disebutkan di teks evaluasi resminya sendiri.

Secara teknis, `path=""` dan `path="."` kemungkinan **berperilaku sama** (keduanya memetakan direktori dasar tanpa subdirektori tambahan), namun `path="/"` dapat memiliki interpretasi berbeda tergantung parser Android — penguji tidak boleh berasumsi rule resmi mencakup kasus ini tanpa verifikasi, dan harus menambahkan pencarian manual untuk kedua varian yang tidak tercakup.

### 1.5 Bukti Nyata: CVE Konkret dan Temuan pada Aplikasi Raksasa (Google, TikTok)

Riset industri menunjukkan bahwa kesalahan konfigurasi ini bukan risiko teoretis, melainkan kelas kerentanan yang **terus ditemukan** pada aplikasi populer, termasuk dari vendor besar sekalipun:

> *"Oversecured has found examples of these vulnerabilities in Google, TikTok, and many other apps."*

Fakta bahwa kerentanan kelas ini ditemukan bahkan pada aplikasi dari **Google sendiri** (pembuat platform Android) menegaskan betapa mudahnya kesalahan konfigurasi `file_paths.xml` terjadi, bahkan oleh tim engineering dengan pemahaman platform yang sangat mendalam — ini seharusnya menjadi sinyal kuat bagi tim lain bahwa audit eksplisit terhadap konfigurasi ini **tidak boleh diasumsikan "pasti sudah benar"** hanya karena developernya berpengalaman.

Kasus nyata CVE yang terdokumentasi secara spesifik:

> *"An issue in vicohome v.2.22.7 allows a remote attacker to execute arbitrary code via the xml/file_paths.xml component (CVE-2023-48984)."*

Dampak CVE ini — **remote code execution**, bukan sekadar information disclosure — menunjukkan bahwa oversharing FileProvider, bila dikombinasikan dengan kelemahan lain (mis. file yang diekspos bisa berupa file konfigurasi/executable yang kemudian dieksekusi lewat jalur lain), dapat bereskalasi jauh melampaui sekadar kebocoran data biasa.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **aapt / Androguard** | Ekstraksi manifest untuk identifikasi `FileProvider` exported (MASTG-TECH-0159) |
| **jadx** | Dekompilasi untuk tracing argumen `getUriForFile()` (MASTG-TECH-0013, MASTG-TECH-0014) |
| **Semgrep** + rule resmi `mastg-android-fileprovider-broad-scope.yml` | Deteksi `path="."` dan `<root-path>` (cakupan terbatas, §1.4) |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **grep/ripgrep** | Menutup celah cakupan rule resmi — mencari `path=""`/`path="/"` secara eksplisit (§1.4) |
| **Drozer / adb shell content** | Verifikasi dinamis — mencoba membuka URI `content://` dengan path yang diduga sensitif untuk mengonfirmasi akses sesungguhnya |

### 2.3 Prasyarat Lingkungan

- Analisis statis tidak butuh device/root.
- Verifikasi dinamis butuh device/emulator dengan aplikasi target terinstal.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0013** untuk reverse engineer aplikasi.
2. Gunakan **MASTG-TECH-0159** untuk mengidentifikasi provider file-based exported dan memeriksa konfigurasi path-nya.
3. Gunakan **MASTG-TECH-0014** untuk mencari API yang relevan.

### 3.2 Metode A — Semgrep dengan Rule Resmi

```bash
semgrep --config mastg-android-fileprovider-broad-scope.yml ./res/xml
```

### 3.3 Metode B — grep/ripgrep untuk Menutup Celah path="" dan path="/"

```bash
R=./res/xml

# Pola yang tercakup rule resmi
rg -n 'path="\."' $R
rg -n '<root-path' $R

# Pola TIDAK tercakup rule resmi, tapi eksplisit disebut evaluasi resmi (§1.2)
rg -n 'path=""' $R
rg -n 'path="/"' $R
```

### 3.4 Metode C — Lacak Argumen getUriForFile() untuk Input Attacker-Controlled (Sesuai §1.3)

```bash
D=./decompiled/sources
rg -n 'FileProvider.getUriForFile\(' $D -A3
```

Untuk setiap hasil, lacak balik variabel `File` yang diteruskan — apakah berasal dari `Intent` extras, parameter URI deep link, atau input pengguna lain, sesuai MASTG-TECH-0159.

### 3.5 Metode D — Review Manual (Wajib, Sesuai MASTG-TECH-0023)

Untuk setiap `FileProvider` exported yang ditemukan:

1. Periksa `android:permission` dan `protectionLevel`-nya (sesuai prinsip MASTG-TEST-0355 yang sudah dibahas).
2. Verifikasi direktori fisik yang dipetakan oleh path yang dideklarasikan — apa isinya saat ini, dan apa kemungkinan isinya di masa depan (§1.2 "files added later").

### 3.6 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Kapan dipakai |
|---|---|---|
| **A** | Semgrep + rule resmi | Baseline, mencakup `path="."` dan `<root-path>` |
| **B** | grep/ripgrep manual | **Wajib** — menutup celah `path=""`/`path="/"` |
| **C** | Lacak getUriForFile() | Menangkap vektor kedua: input attacker-controlled |
| **D** | Review manual | Menilai permission/protectionLevel dan risiko laten isi direktori |

**Kombinasi minimum yang aku rekomendasikan:** **A + B (wajib) + C**, dilanjutkan **D** untuk penilaian akhir.

---

### 3.7 Kriteria Evaluasi: Positive Case & Negative Case

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | `FileProvider` exported dengan konfigurasi path `<root-path>`, `path="/"`, `path="."`, atau `path=""` |
| F2 | *(Vektor tambahan, §1.3)* `getUriForFile()` dipanggil dengan argumen `File` yang berasal dari input attacker-controlled tanpa validasi |

**Contoh bukti (merefleksikan pola nyata §1.5):**

```xml
<!-- res/xml/file_paths.xml -->
<paths>
    <files-path name="all_files" path="." />
</paths>
```

```xml
<provider
    android:name="androidx.core.content.FileProvider"
    android:authorities="com.example.app.fileprovider"
    android:exported="false"
    android:grantUriPermissions="true">
    <meta-data android:name="android.support.FILE_PROVIDER_PATHS" android:resource="@xml/file_paths" />
</provider>
```

Interpretasi: meski provider tidak exported, `path="."` memetakan **seluruh** `filesDir` — bila aplikasi memberikan grant URI ke aplikasi lain melalui `Intent`, penerima bisa mengakses **file apa pun** di `filesDir`, bukan hanya file yang dimaksud untuk dibagikan. **FAIL**.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Seluruh path element memakai subdirektori spesifik dan sempit (`path="reports/"`, dsb.), **dan** |
| P2 | `getUriForFile()` hanya dipanggil dengan argumen `File` yang berasal dari sumber tepercaya/tervalidasi |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Jangan hanya mengandalkan rule resmi** — sesuai §1.4, tambahkan pencarian manual untuk `path=""`/`path="/"` yang disebut eksplisit di evaluasi resmi namun tidak tercakup rule Semgrep.

2. **Nilai risiko laten, bukan hanya isi direktori saat ini** — sesuai §1.2, path yang luas tetap berisiko tinggi meski saat ini direktori yang dipetakan "kebetulan" hanya berisi file non-sensitif; evaluasi harus mempertimbangkan risiko masa depan dari penambahan file baru ke direktori yang sama.

3. **Periksa dua vektor secara independen** — konfigurasi path yang sempit namun dipasangkan dengan input attacker-controlled di `getUriForFile()` (§1.3) tetap berisiko meski lolos pemeriksaan path.

4. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | `path="."`/`<root-path>` pada provider exported dengan grant URI ke aplikasi lain | **Tinggi** |
   | Path sempit namun `getUriForFile()` menerima input attacker-controlled | **Tinggi** |
   | Path sempit, input tervalidasi, permission memadai | **Bukan temuan** |

5. **Dokumentasikan:** konfigurasi `file_paths.xml` lengkap, status exported provider, hasil tracing argumen `getUriForFile()`, dan isi direktori fisik yang dipetakan saat audit dilakukan.

---

## 4. Rekomendasi Perbaikan

### 4.1 Gunakan Subdirektori Spesifik, Bukan Direktori Dasar Penuh

```xml
<!-- SEBELUM -->
<files-path name="all_files" path="." />

<!-- SESUDAH -->
<files-path name="reports" path="reports/" />
```

### 4.2 Validasi Input Sebelum Diteruskan ke getUriForFile()

```java
File file = new File(context.getFilesDir(), "reports/" + sanitizeFileName(userInput));
if (!file.getCanonicalPath().startsWith(reportsDir.getCanonicalPath())) {
    throw new SecurityException("Path traversal terdeteksi");
}
Uri uri = FileProvider.getUriForFile(context, AUTHORITY, file);
```

### 4.3 Checklist Remediasi

- [ ] Tidak ada `path="."`, `path=""`, `path="/"`, atau `<root-path>` di `file_paths.xml`
- [ ] Setiap path element memetakan subdirektori spesifik yang sempit
- [ ] `getUriForFile()` tidak menerima argumen `File` dari input attacker-controlled tanpa validasi
- [ ] Provider diset `exported="false"` dengan `grantUriPermissions="true"` untuk berbagi terkontrol (sesuai MASTG-BEST-0049)

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0357 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0357.md)
- [MASTG-TEST-0355/0356 (dokumen terkait dalam seri riset ini)](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0355/)
- [MASTG-TECH-0159: Verify Usage of File-Based Content Providers](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0159/)
- [MASTG-BEST-0049: Restrict and Validate Access to Exported Content Providers](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0049.md)

### 5.2 Riset dan Kasus Nyata

- [Android Developers: Improperly Exposed Directories to FileProvider](https://developer.android.com/privacy-and-security/risks/file-providers)
- [Guardsquare: Security Risks of Exposed Directories in Android FileProvider](https://www.guardsquare.com/blog/android-fileprovider-directories-security-risks)
- [Oversecured: Android Security Checklist — Theft of Arbitrary Files](https://blog.oversecured.com/Android-security-checklist-theft-of-arbitrary-files/)
- [GitHub: CVE-2023-48984 — vicohome FileProvider RCE](https://github.com/l00neyhacker/CVE-2023-48984)

### 5.3 Dokumentasi Tools

- [Semgrep Documentation](https://semgrep.dev/docs/)
- [FileProvider API Reference](https://developer.android.com/reference/androidx/core/content/FileProvider)

---

*Dokumen ini disusun berdasarkan konten resmi OWASP MASTG (`tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0357.md`, `MASTG-TECH-0159`, `MASTG-BEST-0049`), analisis rule `mastg-android-fileprovider-broad-scope.yml`, serta riset industri (Oversecured, Guardsquare) yang mendokumentasikan kerentanan kelas ini pada aplikasi raksasa (Google, TikTok) dan CVE konkret (CVE-2023-48984, eskalasi hingga RCE). Nuansa metodologis terpenting: evaluasi resmi test ini secara eksplisit menyebut empat pola berbahaya (`<root-path>`, `path="/"`, `path="."`, `path=""`), namun rule Semgrep resmi hanya mencakup dua dari empat pola tersebut (`path="."` dan `<root-path>`) — pencarian manual terhadap `path=""`/`path="/"` adalah langkah wajib yang tidak dapat digantikan hasil otomatis. Risiko konfigurasi path yang luas juga bersifat laten — berbahaya tidak hanya karena isi direktori saat ini, tapi karena file sensitif apa pun yang ditambahkan di masa depan ke direktori yang sama akan otomatis terekspos.*
