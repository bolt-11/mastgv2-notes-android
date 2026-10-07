# MASTG-TEST-0355 References to Unauthorized Database Access through Content Providers

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0355 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-PLATFORM |
| **Weakness** | MASWE-0018 |
| **Tipe Pengujian** | Static, Config, **Manual** |
| **Teknik terkait** | MASTG-TECH-0013, MASTG-TECH-0117 (Obtain Manifest), MASTG-TECH-0150 (Identify Exported Components) |
| **Knowledge terkait** | MASTG-KNOW-0020 (IPC Mechanisms), MASTG-KNOW-0117 (Android ContentProvider) |
| **Best Practice terkait** | MASTG-BEST-0049 (Restrict and Validate Access to Exported Content Providers) |
| **Test terkait** | **MASTG-TEST-0339** (SQL Injection in Content Providers) — dokumen terkait dalam seri riset ini; test ini menyasar **akses tanpa izin**, TEST-0339 menyasar **injeksi setelah akses diperoleh** — keduanya sering muncul bersamaan pada provider yang sama |
| **Rule resmi** | Dua rule pasangan — ditemukan **celah logika signifikan**, lihat §1.4 |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Kutipan overview resmi MASTG:

> *"This test checks whether the app exposes content providers that can be accessed by other apps without appropriate permission enforcement... If a content provider is exported (android:exported="true") without these permissions, any app on the device can query the underlying database to retrieve sensitive data such as user PII, account details, or internal app configurations."*

Berbeda dari MASTG-TEST-0339 yang menyasar **bagaimana** query dibangun (rentan injeksi atau tidak), test ini menyasar pertanyaan yang lebih fundamental: **siapa saja** yang **boleh** mengakses provider tersebut sama sekali. Sebuah provider bisa saja memakai parameterized query yang sempurna (lulus TEST-0339) namun tetap menjadi kebocoran data serius bila **siapa pun** aplikasi di perangkat dapat memanggilnya tanpa izin apa pun.

### 1.2 Nuansa Penting: `protectionLevel="normal"` Bukan Perlindungan Nyata

Poin kedua dari overview yang sering terlewat penguji pemula:

> *"The same applies when no protection level is configured and becomes automatically android:protectionLevel="normal", which is granting access automatically to any requesting app."*

Ini berarti **sekadar mendeklarasikan `android:readPermission`** tidak otomatis berarti provider tersebut aman — bila **permission custom** yang dirujuk tersebut tidak secara eksplisit memberi `protectionLevel="signature"` (atau level lain yang lebih kuat), permission tersebut defaultnya `normal`, yang berarti **sistem secara otomatis memberikannya** ke aplikasi apa pun yang memintanya lewat `<uses-permission>` — tanpa persetujuan pengguna, tanpa pemeriksaan sertifikat. Secara efektif, ini **hampir setara dengan tidak ada perlindungan sama sekali**, hanya menambah satu langkah administratif (deklarasi `<uses-permission>`) yang trivial bagi aplikasi berbahaya mana pun.

### 1.3 Hierarki `protectionLevel` yang Relevan untuk Evaluasi

| `protectionLevel` | Siapa yang Memperoleh Izin | Kekuatan |
|---|---|---|
| `normal` (default bila tidak dideklarasikan) | **Siapa saja** yang meminta, otomatis diberikan | Sangat lemah — setara tidak ada perlindungan |
| `dangerous` | Memerlukan persetujuan eksplisit pengguna saat instalasi/runtime | Lemah — bergantung pengguna tidak sembarangan menyetujui |
| `signature` | **Hanya** aplikasi yang ditandatangani dengan sertifikat developer yang sama | Kuat — batasan yang solid dan tidak bergantung keputusan pengguna |

Kutipan MASTG-BEST-0049 menegaskan: *"A custom permission without an explicit protectionLevel defaults to normal. This means any app can request and typically receive it automatically, so it is a weak security boundary."*

### 1.4 Temuan Analitis Kritis: Rule Resmi Tidak Membedakan Read vs Write — Celah yang Cocok Persis dengan Kesalahan OEM Nyata

Perhatikan logika rule kedua (`mastg-android-provider-exported-without-permissions`):

```yaml
patterns:
  - pattern: <provider ... android:exported="true" ... />
  - pattern-not: <provider ... android:permission="$PERM" ... />
  - pattern-not: <provider ... android:readPermission="$PERM" ... />
  - pattern-not: <provider ... android:writePermission="$PERM" ... />
```

Rule ini hanya menyalakan alarm bila **ketiganya sekaligus tidak ada**. Konsekuensinya: **begitu salah satu** dari `readPermission`/`writePermission`/`permission` hadir — misalnya hanya `readPermission` saja — rule ini **langsung berhenti menandai** provider tersebut sebagai temuan, meski **operasi tulis (insert/update/delete) tetap sepenuhnya terbuka** tanpa perlindungan apa pun.

Ini **bukan kekhawatiran teoretis** — riset keamanan industri secara eksplisit mendokumentasikan pola kesalahan ini sebagai kejadian umum di dunia nyata:

> *"A common OEM mistake is to export a ContentProvider with a readPermission but omit writePermission. When writePermission is null, any app can call insert/update/delete if those methods are implemented."*

Artinya, penguji **tidak boleh** berhenti hanya karena Semgrep tidak menandai suatu provider — rule resmi memang secara desain **tidak dapat membedakan** kasus "keduanya terlindungi" dari kasus "hanya satu dari dua operasi terlindungi, satu lagi terbuka lebar". Validasi manual wajib memeriksa **kombinasi lengkap** ketiga atribut, bukan sekadar "apakah salah satu ada".

### 1.5 Bukti Nyata: Dari Path Traversal hingga Permission Bypass di Chipset Vendor

Beberapa kasus nyata menguatkan urgensi test ini pada berbagai tingkat kompleksitas:

> *"ESC Pocket Guidelines Application: The vulnerability... is a path traversal vulnerability that allows other applications on the device to request sensitive information. The openFile function was rewritten and no '../' filter was added, which allows read/write privileges for the files inside internal storage."*

Kasus ini menunjukkan bahwa risiko provider exported tanpa kontrol yang tepat **bukan hanya soal data database** — bisa meluas ke **akses file sistem** sepenuhnya via path traversal pada implementasi `openFile()` custom.

Pada tingkat yang lebih dalam (firmware vendor chipset), **CVE-2023-20923** menunjukkan bahwa bahkan ketika permission **sudah** dideklarasikan, implementasi yang keliru bisa menciptakan celah bypass:

> *"In exported content providers of ShannonRcs, there is a possible way to get access to protected content providers due to a permissions bypass. This could lead to local information disclosure with no additional execution privileges needed."*

Ini menegaskan prinsip "Further Validation Required" resmi (§1.6) — deklarasi permission di manifest **harus** diverifikasi efektivitasnya, bukan sekadar dicatat keberadaannya.

### 1.6 Validasi Lanjutan Resmi: Dua Pertanyaan Kunci

> *"Determine whether the declared permission uses android:protectionLevel="normal" or android:protectionLevel="dangerous", which does not guarantee that only trusted apps can access the provider. Determine whether the data exposed through the provider is sensitive."*

Ini sejalan dengan prinsip evaluasi kontekstual yang konsisten di banyak test lain dalam seri riset ini — kehadiran atribut keamanan **secara sintaksis** tidak otomatis berarti perlindungan **secara substantif**; `protectionLevel` yang lemah dan data yang tidak sensitif keduanya memengaruhi kesimpulan akhir severity.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **aapt / Androguard** | Ekstraksi `AndroidManifest.xml` (MASTG-TECH-0117) |
| **Semgrep** + dua rule resmi | Deteksi dasar provider exported tanpa permission (cakupan terbatas untuk nuansa read/write, §1.4) |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **grep/ripgrep** | Verifikasi manual kombinasi lengkap `readPermission`/`writePermission`/`permission` per provider, menutup celah §1.4 |
| **Drozer** | Verifikasi dinamis langsung — mencoba query/insert/update/delete terhadap provider exported dari aplikasi lain (tanpa permission) |
| **adb shell content** | Verifikasi cepat tanpa perlu menulis aplikasi exploit |

### 2.3 Prasyarat Lingkungan

- Analisis statis tidak butuh device/root.
- Verifikasi dinamis (Drozer/`adb shell content`) butuh device/emulator dengan aplikasi target terinstal.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0013** untuk reverse engineer aplikasi.
2. Gunakan **MASTG-TECH-0117** untuk memperoleh `AndroidManifest.xml`.
3. Gunakan **MASTG-TECH-0150** untuk mengidentifikasi provider exported dan memeriksa konfigurasi permission-nya.

### 3.2 Metode A — Semgrep dengan Rule Resmi

```bash
semgrep --config mastg-android-provider-exported-without-permissions.yml \
        --config mastg-android-provider-permission-protected.yml \
        ./AndroidManifest.xml
```

### 3.3 Metode B — grep/ripgrep untuk Verifikasi Kombinasi Lengkap Read/Write (Wajib, §1.4)

```bash
# Ekstrak seluruh elemen <provider> beserta atributnya secara lengkap
aapt dump xmltree app.apk AndroidManifest.xml | grep -A15 '<provider'
```

Untuk setiap provider `exported="true"` yang ditemukan, verifikasi manual secara eksplisit:
- Apakah `readPermission` ada? Apakah `writePermission` ada?
- Bila **hanya salah satu** ada, operasi yang tidak terlindungi (read atau write) tetap terbuka penuh.

### 3.4 Metode C — Pemeriksaan `protectionLevel` dari Permission Custom

```bash
aapt dump xmltree app.apk AndroidManifest.xml | grep -B2 -A5 '<permission'
```

Periksa apakah permission custom yang dirujuk oleh provider memakai `protectionLevel="signature"` (kuat) atau default/`normal`/`dangerous` (lemah, §1.3).

### 3.5 Metode D — Verifikasi Dinamis dengan Drozer

```bash
dz> run app.provider.info -a com.example.app
dz> run app.provider.query content://com.example.app.provider/users
dz> run app.provider.insert content://com.example.app.provider/users --string name "test"
```

Mencoba operasi read **dan** write secara terpisah untuk mengonfirmasi secara empiris apakah masing-masing benar-benar terlindungi, menutup celah yang mungkin terlewat analisis statis (§1.4).

### 3.6 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Kapan dipakai |
|---|---|---|
| **A** | Semgrep + rule resmi | Baseline, hanya menangkap kasus tanpa perlindungan sama sekali |
| **B** | grep/ripgrep manual | **Wajib** — verifikasi kombinasi lengkap read/write per provider |
| **C** | Pemeriksaan protectionLevel | Menilai kekuatan sesungguhnya dari permission yang dideklarasikan |
| **D** | Drozer | Bukti empiris paling konklusif, mencakup read dan write secara terpisah |

**Kombinasi minimum yang aku rekomendasikan:** **B (wajib, menutup celah utama) + C → D (verifikasi dinamis)**, dengan Metode A hanya sebagai triase awal.

---

### 3.7 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Evaluation:** *"The test case fails if one or more content providers are exported (android:exported="true") without declaring android:readPermission, android:writePermission, or android:permission."*

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Provider `exported="true"` **tanpa** satu pun dari `readPermission`/`writePermission`/`permission` |
| F2 | *(Temuan tambahan via validasi manual, §1.4)* Provider memiliki `readPermission` **namun tidak ada** `writePermission` (atau sebaliknya) — operasi yang tidak dicakup tetap terbuka |
| F3 | Permission yang dideklarasikan memakai `protectionLevel="normal"` (default) — secara efektif tidak memberi perlindungan nyata |

**Contoh bukti (merefleksikan pola kesalahan OEM nyata §1.4):**

```xml
<provider
    android:name=".UserDataProvider"
    android:authorities="com.example.app.userdata"
    android:exported="true"
    android:readPermission="com.example.app.permission.READ_USER_DATA" />
<!-- writePermission TIDAK dideklarasikan -->
```

Interpretasi: operasi baca terlindungi, namun `insert()`/`update()`/`delete()` sepenuhnya terbuka untuk aplikasi apa pun di perangkat. **FAIL** — meski tidak tertangkap rule Semgrep resmi (§1.4).

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Provider diset `exported="false"` secara eksplisit (sesuai rekomendasi MASTG-BEST-0049), **atau** |
| P2 | Provider exported **dengan** `readPermission` **dan** `writePermission` (atau `permission` yang mencakup keduanya) yang dideklarasikan dengan `protectionLevel="signature"` |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Jangan berhenti pada hasil Semgrep mentah** — sesuai §1.4, rule resmi tidak dapat membedakan kasus read-only-protected dari kasus fully-protected; verifikasi manual kombinasi lengkap wajib dilakukan.

2. **Selalu lacak `protectionLevel` dari permission yang dirujuk** — permission custom yang ada namun `normal` secara efektif setara tidak ada perlindungan (§1.2-1.3).

3. **Pertimbangkan juga implementasi `openFile()` custom** — sesuai kasus nyata ESC Pocket Guidelines (§1.5), provider berbasis file rentan terhadap path traversal terlepas dari konfigurasi permission; audit kode implementasi, bukan hanya manifest.

4. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | Exported tanpa permission apa pun, data sensitif (PII, kredensial) | **Tinggi** |
   | Salah satu dari read/write terlindungi, satu lagi terbuka (§1.4) | **Tinggi** (write tanpa kontrol = risiko integritas data + potensi SQL injection, lihat TEST-0339) |
   | Permission ada namun `protectionLevel="normal"` | **Sedang-Tinggi** |
   | `protectionLevel="signature"` diterapkan dengan benar, atau non-exported | **Bukan temuan** |

5. **Dokumentasikan:** nama provider, status exported, atribut permission lengkap (read/write/kombinasi), `protectionLevel` permission yang dirujuk, dan jenis data yang terekspos.

---

## 4. Rekomendasi Perbaikan

### 4.1 Non-Exported Bila Tidak Perlu Diakses Aplikasi Lain (Sesuai MASTG-BEST-0049)

```xml
<provider
    android:name=".UserDataProvider"
    android:authorities="com.example.app.userdata"
    android:exported="false" />
```

### 4.2 Lindungi Read DAN Write Secara Terpisah dengan Protection Level Kuat

```xml
<provider
    android:name=".UserDataProvider"
    android:authorities="com.example.app.userdata"
    android:exported="true"
    android:readPermission="com.example.app.permission.READ_USER_DATA"
    android:writePermission="com.example.app.permission.WRITE_USER_DATA" />

<permission
    android:name="com.example.app.permission.READ_USER_DATA"
    android:protectionLevel="signature" />
<permission
    android:name="com.example.app.permission.WRITE_USER_DATA"
    android:protectionLevel="signature" />
```

### 4.3 Gunakan FileProvider dengan Scope Sempit untuk Berbagi File

```xml
<provider
    android:name="androidx.core.content.FileProvider"
    android:authorities="com.example.app.fileprovider"
    android:exported="false"
    android:grantUriPermissions="true">
    <meta-data android:name="android.support.FILE_PROVIDER_PATHS" android:resource="@xml/file_paths" />
</provider>
```

### 4.4 Checklist Remediasi

- [ ] Provider yang tidak perlu diakses aplikasi lain diset `exported="false"`
- [ ] Provider exported yang diperlukan melindungi **read DAN write** secara terpisah dan lengkap
- [ ] Permission custom yang dirujuk memakai `protectionLevel="signature"`, bukan default `normal`
- [ ] Implementasi `openFile()` custom (bila ada) divalidasi terhadap path traversal
- [ ] Diverifikasi secara dinamis dengan Drozer untuk operasi read dan write secara terpisah

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0355 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0355.md)
- [MASTG-TEST-0339: SQL Injection in Content Providers (dokumen terkait dalam seri riset ini)](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0339/)
- [MASTG-KNOW-0020: Inter-Process Communication (IPC) Mechanisms](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0020/)
- [MASTG-KNOW-0117: Android ContentProvider](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CODE/MASTG-KNOW-0117/)
- [MASTG-BEST-0049: Restrict and Validate Access to Exported Content Providers](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0049.md)

### 5.2 Riset dan Kasus Nyata

- [Oversecured: Content Providers and the Potential Weak Spots They Can Have](https://oversecured.com/blog/content-providers-and-the-potential-weak-spots-they-can-have)
- [Trend Micro: ContentProvider Path Traversal Flaw on ESC App Reveals Info](https://www.trendmicro.com/en_us/research/20/j/contentprovider-path-traveral-flaw-on-esc-app-reveals-info.html)
- [NVD: CVE-2023-20923 — ShannonRcs Content Provider Permission Bypass](https://nvd.nist.gov/vuln/detail/CVE-2023-20923)
- [CWE-926: Improper Export of Android Application Components](https://cwe.mitre.org/data/definitions/926.html)
- [Guardsquare: Security Risks of Exposed Directories in Android FileProvider](https://www.guardsquare.com/blog/android-fileprovider-directories-security-risks)

### 5.3 Dokumentasi Tools

- [Semgrep Documentation](https://semgrep.dev/docs/)
- [Drozer — Android Security Assessment Framework](https://github.com/WithSecureLabs/drozer)

---

*Dokumen ini disusun berdasarkan konten resmi OWASP MASTG (`tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0355.md`, `MASTG-KNOW-0020/0117`, `MASTG-BEST-0049`), analisis dua rule resmi, serta riset industri (Oversecured) yang mendokumentasikan pola kesalahan OEM nyata, dan kasus CVE konkret (ESC Pocket Guidelines path traversal, CVE-2023-20923 ShannonRcs permission bypass). Nuansa metodologis terpenting: rule resmi hanya menandai provider yang **sama sekali tidak** memiliki satu pun dari ketiga atribut permission — ia tidak dapat mendeteksi kasus di mana hanya `readPermission` dideklarasikan sementara `writePermission` dibiarkan kosong, sebuah pola kesalahan yang menurut riset industri justru **umum terjadi** di ekosistem OEM Android nyata. Validasi manual terhadap kombinasi lengkap read/write, beserta pemeriksaan `protectionLevel` dari setiap permission yang dirujuk, adalah langkah wajib yang tidak dapat digantikan sepenuhnya oleh hasil Semgrep.*
