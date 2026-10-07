# MASTG-TEST-0262 References to Backup Configurations Not Excluding Sensitive Data

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0262 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-STORAGE (MASVS-STORAGE-2) |
| **Weakness** | MASWE-0006 — *Sensitive Data Not Excluded From Backup* |
| **Tipe Pengujian** | Static, Code |
| **Profile** | L1, L2, P |
| **Knowledge** | MASTG-KNOW-0050 (Backups) |
| **Best Practice** | MASTG-BEST-0004 |
| **Teknik terkait** | MASTG-TECH-0117 (Obtaining AndroidManifest), MASTG-TECH-0150 (Analyzing AndroidManifest), MASTG-TECH-0007 (Extract Layout/Resource Files) |
| **Test terkait** | **MASTG-TEST-0216** (Sensitive Data Not Excluded From Backup) — counterpart **dinamis**; overview resmi test tersebut secara eksplisit menyatakan *"See MASTG-TEST-0262 for a static analysis counterpart"* |
| **Demo terkait** | — (tidak ada) |
| **Rule resmi** | **Dua** rule: `mastg-android-backup-manifest-allow-backup` dan `mastg-android-backup-manifest-backup-rules` — keduanya hanya memeriksa **keberadaan** atribut, bukan **isi/kecukupan** file exclude rules (lihat §3.2) |
| **CWE terkait** | CWE-530 (Exposure of Backup File to an Unauthorized Control Sphere), CWE-200 |

---

## 1. Penjelasan

### 1.1 Hubungan dengan MASTG-TEST-0216

Test ini adalah **counterpart statis** dari **MASTG-TEST-0216** yang sudah dibahas mendalam sebelumnya dalam seri riset dokumen ini (termasuk 7 metode multi-tool: `bmgr`/local transport, `adb backup`, Android Backup Extractor, semgrep, apktool+grep/aapt2/MobSF/drozer, verifikasi cloud/device-transfer, dan pengujian integritas restore). Overview resmi MASTG-TEST-0216 sendiri secara eksplisit merujuk balik ke test ini:

> *"See MASTG-TEST-0262 for a static analysis counterpart."*

Karena banyak metodologi inti (mekanisme `adb backup`, Android Backup Extractor, rule semgrep dasar) **sudah dibahas rinci** di dokumen MASTG-TEST-0216, dokumen ini berfokus pada **detail evaluasi statis murni** — pembacaan `AndroidManifest.xml` dan file `backup_rules.xml`/`data_extraction_rules.xml` — tanpa perlu menjalankan aplikasi atau device sama sekali.

### 1.2 Dua Jalur Backup, Dua Skema Konfigurasi Berbeda

Overview resmi menjelaskan **dua pendekatan backup** yang tersedia di Android, dengan mekanisme exclude yang berbeda:

| Pendekatan | Sejak Versi | Mekanisme Exclude |
|---|---|---|
| **Auto Backup** (direkomendasikan) | Android 6.0 (API 23)+ | File XML deklaratif (`backup_rules.xml`/`data_extraction_rules.xml`) dengan tag `<exclude>` |
| **Key-Value Backup** | Android 2.2 (API 8)+ | `BackupAgent`/`BackupAgentHelper` — logika eksklusi ditentukan **secara terprogram** di kode Java/Kotlin, bukan file XML deklaratif |

Auto Backup adalah pendekatan yang **direkomendasikan** karena diaktifkan secara default dan tidak memerlukan kerja implementasi tambahan — namun inilah yang membuatnya juga **paling berisiko** bila developer tidak sadar untuk secara eksplisit mengecualikan data sensitif, karena defaultnya justru **menyertakan semuanya**. Key-Value Backup, sebaliknya, menuntut developer secara eksplisit menulis kode untuk menentukan apa yang di-backup — desain yang secara tidak langsung memaksa kesadaran, tapi jarang dipakai pada aplikasi modern.

### 1.3 Skema File Berdasarkan Versi Android — Nuansa yang Mudah Terlewat

Ini poin krusial yang membedakan test ini dari evaluasi backup sederhana: **nama atribut manifest dan file konfigurasi berbeda tergantung versi Android target**:

| Versi Android | Atribut Manifest | Nama File Konvensional |
|---|---|---|
| Android 11 (API 30) ke bawah | `android:fullBackupContent` | `backup_rules.xml` |
| Android 12 (API 31) ke atas | `android:dataExtractionRules` | `data_extraction_rules.xml` |

Aplikasi yang menargetkan rentang API luas (mis. `minSdkVersion` rendah, `targetSdkVersion` tinggi) **idealnya perlu mendeklarasikan keduanya sekaligus** — satu untuk device lawas, satu untuk device modern. Kesalahan umum yang perlu diwaspadai penguji: developer yang hanya memperbarui `data_extraction_rules.xml` (mengikuti versi terbaru) namun **melupakan** `backup_rules.xml` yang lama — meninggalkan celah eksklusi yang tidak konsisten untuk pengguna dengan device Android 11 ke bawah.

### 1.4 Parameter `cloud-backup` vs `device-transfer` — Granularitas yang Sering Terlewat

Ini nuansa teknis yang **secara eksplisit** disorot overview resmi dan sangat mudah luput dari pemeriksaan sekilas:

> *"The `cloud-backup` and `device-transfer` parameters can be used to exclude files from cloud backups and device-to-device transfers, respectively."*

Sejak `dataExtractionRules` (Android 12+), Android memisahkan **dua skenario transfer data yang berbeda**:

- **`cloud-backup`**: data yang disinkronkan ke akun Google Drive pengguna (dapat dipulihkan di device baru mana pun yang login dengan akun sama).
- **`device-transfer`**: data yang dipindahkan langsung antar-perangkat (mis. lewat kabel/Wi-Fi Direct saat setup device baru), **tanpa** melibatkan cloud sama sekali.

Contoh konfigurasi yang membedakan keduanya:

```xml
<data-extraction-rules>
    <cloud-backup>
        <exclude domain="sharedpref" path="auth_tokens.xml"/>
    </cloud-backup>
    <device-transfer>
        <exclude domain="sharedpref" path="auth_tokens.xml"/>
    </device-transfer>
</data-extraction-rules>
```

**Celah evaluasi yang sering terlewat**: developer yang hanya mengecualikan file dalam blok `<cloud-backup>` tapi **lupa** menyertakan pengecualian yang sama di blok `<device-transfer>` (atau sebaliknya) akan tetap membocorkan data sensitif lewat jalur yang tidak dikecualikan — meski secara sekilas file `data_extraction_rules.xml` **tampak** sudah benar karena mengandung tag `<exclude>` untuk file yang dimaksud. Penguji **wajib memeriksa kedua blok secara terpisah**, bukan hanya memastikan tag `<exclude>` untuk file terkait "ada di suatu tempat" dalam file tersebut.

### 1.5 Empat Kondisi FAIL yang Harus Dibaca sebagai Rangkaian OR, Bukan AND Tunggal

Klausul Evaluation resmi test ini memiliki struktur yang perlu dibaca hati-hati:

> *"The test case fails if the app allows sensitive data to be backed up. Specifically, if the following conditions are met: `android:allowBackup="true"`... `fullBackupContent` isn't declared (Android 11-)... `dataExtractionRules` isn't declared (Android 12+)... `backup_rules.xml`/`data_extraction_rules.xml` aren't present or don't exclude all sensitive files."*

Prasyarat mutlak untuk FAIL adalah **`allowBackup="true"`** (atau tidak dideklarasikan sama sekali — default-nya `true`, ditegaskan MASTG-KNOW-0050: *"When this attribute is unavailable, the allowBackup setting is enabled by default"*). Setelah prasyarat ini terpenuhi, kondisi FAIL berikutnya bercabang tergantung versi Android yang relevan (fullBackupContent **atau** dataExtractionRules, bergantung versi target) **atau** — bahkan bila atribut file rules sudah dideklarasikan — file rules tersebut **tidak ada** atau **tidak mengecualikan semua file sensitif** (§1.4 tentang cakupan cloud-backup/device-transfer).

---

## 2. Tools yang Dipakai untuk Pengujian

Karena metodologi inti (semgrep, apktool, aapt2, drozer) sudah dibahas mendalam di dokumen MASTG-TEST-0216, bagian ini menyoroti tools yang relevan **khusus untuk evaluasi statis presisi** test ini.

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **jadx --no-src / apktool** | Ekstraksi `AndroidManifest.xml` dan resource `res/xml/*.xml` |
| **xmlstarlet / yq** | Parsing terstruktur untuk membedakan isi blok `<cloud-backup>` vs `<device-transfer>` secara presisi (§1.4) |
| **semgrep** | Rule resmi sebagai baseline keberadaan atribut |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **CodeQL** | Untuk aplikasi yang memakai Key-Value Backup — menelusuri implementasi `BackupAgent`/`onBackup()` untuk memverifikasi data sensitif memang dikecualikan secara terprogram |
| **MobSF** | Menampilkan status `allowBackup` dan keberadaan file rules dalam laporan Manifest Analysis |
| **androguard** | Parsing manifest terprogram untuk audit skala besar/CI |

### 2.3 Prasyarat Lingkungan

- **Tidak butuh device/root** — sepenuhnya dapat dilakukan dari file APK.
- **Ekstrak KEDUA file konfigurasi** (`backup_rules.xml` DAN `data_extraction_rules.xml`) bila keduanya ada — jangan berasumsi hanya satu yang relevan tanpa memeriksa `minSdkVersion`/`targetSdkVersion` aplikasi (§1.3).

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0117** untuk memperoleh `AndroidManifest.xml`.
2. Gunakan **MASTG-TECH-0150** untuk memperoleh flag dan atribut relevan.
3. Gunakan **MASTG-TECH-0007** untuk mengekstrak `backup_rules.xml`/`data_extraction_rules.xml`.

### 3.2 Metode A — Rule Semgrep Resmi + Verifikasi Isi File *(rule resmi ada, tapi hanya cek keberadaan)*

```yaml
rules:
  - id: mastg-android-backup-manifest-allow-backup
    severity: WARNING
    languages: [xml]
    message: "[MASVS-STORAGE-2] allowBackup detected as $ARG."
    patterns:
      - pattern: 'android:allowBackup="$ARG"'
  - id: mastg-android-backup-manifest-backup-rules
    severity: WARNING
    languages: [xml]
    message: "[MASVS-STORAGE-2] Backup rules detected."
    pattern-either:
      - pattern: 'android:fullBackupContent="@xml/backup_rules"'
      - pattern: 'android:dataExtractionRules="@xml/data_extraction_rules"'
```

```bash
semgrep --config https://raw.githubusercontent.com/OWASP/mastg/master/rules/mastg-android-backup-manifest.yml ./out/resources/AndroidManifest.xml
```

**Celah cakupan**: kedua rule ini **hanya mendeteksi keberadaan atribut/pola nama file**, sama sekali **tidak memvalidasi isi** `backup_rules.xml`/`data_extraction_rules.xml` — yaitu apakah file tersebut benar-benar mengecualikan **seluruh** file sensitif (dan mencakup **kedua** blok `cloud-backup`/`device-transfer`, §1.4). Sebuah aplikasi bisa lolos kedua rule ini (atribut ada, nama file sesuai konvensi) namun tetap FAIL secara substansi bila isi file rules-nya kosong atau tidak lengkap.

### 3.3 Metode B — Ekstraksi dan Parsing Terstruktur Isi File Rules

```bash
jadx --no-src -d ./out target-app.apk

# 1. Cek allowBackup
grep -o 'android:allowBackup="[^"]*"' ./out/resources/AndroidManifest.xml

# 2. Cek atribut file rules SESUAI versi target
grep -o 'android:fullBackupContent="[^"]*"\|android:dataExtractionRules="[^"]*"' ./out/resources/AndroidManifest.xml

# 3. Ekstrak dan parse isi file rules secara terstruktur
BACKUP_RULES=./out/resources/res/xml/backup_rules.xml
DATA_EXTRACTION=./out/resources/res/xml/data_extraction_rules.xml

echo "=== backup_rules.xml (Android 11-) ==="
[ -f "$BACKUP_RULES" ] && cat "$BACKUP_RULES" || echo "TIDAK DITEMUKAN"

echo "=== data_extraction_rules.xml (Android 12+) ==="
if [ -f "$DATA_EXTRACTION" ]; then
    echo "-- Isi blok cloud-backup --"
    xmlstarlet sel -t -c "//cloud-backup" "$DATA_EXTRACTION"
    echo "-- Isi blok device-transfer --"
    xmlstarlet sel -t -c "//device-transfer" "$DATA_EXTRACTION"
else
    echo "TIDAK DITEMUKAN"
fi
```

### 3.4 Metode C — Korelasi dengan Daftar File Sensitif Aktual Aplikasi

Langkah paling penting yang tidak bisa diotomasi murni: **daftar apa yang seharusnya dikecualikan** harus dibandingkan dengan **file yang benar-benar dibuat aplikasi** saat runtime (database, SharedPreferences, file internal):

```bash
# Jalankan aplikasi, gunakan fitur yang menyimpan data sensitif, lalu:
adb shell run-as com.target.app find /data/data/com.target.app -type f

# Bandingkan daftar file ini dengan tag <exclude> di backup_rules.xml/data_extraction_rules.xml
```

Rujuk dokumen MASTG-TEST-0216 §3 untuk metodologi lengkap verifikasi lewat backup/restore aktual (`adb backup`, Android Backup Extractor) sebagai pembuktian definitif — pendekatan statis di sini hanya memvalidasi **konfigurasi**, sedangkan MASTG-TEST-0216 memvalidasi **hasil nyata**.

### 3.5 Metode D — Verifikasi Key-Value Backup (Bila Dipakai)

```bash
rg -n 'extends BackupAgent\b|extends BackupAgentHelper\b' ./decompiled/sources/
rg -n -A20 'onBackup\(' ./decompiled/sources/ | grep -i "password\|token\|key\|secret"
```

Bila ditemukan implementasi `BackupAgent` kustom, tinjau `onBackup()` untuk memastikan data sensitif secara eksplisit **tidak** dimasukkan ke `BackupDataOutput`.

### 3.6 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Memvalidasi keberadaan? | Memvalidasi kecukupan isi? | Kapan dipakai |
|---|---|---|---|---|
| **A** | Rule semgrep resmi | ✅ | ❌ | Baseline cepat |
| **B** | Parsing terstruktur | ✅ | ✅ (isi & pemisahan blok) | **Wajib** untuk evaluasi lengkap |
| **C** | Korelasi file aktual | N/A | ✅ (paling definitif secara statis) | Sebelum menyimpulkan PASS final |
| **D** | Review kode BackupAgent | ✅ | ✅ | Khusus aplikasi Key-Value Backup |

**Kombinasi minimum yang aku rekomendasikan:** **B (parsing terstruktur kedua blok) → C (korelasi dengan file aktual aplikasi)**, dilengkapi konfirmasi dinamis via MASTG-TEST-0216 sebagai pembuktian akhir yang tidak bisa digantikan analisis statis semata.

---

### 3.7 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG** (rujuk §1.5 untuk struktur logika kondisinya).

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | `allowBackup` bernilai `true` atau tidak dideklarasikan sama sekali (default `true`), **dan** tidak ada `fullBackupContent`/`dataExtractionRules` yang relevan dengan versi target |
| F2 | Atribut file rules ada, tapi file `backup_rules.xml`/`data_extraction_rules.xml` **tidak ditemukan** di resource APK |
| F3 | File rules ada, tapi **tidak mengecualikan** file yang diketahui menyimpan data sensitif (dikonfirmasi Metode C) |
| F4 | File sensitif dikecualikan di blok `<cloud-backup>` tapi **tidak** di `<device-transfer>` (atau sebaliknya) — celah granularitas §1.4 |

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | `allowBackup="false"` secara eksplisit — cara paling sederhana dan tegas |
| P2 | `allowBackup="true"`, **dan** file rules yang sesuai versi target ada dan ditemukan mengecualikan **seluruh** file sensitif di **kedua** blok cloud-backup dan device-transfer (bila berlaku) |
| P3 | Aplikasi memakai Key-Value Backup dengan `BackupAgent` yang terverifikasi (Metode D) tidak menyertakan data sensitif |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Rule resmi hanya memvalidasi keberadaan, bukan kecukupan** — jangan simpulkan PASS hanya dari hasil semgrep kosong; verifikasi isi file rules secara manual/terstruktur (Metode B) adalah wajib.

2. **Periksa kedua blok `cloud-backup` dan `device-transfer` secara terpisah** (§1.4) — ini celah paling halus dan mudah terlewat dalam evaluasi test ini.

3. **Periksa kesesuaian versi atribut-file** (§1.3) — aplikasi dengan rentang API luas idealnya punya kedua skema (lama dan baru) secara konsisten.

4. **Korelasikan selalu dengan MASTG-TEST-0216** untuk pembuktian definitif — konfigurasi yang **tampak** benar secara statis tetap perlu diverifikasi lewat backup/restore aktual, karena kesalahan sintaks/path pada tag `<exclude>` bisa membuat pengecualian gagal berfungsi meski file konfigurasinya "ada".

5. **Severity dimodulasi** oleh sensitivitas data yang berpotensi ikut ter-backup — kredensial/kunci kriptografi jauh lebih kritis dibanding cache non-sensitif.

6. **Dokumentasikan:** status `allowBackup`, versi target aplikasi (menentukan skema mana yang relevan), isi lengkap kedua blok file rules, dan hasil korelasi dengan file aktual aplikasi.

---

## 4. Rekomendasi Perbaikan

Rujuk **dokumen MASTG-TEST-0216 §4** untuk rekomendasi mendalam. Tambahan spesifik dari sudut pandang statis:

### 4.1 Deklarasikan Kedua Skema Secara Konsisten

```xml
<application
    android:allowBackup="true"
    android:fullBackupContent="@xml/backup_rules"
    android:dataExtractionRules="@xml/data_extraction_rules">
```

```xml
<!-- data_extraction_rules.xml -->
<data-extraction-rules>
    <cloud-backup>
        <exclude domain="sharedpref" path="auth_tokens.xml"/>
        <exclude domain="database" path="secure_vault.db"/>
    </cloud-backup>
    <device-transfer>
        <exclude domain="sharedpref" path="auth_tokens.xml"/>
        <exclude domain="database" path="secure_vault.db"/>
    </device-transfer>
</data-extraction-rules>
```

### 4.2 Integrasikan ke CI/CD

```bash
#!/bin/bash
# ci-check-backup-rules-completeness.sh
DATA_EXTRACTION=./res/xml/data_extraction_rules.xml
CLOUD_EXCLUDES=$(xmlstarlet sel -t -c "//cloud-backup/exclude" "$DATA_EXTRACTION" | wc -l)
TRANSFER_EXCLUDES=$(xmlstarlet sel -t -c "//device-transfer/exclude" "$DATA_EXTRACTION" | wc -l)
if [ "$CLOUD_EXCLUDES" != "$TRANSFER_EXCLUDES" ]; then
    echo "[PERINGATAN] Jumlah exclude di cloud-backup ($CLOUD_EXCLUDES) berbeda dari device-transfer ($TRANSFER_EXCLUDES)"
fi
```

### 4.3 Checklist Remediasi

- [ ] `allowBackup` dievaluasi — diset `false` bila backup tidak diperlukan sama sekali
- [ ] Bila backup diperlukan, kedua skema (`fullBackupContent`/`dataExtractionRules`) dideklarasikan konsisten
- [ ] Kedua blok `cloud-backup` dan `device-transfer` mengecualikan file sensitif yang sama
- [ ] Daftar file sensitif aktual aplikasi dikorelasikan dengan tag `<exclude>` (Metode C)
- [ ] Verifikasi silang dengan MASTG-TEST-0216 (backup/restore aktual) sudah dilakukan
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0262 setiap penambahan penyimpanan data baru

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0262: References to Backup Configurations Not Excluding Sensitive Data](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0262/)
- [MASTG-TEST-0216: Sensitive Data Not Excluded From Backup](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0216/)
- [MASWE-0006: Sensitive Data Not Excluded From Backup](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0006/)
- [MASTG-KNOW-0050: Backups](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0050/)
- [MASTG-BEST-0004](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0004/)
- [Rule resmi: mastg-android-backup-manifest.yml (GitHub)](https://github.com/OWASP/mastg/blob/master/rules/mastg-android-backup-manifest.yml)

### 5.2 Dokumentasi Resmi Android

- [Android Developers — Back up user data with Auto Backup](https://developer.android.com/identity/data/autobackup)
- [Android Developers — `dataExtractionRules` XML schema](https://developer.android.com/identity/data/autobackup#IncludingFiles)
- [Android Developers — Key/Value Backup](https://developer.android.com/identity/data/keyvaluebackup)
- [Android Developers — `allowBackup` attribute reference](https://developer.android.com/guide/topics/manifest/application-element#allowbackup)

### 5.3 Dokumentasi Tools

- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [xmlstarlet](http://xmlstar.sourceforge.net/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026) dan dokumentasi resmi Android Developers. Sebagai counterpart statis dari MASTG-TEST-0216, dokumen ini berfokus pada detail evaluasi konfigurasi manifest dan file rules yang tidak diulang dari dokumen tersebut. Dua nuansa terpenting: (1) skema atribut/file berbeda antara Android 11- dan 12+, menuntut aplikasi dengan rentang API luas mendeklarasikan keduanya secara konsisten, dan (2) parameter `cloud-backup` vs `device-transfer` pada `data_extraction_rules.xml` harus diperiksa terpisah — pengecualian yang lengkap di satu blok tidak menjamin kelengkapan yang sama di blok lainnya.*
