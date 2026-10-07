# MASTG-TEST-0202 References to APIs and Permissions for Accessing External Storage

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0202 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-STORAGE (MASVS-STORAGE-1: Aplikasi menyimpan data sensitif secara aman) |
| **Weakness** | MASWE-0002 — *Sensitive Data Stored Unencrypted Outside of Private Storage* |
| **Tipe Pengujian** | **Static**, Code, Manual |
| **Profile** | L1, L2 |
| **Knowledge** | MASTG-KNOW-0042 (External Storage) |
| **APIs yang disorot** | `Environment#getExternalStoragePublicDirectory`, `Environment#getExternalStorageDirectory`, `Environment#getExternalFilesDir`, `Environment#getExternalCacheDir`, `MediaStore`, `WRITE_EXTERNAL_STORAGE`, `MANAGE_EXTERNAL_STORAGE` |
| **Teknik terkait** | MASTG-TECH-0013 (Reverse Engineering Android Apps), MASTG-TECH-0014 (Static Analysis on Android), MASTG-TECH-0117 (Obtaining Information from the AndroidManifest), MASTG-TECH-0126 (Obtaining App Permissions), MASTG-TECH-0023 (Reviewing Decompiled Java Code) |
| **Demo terkait** | MASTG-DEMO-0003, MASTG-DEMO-0004, MASTG-DEMO-0005 |
| **CWE terkait** | CWE-312 (Cleartext Storage of Sensitive Information), CWE-921 (Storage of Sensitive Data in a Mechanism without Access Control), CWE-200 (Exposure of Sensitive Information), CWE-250 (Execution with Unnecessary Privileges — untuk `MANAGE_EXTERNAL_STORAGE`) |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Test ini menggunakan **analisis statis** untuk mencari penggunaan API yang memungkinkan aplikasi menulis ke lokasi yang dibagikan dengan aplikasi lain — yaitu External Storage API atau `MediaStore` API — **beserta permission terkait storage yang dideklarasikan di AndroidManifest**.

Kutipan langsung dari overview MASTG:

> *"This test uses static analysis to look for uses of APIs allowing an app to write to locations that are shared with other apps such as the External Storage APIs or the `MediaStore` API as well as the relevant Android manifest storage-related permissions."*
>
> *"Some APIs used to write to shared storage include `getExternalStoragePublicDirectory`, `getExternalStorageDirectory`, `getExternalFilesDir`, or `MediaStore`. Permissions include `WRITE_EXTERNAL_STORAGE`, and `MANAGE_EXTERNAL_STORAGE`."*

Jadi test ini punya **dua sasaran yang harus dikorelasikan**:

1. **Sisi kode** — di mana saja (file + nomor baris) aplikasi memanggil API external/shared storage.
2. **Sisi manifest** — permission storage apa yang dideklarasikan, dan apakah ada flag opt-out scoped storage.

Keduanya harus diperiksa bersamaan. Permission tanpa pemanggilan API bisa jadi sisa warisan (leftover); pemanggilan API tanpa permission justru normal untuk API scoped storage (lihat §1.4).

### 1.2 Catatan Resmi MASTG: Keterbatasan Test Ini

MASTG sendiri secara eksplisit memberi peringatan (blok `!!! note`) tentang batas kemampuan test ini:

> *"This static test is great for identifying **all code locations** where the app is writing data to shared storage. However, it **does not provide the actual data being written**, and in some cases, **the actual path in the device storage** where the data is being written. Therefore, it is recommended to **combine this test with others that take a dynamic approach**, as this will provide a more complete view of the data being written to shared storage."*

Tiga konsekuensi praktis dari catatan ini:

- **Test ini tidak bisa berdiri sendiri untuk memutuskan FAIL.** Ia menemukan *lokasi*, bukan *isi*. Keputusan sensitif/tidak sensitif harus datang dari review kode manual (MASTG-TECH-0023) atau dari test dinamis.
- **Path sebenarnya kadang tidak dapat ditentukan secara statis.** Contoh: `getExternalFilesDir(null)` → path-nya bergantung package name dan runtime; `MediaStore` → path bergantung `relative_path` di `ContentValues` yang bisa dinamis.
- **Wajib dikombinasikan** dengan MASTG-TEST-0200 (diff filesystem) dan MASTG-TEST-0201 (hooking).

### 1.3 Posisi Test Ini dalam Rangkaian MASVS-STORAGE

| Test | Pendekatan | Menjawab | Kekuatan | Kelemahan |
|---|---|---|---|---|
| **MASTG-TEST-0200** | Dinamis — *filesystem diffing* | "File apa yang **benar-benar muncul** di disk?" | Bukti nyata, API-agnostic total, tanpa root | Tidak tahu siapa penulis & baris kodenya |
| **MASTG-TEST-0201** | Dinamis — *method hooking* | "**API apa** yang dipanggil, oleh **kode mana**?" | Atribusi presisi + backtrace, menangkap kode native & temp file | Butuh Frida/root, hanya alur yang di-*exercise*, bisa dihalangi anti-instrumentation |
| **MASTG-TEST-0202** *(dokumen ini)* | **Statis** — reverse engineering + pattern matching | "API & permission apa yang **direferensikan** di seluruh kode?" | **Cakupan menyeluruh** atas kode yang ada tanpa menjalankan app; cepat & otomatis; CI-friendly; tidak terhalang anti-instrumentation | Banyak false positive (dead code, library tak terpakai); tidak tahu isi data; buta terhadap kode dinamis/native/obfuscated |

**Nilai unik test ini:** ia satu-satunya yang memberi **cakupan lengkap (coverage)**. Test dinamis hanya melihat alur yang kamu jalankan; test statis melihat **semua** jalur kode yang ada di APK, termasuk fitur yang hanya aktif untuk akun premium, fitur yang di-*feature-flag*, atau alur error yang sulit dipicu. Karena itu test ini paling baik dipakai **lebih dulu** — sebagai peta untuk mengarahkan pengujian dinamis.

**Alur kerja yang direkomendasikan:**

```
TEST-0202 (statis)  ──►  daftar lokasi kode + permission  ──►  peta area berisiko
        │
        ├──►  TEST-0201 (hooking)  ──►  konfirmasi API mana yang aktif + backtrace
        │
        └──►  TEST-0200 (diffing)  ──►  bukti file nyata + isi data
                                              │
                                              ▼
                                    Keputusan PASS / FAIL
```

Sebaliknya, hubungan ini juga berlaku untuk menutup titik buta: bila TEST-0202 menemukan referensi `getExternalFilesDir` tetapi TEST-0201 tidak pernah merekam pemanggilannya, artinya **alur pemicunya belum di-*exercise*** — statusnya inkonklusif, bukan PASS.

### 1.4 Landasan Teknis: API dan Permission yang Dicari

Penting untuk memahami bahwa API-API ini **tidak setara tingkat risikonya**. MASTG sendiri memisahkannya menjadi dua rule semgrep berbeda dengan pesan berbeda.

**Kelompok A — API ke shared storage "publik" (risiko tertinggi):**

| API | Path | Permission | Catatan |
|---|---|---|---|
| `Environment.getExternalStorageDirectory()` | `/storage/emulated/0` (root shared storage) | Butuh `MANAGE_EXTERNAL_STORAGE` ("All files access") pada API 30+ | **Deprecated (API 29)**. Indikator kuat kode legacy |
| `Environment.getExternalStoragePublicDirectory(type)` | `/sdcard/Download/`, `/sdcard/Documents/`, `/sdcard/DCIM/` | Sama seperti di atas | **Deprecated (API 29)**. Bertahan pasca-uninstall |
| `Environment.getDownloadCacheDirectory()` | Cache download sistem | — | Juga dipindai oleh rule MASTG |
| `Intent.ACTION_CREATE_DOCUMENT` | Ditentukan user via SAF | Tidak perlu | Dipindai MASTG karena menulis keluar sandbox; risiko lebih rendah karena melibatkan interaksi user |

Pesan rule MASTG untuk kelompok ini: *"[MASVS-STORAGE] Make sure to encrypt files at these locations if necessary"*.

**Kelompok B — API ke scoped external storage (risiko menengah):**

| API | Path | Permission |
|---|---|---|
| `Context.getExternalFilesDir()` / `getExternalFilesDirs()` | `/sdcard/Android/data/<pkg>/files/` | **Tidak perlu permission** (API 19+) |
| `Context.getExternalCacheDir()` / `getExternalCacheDirs()` | `/sdcard/Android/data/<pkg>/cache/` | **Tidak perlu permission** |
| `Context.getExternalMediaDirs()` | `/sdcard/Android/media/<pkg>/` | **Tidak perlu permission**; terlihat di MediaStore |

Pesan rule MASTG untuk kelompok ini: *"[MASVS-STORAGE] These locations might be accessible to other apps on Android 10 and below given relevant permissions"*.

> **Poin kunci yang sering disalahpahami:** API Kelompok B **tidak memerlukan permission apa pun**. Jadi ketiadaan `WRITE_EXTERNAL_STORAGE` di manifest **sama sekali tidak berarti aplikasi aman**. Ini penting untuk interpretasi kriteria evaluasi (lihat §3.6).

**Kelompok C — MediaStore (risiko tinggi, persisten):**

| API | Catatan |
|---|---|
| `MediaStore.Downloads` / `Images` / `Video` / `Audio` / `Files` `.EXTERNAL_CONTENT_URI` | Menulis ke `/sdcard/Download/`, `/sdcard/Pictures/`, dst. |
| `ContentResolver.insert()` + `openOutputStream()` | Titik penulisan aktual |
| `MediaStore.MediaColumns.RELATIVE_PATH` / `DISPLAY_NAME` | Menentukan path final |

Tidak butuh permission untuk file yang dibuat sendiri (API 29+), **tidak dihapus saat aplikasi di-uninstall**, dan dapat diakses aplikasi lain dengan permission media yang sesuai.

**Permission dan flag manifest yang dipindai:**

| Item manifest | Arti & risiko |
|---|---|
| `WRITE_EXTERNAL_STORAGE` | Tulis ke shared storage. **Deprecated & tidak berefek pada API 30+** (hanya setara READ). Kehadirannya pada aplikasi modern = leftover atau indikasi target SDK rendah |
| `MANAGE_EXTERNAL_STORAGE` | **"All files access"** — bypass scoped storage sepenuhnya. Dibatasi kebijakan Google Play. **Red flag paling kuat** |
| `ACCESS_ALL_EXTERNAL_STORAGE` | Permission sistem (signature-level), tidak untuk app biasa. Kehadirannya sangat mencurigakan |
| `android:requestLegacyExternalStorage="true"` | **Opt-out scoped storage.** Berefek hanya bila target ≤ API 29; diabaikan sistem bila target ≥ API 30 |
| `android:preserveLegacyExternalStorage="true"` | Mempertahankan akses legacy saat upgrade app ke target API 30 |
| `android:requestRawExternalStorageAccess="true"` | Melewati abstraksi FUSE untuk akses raw I/O (API 30+) |

Tiga flag terakhir semuanya **menaikkan severity** karena memperluas eksposur lintas-aplikasi.

### 1.5 Risiko yang Diindikasikan Test Ini

Akar risikonya sama dengan MASTG-TEST-0200 dan 0201 (MASWE-0002) — silakan lihat dokumen tersebut untuk detail. Ringkasnya:

1. **Information disclosure lintas-aplikasi** — file plaintext di shared storage terbaca app lain (terutama target API ≤ 29 atau dengan `requestLegacyExternalStorage="true"`).
2. **Man-in-the-Disk** (Check Point, DEF CON 2018) — penyerang menimpa data di external storage; berpotensi DoS, crash, hingga **code injection dalam konteks privileged aplikasi target**.
3. **Persistensi pasca-uninstall** — file MediaStore di `Download/`, `Documents/` tidak dihapus saat aplikasi di-uninstall.
4. **Over-privilege** — `MANAGE_EXTERNAL_STORAGE` memberi akses ke seluruh storage device; bila aplikasi dikompromikan, dampaknya meluas ke data aplikasi lain (CWE-250).

**Risiko khas yang paling efektif ditemukan test ini** (dan sulit ditemukan test dinamis):
- **API deprecated berisiko tinggi di jalur kode yang jarang dieksekusi** — misalnya `getExternalStorageDirectory()` di modul legacy export/backup yang hanya aktif di kondisi tertentu.
- **Permission leftover** — `WRITE_EXTERNAL_STORAGE` / `MANAGE_EXTERNAL_STORAGE` yang masih dideklarasikan padahal fiturnya sudah dihapus, memperluas attack surface tanpa manfaat.
- **Flag opt-out scoped storage** yang terlupakan di manifest.
- **Referensi dari library pihak ketiga** yang tidak terlihat saat pengujian dinamis normal.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | MASTG ID | Fungsi dalam test ini |
|---|---|---|
| **jadx** | MASTG-TOOL-0018 | **Dekompilasi DEX → Java** (MASTG-TECH-0013/0017). Juga mengekstrak manifest lengkap termasuk `<uses-sdk>` via `jadx --no-src`. Wajib untuk MASTG-TECH-0023 (review lokasi kode temuan) |
| **semgrep** | MASTG-TOOL-0110 | **Pattern matching** pada kode hasil dekompilasi dan pada manifest. Tool utama untuk otomatisasi test ini; MASTG menyediakan rule siap pakai |
| **apktool** | MASTG-TOOL-0011 | Decode manifest binary → XML (`apktool d -s -f`). Catat: `minSdkVersion`/`targetSdkVersion` dipindahkan ke `apktool.yml`, bukan di manifest hasil decode |
| **aapt2** | MASTG-TOOL-0124 | Ekstraksi cepat metadata & permission: `aapt2 d badging`, `aapt d permissions`. Output **bukan** XML |
| **grep** | — | Analisis statis paling sederhana namun efektif (MASTG-TECH-0014), mis. `grep 'android:minSdkVersion' AndroidManifest.xml` |
| **adb** | MASTG-TOOL-0004 | `adb shell dumpsys package <pkg> \| grep permission` — melihat permission **beserta status grant** saat runtime (MASTG-TECH-0126) |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **mobsfscan** | SAST khusus mobile berbasis semgrep + libsast, mendukung Java/Kotlin/Swift/Obj-C dan XML manifest. Ringan dan cocok untuk pipeline CI |
| **MobSF** (Mobile Security Framework) | Analisis statis menyeluruh atas APK: permission berbahaya, insecure data storage, hardcoded secret, exported component. Bagus untuk pass pertama yang luas |
| **semgrep-rules-android-security** (IMQ Minded Security) | Koleksi rule semgrep pihak ketiga khusus keamanan Android — pelengkap rule resmi MASTG |
| **CodeQL** | Analisis alur data (taint analysis) — lebih kuat dari semgrep untuk melacak *apakah data sensitif benar-benar sampai* ke API storage. Tersedia query `java/android-cleartext-storage-filesystem` |
| **SonarQube** | Rule `java:S5324` — *Accessing Android external storage is security-sensitive* |
| **jadx-gui** | Navigasi interaktif, rename simbol saat menganalisis kode ter-obfuscate (MASTG-TECH-0023) |
| **APKiD / apkid** | Deteksi packer/obfuscator — penting untuk menilai keandalan hasil analisis statis |
| **dex2jar + JD-GUI / CFR / Procyon** | Dekompiler alternatif bila jadx gagal pada kode tertentu |
| **Ghidra / radare2** | Analisis kode native (`.so`) — menutup titik buta analisis DEX; cari string `/sdcard`, `/storage/emulated`, dan panggilan `open`/`fopen` |
| **TruffleHog / gitleaks** | Pemindaian hardcoded secret pada kode hasil dekompilasi — mendukung langkah evaluasi "apakah datanya sensitif" |
| **apksigner / bundletool** | Menangani AAB dan split APK agar semua modul (termasuk dynamic feature) ikut dianalisis |

### 2.3 Prasyarat Lingkungan

- **Tidak butuh device dan tidak butuh root.** Ini keunggulan besar test ini dibanding TEST-0200/0201 — cukup file APK saja. Karena itu paling mudah diotomatisasi di CI/CD.
- **File APK target.** Jika aplikasi berupa **AAB / split APK**, pastikan **semua** split dan dynamic feature module ikut dianalisis (`adb shell pm path <pkg>` lalu pull semuanya), jika tidak akan ada modul yang terlewat.
- **semgrep terinstall** (`pip install semgrep`) dan **rule MASTG** tersedia (clone `github.com/OWASP/mastg`, direktori `rules/`).
- **Waspadai obfuscation.** Jika aplikasi diproteksi ProGuard/R8 agresif, packer, atau string encryption, hasil pattern matching bisa tidak lengkap. Jalankan APKiD lebih dulu dan **dokumentasikan keterbatasan ini** di laporan. Catatan penting: nama API framework Android (`getExternalFilesDir`, `MediaStore`) **tidak di-obfuscate** oleh ProGuard/R8 karena merupakan API sistem — jadi test ini tetap efektif pada aplikasi ter-obfuscate; yang ter-obfuscate adalah nama kelas/metode aplikasi sendiri, yang menyulitkan tahap review kode (MASTG-TECH-0023), bukan tahap deteksi.
- **Analisis kode native terpisah.** Rule semgrep hanya bekerja pada Java/Kotlin. Penulisan dari `.so` harus dicari dengan `strings`/Ghidra.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0013** (*Reverse Engineering Android Apps*) untuk me-reverse engineer aplikasi.
2. Gunakan **MASTG-TECH-0014** (*Static Analysis on Android*) untuk mencari API yang relevan.
3. Gunakan **MASTG-TECH-0117** (*Obtaining Information from the AndroidManifest*) untuk mendapatkan `AndroidManifest.xml`.
4. Gunakan **MASTG-TECH-0126** (*Obtaining App Permissions*) untuk mendapatkan permission yang relevan.

Untuk evaluasi, gunakan **MASTG-TECH-0023** (*Reviewing Decompiled Java Code*) pada setiap lokasi kode yang dilaporkan.

### 3.2 Implementasi Praktis

**Langkah 1 — Dekompilasi aplikasi (MASTG-TECH-0013)**

```bash
# Dekompilasi DEX ke Java dengan jadx
jadx -d ./decompiled ./target-app.apk

# Jika aplikasi berupa split APK / AAB, ambil semua bagiannya dulu
adb shell pm path com.example.target
# package:/data/app/.../base.apk
# package:/data/app/.../split_config.arm64_v8a.apk
# ... lalu adb pull semuanya dan dekompilasi masing-masing

# Cek apakah aplikasi diproteksi packer/obfuscator
apkid ./target-app.apk
```

**Langkah 2 — Ekstraksi manifest (MASTG-TECH-0117)**

Tiga opsi, dengan karakteristik berbeda:

```bash
# Opsi A: jadx — manifest PALING LENGKAP, termasuk elemen <uses-sdk>
jadx --no-src -d out_dir ./target-app.apk
# -> out_dir/resources/AndroidManifest.xml

# Opsi B: apktool — cepat dengan -s (skip baksmali)
apktool d -s -f -o output_dir ./target-app.apk
# -> output_dir/AndroidManifest.xml
# CATATAN: <uses-sdk> TIDAK ada di sini; nilainya dipindah ke apktool.yml:
cat output_dir/apktool.yml | grep -A2 sdkInfo
#   sdkInfo:
#     minSdkVersion: 29
#     targetSdkVersion: 35

# Opsi C: aapt2 — tercepat untuk nilai spesifik. Output BUKAN XML
aapt2 d badging ./target-app.apk
# package: name='org.owasp.mastestapp' versionCode='1' ... compileSdkVersion='35'
# sdkVersion:'29'
# targetSdkVersion:'35'
# uses-permission: name='android.permission.INTERNET'
```

> Pemilihan tool di sini punya konsekuensi nyata: kalau kamu pakai apktool lalu mencari `targetSdkVersion` di manifest, kamu tidak akan menemukannya dan bisa salah menyimpulkan. Gunakan jadx atau aapt2 untuk atribut SDK.

**Langkah 3 — Ekstraksi permission (MASTG-TECH-0126)**

```bash
# Opsi A: dari manifest hasil decode
grep -E "uses-permission" out_dir/resources/AndroidManifest.xml

# Opsi B: aapt
aapt d permissions ./target-app.apk
# package: org.owasp.mastestapp
# uses-permission: name='android.permission.INTERNET'
# uses-permission: name='android.permission.CAMERA'
# uses-permission: name='android.permission.WRITE_EXTERNAL_STORAGE'
# uses-permission: name='android.permission.READ_EXTERNAL_STORAGE'

# Opsi C: adb — KEUNGGULAN: menampilkan status GRANT saat runtime
adb shell dumpsys package com.example.target | grep -A30 permission
#     runtime permissions:
#       android.permission.WRITE_EXTERNAL_STORAGE: granted=false, flags=[ RESTRICTION_INSTALLER_EXEMPT]
```

> Opsi C memberi informasi yang tidak bisa didapat dari analisis statis murni: permission yang **dideklarasikan tapi tidak pernah di-grant** punya dampak nyata lebih rendah. Ini berguna untuk kalibrasi severity — meski deklarasinya sendiri tetap layak dilaporkan sebagai over-privilege.

**Langkah 4 — Pattern matching dengan semgrep (MASTG-TECH-0014)**

Rule resmi MASTG untuk API — `mastg-android-data-unencrypted-shared-storage-no-user-interaction-apis.yml`:

```yaml
rules:
  - id: mastg-android-data-unencrypted-shared-storage-no-user-interaction-external-api-public
    severity: WARNING
    languages:
      - java
    metadata:
      summary: This rule looks for methods that returns locations to "external storage" which is shared with other apps
    message: "[MASVS-STORAGE] Make sure to encrypt files at these locations if necessary"
    pattern-either:
      - pattern: $X.getExternalStorageDirectory(...)
      - pattern: $X.getExternalStoragePublicDirectory(...)
      - pattern: $X.getDownloadCacheDirectory(...)
      - pattern: Intent.ACTION_CREATE_DOCUMENT

  - id: mastg-android-data-unencrypted-shared-storage-no-user-interaction-external-api-scoped
    severity: WARNING
    languages:
      - java
    metadata:
      summary: This rule looks for methods that returns locations to "scoped external storage"
    message: "[MASVS-STORAGE] These locations might be accessible to other apps on Android 10 and below given relevant permissions"
    pattern-either:
      - pattern: $X.getExternalFilesDir(...)
      - pattern: $X.getExternalFilesDirs(...)
      - pattern: $X.getExternalCacheDir(...)
      - pattern: $X.getExternalCacheDirs(...)
      - pattern: $X.getExternalMediaDirs(...)

  - id: mastg-android-data-unencrypted-shared-storage-no-user-interaction-mediastore
    severity: WARNING
    languages:
      - java
    metadata:
      summary: This rule scans for uses of MediaStore API that writes data to the external storage. This data can be accessed by other apps.
    message: "[MASVS-STORAGE] Make sure to want this data to be shared with other apps"
    pattern-either:
      - pattern: import android.provider.MediaStore
      - pattern: $X.MediaStore
```

Rule resmi MASTG untuk manifest — `mastg-android-data-unencrypted-shared-storage-no-user-interaction-manifest.yml`:

```yaml
rules:
  - id: mastg-android-data-unencrypted-shared-storage-no-user-interaction-manifest
    severity: WARNING
    languages:
      - generic
    metadata:
      summary: This rule scans for permissions that allows your app to write to external storage or shared storage
    message: "[MASVS-STORAGE] Make sure to encrypt files in external storage if necessary"
    pattern-either:
      - pattern: WRITE_EXTERNAL_STORAGE
      - pattern: MANAGE_EXTERNAL_STORAGE
      - pattern: ACCESS_ALL_EXTERNAL_STORAGE
      - pattern: requestLegacyExternalStorage="true"
      - pattern: preserveLegacyExternalStorage="true"
      - pattern: android:requestRawExternalStorageAccess="true"
```

Menjalankannya (`run.sh` dari MASTG-DEMO-0003):

```bash
NO_COLOR=true semgrep \
  -c ../../../../rules/mastg-android-data-unencrypted-shared-storage-no-user-interaction-apis.yml \
  ./MastgTest_reversed.java > output.txt

NO_COLOR=true semgrep \
  -c ../../../../rules/mastg-android-data-unencrypted-shared-storage-no-user-interaction-manifest.yml \
  ./AndroidManifest_reversed.xml > output2.txt
```

Untuk aplikasi nyata, jalankan pada seluruh direktori hasil dekompilasi:

```bash
# Scan seluruh kode hasil dekompilasi
NO_COLOR=true semgrep \
  -c ./mastg/rules/mastg-android-data-unencrypted-shared-storage-no-user-interaction-apis.yml \
  ./decompiled/sources/ --json -o findings-apis.json

# Scan manifest
NO_COLOR=true semgrep \
  -c ./mastg/rules/mastg-android-data-unencrypted-shared-storage-no-user-interaction-manifest.yml \
  ./out_dir/resources/AndroidManifest.xml -o findings-manifest.txt
```

**Langkah 5 — Pemeriksaan pelengkap dengan grep (dan penutup titik buta)**

Rule MASTG tidak mencakup semua permukaan. Lengkapi dengan:

```bash
# API storage tambahan yang tidak ada di rule MASTG
grep -rnE "getExternalStorageState|getExternalStorageDirectory|getStorageDirectory|DIRECTORY_(DOWNLOADS|DOCUMENTS|PICTURES|DCIM|MUSIC|MOVIES)" ./decompiled/sources/

# Titik penulisan aktual MediaStore/SAF (lebih bermakna daripada sekadar import MediaStore)
grep -rnE "ContentResolver|\.insert\(|openOutputStream|openFileDescriptor|createWriteRequest" ./decompiled/sources/

# DownloadManager — menulis langsung ke shared storage
grep -rnE "DownloadManager|setDestinationInExternalPublicDir|setDestinationInExternalFilesDir" ./decompiled/sources/

# String path external storage yang di-hardcode
grep -rnE "\"/sdcard|/storage/emulated|/mnt/sdcard|/storage/self/primary" ./decompiled/sources/

# BAHAYA TINGGI: pemuatan kode dari path eksternal (indikasi Man-in-the-Disk)
grep -rnE "DexClassLoader|PathClassLoader|System\.load\(|loadLibrary\(|InMemoryDexClassLoader" ./decompiled/sources/

# Indikasi enkripsi pada jalur penulisan (untuk menilai kemungkinan PASS)
grep -rnE "EncryptedFile|CipherOutputStream|MasterKey|AndroidKeyStore|SQLCipher|Tink" ./decompiled/sources/

# Kelemahan kripto yang membatalkan klaim "sudah dienkripsi"
grep -rnE "AES/ECB|DES|RC4|SecretKeySpec\(\"|Base64\.encode" ./decompiled/sources/

# Konfigurasi scoped storage & atribut SDK
grep -nE "requestLegacyExternalStorage|preserveLegacyExternalStorage|requestRawExternalStorageAccess|targetSdkVersion|minSdkVersion" \
  ./out_dir/resources/AndroidManifest.xml

# Kode native — rule semgrep tidak menjangkau ini
for so in $(find ./decompiled -name "*.so"); do
  echo "--- $so"; strings "$so" | grep -E "/sdcard|/storage/emulated|getExternal"
done
```

**Langkah 6 — Review setiap lokasi temuan (MASTG-TECH-0023)** — **wajib, bukan opsional**

Untuk setiap baris yang dilaporkan semgrep, buka lokasinya di jadx dan jawab tiga pertanyaan:

1. **Apakah code path ini benar-benar dieksekusi?** (bukan dead code / library tak terpakai)
2. **Data apa yang ditulis di sana?** Lacak variabel yang masuk ke `write()` — apakah berasal dari input user, respons API, atau kredensial?
3. **Apakah ada enkripsi pada jalur tersebut?** Cari frame `EncryptedFile` / `CipherOutputStream`; bila ada, periksa mode cipher (tolak ECB) dan **asal kunci** (tolak hardcoded).

```bash
# Setelah semgrep melaporkan mis. MastgTest.java:27, buka konteksnya
sed -n '15,45p' ./decompiled/sources/org/owasp/mastestapp/MastgTest.java

# Lacak variabel yang ditulis untuk menentukan sensitivitas data
grep -rn "fileContent\|getBytes\|\.write(" ./decompiled/sources/org/owasp/mastestapp/MastgTest.java
```

### 3.3 Metode Pengujian Alternatif (Multi-Tool)

Rule semgrep MASTG punya banyak celah (lihat §3.5 catatan 4). Berikut jalur alternatif yang bisa dipakai berdiri sendiri atau sebagai verifikasi silang.

#### Metode B — apktool + grep/ripgrep *(paling portabel, tanpa dependency)*

Keunggulan utama: **menangkap nama variabel/konstanta apa pun** dan bekerja pada field initializer tingkat kelas — dua celah terbesar rule MASTG.

```bash
apktool d -f -o ./decoded ./target-app.apk
jadx -d ./decompiled ./target-app.apk
D=./decompiled/sources

# --- 1. API shared storage "publik" (Kelompok A) ---
rg -n --no-heading "getExternalStorageDirectory|getExternalStoragePublicDirectory|getDownloadCacheDirectory" $D

# --- 2. API scoped external storage (Kelompok B) ---
rg -n --no-heading "getExternalFilesDirs?|getExternalCacheDirs?|getExternalMediaDirs" $D

# --- 3. MediaStore — cari TITIK PENULISAN, bukan sekadar import ---
rg -n --no-heading "ContentResolver|\.insert\(|openOutputStream|openFileDescriptor|createWriteRequest" $D
rg -n --no-heading "MediaStore\.(Downloads|Images|Video|Audio|Files)" $D

# --- 4. DownloadManager (tidak ada di rule MASTG) ---
rg -n --no-heading "setDestinationInExternalPublicDir|setDestinationInExternalFilesDir|DownloadManager" $D

# --- 5. Hardcoded path (tidak ada di rule MASTG) ---
rg -n --no-heading '"/sdcard|/storage/emulated|/mnt/sdcard|/storage/self/primary' $D

# --- 6. Permission & flag manifest — TANGKAP SEMUA, bukan hanya nama default ---
rg -o 'android:name="android\.permission\.[A-Z_]*(STORAGE|MEDIA)[A-Z_]*"' ./decoded/AndroidManifest.xml
rg -o 'android:(requestLegacyExternalStorage|preserveLegacyExternalStorage|requestRawExternalStorageAccess)="[^"]*"' ./decoded/AndroidManifest.xml

# --- 7. BAHAYA TINGGI: pemuatan kode dari external storage (Man-in-the-Disk) ---
rg -n --no-heading "DexClassLoader|PathClassLoader|InMemoryDexClassLoader|System\.load\(|loadLibrary\(" $D

# --- 8. Indikator enkripsi pada jalur penulisan (untuk menilai PASS) ---
rg -n --no-heading "EncryptedFile|CipherOutputStream|MasterKey|AndroidKeyStore|SQLCipher|Tink" $D
```

#### Metode C — aapt2 *(tercepat untuk permission, tanpa dekompilasi)*

```bash
# Permission + atribut SDK dalam satu perintah
aapt2 d badging ./target-app.apk | grep -E "uses-permission|sdkVersion|targetSdkVersion"

# Manifest tree — menampilkan atribut yang tidak muncul di badging
aapt2 d xmltree --file AndroidManifest.xml ./target-app.apk \
  | grep -iE "STORAGE|MEDIA|LegacyExternal|RawExternal"

# Batch scan banyak APK
for a in ./apks/*.apk; do
  echo "=== $a"
  aapt2 d badging "$a" 2>/dev/null | grep -E "MANAGE_EXTERNAL_STORAGE|WRITE_EXTERNAL_STORAGE"
done
```

> Ingat catatan MASTG-TECH-0150: aapt2 mengeluarkan **format decoded kustom**, bukan XML — nama atributnya berbeda.

#### Metode D — MobSF *(GUI, laporan siap kutip)*

```bash
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
# Upload APK via http://localhost:8000
```

Yang dicari di laporan:

| Bagian laporan MobSF | Temuan yang relevan |
|---|---|
| **Manifest Analysis** | `WRITE_EXTERNAL_STORAGE` / `MANAGE_EXTERNAL_STORAGE` ditandai *dangerous permission*; `requestLegacyExternalStorage` |
| **Code Analysis** | Pola *"App can read/write to external storage"* |
| **Permissions** | Daftar permission dengan klasifikasi severity |
| **Files** | Daftar aset yang di-bundle |

Keunggulan: severity dan deskripsi risikonya bisa langsung dikutip ke laporan; sekaligus memeriksa `debuggable`, `allowBackup`, dan exported component dalam satu pass.

#### Metode E — mobsfscan *(CLI ringan untuk CI/CD)*

```bash
pip install mobsfscan
mobsfscan --json -o mobsfscan.json ./decompiled/sources/ ./decoded/
jq '.results | to_entries[] | select(.key | test("storage|external|permission"))' mobsfscan.json

# Sebagai gate CI (exit code non-zero bila ada temuan)
mobsfscan --exit-warning ./decompiled/sources/
```

#### Metode F — CodeQL *(taint analysis — menjawab "apakah data sensitif BENAR-BENAR mengalir ke API storage?")*

Ini keunggulan yang tidak dimiliki semgrep: semgrep hanya pattern matching intra-file, sedangkan CodeQL melacak aliran data lintas fungsi.

```bash
# Buat database dari source Java/Kotlin (bila tersedia)
codeql database create ./cqldb --language=java --command="./gradlew assembleDebug"

# Query bawaan yang relevan
codeql database analyze ./cqldb \
  codeql/java-queries:Security/CWE/CWE-312/CleartextStorageAndroidFilesystem.ql \
  --format=sarif-latest --output=results.sarif

# Baca hasil
jq '.runs[].results[] | {rule: .ruleId, msg: .message.text, loc: .locations[0].physicalLocation.artifactLocation.uri}' results.sarif
```

Query kustom untuk memetakan aliran ke external storage:

```ql
/**
 * @name Sensitive data flows to external storage
 * @kind path-problem
 */
import java
import semmle.code.java.dataflow.TaintTracking

class ExternalStorageSink extends DataFlow::Node {
  ExternalStorageSink() {
    exists(MethodAccess ma |
      ma.getMethod().hasName(["getExternalFilesDir", "getExternalStorageDirectory",
                              "getExternalStoragePublicDirectory", "getExternalCacheDir"]) and
      this.asExpr() = ma
    )
  }
}
```

#### Metode G — drozer *(audit dari sisi device)*

```bash
drozer console connect
dz> run app.package.info -a com.example.target        # permission yang diminta & di-grant
dz> run app.package.attacksurface com.example.target
dz> run scanner.misc.readablefiles --privileged /sdcard
dz> run scanner.misc.writablefiles --privileged /sdcard
```

#### Metode H — `adb dumpsys` *(status grant runtime — informasi yang TIDAK bisa didapat analisis statis)*

```bash
PKG=com.example.target

# Permission beserta status grant — kalibrasi severity
adb shell dumpsys package $PKG | grep -A40 "requested permissions"
adb shell dumpsys package $PKG | grep -E "granted=(true|false)"

# targetSdk aktual sebagaimana dilihat sistem
adb shell dumpsys package $PKG | grep -E "targetSdk|versionName"

# Cek apakah app punya All-files access (MANAGE_EXTERNAL_STORAGE)
adb shell appops get $PKG MANAGE_EXTERNAL_STORAGE
adb shell appops get $PKG LEGACY_STORAGE
```

> `appops get ... LEGACY_STORAGE` sangat berguna: ia memperlihatkan apakah sistem **benar-benar** memberikan akses legacy (scoped storage dimatikan) pada aplikasi ini — sesuatu yang tidak selalu terbaca dari manifest saja.

#### Metode I — APKHunt & pemindai lain *(pass otomatis tambahan)*

```bash
# APKHunt — OWASP MASVS static analyzer
go install github.com/Cyber-Buddy/APKHunt@latest
APKHunt -p ./target-app.apk -l

# Semgrep registry rules (di luar rule MASTG)
semgrep --config "p/mobsfscan" ./decompiled/sources/
semgrep --config "p/java" ./decompiled/sources/

# Rule pihak ketiga khusus Android
git clone https://github.com/mindedsecurity/semgrep-rules-android-security
semgrep -c ./semgrep-rules-android-security/rules/ ./decompiled/sources/
```

#### Metode J — jadx-gui *(manual, untuk kode ter-obfuscate)*

Ketika aplikasi diproteksi obfuscator berat dan pattern matching gagal:

1. Buka APK di jadx-gui
2. **Search** (`Ctrl+Shift+F`) → cari `getExternalFilesDir`, `MediaStore`, `/sdcard` — nama API framework **tidak di-obfuscate**, jadi ini tetap efektif
3. Klik kanan metode → **Find Usage** untuk melacak pemanggil
4. Rename simbol yang sudah dipahami (tombol `N`) sesuai MASTG-TECH-0023

#### Metode K — Analisis kode native *(titik buta semua rule Java)*

```bash
unzip -o ./target-app.apk -d ./apk_x >/dev/null
for so in $(find ./apk_x -name "*.so"); do
  echo "--- $so"
  strings "$so" | grep -aE "/sdcard|/storage/emulated|getExternal|MediaStore" | head
done

# Analisis lebih dalam bila ada hit
ghidra_headless ./project ./apk_x/lib/arm64-v8a/libnative.so   # atau buka di Ghidra GUI
```

---

### 3.4 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Butuh device? | Menangkap nama non-default? | Taint analysis? | Kapan dipakai |
|---|---|---|---|---|---|
| **A** | semgrep (MASTG) | Tidak | ❌ | ❌ | Baseline resmi & gate CI |
| **B** | apktool + ripgrep | Tidak | ✅ | ❌ | **Verifikasi silang wajib** — paling akurat untuk statis |
| **C** | aapt2 | Tidak | ✅ (permission) | ❌ | Triase kilat banyak APK |
| **D** | MobSF | Tidak | ✅ | ❌ | Laporan siap kutip + audit luas sekaligus |
| **E** | mobsfscan | Tidak | ✅ | ❌ | Gate CI/CD ringan |
| **F** | CodeQL | Tidak | ✅ | ✅ | **Membuktikan aliran data sensitif** → mengurangi false positive |
| **G** | drozer | Ya | ✅ | ❌ | Bagian sesi drozer yang lebih luas |
| **H** | `adb dumpsys` / `appops` | Ya | — | ❌ | **Kalibrasi severity** — status grant & LEGACY_STORAGE aktual |
| **I** | APKHunt / semgrep registry | Tidak | ✅ | ❌ | Pass otomatis tambahan, cakupan rule lebih luas |
| **J** | jadx-gui manual | Tidak | ✅ | Manual | Kode ter-obfuscate berat |
| **K** | `strings` / Ghidra | Tidak | ✅ | ❌ | Kode native (`.so`) |

**Kombinasi minimum yang aku rekomendasikan:** **B (apktool+ripgrep) → A (semgrep) → H (dumpsys)**.
B memberi cakupan statis paling lengkap tanpa celah nama, A memberi baseline yang selaras MASTG, H mengkalibrasi severity dengan status grant nyata. Tambahkan **F (CodeQL)** bila tersedia source code — ia satu-satunya yang bisa membuktikan aliran data. Tambahkan **K** bila APK memuat `.so`.

---

### 3.5 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Observation:** *"The output should contain a list of APIs and storage-related permissions used to write to shared storage and their code locations."*
>
> **Evaluation:** *"The test case fails if **all of the following** apply:*
> - *the app has the proper permissions declared in the Android manifest (e.g. `WRITE_EXTERNAL_STORAGE`, `MANAGE_EXTERNAL_STORAGE`, etc.)*
> - *the app uses APIs that write to shared storage (e.g. `getExternalStoragePublicDirectory`, `getExternalStorageDirectory`, `getExternalFilesDir`, `getExternalCacheDir`, `MediaStore`, etc.)*
> - *the data being written to shared storage is sensitive and not encrypted."*
>
> **Further Validation Required** — inspeksi setiap lokasi kode yang dilaporkan menggunakan MASTG-TECH-0023 untuk menentukan apakah datanya sensitif:
> - Tentukan apakah data yang ditulis ke shared storage mengandung informasi sensitif (mis. data pribadi, kredensial, atau token).
> - Tentukan apakah data disimpan tanpa enkripsi.

#### ⚠️ Catatan kritis tentang kondisi pertama

Kriteria resmi menyebut ketiga kondisi harus terpenuhi (**"all of the following"**), termasuk *"the app has the proper permissions declared in the Android manifest"*. **Kondisi ini tidak boleh diterapkan secara literal**, karena bertentangan dengan demo MASTG sendiri:

- **MASTG-DEMO-0004** memakai `getExternalFilesDir()` — API yang **tidak memerlukan permission apa pun** (API 19+). Manifest-nya tidak mendeklarasikan permission storage. Namun MASTG tetap menyatakan: *"the test **fails** because the file written by this instance contains sensitive data, specifically a password."*
- **MASTG-DEMO-0005** memakai MediaStore untuk menulis ke `Downloads` — juga **tanpa permission** untuk file yang dibuat sendiri (API 29+). MASTG juga menyatakan **fails**.

Jadi secara praktis, **kondisi permission bersifat kontekstual, bukan prasyarat mutlak**. Interpretasi yang benar:

> **FAIL apabila: aplikasi menulis ke shared/external storage menggunakan API yang relevan, DAN data yang ditulis bersifat sensitif serta tidak ter-enkripsi.**
>
> Deklarasi permission (`WRITE_EXTERNAL_STORAGE`, `MANAGE_EXTERNAL_STORAGE`, flag legacy) berfungsi sebagai **penguat temuan dan pengali severity** — bukan sebagai syarat yang harus ada. Ketiadaan permission tidak membuat temuan menjadi PASS, karena API scoped storage dan MediaStore memang tidak membutuhkannya.

Yang benar-benar menjadi **AND wajib** hanyalah dua kondisi terakhir: **ada penulisan ke shared storage** DAN **data sensitif tanpa enkripsi**.

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi | Contoh bukti |
|---|---|---|
| F1 | Semgrep menemukan pemanggilan API **shared storage publik** (Kelompok A), dan review kode membuktikan data yang ditulis **sensitif & plaintext** | `27┆ File externalStorageDir = Environment.getExternalStorageDirectory();` + review menunjukkan penulisan password |
| F2 | Semgrep menemukan pemanggilan API **scoped external storage** (Kelompok B) dengan data sensitif plaintext | `25┆ File externalStorageDir = this.context.getExternalFilesDir(null);` + `"secr3tPa$$W0rd\n".getBytes(...)` |
| F3 | Semgrep menemukan penggunaan **MediaStore** untuk menulis data sensitif ke shared storage | `35┆ Uri textUri = resolver.insert(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, contentValues);` + `"MAS_API_KEY=8767086b9f6f976g-a8df76\n"` |
| F4 | Manifest mendeklarasikan **`MANAGE_EXTERNAL_STORAGE`** ("All files access") dan aplikasi menulis data sensitif ke shared storage | `2┆ <uses-permission android:name="android.permission.MANAGE_EXTERNAL_STORAGE"/>` + temuan F1 |
| F5 | Manifest memuat **flag opt-out scoped storage** (`requestLegacyExternalStorage="true"` / `preserveLegacyExternalStorage="true"` / `requestRawExternalStorageAccess="true"`) disertai penulisan data sensitif | Hasil rule manifest + temuan F1/F2/F3 → **severity dinaikkan** |
| F6 | Ditemukan API **deprecated berisiko tinggi** (`getExternalStorageDirectory`, `getExternalStoragePublicDirectory`) pada aplikasi dengan `targetSdkVersion` modern | Indikasi kode legacy yang belum dimigrasi; evaluasi data yang ditulisnya |
| F7 | Ditemukan **hardcoded path** external storage yang diikuti operasi tulis data sensitif | `grep` → `"/sdcard/MyApp/credentials.json"` |
| F8 | "Enkripsi" yang ditemukan pada jalur penulisan hanyalah **encoding/obfuscation** atau kripto lemah | `Base64.encode(...)` sebelum `write()`; atau `SecretKeySpec(key, "AES/ECB/PKCS7Padding")` |
| F9 | Ditemukan enkripsi, tetapi **kunci hardcoded** atau diturunkan dari nilai statis | `new SecretKeySpec("hardcodedkey123".getBytes(), "AES")` di jadx |
| F10 | Ditemukan pemuatan **kode eksekutabel** dari path external storage tanpa integrity check | `DexClassLoader` / `System.load()` dengan argumen path `/sdcard` → **Man-in-the-Disk / code injection**, severity kritis |
| F11 | `DownloadManager.setDestinationInExternalPublicDir()` dipakai untuk mengunduh data sensitif | Data sensitif mendarat di shared storage dan bertahan pasca-uninstall |
| F12 | Kode native (`.so`) mengandung string path external storage disertai operasi tulis | `strings lib.so` → `/storage/emulated/0/...` — titik buta rule semgrep |

**Contoh output yang menandakan FAIL — MASTG-DEMO-0003** (`getExternalStorageDirectory` + `MANAGE_EXTERNAL_STORAGE`):

`output.txt` (hasil scan kode):
```
┌────────────────┐
│ 1 Code Finding │
└────────────────┘

    MastgTest_reversed.java
    ❯❱ rules.mastg-android-data-unencrypted-shared-storage-no-user-interaction-external-api-public
          [MASVS-STORAGE] Make sure to encrypt files at these locations if necessary

           27┆ File externalStorageDir = Environment.getExternalStorageDirectory();
```

`output2.txt` (hasil scan manifest):
```
┌────────────────┐
│ 1 Code Finding │
└────────────────┘

    AndroidManifest_reversed.xml
    ❯❱ rules.mastg-android-data-unencrypted-shared-storage-no-user-interaction-manifest
          [MASVS-STORAGE] Make sure to encrypt files in external storage if necessary

            2┆ <uses-permission android:name="android.permission.MANAGE_EXTERNAL_STORAGE"/>
```

Kode sumber & hasil dekompilasinya:

```kotlin
// MastgTest.kt — sumber asli
val externalStorageDir = Environment.getExternalStorageDirectory()
val fileName = File(externalStorageDir, "secret.txt")
val fileContent = "Secret not using scoped storage"
FileOutputStream(fileName).use { output ->
    output.write(fileContent.toByteArray())
}
```

```java
// MastgTest_reversed.java — yang dilihat semgrep (baris 27)
public final String mastgTest() {
    File externalStorageDir = Environment.getExternalStorageDirectory();
    File fileName = new File(externalStorageDir, "secret.txt");
    try {
        FileOutputStream fileOutputStream = new FileOutputStream(fileName);
        byte[] bytes = "Secret not using scoped storage".getBytes(Charsets.UTF_8);
        output.write(bytes);
        ...
```

```xml
<!-- AndroidManifest.xml -->
<uses-permission android:name="android.permission.MANAGE_EXTERNAL_STORAGE" />
```

Evaluasi MASTG: *"After reviewing the decompiled code at the location specified in the output (file and line number) we can conclude that the test **fails** because the file written by this instance contains sensitive data, specifically a password."*

Inilah kasus **paling berat** dari ketiga demo: API deprecated ke root shared storage **plus** `MANAGE_EXTERNAL_STORAGE` yang mem-bypass scoped storage sepenuhnya.

---

**Contoh output yang menandakan FAIL — MASTG-DEMO-0004** (`getExternalFilesDir`, scoped storage aktif, **tanpa permission apa pun**):

```
┌────────────────┐
│ 1 Code Finding │
└────────────────┘

    MastgTest_reversed.java
    ❯❱ rules.mastg-android-data-unencrypted-shared-storage-no-user-interaction-external-api-scoped
          [MASVS-STORAGE] These locations might be accessible to other apps on Android 10 and below given
          relevant permissions

           25┆ File externalStorageDir = this.context.getExternalFilesDir(null);
```

```java
// MastgTest_reversed.java
File externalStorageDir = this.context.getExternalFilesDir(null);      // <-- baris 25
File fileName = new File(externalStorageDir, "secret.txt");
FileOutputStream fileOutputStream = new FileOutputStream(fileName);
byte[] bytes = "secr3tPa$$W0rd\n".getBytes(Charsets.UTF_8);            // <-- password plaintext
output.write(bytes);
```

Evaluasi MASTG: *"the test **fails** because the file written by this instance contains sensitive data, specifically a password."*

**Ini demo yang paling penting untuk dipahami.** Aplikasi ini:
- Menargetkan Android 12 (API 31) → **scoped storage aktif**
- Memakai `getExternalFilesDir()` → path `/storage/emulated/0/Android/data/org.owasp.mastestapp/files`
- **Tidak mendeklarasikan permission storage apa pun** (tidak perlu)

Tetap **FAIL**. Ini bukti langsung bahwa scoped storage dan ketiadaan permission **tidak** membuat penyimpanan data sensitif plaintext di external storage menjadi dapat diterima — file itu masih terbaca oleh user via MTP/USB, pada device rooted, oleh layanan backup pihak ketiga, dan oleh aplikasi dengan `MANAGE_EXTERNAL_STORAGE`. Sekaligus ini yang mengonfirmasi bahwa kondisi "permission declared" pada kriteria evaluasi resmi tidak boleh dibaca sebagai prasyarat mutlak.

---

**Contoh output yang menandakan FAIL — MASTG-DEMO-0005** (MediaStore API):

```
┌─────────────────┐
│ 2 Code Findings │
└─────────────────┘

    MastgTest_reversed.java
    ❯❱ rules.mastg-android-data-unencrypted-shared-storage-no-user-interaction-mediastore
          [MASVS-STORAGE] Make sure to want this data to be shared with other apps

            8┆ import android.provider.MediaStore;
            ⋮┆----------------------------------------
           35┆ Uri textUri = resolver.insert(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, contentValues);
```

MASTG menjelaskan: *"The first location is the import statement for the `MediaStore` API and the second location is where the `MediaStore` API is used to write to shared storage."*

```java
// MastgTest_reversed.java
ContentResolver resolver = this.context.getContentResolver();
ContentValues contentValues = new ContentValues();
contentValues.put("_display_name", "secretFile.txt");
contentValues.put("mime_type", "text/plain");
contentValues.put("relative_path", Environment.DIRECTORY_DOCUMENTS);
Uri textUri = resolver.insert(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, contentValues);  // <-- baris 35
if (textUri != null) {
    OutputStream outputStream = resolver.openOutputStream(textUri);
    byte[] bytes = "MAS_API_KEY=8767086b9f6f976g-a8df76\n".getBytes(Charsets.UTF_8);        // <-- API key plaintext
    it.write(bytes);
```

Evaluasi MASTG: *"the test **fails** because the file written by this instance contains sensitive data, specifically a API key."*

Dua catatan teknis pada demo ini yang perlu diperhatikan saat kamu mereplikasinya:

1. **Temuan pertama (baris 8) adalah sekadar `import` statement** — bukan bukti penulisan. Rule MediaStore MASTG memang sengaja dibuat luas (`pattern: import android.provider.MediaStore`), sehingga rawan false positive: aplikasi yang hanya **membaca** galeri foto juga akan terpicu. Ini contoh nyata mengapa langkah review manual (MASTG-TECH-0023) bersifat wajib, bukan opsional.
2. **Ada ketidaksesuaian kecil antara artefak `.kt` dan `.java` di demo ini.** Sumber Kotlin memakai `MediaStore.Downloads.EXTERNAL_CONTENT_URI` + `DIRECTORY_DOWNLOADS`, sedangkan Java hasil dekompilasi (yang dipindai semgrep) memakai `MediaStore.Images.Media.EXTERNAL_CONTENT_URI` + `DIRECTORY_DOCUMENTS` — menandakan kedua artefak berasal dari build yang berbeda. Tidak mempengaruhi kesimpulan test, tapi jangan bingung jika kamu membandingkan keduanya.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi | Contoh bukti |
|---|---|---|
| P1 | **Semgrep tidak menemukan temuan apa pun** pada kode maupun manifest | `0 Code Findings` pada kedua scan; tidak ada `uses-permission` storage; tidak ada flag legacy |
| P2 | Ada temuan API external storage, tetapi review kode (MASTG-TECH-0023) membuktikan data yang ditulis **tidak sensitif** | `getExternalCacheDir()` dipakai untuk cache thumbnail gambar publik / tile peta / file `.nomedia` |
| P3 | Ada temuan API external storage dengan data sensitif, tetapi review membuktikan data **ter-enkripsi dengan benar** — AES-256-GCM dan kunci dari Android KeyStore | Jalur penulisan melewati `EncryptedFile.openFileOutput()` dengan `MasterKey.KeyScheme.AES256_GCM`; tidak ada kunci hardcoded |
| P4 | Temuan hanya berupa **dead code / library yang tidak pernah dieksekusi** | Lokasi temuan berada di kelas yang tidak pernah direferensikan; dikonfirmasi dengan call-graph di jadx **dan** dengan MASTG-TEST-0201 (tidak pernah muncul di trace runtime) |
| P5 | Temuan berupa `Intent.ACTION_CREATE_DOCUMENT` / SAF di mana **user secara eksplisit memilih lokasi**, dan data yang diekspor tidak memuat kredensial/token | Fitur "Export laporan" yang dipicu user; berkas hasil tidak berisi secret. *(Tetap dicatat sebagai informational.)* |
| P6 | Semua data sensitif terbukti ditulis ke **internal storage** | Hanya `context.getFilesDir()` / `openFileOutput(..., MODE_PRIVATE)` yang muncul; tidak ada API eksternal |
| P7 | Manifest **bersih**: tidak ada `WRITE_EXTERNAL_STORAGE` / `MANAGE_EXTERNAL_STORAGE` / `ACCESS_ALL_EXTERNAL_STORAGE`, tidak ada flag opt-out scoped storage, dan `targetSdkVersion` ≥ 30 | Rule manifest → `0 Code Findings`; `aapt2 d badging` → `targetSdkVersion:'35'` |

**Contoh output yang menandakan PASS:**

```bash
$ NO_COLOR=true semgrep -c mastg-...-apis.yml ./decompiled/sources/
┌──────────────────┐
│ 0 Code Findings  │
└──────────────────┘

$ NO_COLOR=true semgrep -c mastg-...-manifest.yml ./out_dir/resources/AndroidManifest.xml
┌──────────────────┐
│ 0 Code Findings  │
└──────────────────┘

$ aapt d permissions ./target-app.apk
package: com.example.secureapp
uses-permission: name='android.permission.INTERNET'
# -> tidak ada permission storage sama sekali
```

atau — ada temuan, tetapi review membuktikan enkripsi yang benar:

```
    SecureVault.java
    ❯❱ rules.mastg-android-data-unencrypted-shared-storage-no-user-interaction-external-api-scoped
           41┆ File dir = this.context.getExternalFilesDir(null);
```

Review di jadx pada lokasi tersebut:

```java
// SecureVault.java:41-52 — data sensitif, tetapi ter-enkripsi dengan kunci dari KeyStore
File dir = this.context.getExternalFilesDir(null);
MasterKey masterKey = new MasterKey.Builder(this.context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build();
EncryptedFile encryptedFile = new EncryptedFile.Builder(
        this.context,
        new File(dir, "vault.bin"),
        masterKey,
        EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
).build();
OutputStream out = encryptedFile.openFileOutput();
out.write(sensitiveBytes);
```

Diperkuat dengan verifikasi negatif:

```bash
# Tidak ada kunci hardcoded maupun kripto lemah
$ grep -rnE "SecretKeySpec\(\"|AES/ECB|\"DES\"|RC4" ./decompiled/sources/
# (tidak ada hasil)
```

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Temuan semgrep saja BUKAN kerentanan.** Ini kesalahan paling umum pada test ini. Rule MASTG bersifat *indikatif* — pesannya pun berbunyi *"Make sure to encrypt files at these locations **if necessary**"*, yaitu peringatan untuk ditinjau, bukan pernyataan kerentanan. Melaporkan output semgrep apa adanya sebagai daftar kerentanan adalah praktik yang salah. Langkah **Further Validation Required** (MASTG-TECH-0023) bersifat wajib.

2. **Rule MediaStore sangat rawan false positive.** Pattern `import android.provider.MediaStore` dan `$X.MediaStore` akan terpicu bahkan pada aplikasi yang hanya **membaca** galeri, atau yang sama sekali tidak memakai import tersebut secara fungsional. Selalu konfirmasi ke titik penulisan aktual: `ContentResolver.insert()` + `openOutputStream()`.

3. **Rule manifest memakai `languages: generic`** dengan pattern string biasa. Konsekuensinya: ia akan mencocokkan string `WRITE_EXTERNAL_STORAGE` di **mana pun** — termasuk di dalam komentar, nilai atribut lain, atau bahkan di file non-manifest. Verifikasi bahwa yang cocok benar-benar berada dalam elemen `<uses-permission>`.

4. **Output kosong ≠ otomatis PASS.** Penyebab false pass pada test statis:
   - **Obfuscation/packing berat** — kode dienkripsi atau dimuat saat runtime sehingga tidak terlihat oleh semgrep.
   - **Kode native** — penulisan dari `.so` tidak terjangkau rule Java.
   - **Refleksi** — `Class.forName("android.os.Environment").getMethod("getExternalStorageDirectory")` tidak cocok dengan pattern.
   - **Split APK / dynamic feature module** yang tidak ikut dianalisis.
   - **Kode yang dimuat saat runtime** via `DexClassLoader` dari sumber jaringan.
   
   **Mitigasi:** jalankan APKiD untuk mendeteksi proteksi, analisis semua split APK, grep string pada `.so`, cari pola refleksi, dan **selalu korelasikan** dengan MASTG-TEST-0200 (diff filesystem — API-agnostic total). Bila TEST-0200 menemukan file baru sementara TEST-0202 bersih, berarti analisis statis punya titik buta.

5. **Kondisi "permission declared" bukan prasyarat mutlak** — lihat pembahasan di §3.3. API scoped storage dan MediaStore tidak memerlukan permission, namun MASTG-DEMO-0004 dan 0005 tetap dinyatakan FAIL.

6. **Permission tanpa pemanggilan API tetap layak dilaporkan** sebagai temuan terpisah (over-privilege, CWE-250) meski dengan severity lebih rendah. `WRITE_EXTERNAL_STORAGE` leftover memperluas attack surface tanpa manfaat; `MANAGE_EXTERNAL_STORAGE` leftown bahkan berisiko penolakan review Google Play.

7. **Bedakan asal-usul temuan.** Periksa apakah lokasi temuan berada di package aplikasi sendiri atau di package library pihak ketiga (`com.google.*`, `com.facebook.*`, `io.*`). Temuan pada library tetap tanggung jawab developer aplikasi, tetapi remediasinya berbeda (update/konfigurasi/ganti vendor, bukan edit kode).

8. **Severity dimodulasi oleh kombinasi faktor:**

   | Faktor | Efek pada severity |
   |---|---|
   | Data sensitif plaintext di shared storage publik (`Download/`, `Documents/`, MediaStore) | **Tertinggi** — terbaca app lain + bertahan pasca-uninstall |
   | `MANAGE_EXTERNAL_STORAGE` dideklarasikan | Naik — bypass scoped storage total |
   | `requestLegacyExternalStorage="true"` dengan target ≤ API 29 | Naik — eksposur lintas-app aktif |
   | `targetSdkVersion` ≤ 29 | Naik — scoped storage tidak di-enforce |
   | Data sensitif plaintext di app-specific external dir, target ≥ API 30 | Menengah — tetap FAIL, tetapi terlindungi dari app lain |
   | Pemuatan kode dari external storage | **Kritis** — terlepas dari sensitivitas data |
   | Permission dideklarasikan tapi tidak pernah di-grant (`dumpsys` → `granted=false`) | Turun sedikit — dampak nyata lebih rendah, deklarasinya tetap dilaporkan |

9. **Dokumentasikan bukti lengkap per temuan:** rule ID yang terpicu, path file + nomor baris, potongan kode hasil dekompilasi, hasil review MASTG-TECH-0023 (jenis data + ada/tidaknya enkripsi), status permission dari manifest dan dari `dumpsys`, `targetSdkVersion`/`minSdkVersion`, serta korelasi dengan hasil TEST-0200/0201. Cantumkan juga keterbatasan yang berlaku (obfuscation, kode native yang tidak dianalisis) agar pembaca laporan tahu batas kepercayaan hasilnya.

---

## 4. Rekomendasi Perbaikan

Akar masalahnya sama dengan MASTG-TEST-0200 dan 0201 (MASWE-0002). Keunggulan test ini untuk remediasi: ia memberi **daftar lengkap semua lokasi kode** yang perlu diperbaiki — bukan hanya yang kebetulan tereksekusi saat pengujian dinamis. Jadikan output semgrep sebagai *worklist* remediasi.

### 4.1 Prinsip Utama (urutan prioritas)

**Prioritas 1 — Hapus pemanggilan API external storage untuk data sensitif.**

```kotlin
// ❌ SALAH — terdeteksi rule "external-api-public" (DEMO-0003)
val dir = Environment.getExternalStorageDirectory()
FileOutputStream(File(dir, "secret.txt")).use { it.write(password.toByteArray()) }

// ❌ SALAH — terdeteksi rule "external-api-scoped" (DEMO-0004)
val dir = context.getExternalFilesDir(null)
FileOutputStream(File(dir, "secret.txt")).use { it.write(password.toByteArray()) }

// ❌ SALAH — terdeteksi rule "mediastore" (DEMO-0005)
val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, contentValues)
resolver.openOutputStream(uri!!)?.use { it.write(apiKey.toByteArray()) }

// ✅ BENAR — internal storage, tidak terdeteksi rule mana pun
context.openFileOutput("secret.txt", Context.MODE_PRIVATE).use { it.write(data) }
// atau
File(context.filesDir, "secret.txt").writeBytes(data)
```

Jangan pernah gunakan `MODE_WORLD_READABLE` / `MODE_WORLD_WRITEABLE` (deprecated sejak API 17, melempar `SecurityException` sejak API 24).

**Prioritas 2 — Bersihkan manifest dari permission dan flag berisiko.**

```xml
<!-- ❌ HAPUS semua ini jika tidak benar-benar dibutuhkan -->
<uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" />
<uses-permission android:name="android.permission.MANAGE_EXTERNAL_STORAGE" />
<application
    android:requestLegacyExternalStorage="true"
    android:preserveLegacyExternalStorage="true"
    android:requestRawExternalStorageAccess="true">

<!-- ✅ BENAR — target modern, scoped storage dipaksa aktif, permission granular -->
<uses-permission android:name="android.permission.READ_MEDIA_IMAGES" />
<application android:requestLegacyExternalStorage="false">
```

- Target **Android 11 (API 30) ke atas** — scoped storage dipaksa aktif oleh OS dan `requestLegacyExternalStorage` diabaikan.
- `WRITE_EXTERNAL_STORAGE` sudah **tidak berefek** pada API 30+ — jika masih ada, itu hampir selalu leftover yang harus dihapus.
- Hindari `MANAGE_EXTERNAL_STORAGE` kecuali benar-benar wajib (file manager, antivirus, backup app) — dibatasi kebijakan Google Play dan butuh justifikasi saat review.
- Bila hanya perlu memilih foto: gunakan **Photo Picker** (tanpa permission sama sekali), bukan `READ_MEDIA_IMAGES`.

**Prioritas 3 — Ganti API deprecated yang terdeteksi.**

| API terdeteksi | Pengganti yang benar |
|---|---|
| `Environment.getExternalStorageDirectory()` | `context.filesDir` (data sensitif) atau `context.getExternalFilesDir()` (file besar non-sensitif) |
| `Environment.getExternalStoragePublicDirectory()` | MediaStore API / Storage Access Framework — **hanya untuk data non-sensitif** |
| `WRITE_EXTERNAL_STORAGE` + `File` API langsung | MediaStore (media) / SAF (dokumen) / internal storage (sensitif) |
| Menaruh file di `/sdcard` agar bisa dibagikan ke app lain | **FileProvider** + `content://` URI dengan grant permission temporer |
| `DownloadManager.setDestinationInExternalPublicDir()` untuk data sensitif | Unduh ke `context.filesDir` melalui HTTP client aplikasi |

**Prioritas 4 — Gunakan mekanisme penyimpanan yang tepat per jenis data.**

| Jenis data | Mekanisme yang benar |
|---|---|
| Kunci kriptografi | **Android KeyStore** (`setUserAuthenticationRequired`, StrongBox bila tersedia) |
| Password, token, API key | Hindari penyimpanan bila mungkin (token sesi cukup di memori). Bila perlu: enkripsi dengan kunci KeyStore di internal storage |
| Key-value preferences sensitif | Internal storage + enkripsi. Catat: Jetpack Security `androidx.security:security-crypto` kini **deprecated** — pertimbangkan AES-GCM sendiri dengan kunci KeyStore, atau **Google Tink** |
| Data terstruktur | Room + **SQLCipher**, di internal storage |
| File besar milik aplikasi | Internal storage; bila ukuran memaksa external, wajib enkripsi (Prioritas 5) |
| File yang memang untuk dibagikan | MediaStore / SAF — **hanya data non-sensitif**, idealnya atas aksi eksplisit user |

**Prioritas 5 — Jika external storage tak terhindarkan: enkripsi dengan kunci dari KeyStore.**

```kotlin
val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build()

val encryptedFile = EncryptedFile.Builder(
    context,
    File(context.getExternalFilesDir(null), "data.enc"),
    masterKey,
    EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
).build()

encryptedFile.openFileOutput().use { it.write(sensitiveBytes) }
```

Syarat agar dianggap memadai:
- **AES-256-GCM** atau ChaCha20-Poly1305 (authenticated encryption). Tolak ECB, DES/3DES/RC4, CBC tanpa MAC.
- IV/nonce acak per operasi, tidak pernah diulang.
- Kunci **dihasilkan & disimpan di Android KeyStore** — bukan hardcoded, bukan diturunkan dari nilai statis (IMEI, package name, konstanta), bukan ditulis ke external storage.
- Bila kunci diturunkan dari password user: KDF kuat (PBKDF2 iterasi tinggi / **Argon2id** / scrypt) dengan salt acak.

> **Konsekuensi penting:** setelah remediasi ini, temuan semgrep **tetap akan muncul** (pemanggilan `getExternalFilesDir` masih ada). Yang berubah adalah hasil review MASTG-TECH-0023: data terbukti ter-enkripsi → PASS (P3). Jadi jangan menilai keberhasilan remediasi hanya dari jumlah temuan semgrep turun ke nol.

**Prioritas 6 — Validasi input & integritas untuk data yang DIBACA dari external storage** (mitigasi Man-in-the-Disk; menutup temuan F10).

- **Jangan pernah** memuat kode eksekutabel (DEX, SO, APK, JS bundle, script) dari external storage. Jika grep menemukan `DexClassLoader` / `System.load()` dengan path `/sdcard`, hapus total.
- Validasi ketat: ukuran, tipe MIME, magic bytes, struktur skema, batas nilai. Jangan deserialisasi objek Java/Kotlin dari file external storage.
- Cegah path traversal & symlink attack: kanonikalisasi path (`File.canonicalPath`), pastikan tetap di dalam direktori yang diizinkan.
- Verifikasi integritas dengan **HMAC-SHA256** berkunci KeyStore atau AEAD (AES-GCM) — bukan hash telanjang yang disimpan di sebelah file.

### 4.2 Perbaikan Praktik Tambahan

- **Integrasikan test ini ke CI/CD.** Ini keunggulan terbesar test statis: tidak butuh device maupun root. Jalankan semgrep dengan rule MASTG (atau mobsfscan) pada setiap PR, dan gagalkan build bila muncul temuan baru di luar allowlist. Ini mencegah regresi — termasuk yang masuk lewat update library.

```bash
# Contoh gate di CI
semgrep --config ./mastg/rules/ --error --json -o findings.json ./app/src/
# --error membuat exit code non-zero bila ada temuan
```

- **Buat allowlist eksplisit** untuk pemanggilan external storage yang memang disengaja dan sudah ter-enkripsi, dengan komentar justifikasi di kode. Ini membuat review berikutnya cepat dan membedakan keputusan desain dari kebocoran tak sengaja.
- **Audit library pihak ketiga.** Jalankan semgrep juga pada kode library hasil dekompilasi, bukan hanya pada kode aplikasi sendiri.
- **Data minimization.** Jangan simpan apa yang tidak perlu disimpan; gunakan refresh token berumur pendek.
- **Arahkan cache ke internal storage** (`context.cacheDir`) alih-alih `getExternalCacheDir()`.
- **Matikan logging verbose di build release** (`BuildConfig.DEBUG`); pastikan crash handler tidak menulis dump ke external storage.
- **Exclude file sensitif dari backup** (`android:allowBackup="false"` atau `dataExtractionRules`/`fullBackupContent`) — lihat MASWE-0006.
- **Lengkapi dengan analisis taint.** Semgrep melakukan pattern matching intra-file. Untuk membuktikan apakah data sensitif **benar-benar mengalir** ke API storage, gunakan **CodeQL** (query `java/android-cleartext-storage-filesystem`) yang mampu melakukan taint analysis lintas-fungsi.

### 4.3 Checklist Remediasi

- [ ] Setiap lokasi kode dari output semgrep sudah ditinjau dengan MASTG-TECH-0023 dan diklasifikasikan (sensitif/tidak, ter-enkripsi/tidak)
- [ ] Tidak ada data sensitif (kredensial, token, PII, data finansial) yang ditulis ke external/shared storage
- [ ] `Environment.getExternalStorageDirectory()` dan `getExternalStoragePublicDirectory()` (deprecated) sudah dihapus dari kode
- [ ] Penulisan via MediaStore hanya untuk data non-sensitif
- [ ] Data sensitif disimpan di internal storage (`context.filesDir`, `openFileOutput(..., MODE_PRIVATE)`)
- [ ] Tidak ada penggunaan `MODE_WORLD_READABLE` / `MODE_WORLD_WRITEABLE`
- [ ] Bila external storage tetap dipakai: data ter-enkripsi AES-256-GCM dengan kunci di Android KeyStore
- [ ] Tidak ada kunci/secret hardcoded (`SecretKeySpec("...")`) dan tidak ada kripto lemah (ECB/DES/RC4)
- [ ] `WRITE_EXTERNAL_STORAGE` dihapus dari manifest (tidak berefek pada API 30+)
- [ ] `MANAGE_EXTERNAL_STORAGE` dan `ACCESS_ALL_EXTERNAL_STORAGE` tidak dideklarasikan (kecuali dengan justifikasi kuat + approval Play)
- [ ] `requestLegacyExternalStorage`, `preserveLegacyExternalStorage`, `requestRawExternalStorageAccess` tidak di-set `true`
- [ ] `targetSdkVersion` ≥ 30 (idealnya mengikuti requirement Play terbaru)
- [ ] Permission storage minimal; gunakan Photo Picker / SAF / `READ_MEDIA_*` granular
- [ ] Tidak ada kode eksekutabel (DEX/SO/APK/JS) yang dimuat dari external storage
- [ ] Data yang dibaca dari external storage divalidasi dan diverifikasi integritasnya (HMAC/AEAD berkunci KeyStore)
- [ ] Cache diarahkan ke `context.cacheDir`, bukan `getExternalCacheDir()`
- [ ] Logging verbose & crash dump ke external storage dimatikan pada build release
- [ ] Library pihak ketiga sudah diaudit (semgrep dijalankan juga pada kode library)
- [ ] Kode native (`.so`) sudah diperiksa untuk string path external storage
- [ ] Semua split APK / dynamic feature module ikut dianalisis
- [ ] Scan semgrep terintegrasi di CI/CD sebagai gate, dengan allowlist terdokumentasi
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0202 → temuan nol, atau semua temuan tersisa terbukti ter-enkripsi/non-sensitif
- [ ] **Verifikasi silang:** jalankan MASTG-TEST-0200 (diff filesystem) dan MASTG-TEST-0201 (hooking) untuk menutup titik buta analisis statis

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0202: References to APIs and Permissions for Accessing External Storage](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0202/)
- [MASTG-TEST-0200: Files Written to External Storage](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0200/)
- [MASTG-TEST-0201: Runtime Use of APIs to Access External Storage](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0201/)
- [MASTG-TEST-0001: Testing Local Storage for Sensitive Data](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0001/)
- [MASWE-0002: Sensitive Data Stored Unencrypted Outside of Private Storage](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0002/)
- [MASTG-DEMO-0003: App Writing to External Storage without Scoped Storage Restrictions](https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0003/MASTG-DEMO-0003/)
- [MASTG-DEMO-0004: App Writing to External Storage with Scoped Storage Restrictions](https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0004/MASTG-DEMO-0004/)
- [MASTG-DEMO-0005: App Writing to External Storage via the MediaStore API](https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0005/MASTG-DEMO-0005/)
- [MASTG-DEMO-0001: File System Snapshots from External Storage](https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0001/MASTG-DEMO-0001/)
- [MASTG-DEMO-0002: External Storage APIs Tracing with Frida](https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0002/MASTG-DEMO-0002/)
- [MASTG-KNOW-0042: External Storage](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0042/)
- [MASTG-TECH-0013: Reverse Engineering Android Apps](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/)
- [MASTG-TECH-0014: Static Analysis on Android](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/)
- [MASTG-TECH-0017: Decompiling Java Code](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0017/)
- [MASTG-TECH-0023: Reviewing Decompiled Java Code](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/)
- [MASTG-TECH-0117: Obtaining Information from the AndroidManifest](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0117/)
- [MASTG-TECH-0126: Obtaining App Permissions](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0126/)
- [MASTG-TOOL-0110: semgrep](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0110/)
- [MASTG-TOOL-0018: jadx](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/)
- [MASTG-TOOL-0011: apktool](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0011/)
- [MASTG-TOOL-0124: aapt2](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0124/)
- [MASTG Rules — direktori `rules/` di repo OWASP/mastg](https://github.com/OWASP/mastg/tree/master/rules)
- [MASVS-STORAGE: Storage](https://mas.owasp.org/MASVS/05-MASVS-STORAGE/)
- [OWASP Mobile Top 10 2024 — M9: Insecure Data Storage](https://owasp.org/www-project-mobile-top-10/2023-risks/m9-insecure-data-storage)

### 5.2 Tools Analisis Statis (di luar MASTG)

- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [Semgrep — Pattern syntax reference](https://semgrep.dev/docs/writing-rules/pattern-syntax/)
- [Semgrep — Rule syntax (`pattern-either`, metavariables)](https://semgrep.dev/docs/writing-rules/rule-syntax/)
- [mobsfscan — static analysis untuk Android/iOS berbasis semgrep + libsast](https://github.com/MobSF/mobsfscan)
- [mobsfscan — rules semgrep untuk Android](https://github.com/MobSF/mobsfscan/tree/main/mobsfscan/rules/semgrep/android)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
- [IMQ Minded Security — Semgrep Rules for Android Application Security](https://blog.mindedsecurity.com/2023/10/semgrep-rules-for-android-application.html)
- [IMQ Intuity — Semgrep Rules for Android Application Security](https://www.intuity.it/2023/10/23/semgrep-rules-for-android-application-security-2/)
- [mindedsecurity/semgrep-rules-android-security](https://github.com/mindedsecurity/semgrep-rules-android-security)
- [CodeQL — Cleartext storage of sensitive information in the Android filesystem](https://codeql.github.com/codeql-query-help/java/java-android-cleartext-storage-filesystem/)
- [CodeQL — Java/Kotlin query help](https://codeql.github.com/codeql-query-help/java/)
- [SonarQube Rule java:S5324 — Accessing Android external storage is security-sensitive](https://rules.sonarsource.com/java/RSPEC-5324/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [apktool — Reverse engineering Android APK files](https://apktool.org/)
- [aapt2 — Android Asset Packaging Tool](https://developer.android.com/tools/aapt2)
- [APKiD — Android Application Identifier (packer/obfuscator detection)](https://github.com/rednaga/APKiD)
- [bundletool — bekerja dengan Android App Bundle](https://developer.android.com/tools/bundletool)
- [Ghidra — software reverse engineering framework (analisis `.so`)](https://ghidra-sre.org/)
- [TruffleHog — secret scanning](https://github.com/trufflesecurity/trufflehog)

### 5.3 Dokumentasi Resmi Android / Google

- [Sensitive Data Stored in External Storage — Android Security Risks](https://developer.android.com/privacy-and-security/risks/sensitive-data-external-storage)
- [Data and file storage overview](https://developer.android.com/training/data-storage)
- [Access app-specific files](https://developer.android.com/training/data-storage/app-specific)
- [Scoped storage](https://developer.android.com/training/data-storage#scoped-storage)
- [Storage use cases and best practices](https://developer.android.com/training/data-storage/use-cases)
- [Access media files from shared storage (MediaStore)](https://developer.android.com/training/data-storage/shared/media)
- [Access documents and other files (Storage Access Framework)](https://developer.android.com/training/data-storage/shared/documents-files)
- [Manage all files on a storage device (`MANAGE_EXTERNAL_STORAGE`)](https://developer.android.com/training/data-storage/manage-all-files)
- [All files access (Android 11 privacy)](https://developer.android.com/preview/privacy/storage#all-files-access)
- [`<uses-permission>` element](https://developer.android.com/guide/topics/manifest/uses-permission-element)
- [`Environment` — API reference](https://developer.android.com/reference/android/os/Environment)
- [`Context.getExternalFilesDir()` — API reference](https://developer.android.com/reference/android/content/Context#getExternalFilesDir(java.lang.String))
- [`MediaStore` — API reference](https://developer.android.com/reference/android/provider/MediaStore)
- [`R.attr.requestLegacyExternalStorage`](https://developer.android.com/reference/android/R.attr#requestLegacyExternalStorage)
- [`R.attr.preserveLegacyExternalStorage`](https://developer.android.com/reference/android/R.attr#preserveLegacyExternalStorage)
- [`EncryptedFile` (Jetpack Security)](https://developer.android.com/reference/androidx/security/crypto/EncryptedFile)
- [Android Keystore system](https://developer.android.com/privacy-and-security/keystore)
- [Cryptography best practices](https://developer.android.com/privacy-and-security/cryptography)
- [App security best practices — Store data safely](https://developer.android.com/privacy-and-security/security-best-practices#external-storage)
- [Security tips — Using external storage](https://developer.android.com/privacy-and-security/security-tips#external-storage)
- [FileProvider](https://developer.android.com/reference/androidx/core/content/FileProvider)
- [Photo picker](https://developer.android.com/training/data-storage/shared/photopicker)
- [Google Play — Use of the All files access permission](https://support.google.com/googleplay/android-developer/answer/10467955)
- [Google Tink — cryptographic library](https://developers.google.com/tink)

### 5.4 Standar, Taksonomi, dan Guideline Lain

- [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
- [CWE-921: Storage of Sensitive Data in a Mechanism without Access Control](https://cwe.mitre.org/data/definitions/921.html)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [CWE-250: Execution with Unnecessary Privileges](https://cwe.mitre.org/data/definitions/250.html)
- [CWE-732: Incorrect Permission Assignment for Critical Resource](https://cwe.mitre.org/data/definitions/732.html)
- [SEI CERT Android — DRD00: Do not store sensitive information on external storage (SD card) unless encrypted first](https://wiki.sei.cmu.edu/confluence/display/android/DRD00.+Do+not+store+sensitive+information+on+external+storage+%28SD+card%29+unless+encrypted+first)
- [NIST SP 800-163 Rev.1 — Vetting the Security of Mobile Applications](https://csrc.nist.gov/publications/detail/sp/800-163/rev-1/final)
- [NIST SP 800-124 Rev.2 — Guidelines for Managing the Security of Mobile Devices](https://csrc.nist.gov/publications/detail/sp/800-124/rev-2/final)
- [MITRE ATT&CK Mobile — T1533: Data from Local System](https://attack.mitre.org/techniques/T1533/)
- [MITRE ATT&CK Mobile — T1409: Stored Application Data](https://attack.mitre.org/techniques/T1409/)

### 5.5 Riset Keamanan & Artikel Teknis

- [Check Point Research — Man-in-the-Disk: Android Apps Exposed via External Storage](https://research.checkpoint.com/2018/androids-man-in-the-disk/)
- [Check Point Blog — Man-in-the-Disk: A New Attack Surface for Android Apps](https://blog.checkpoint.com/security/man-in-the-disk-a-new-attack-surface-for-android-apps/)
- [Threatpost — DEF CON 2018: 'Man in the Disk' Attack Surface Affects All Android Phones](https://threatpost.com/def-con-2018-man-in-the-disk-attack-surface-affects-all-android-phones/134993/)
- [The Hacker News — New Man-in-the-Disk attack leaves millions of Android phones vulnerable](https://thehackernews.com/2018/08/man-in-the-disk-android-hack.html)
- [NDSS 2025 — ScopeVerif: Analyzing the Security of Android's Scoped Storage via Differential Analysis](https://www.ndss-symposium.org/wp-content/uploads/2025-340-paper.pdf)
- [PolyScope: Multi-Policy Access Control Analysis to Triage Android Scoped Storage (arXiv)](https://arxiv.org/pdf/2302.13506)
- [Security Smells in Android (arXiv)](https://arxiv.org/pdf/2006.01181)
- [HackTricks — Android Applications Pentesting](https://book.hacktricks.wiki/en/mobile-pentesting/android-app-pentesting/index.html)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026), dokumentasi resmi Semgrep dan Android Developers, standar CWE/SEI CERT/NIST, serta riset keamanan pihak ketiga.*
