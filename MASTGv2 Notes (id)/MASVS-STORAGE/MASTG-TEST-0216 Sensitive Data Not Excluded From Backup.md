# MASTG-TEST-0216 Sensitive Data Not Excluded From Backup

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0216 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-STORAGE (MASVS-STORAGE-2: Aplikasi mencegah kebocoran data sensitif yang tidak diperlukan) |
| **Weakness** | **MASWE-0006** — *Sensitive Data Not Excluded From Backup* |
| **Tipe Pengujian** | **Dynamic**, Filesystem |
| **Profile** | L1, L2, **P** (Privacy) |
| **Knowledge** | MASTG-KNOW-0050 (Backups) |
| **Best Practice** | MASTG-BEST-0004 (Exclude Sensitive Data from Backups) |
| **Teknik terkait** | MASTG-TECH-0005 (Installing Apps), MASTG-TECH-0128 (Performing a Backup and Restore of App Data), MASTG-TECH-0127 (Inspecting an App's Backup Data) |
| **Demo terkait** | MASTG-DEMO-0020 (via Backup Manager `bmgr`), MASTG-DEMO-0035 (via `adb backup`) |
| **Counterpart statis** | **MASTG-TEST-0262** (References to Backup Configurations Not Excluding Sensitive Data) — demo: MASTG-DEMO-0034 |
| **CWE terkait** | CWE-530 (Exposure of Backup File to an Unauthorized Control Sphere), CWE-200 (Exposure of Sensitive Information), CWE-312 (Cleartext Storage of Sensitive Information), CWE-359 (Exposure of Private Personal Information), CWE-16 (Configuration) |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Kutipan langsung dari overview MASTG:

> *"This test verifies whether apps correctly instruct the system to **exclude sensitive files from backups** by **performing a backup and restore of the app data and checking which files are restored**."*
>
> *"Android provides a way to start the backup daemon to back up and restore app files, which you can use to verify **which files are actually restored** from the backup."*

Kata kunci yang membedakan test ini dari counterpart statisnya: **"actually restored"**. Test ini tidak membaca konfigurasi — ia **membuktikan secara empiris** file apa yang benar-benar keluar dan masuk kembali melalui mekanisme backup. Konfigurasi bisa terlihat benar di atas kertas tetapi gagal dalam praktik (typo path, domain salah, aturan tidak mencakup subdirektori, `device-transfer` terlupakan).

### 1.2 Mengapa Backup Adalah Permukaan Serangan

MASTG-KNOW-0050 menjelaskan bahwa ekosistem Android mendukung banyak opsi backup, dan **masing-masing adalah jalur keluar data**:

| Jalur backup | Ke mana data pergi | Catatan |
|---|---|---|
| **`adb backup`** (USB) | Ke komputer penguji/penyerang | Dibatasi sejak Android 12; butuh `android:debuggable="true"` |
| **Google "Back Up My Data"** | Server Google | Otomatis, tanpa interaksi khusus dari user |
| **Auto Backup for Apps** (API 23+) | Google Drive user, maks. **25 MB** per app | **Aktif secara default** — inilah sumber masalah utama |
| **Key/Value Backup** (Backup API) | Android Backup Service cloud | Perlu `BackupAgent`/`BackupAgentHelper` |
| **Device-to-device transfer** | Perangkat baru user | Sering terlupakan — **aturan terpisah** dari cloud backup |
| **Backup OEM** (mis. HTC Backup, Samsung/Xiaomi Cloud) | Server vendor | Di luar kendali Google, kebijakannya berbeda-beda |

MASTG-KNOW-0050 menegaskan:

> *"Apps must carefully ensure that **sensitive user data doesn't end within these backups** as this may allow an attacker to extract it."*

**Titik paling penting untuk dipahami:** atribut `allowBackup` **bernilai `true` secara default** bila tidak dinyatakan. Jadi aplikasi yang tidak pernah memikirkan backup sama sekali **otomatis** mengizinkan seluruh data sandbox-nya di-backup.

> *"When this attribute is unavailable, the `allowBackup` setting is **enabled by default**, and backup must be **manually deactivated**."*

Skenario serangan konkret:

| Skenario | Bagaimana terjadi |
|---|---|
| **Akses fisik singkat** | Perangkat unlocked + USB debugging aktif → `adb backup` menarik data sandbox tanpa root, dalam hitungan detik |
| **Data ikut ke cloud** | Auto Backup menyinkronkan token/kredensial ke Google Drive user; kompromi akun Google = kompromi data aplikasi |
| **Perangkat lama dijual/diserahkan** | D2D transfer atau backup cloud membawa data sensitif ke perangkat baru — atau tertinggal di cloud |
| **Perangkat kerja/bersama** | Admin atau pengguna lain memicu restore ke perangkat yang mereka kendalikan |
| **Penyerang dengan akun Google korban** | Restore aplikasi ke perangkat penyerang → data sensitif ikut ter-restore tanpa perlu kredensial aplikasi |
| **APK injection via backup archive** | Riset menunjukkan `BackupAgent` dapat menyisipkan APK tambahan ke arsip backup tanpa persetujuan user |

### 1.3 Dua Generasi Konfigurasi Backup — Keduanya Harus Ada

Ini sumber kesalahan paling umum. Android punya **dua atribut berbeda** untuk dua rentang versi, dan keduanya perlu dideklarasikan bila `minSdkVersion` aplikasi mencakup keduanya:

| Atribut | Berlaku untuk | File aturan | Elemen root |
|---|---|---|---|
| `android:fullBackupContent` | **Android 11 (API 30) ke bawah** | `backup_rules.xml` | `<full-backup-content>` |
| `android:dataExtractionRules` | **Android 12 (API 31) ke atas** | `data_extraction_rules.xml` | `<data-extraction-rules>` |

Dan di dalam `data_extraction_rules.xml`, ada **dua bagian terpisah** yang masing-masing harus dikonfigurasi:

```xml
<data-extraction-rules>
    <cloud-backup>    <!-- backup ke Google Drive -->
        <exclude domain="..." path="..." />
    </cloud-backup>
    <device-transfer> <!-- transfer perangkat-ke-perangkat -->
        <exclude domain="..." path="..." />
    </device-transfer>
</data-extraction-rules>
```

**MASTG-BEST-0004 secara eksplisit menegaskan:** *"Make sure to use **both** the `cloud-backup` and `device-transfer` parameters."* Mengecualikan file hanya dari `cloud-backup` tetap membiarkannya bocor lewat D2D transfer — dan sebaliknya.

**Nilai `domain` yang tersedia** untuk `<include>`/`<exclude>`:

| `domain` | Merujuk ke |
|---|---|
| `file` | `getFilesDir()` — `/data/data/<pkg>/files/` |
| `database` | `getDatabasePath()` — `/data/data/<pkg>/databases/` |
| `sharedpref` | `getSharedPreferences()` — `/data/data/<pkg>/shared_prefs/` |
| `root` | Akar direktori data aplikasi |
| `external` | `getExternalFilesDir()` |
| `device_file`, `device_database`, `device_sharedpref`, `device_root` | Varian *device-protected storage* (Direct Boot) |

> Kesalahan umum: mengecualikan `domain="file"` tetapi lupa `domain="sharedpref"` dan `domain="database"` — padahal token biasanya justru ada di `shared_prefs/`.

**Enkripsi end-to-end.** Untuk data sangat sensitif, ada mekanisme yang memastikan backup hanya terjadi bila perangkat mendukung enkripsi client-side (Android 9+ dengan lock screen):

```xml
<!-- Android 11 dan bawah -->
<full-backup-content requireFlags="clientSideEncryption"> ... </full-backup-content>

<!-- Android 12 dan atas -->
<cloud-backup disableIfNoEncryptionCapabilities="true"> ... </cloud-backup>
```

Ini **mitigasi tambahan, bukan pengganti `<exclude>`** — data tetap masuk backup, hanya terenkripsi dengan kunci yang tidak diketahui Google.

### 1.4 Posisi Test Ini vs MASTG-TEST-0262 (Statis)

MASTG menyatakan hubungan ini eksplisit: *"See MASTG-TEST-0262 for a static analysis counterpart."*

| | MASTG-TEST-0216 *(dokumen ini)* | MASTG-TEST-0262 |
|---|---|---|
| **Pendekatan** | Dinamis — backup & restore nyata | Statis — baca manifest + file aturan |
| **Menjawab** | "File apa yang **benar-benar** ter-restore?" | "Konfigurasinya **seperti apa**?" |
| **Kekuatan** | **Bukti empiris**; menangkap typo path, domain salah, subdirektori terlewat, file yang dibuat runtime | Cepat, tanpa device, CI-friendly, melihat seluruh konfigurasi |
| **Kelemahan** | Butuh device + root (untuk bmgr local transport); hanya file yang sudah dibuat selama exercise | **Tidak bisa menilai apakah aturan mencakup SEMUA file sensitif** — ini keterbatasan fundamental |
| **Kriteria FAIL** | *"if any of the files are considered sensitive"* | Kombinasi 4 kondisi konfigurasi |

**Keterbatasan fundamental TEST-0262** yang membuat TEST-0216 wajib: analisis statis dapat melihat bahwa `backup_rules.xml` ada dan berisi `<exclude>`, tetapi **tidak dapat mengetahui file apa saja yang akan dibuat aplikasi saat runtime**, sehingga tidak dapat memastikan semuanya tercakup. Kriteria evaluasi TEST-0262 sendiri berbunyi *"don't exclude **all** sensitive files"* — penilaian "all" itu hanya bisa dibuktikan secara dinamis.

**Alur kerja yang direkomendasikan:**

```
TEST-0262 (statis)  ──►  allowBackup? atribut ada? isi file aturan?
        │                        (cepat, cakupan konfigurasi penuh)
        ▼
TEST-0216 (dinamis) ──►  backup + restore nyata → daftar file ter-restore
        │                        (bukti empiris, menangkap celah aturan)
        ▼
   Bandingkan dengan inventaris data sensitif (dari MASTG-TEST-0207)
        ▼
   Keputusan PASS / FAIL
```

Dan bertaut kuat dengan **MASTG-TEST-0207**: inventaris file sandbox dari test tersebut adalah daftar yang perlu kamu cek apakah masing-masing terkecualikan dari backup.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | MASTG ID | Fungsi |
|---|---|---|
| **adb** | MASTG-TOOL-0004 | `bmgr`, `adb backup`, `adb pull`, enumerasi file. Tool utama |
| **`bmgr`** (Backup Manager) | — | Daemon backup Android via `adb shell bmgr`. **Metode yang direkomendasikan** karena tidak terkena restriksi Android 12 |
| **Android device / emulator (rooted)** | MASTG-TOOL-0003 | Root diperlukan untuk menarik `.ab` dari `/data/data/com.android.localtransport/` dan untuk `find` di sandbox |
| **`tar`** | — | Membuka arsip `.ab` (TAR dengan header khusus) |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **Android Backup Extractor (`abe`)** | Direkomendasikan MASTG-TECH-0128. Membuka `.ab` termasuk yang **terenkripsi dengan password** — `adb backup` menghasilkan format yang tidak selalu bisa dibuka `tar` biasa |
| **semgrep** (MASTG-TOOL-0110) | Untuk MASTG-TEST-0262 — memindai atribut backup di manifest |
| **apktool** (MASTG-TOOL-0011) | Mengekstrak `AndroidManifest.xml` **dan** `res/xml/backup_rules.xml` / `data_extraction_rules.xml` |
| **aapt2** (MASTG-TOOL-0124) | Query cepat atribut manifest tanpa ekstraksi |
| **jadx** (MASTG-TOOL-0018) | Manifest lengkap + mencari implementasi `BackupAgent` |
| **MobSF** | Menandai `allowBackup` otomatis dalam laporan; berguna untuk pass pertama |
| **mobsfscan** | CLI ringan untuk CI |
| **drozer** | Modul `app.package.backup` / `scanner.misc.*` untuk audit atribut backup |
| **`sqlite3`, `strings`, `file`, `ent`** | Inspeksi isi file hasil restore |
| **Frida** (MASTG-TOOL-0001) | Hook `BackupAgent.onBackup()` / `onFullBackup()` untuk melihat apa yang dikirim aplikasi ke backup (jalur key-value) |
| **Google Drive UI / Settings** | Verifikasi manual ukuran & keberadaan backup cloud |

### 2.3 Prasyarat Lingkungan

- **Root** untuk metode `bmgr` (menarik `.ab` dari `/data/data/com.android.localtransport/files/`). Emulator AVD dengan image *Google APIs* paling praktis (`adb root` langsung berhasil).
- **Untuk `adb backup`:** hanya bekerja bila `android:allowBackup="true"` **dan** — sejak Android 12 (targetSdk 31+) — `android:debuggable="true"`. Pada aplikasi release yang benar, `debuggable=false`, sehingga **`adb backup` tidak akan mengembalikan data aplikasi**. Ini bukan kegagalan pengujian; gunakan `bmgr`.
- **Device/emulator bersih** (fresh wipe atau snapshot) agar tidak ada sisa backup dari sesi sebelumnya.
- **Canary value unik** untuk setiap input — mempermudah identifikasi di file hasil restore (`MASTG_CANARY_PWD_7f3a`, dsb.).
- **Inventaris data sensitif terlebih dahulu.** Idealnya jalankan MASTG-TEST-0207 lebih dulu agar kamu punya daftar file sandbox beserta isinya sebagai pembanding.
- **JANGAN buka aplikasi setelah reinstall/restore.** Ini instruksi eksplisit MASTG (langkah 4: *"Uninstall and reinstall the app but **don't open it anymore**"*). Membuka aplikasi akan membuat ulang file sehingga hasil diff tercemar dan kamu tidak bisa membedakan file hasil restore dari file yang baru dibuat.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0005** untuk menginstall aplikasi.
2. **Jalankan dan gunakan aplikasi** melalui berbagai alur kerja sambil memasukkan data sensitif di setiap tempat yang memungkinkan.
3. Gunakan **MASTG-TECH-0128** untuk melakukan backup dan restore data aplikasi.
4. **Uninstall dan reinstall aplikasi, tetapi jangan buka lagi.**
5. Restore data dari backup dan dapatkan daftar file yang ter-restore.

---

### 3.2 Metode A — Backup Manager (`bmgr`) + Local Transport *(resmi, MASTG-DEMO-0020)*

Ini metode yang paling andal karena **tidak terkena restriksi `adb backup` Android 12** dan bekerja pada aplikasi non-debuggable.

**Script backup resmi MASTG** (`utils/mastg-android-backup-bmgr.sh`):

```bash
#!/bin/bash
package_name="$1"

# Script from https://developer.android.com/identity/data/testingbackup
# Initialize and create a backup
adb shell bmgr enable true
adb shell bmgr transport com.android.localtransport/.LocalTransport | grep -q "Selected transport" \
    || (echo "Error: error selecting local transport"; exit 1)
adb shell settings put secure backup_local_transport_parameters 'is_encrypted=true'
adb shell bmgr backupnow "$package_name" | grep -F "Package $package_name with result: Success" \
    || (echo "Backup failed"; exit 1)

# Uninstall and reinstall the app to clear the data and trigger a restore
apk_path_list=$(adb shell pm path "$package_name")
OIFS=$IFS; IFS=$'\n'
apk_number=0
for apk_line in $apk_path_list; do
    (( ++apk_number ))
    apk_path=${apk_line:8:1000}
    adb pull "$apk_path" "myapk${apk_number}.apk"
done
IFS=$OIFS
adb shell pm uninstall --user 0 "$package_name"
apks=$(seq -f 'myapk%.f.apk' 1 $apk_number)
adb install-multiple -t --user 0 $apks

# Clean up
adb shell bmgr transport com.google.android.gms/.backup.BackupTransportService
rm $apks
echo "Done"
```

Yang dilakukan script ini, langkah demi langkah:

| Perintah | Fungsi |
|---|---|
| `bmgr enable true` | Mengaktifkan Backup Manager |
| `bmgr transport com.android.localtransport/.LocalTransport` | Mengalihkan backup dari cloud Google ke **transport lokal** — sehingga `.ab` tersimpan di device dan dapat diinspeksi |
| `settings put secure backup_local_transport_parameters 'is_encrypted=true'` | Menandai transport lokal sebagai terenkripsi — penting agar aturan `requireFlags="clientSideEncryption"` / `disableIfNoEncryptionCapabilities` tidak memblokir backup |
| `bmgr backupnow <pkg>` | Memicu backup segera |
| `pm path` + `adb pull` | Menyimpan APK (termasuk split APK) sebelum uninstall |
| `pm uninstall --user 0` | Menghapus aplikasi **dan datanya** |
| `install-multiple -t --user 0` | Install ulang → **restore otomatis terjadi di sini** |
| `bmgr transport com.google.android.gms/...` | Mengembalikan transport ke cloud (housekeeping) |

**Script pengujian (`run.sh` dari MASTG-DEMO-0020):**

```bash
#!/bin/bash
package_name="org.owasp.mastestapp"

adb root
adb shell "find /data/user/0/$package_name/files -type f" > output_before.txt

../../../../utils/mastg-android-backup-bmgr.sh $package_name

adb shell "find /data/user/0/$package_name/files -type f" > output_after.txt

mkdir -p restored_files
while read -r line; do
  adb pull "$line" ./restored_files/
done < output_after.txt
```

**Mengekstrak arsip `.ab` secara langsung** (MASTG-TECH-0128), bila kamu ingin melihat isi backup itu sendiri alih-alih hasil restore:

```bash
adb root
adb pull /data/data/com.android.localtransport/files/1/_full/org.owasp.mastestapp \
         org.owasp.mastestapp.ab
tar xvf org.owasp.mastestapp.ab
```

> **Catatan penting tentang `run.sh` demo:** script hanya memeriksa `.../files` (`filesDir`). Untuk pengujian nyata, **perluas ke seluruh sandbox** — terutama `shared_prefs/` dan `databases/` yang justru paling sering memuat token. Versi yang diperluas ada di §3.9.

---

### 3.3 Metode B — `adb backup` *(resmi, MASTG-DEMO-0035)*

**Script backup resmi MASTG** (`utils/mastg-android-backup-adb.sh`):

```bash
#!/bin/bash
package_name="$1"

adb backup -apk -nosystem $package_name
tail -c +25 backup.ab | python3 -c "import zlib,sys;sys.stdout.buffer.write(zlib.decompress(sys.stdin.buffer.read()))" > backup.tar
tar xvf backup.tar

echo "Done, extracted as apps/ to current directory"
```

Perhatikan `tail -c +25` — ini melewati **24 byte header `.ab`** sebelum aliran zlib dimulai. Format `.ab` = header teks + payload zlib berisi TAR.

**Script pengujian (`run.sh` dari MASTG-DEMO-0035):**

```bash
#!/bin/bash
package_name="org.owasp.mastestapp"

../../../../utils/mastg-android-backup-adb.sh $package_name

ls -l1 apps/org.owasp.mastestapp/f > output.txt

# Cleanup
rm backup.ab backup.tar
find apps/org.owasp.mastestapp/ -mindepth 1 -maxdepth 1 ! -name 'f*' -exec rm -rf {} +
```

**Struktur arsip backup** (MASTG-TECH-0127) — penting untuk memetakan file ke lokasi aslinya:

| Path dalam arsip | Asal di device |
|---|---|
| `apps/<pkg>/a/` | File `.apk` aplikasi itu sendiri |
| `apps/<pkg>/obb/` | Kontainer `.obb` terkait |
| `apps/<pkg>/f/` | Subtree dari `getFilesDir()` |
| `apps/<pkg>/db/` | Subtree dari parent `getDatabasePath()` |
| `apps/<pkg>/sp/` | Subtree dari parent `getSharedPrefsFile()` |
| `apps/<pkg>/r/` | File relatif terhadap akar file tree aplikasi |
| `apps/<pkg>/c/` | Direktori `getCacheDir()` — **tidak disimpan** |

> **Keterbatasan metode ini — dan MASTG memberi peringatan eksplisit:** *"`adb backup` is **restricted since Android 12** and requires `android:debuggable=true` in the AndroidManifest.xml."*
>
> Pada aplikasi release yang dikonfigurasi benar (`debuggable=false`), `adb backup` **tidak akan mengembalikan data aplikasi** — arsipnya kosong. Itu **bukan PASS**; itu berarti metode ini tidak dapat dipakai. Gunakan Metode A (`bmgr`).
>
> MASTG juga mencatat: *"The behavior might differ between an emulator and a physical device."*

---

### 3.4 Metode C — Android Backup Extractor (`abe`) untuk arsip terenkripsi

MASTG-TECH-0128 merekomendasikan tool ini, dan ia menyelesaikan masalah nyata: `adb backup` dapat menghasilkan `.ab` **terenkripsi dengan password** (bila user menetapkan password backup), yang tidak bisa dibuka dengan `tail` + `zlib` seperti di §3.3.

```bash
# Unduh abe (Android Backup Extractor)
#   https://github.com/nelenkov/android-backup-extractor

# Backup tanpa password
java -jar abe.jar unpack backup.ab backup.tar
tar xvf backup.tar

# Backup DENGAN password
java -jar abe.jar unpack backup.ab backup.tar "MyBackupPassword"
tar xvf backup.tar

# Kebalikannya — repack (berguna untuk uji integritas restore, lihat §3.8)
java -jar abe.jar pack backup.tar modified.ab "MyBackupPassword"
adb restore modified.ab

# Info arsip tanpa mengekstraksi
java -jar abe.jar info backup.ab
```

Kapan memakai ini: ketika `tar xvf` gagal dengan error format, atau ketika kamu perlu **memodifikasi lalu me-restore** arsip (uji apakah aplikasi memvalidasi data hasil restore — lihat §3.8).

---

### 3.5 Metode D — Statis dengan semgrep *(MASTG-TEST-0262 / MASTG-DEMO-0034)*

Ini counterpart statis resmi. Cepat, tanpa device, cocok untuk CI.

**Rule resmi MASTG** (`rules/mastg-android-backup-manifest.yml`):

```yaml
rules:
  - id: mastg-android-backup-manifest-allow-backup
    severity: WARNING
    languages:
      - xml
    metadata:
      summary: This rule inspects the AndroidManifest.xml for allowBackup.
      references:
        - https://developer.android.com/guide/topics/data/autobackup
    message: "[MASVS-STORAGE-2] allowBackup detected as $ARG."
    patterns:
      - pattern: 'android:allowBackup="$ARG"'

  - id: mastg-android-backup-manifest-backup-rules
    severity: WARNING
    languages:
      - xml
    metadata:
      summary: This rule inspects the AndroidManifest.xml for backup rules.
      references:
        - https://developer.android.com/guide/topics/data/autobackup
    message: "[MASVS-STORAGE-2] Backup rules detected."
    pattern-either:
      - pattern: 'android:fullBackupContent="@xml/backup_rules"'
      - pattern: 'android:dataExtractionRules="@xml/data_extraction_rules"'
```

Menjalankannya:

```bash
apktool d -f -o ./decoded ./target-app.apk

NO_COLOR=true semgrep -c ./mastg/rules/mastg-android-backup-manifest.yml \
  ./decoded/AndroidManifest.xml > output.txt

# Lalu baca file aturannya — semgrep TIDAK melakukan ini
cat ./decoded/res/xml/backup_rules.xml
cat ./decoded/res/xml/data_extraction_rules.xml
```

> ⚠️ **Celah serius pada rule ini:** pattern-nya mencocokkan **nama file literal** `@xml/backup_rules` dan `@xml/data_extraction_rules`. Bila developer menamai filenya berbeda — dan ini sangat umum — rule akan **melaporkan "tidak ada backup rules"** padahal aturannya ada.
>
> Ironisnya, **contoh resmi dokumentasi Android sendiri** memakai `@xml/backup_rules_extraction` dan `@xml/backup_rules_full`, yang **tidak akan cocok** dengan rule MASTG. Jadi rule ini berpotensi menghasilkan **false positive tinggi** (melaporkan aturan tidak ada padahal ada).
>
> Rule perluasan yang menutup celah ini ada di §3.9.

---

### 3.6 Metode E — Statis alternatif: apktool + grep, aapt2, MobSF, drozer

Beberapa jalur yang tidak bergantung pada semgrep, berguna ketika kamu tidak punya rule MASTG atau ingin verifikasi silang.

**E1 — apktool + grep (paling portabel, tanpa dependency tambahan):**

```bash
apktool d -f -o ./decoded ./target-app.apk

# 1. Atribut backup di manifest (tangkap nama file APA PUN, bukan hanya nama default)
grep -oE 'android:(allowBackup|fullBackupContent|dataExtractionRules|backupAgent|restoreAnyVersion|fullBackupOnly|backupInForeground)="[^"]*"' \
  ./decoded/AndroidManifest.xml

# Contoh output:
#   android:allowBackup="true"
#   android:dataExtractionRules="@xml/data_extraction_rules"
#   android:fullBackupContent="@xml/backup_rules"

# 2. CEK: apakah allowBackup ADA sama sekali? Bila tidak ada -> default TRUE (temuan!)
grep -q 'android:allowBackup' ./decoded/AndroidManifest.xml \
  && echo "allowBackup dideklarasikan" \
  || echo "[!] allowBackup TIDAK dideklarasikan -> default TRUE"

# 3. Resolusi nama file aturan secara dinamis, lalu tampilkan isinya
for attr in fullBackupContent dataExtractionRules; do
  ref=$(grep -oE "android:$attr=\"@xml/[^\"]+\"" ./decoded/AndroidManifest.xml \
        | sed -E 's/.*@xml\/([^"]+)".*/\1/')
  if [ -n "$ref" ]; then
    echo "=== $attr -> res/xml/$ref.xml ==="
    cat "./decoded/res/xml/$ref.xml"
  else
    echo "[!] $attr tidak dideklarasikan"
  fi
done

# 4. Cek apakah device-transfer ikut dikecualikan (sering terlupakan)
grep -c "device-transfer" ./decoded/res/xml/*.xml

# 5. Cek domain apa saja yang dikecualikan — sharedpref & database sering terlewat
grep -oE 'domain="[^"]*"' ./decoded/res/xml/data_extraction_rules.xml | sort -u

# 6. Cek BackupAgent kustom (jalur key-value)
grep -n "android:backupAgent" ./decoded/AndroidManifest.xml
grep -rn "extends BackupAgent\|extends BackupAgentHelper\|onBackup\|onFullBackup" \
  ./decompiled/sources/ 2>/dev/null
```

**E2 — aapt2 (tercepat, tanpa perlu dekompilasi):**

```bash
aapt2 d badging ./target-app.apk | grep -iE "allowBackup|application-debuggable"
aapt2 d xmltree --file AndroidManifest.xml ./target-app.apk | grep -iE "allowBackup|BackupContent|dataExtraction|backupAgent"
```

> Ingat catatan MASTG-TECH-0150: aapt2 mengeluarkan **format decoded kustom**, bukan XML standar — nama atributnya berbeda (mis. `application-debuggable`, bukan `android:debuggable`).

**E3 — MobSF (GUI + laporan siap pakai):**

```bash
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
# Upload APK via http://localhost:8000
```

Cari di laporan: bagian **Manifest Analysis** → temuan `[android:allowBackup=true]` dengan judul *"Application Data can be Backed up"*. Keunggulannya: langsung memberi penjelasan risiko dan severity yang bisa dikutip ke laporan; juga memeriksa `debuggable` sekaligus.

**E4 — mobsfscan (CLI, cocok untuk CI):**

```bash
pip install mobsfscan
mobsfscan --json -o mobsfscan.json ./decoded/
jq '.results | to_entries[] | select(.key | test("backup"))' mobsfscan.json
```

**E5 — drozer (audit dari sisi device):**

```bash
drozer console connect
dz> run app.package.info -a com.example.target      # menampilkan flag aplikasi
dz> run scanner.misc.readablefiles --privileged      # pelengkap
```

**E6 — One-liner tanpa tool apa pun (cepat untuk triase awal):**

```bash
unzip -p ./target-app.apk AndroidManifest.xml | strings | grep -iE "allowBackup|backupAgent|dataExtraction"
```

Ini bekerja karena manifest biner tetap menyimpan nama atribut sebagai string — berguna untuk cek kilat, meski tidak memberi nilainya.

---

### 3.7 Metode F — Verifikasi jalur cloud & device-transfer

Metode A–C memverifikasi mekanisme backup lokal. Tetapi aturan `cloud-backup` dan `device-transfer` adalah **bagian yang terpisah**, dan kesalahan konfigurasi di sana tidak akan terlihat oleh transport lokal.

```bash
# 1. Paksa backup ke transport CLOUD (bukan local) untuk menguji jalur nyata
adb shell bmgr transport com.google.android.gms/.backup.BackupTransportService
adb shell bmgr backupnow com.example.target

# 2. Periksa status & antrean backup
adb shell bmgr list transports
adb shell dumpsys backup | head -60
adb shell dumpsys backup | grep -iE "Ancestral|Current|Pending|allowBackup"

# 3. Verifikasi ukuran backup cloud (Auto Backup dibatasi 25 MB)
#    Settings > Google > Backup > App data  — atau:
adb shell dumpsys backup | grep -iE "size|quota"

# 4. Uji device-transfer: jalankan backup dengan transport D2D bila tersedia
adb shell bmgr list transports        # cari transport bertipe transfer
```

**Verifikasi `device-transfer` secara praktis** sulit diotomatisasi karena butuh dua perangkat. Alternatif yang realistis: **audit konfigurasi secara ketat** (§3.6 E1 langkah 4) dan pastikan setiap `<exclude>` di `<cloud-backup>` juga ada di `<device-transfer>` — perbedaan di antara keduanya hampir selalu bug, bukan keputusan desain.

---

### 3.8 Metode G — Pengujian lanjutan: integritas data hasil restore

Ini di luar lingkup formal MASTG-TEST-0216, tetapi merupakan pertanyaan keamanan yang wajar muncul dari mekanisme yang sama: **apakah aplikasi memvalidasi data yang di-restore?** Data backup dapat dimodifikasi penyerang sebelum di-restore.

```bash
# 1. Backup
adb backup -apk -nosystem com.example.target        # atau via bmgr

# 2. Ekstrak, MODIFIKASI, repack
java -jar abe.jar unpack backup.ab backup.tar
tar xvf backup.tar
#    -> ubah nilai di apps/<pkg>/sp/auth_prefs.xml, mis. is_premium=false -> true
#    -> atau ubah user_id ke user lain
tar cvf modified.tar apps/
java -jar abe.jar pack modified.tar modified.ab

# 3. Restore data yang sudah dimodifikasi
adb shell pm uninstall --user 0 com.example.target
adb install ./target-app.apk
adb restore modified.ab

# 4. Buka aplikasi dan periksa: apakah modifikasi diterima?
```

Bila aplikasi menerima nilai yang dimodifikasi (mis. status premium, kuota, ID user), itu temuan tersendiri: data hasil restore diperlakukan sebagai *trusted input*. Terkait juga dengan atribut `android:restoreAnyVersion="true"`, yang mengizinkan restore dari versi aplikasi **mana pun** — termasuk versi lama yang lebih rentan.

> Lakukan hanya dalam lingkup engagement yang diizinkan.

---

### 3.9 Script yang Diperluas dan Rule Perluasan

**Script `run.sh` yang mencakup SELURUH sandbox** (bukan hanya `files/`):

```bash
#!/bin/bash
PKG=${1:-com.example.target}
D=/data/user/0/$PKG

adb root >/dev/null

echo "[*] Snapshot SEBELUM backup (seluruh sandbox)..."
adb shell "find $D -type f" | sort > output_before.txt
wc -l output_before.txt

echo "[*] Backup + uninstall + reinstall (restore otomatis)..."
./mastg-android-backup-bmgr.sh "$PKG" || exit 1

# Beri waktu restore selesai; JANGAN buka aplikasi
sleep 5

echo "[*] Snapshot SESUDAH restore..."
adb shell "find $D -type f" | sort > output_after.txt
wc -l output_after.txt

echo "[*] File yang TER-RESTORE (ada di after):"
mkdir -p restored_files
while read -r remote; do
  [ -z "$remote" ] && continue
  rel="${remote#$D/}"
  mkdir -p "./restored_files/$(dirname "$rel")"     # pertahankan struktur direktori
  adb pull "$remote" "./restored_files/$rel" >/dev/null 2>&1 \
    || adb shell "su -c 'cat $remote'" > "./restored_files/$rel"
done < output_after.txt

echo "[*] File yang BERHASIL DIKECUALIKAN (ada sebelum, hilang sesudah):"
comm -23 output_before.txt output_after.txt

echo "[*] Cari canary value di file hasil restore:"
grep -raiE "MASTG_CANARY_PWD_7f3a|password|token|bearer|api[_-]?key|secret" ./restored_files/ || echo "  (bersih)"

echo "[*] Inspeksi shared_prefs & databases hasil restore:"
for f in ./restored_files/shared_prefs/*.xml; do [ -f "$f" ] && echo "--- $f" && cat "$f"; done
for db in $(find ./restored_files -name "*.db"); do echo "--- $db"; sqlite3 "$db" ".tables"; done
```

**Rule semgrep perluasan** — menutup celah nama file literal di §3.5:

```yaml
rules:
  # 1. allowBackup=true (tanpa mengasumsikan nama file aturan)
  - id: custom-backup-allowbackup-true
    severity: WARNING
    languages: [xml, generic]
    message: "[MASVS-STORAGE-2] android:allowBackup=\"true\" — data aplikasi dapat di-backup"
    pattern-regex: 'android:allowBackup\s*=\s*"true"'

  # 2. Atribut aturan backup dengan nama file APA PUN
  - id: custom-backup-rules-any-name
    severity: INFO
    languages: [xml, generic]
    message: "[MASVS-STORAGE-2] Atribut aturan backup ditemukan — verifikasi ISI file aturannya"
    pattern-either:
      - pattern-regex: 'android:fullBackupContent\s*=\s*"@xml/[^"]+"'
      - pattern-regex: 'android:dataExtractionRules\s*=\s*"@xml/[^"]+"'

  # 3. Atribut backup berisiko lainnya
  - id: custom-backup-risky-attributes
    severity: WARNING
    languages: [xml, generic]
    message: "[MASVS-STORAGE-2] Atribut backup berisiko (restoreAnyVersion / backupAgent kustom)"
    pattern-either:
      - pattern-regex: 'android:restoreAnyVersion\s*=\s*"true"'
      - pattern-regex: 'android:backupAgent\s*=\s*"[^"]+"'

  # 4. data_extraction_rules.xml yang HANYA punya cloud-backup (device-transfer terlupakan)
  - id: custom-backup-missing-device-transfer
    severity: ERROR
    languages: [generic]
    paths:
      include: ["*data_extraction_rules*.xml", "*extraction*.xml"]
    message: "[MASVS-STORAGE-2] <cloud-backup> ada tetapi <device-transfer> tidak — data bocor via D2D transfer"
    patterns:
      - pattern-regex: '<cloud-backup'
      - pattern-not-regex: '<device-transfer'

  # 5. Aturan backup yang meng-include semuanya tanpa exclude
  - id: custom-backup-include-all-no-exclude
    severity: ERROR
    languages: [generic]
    paths:
      include: ["*backup_rules*.xml", "*data_extraction_rules*.xml", "*extraction*.xml"]
    message: "[MASVS-STORAGE-2] <include> mencakup semuanya tanpa <exclude> apa pun"
    patterns:
      - pattern-regex: '<include[^>]+path\s*=\s*"\."'
      - pattern-not-regex: '<exclude'
```

Jalankan pada manifest **dan** file aturan:

```bash
NO_COLOR=true semgrep -c ./custom-backup-rules.yml ./decoded/AndroidManifest.xml ./decoded/res/xml/
```

---

### 3.10 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Butuh root? | Bekerja pada app non-debuggable? | Terkena restriksi Android 12? | Kekuatan | Kapan dipakai |
|---|---|---|---|---|---|
| **A — `bmgr` local transport** | Ya (untuk pull `.ab`/`find`) | ✅ Ya | ❌ Tidak | **Paling andal & representatif**; menguji jalur Auto Backup yang sebenarnya | **Default untuk test ini** |
| **B — `adb backup`** | Tidak | ❌ Tidak (butuh `debuggable=true`) | ✅ Ya | Cepat, tanpa root, arsip mudah diinspeksi | Aplikasi debug/legacy, atau target SDK < 31 |
| **C — `abe`** | Tidak | — | — | Membuka `.ab` **terenkripsi**; bisa repack | Saat `tar` gagal, atau untuk uji integritas restore |
| **D — semgrep (TEST-0262)** | Tidak | ✅ Ya | ❌ Tidak | Cepat, CI-friendly, tanpa device | Pass pertama & gate CI |
| **E1 — apktool + grep** | Tidak | ✅ Ya | ❌ Tidak | Portabel, menangkap **nama file aturan apa pun** | Verifikasi silang semgrep; paling akurat untuk statis |
| **E2 — aapt2** | Tidak | ✅ Ya | ❌ Tidak | Tercepat, tanpa dekompilasi | Triase kilat banyak APK |
| **E3 — MobSF** | Tidak | ✅ Ya | ❌ Tidak | Laporan siap kutip + severity | Dokumentasi laporan, audit luas |
| **E4 — mobsfscan** | Tidak | ✅ Ya | ❌ Tidak | Ringan untuk pipeline | CI/CD gate |
| **E5 — drozer** | Tidak | ✅ Ya | ❌ Tidak | Audit dari sisi device | Bagian dari sesi drozer yang lebih luas |
| **F — cloud/D2D** | Sebagian | ✅ Ya | ❌ Tidak | Menguji jalur `cloud-backup` & `device-transfer` yang sebenarnya | Aplikasi L2/privasi tinggi |
| **G — integritas restore** | Tidak | ❌ Tidak (butuh `adb restore`) | ✅ Ya | Menemukan kelemahan validasi data restore | Pengujian lanjutan, di luar lingkup formal |

**Rekomendasi praktis:** jalankan **E1 (apktool+grep) → A (bmgr)** sebagai kombinasi minimum. E1 memberi gambaran konfigurasi lengkap tanpa celah nama file, A memberi bukti empiris. Tambahkan D untuk CI, F untuk aplikasi dengan kebutuhan privasi tinggi.

---

### 3.11 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG (TEST-0216):**

> **Observation:** *"The output should contain a list of files that are restored from the backup."*
>
> **Evaluation:** *"The test case **fails if any of the files are considered sensitive**."*

Kriterianya sangat lugas — tidak ada klausa tambahan. **Ada file sensitif yang ter-restore → FAIL.**

**Sebagai pembanding, kriteria MASTG-TEST-0262 (statis)** menyebutkan kombinasi kondisi:

> *The test case fails if the app allows sensitive data to be backed up. Specifically, if the following conditions are met:*
> - *`android:allowBackup="true"` in the `AndroidManifest.xml`*
> - *`android:fullBackupContent="@xml/backup_rules"` isn't declared (for Android 11 or lower)*
> - *`android:dataExtractionRules="@xml/data_extraction_rules"` isn't declared (for Android 12 and higher)*
> - *`backup_rules.xml` or `data_extraction_rules.xml` aren't present or **don't exclude all sensitive files**.*

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi | Contoh bukti |
|---|---|---|
| F1 | File berisi **kredensial/token** ter-restore dari backup | `restored_files/secret.txt` berisi `secr3tPa$$W0rd` |
| F2 | **`shared_prefs/*.xml`** ter-restore dan memuat token/flag autentikasi plaintext | `<string name="auth_token">eyJ...</string>` di `restored_files/shared_prefs/` |
| F3 | **Database** ter-restore dan memuat data user | `restored_files/databases/app.db` → tabel `users` |
| F4 | **Canary value** yang kamu masukkan ditemukan di file hasil restore | `grep -r MASTG_CANARY_PWD_7f3a ./restored_files/` → ada hasil |
| F5 | `allowBackup` **tidak dideklarasikan** di manifest (default `true`) dan data sensitif ada di sandbox | `grep android:allowBackup` → tidak ada hasil |
| F6 | `android:allowBackup="true"` tanpa **atribut aturan** apa pun | Manifest tanpa `fullBackupContent` maupun `dataExtractionRules` |
| F7 | File aturan ada tetapi **tidak mengecualikan semua** file sensitif | Demo MASTG: `backup_excluded_secret.txt` dikecualikan, tetapi `secret.txt` tidak |
| F8 | `<exclude>` hanya ada di **`cloud-backup`**, tidak di **`device-transfer`** (atau sebaliknya) | Pelanggaran MASTG-BEST-0004 → bocor via D2D transfer |
| F9 | Hanya `dataExtractionRules` yang ada, sementara `minSdkVersion` ≤ 30 | Perangkat Android 11 ke bawah tidak terlindungi |
| F10 | Hanya `fullBackupContent` yang ada, sementara `targetSdkVersion` ≥ 31 | Perangkat Android 12 ke atas memakai aturan yang diabaikan |
| F11 | **Domain terlewat** — mengecualikan `domain="file"` tetapi bukan `sharedpref`/`database` | Token di `shared_prefs/` tetap ter-backup |
| F12 | **Path `<exclude>` salah/typo** sehingga tidak berefek | Terbukti dinamis: file tetap ter-restore meski ada aturan exclude |
| F13 | `android:debuggable="true"` pada build release, sehingga `adb backup` dapat menarik data tanpa root | Temuan gabungan: eksposur backup + data plaintext |
| F14 | `android:restoreAnyVersion="true"` | Mengizinkan restore dari versi aplikasi mana pun, termasuk versi rentan |
| F15 | `BackupAgent` kustom menyertakan data sensitif | Review `onBackup()`/`onFullBackup()` |
| F16 | Data ter-backup **tanpa** `requireFlags="clientSideEncryption"` / `disableIfNoEncryptionCapabilities="true"` pada aplikasi yang menangani data sangat sensitif | Data sensitif dapat tersimpan di cloud tanpa E2E encryption |
| F17 | **File aturan direferensikan tetapi tidak ada** di APK | `android:fullBackupContent="@xml/backup_rules"` tetapi `res/xml/backup_rules.xml` tidak ditemukan |

**Contoh output yang menandakan FAIL — MASTG-DEMO-0020 (`bmgr`):**

Kode sampel (`MastgTest.kt`) — membuat **dua** file dengan isi sama, satu dikecualikan dan satu tidak:

```kotlin
val internalStorageDir = context.filesDir
val fileName = File(internalStorageDir, "secret.txt")
val fileNameOfBackupExcludedFile = File(internalStorageDir, "backup_excluded_secret.txt")
val fileContent = "secr3tPa\$\$W0rd\n"

FileOutputStream(fileName).use { it.write(fileContent.toByteArray()) }
FileOutputStream(fileNameOfBackupExcludedFile).use { it.write(fileContent.toByteArray()) }
```

`AndroidManifest.xml`:

```xml
<application
    android:allowBackup="true"
    android:dataExtractionRules="@xml/data_extraction_rules"
    android:fullBackupContent="@xml/backup_rules"
    ... >
```

`backup_rules.xml` (Android 11 ke bawah):

```xml
<?xml version="1.0" encoding="utf-8"?>
<full-backup-content>
    <include domain="file" path="." requireFlags="clientSideEncryption" />
    <exclude domain="file" path="backup_excluded_secret.txt" />
</full-backup-content>
```

`data_extraction_rules.xml` (Android 12 ke atas) — perhatikan bahwa demo **benar** mengecualikan di kedua bagian:

```xml
<?xml version="1.0" encoding="utf-8"?>
<data-extraction-rules>
    <cloud-backup disableIfNoEncryptionCapabilities="true">
        <exclude domain="file" path="backup_excluded_secret.txt" />
    </cloud-backup>

    <device-transfer disableIfNoEncryptionCapabilities="true">
        <exclude domain="file" path="backup_excluded_secret.txt" />
    </device-transfer>
</data-extraction-rules>
```

**`output_before.txt`** (sebelum backup):

```
/data/user/0/org.owasp.mastestapp/files/secret.txt
/data/user/0/org.owasp.mastestapp/files/backup_excluded_secret.txt
/data/user/0/org.owasp.mastestapp/files/profileInstalled
```

**`output_after.txt`** (setelah restore) — **inilah buktinya**:

```
/data/user/0/org.owasp.mastestapp/files/profileInstalled
/data/user/0/org.owasp.mastestapp/files/secret.txt
```

**`restored_files/secret.txt`**:

```
secr3tPa$$W0rd
```

Evaluasi MASTG: *"The test **fails** because `secret.txt` is restored from the backup and it contains sensitive data. Note that `output_after.txt` does **not** contain the `backup_excluded_secret.txt` file, which is expected as it was marked as `exclude` in the `backup_rules.xml` file."*

**Contoh output yang menandakan FAIL — MASTG-DEMO-0035 (`adb backup`):**

`output.txt` (isi `apps/org.owasp.mastestapp/f`):

```
profileInstalled
secret.txt
```

`apps/org.owasp.mastestapp/f/secret.txt`:

```
secr3tPa$$W0rd
```

Evaluasi MASTG: *"The test **fails** because `secret.txt` is part of the backup and it contains sensitive data. Note that `backup_excluded_secret.txt` file is not part of the backup, which is expected."*

**Contoh output MASTG-TEST-0262 (statis, DEMO-0034):**

```
┌─────────────────┐
│ 3 Code Findings │
└─────────────────┘

    ../MASTG-DEMO-0020/AndroidManifest.xml
    ❯❱ rules.mastg-android-backup-manifest-allow-backup
          [MASVS-STORAGE-2] allowBackup detected as true.

            6┆ android:allowBackup="true"

    ❯❱ rules.mastg-android-backup-manifest-backup-rules
          [MASVS-STORAGE-2] Backup rules detected.

            7┆ android:dataExtractionRules="@xml/data_extraction_rules"
            ⋮┆----------------------------------------
            8┆ android:fullBackupContent="@xml/backup_rules"
```

Evaluasi MASTG-DEMO-0034: *"The test **fails** because the sensitive file `secret.txt` ends up in the backup. This is due to: `android:allowBackup="true"`; the `android:fullBackupContent` attribute is present; the `backup_rules.xml` file is present in the APK and **does not exclude all sensitive files**."*

**Empat observasi penting dari demo ini:**

1. **Konfigurasi backup-nya secara teknis "benar" — dan tetap FAIL.** Aplikasi ini mendeklarasikan **kedua** atribut (`fullBackupContent` dan `dataExtractionRules`), mengecualikan di **kedua** bagian (`cloud-backup` dan `device-transfer`), **dan** memakai `requireFlags="clientSideEncryption"` / `disableIfNoEncryptionCapabilities="true"`. Yang salah bukan mekanismenya, melainkan **cakupannya**: hanya satu dari dua file sensitif yang dikecualikan. Ini menunjukkan bahwa test ini menilai **kelengkapan**, bukan keberadaan konfigurasi.

2. **Inilah bukti mengapa test statis tidak cukup.** Output semgrep pada DEMO-0034 melaporkan hal yang "menenangkan": *allowBackup detected as true* dan *Backup rules detected*. Dari output itu saja, tester bisa saja menyimpulkan aplikasi sudah mengelola backup. Hanya pengujian dinamis yang memperlihatkan `secret.txt` benar-benar ter-restore.

3. **Demo memperlihatkan kontrol positif dan negatif dalam satu sesi.** `backup_excluded_secret.txt` **hilang** dari `output_after.txt` — membuktikan mekanisme `<exclude>` berfungsi dan pengujiannya valid. Ini pola yang baik untuk direplikasi: sertakan satu file yang kamu tahu dikecualikan sebagai *sanity check*. Bila keduanya hilang, mungkin backup-nya gagal sama sekali, bukan aturannya bekerja.

4. **`profileInstalled` adalah noise, bukan temuan.** File ini dibuat `androidx.profileinstaller` (baseline profile), bukan data aplikasi. Saring file semacam ini agar laporan tetap fokus.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi | Contoh bukti |
|---|---|---|
| P1 | **Tidak ada file** yang ter-restore dari backup | `output_after.txt` kosong (selain file yang dibuat sistem seperti `profileInstalled`) |
| P2 | Ada file ter-restore, tetapi **tidak ada yang sensitif** | Hanya preferensi UI (tema, bahasa), cache aset publik, flag onboarding |
| P3 | `android:allowBackup="false"` — backup dimatikan total | `grep android:allowBackup` → `"false"`; `bmgr backupnow` → tidak ada data |
| P4 | Semua file sensitif **dikecualikan** dan terbukti hilang setelah restore | `comm -23 output_before.txt output_after.txt` memuat semua file sensitif |
| P5 | Canary value **tidak ditemukan** di file hasil restore | `grep -r MASTG_CANARY_PWD_7f3a ./restored_files/` → kosong |
| P6 | File sensitif ter-restore tetapi **ter-enkripsi dengan kunci dari Android KeyStore** | Kunci tidak dapat di-backup (KeyStore tidak ikut backup) → data tidak dapat didekripsi di perangkat lain |
| P7 | Kedua atribut dideklarasikan sesuai rentang `minSdk`–`targetSdk`, dan `<exclude>` ada di **kedua** bagian (`cloud-backup` + `device-transfer`) | Konfigurasi lengkap |
| P8 | Semua domain relevan dicakup (`file`, `sharedpref`, `database`, `external`, dan varian `device_*` bila memakai Direct Boot) | `grep -oE 'domain="[^"]*"'` menampilkan semuanya |
| P9 | `android:debuggable="false"` diverifikasi pada APK release | `aapt2 d badging` tidak menampilkan `application-debuggable` |

**Contoh output yang menandakan PASS:**

```bash
$ ./run_extended.sh com.example.secureapp
[*] Snapshot SEBELUM backup (seluruh sandbox)...
      23 output_before.txt
[*] Backup + uninstall + reinstall (restore otomatis)...
Backup Manager now enabled
Package com.example.secureapp with result: Success
[*] Snapshot SESUDAH restore...
       1 output_after.txt
[*] File yang TER-RESTORE (ada di after):
[*] File yang BERHASIL DIKECUALIKAN (ada sebelum, hilang sesudah):
/data/user/0/com.example.secureapp/shared_prefs/auth_prefs.xml
/data/user/0/com.example.secureapp/databases/app.db
/data/user/0/com.example.secureapp/files/session.bin
...
[*] Cari canary value di file hasil restore:
  (bersih)
```

Konfigurasi yang benar:

```xml
<!-- AndroidManifest.xml — deklarasikan KEDUANYA -->
<application
    android:allowBackup="true"
    android:fullBackupContent="@xml/backup_rules"
    android:dataExtractionRules="@xml/data_extraction_rules"
    android:debuggable="false"
    ... >
```

```xml
<!-- res/xml/data_extraction_rules.xml (Android 12+) -->
<?xml version="1.0" encoding="utf-8"?>
<data-extraction-rules>
    <cloud-backup disableIfNoEncryptionCapabilities="true">
        <include domain="root" path="." />
        <exclude domain="sharedpref" path="auth_prefs.xml" />
        <exclude domain="database"   path="app.db" />
        <exclude domain="database"   path="app.db-wal" />
        <exclude domain="database"   path="app.db-journal" />
        <exclude domain="file"       path="session.bin" />
        <exclude domain="file"       path="vault/" />
        <exclude domain="external"   path="cache/" />
    </cloud-backup>

    <device-transfer disableIfNoEncryptionCapabilities="true">
        <!-- Cerminkan SELURUH exclude di atas -->
        <include domain="root" path="." />
        <exclude domain="sharedpref" path="auth_prefs.xml" />
        <exclude domain="database"   path="app.db" />
        <exclude domain="database"   path="app.db-wal" />
        <exclude domain="database"   path="app.db-journal" />
        <exclude domain="file"       path="session.bin" />
        <exclude domain="file"       path="vault/" />
        <exclude domain="external"   path="cache/" />
    </device-transfer>
</data-extraction-rules>
```

```xml
<!-- res/xml/backup_rules.xml (Android 11 ke bawah) — cerminkan aturan yang sama -->
<?xml version="1.0" encoding="utf-8"?>
<full-backup-content requireFlags="clientSideEncryption">
    <include domain="root" path="." />
    <exclude domain="sharedpref" path="auth_prefs.xml" />
    <exclude domain="database"   path="app.db" />
    <exclude domain="database"   path="app.db-wal" />
    <exclude domain="database"   path="app.db-journal" />
    <exclude domain="file"       path="session.bin" />
    <exclude domain="file"       path="vault/" />
</full-backup-content>
```

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Jangan buka aplikasi setelah reinstall.** Instruksi eksplisit MASTG. Membuka aplikasi membuat ulang file (token baru, database baru), sehingga kamu tidak bisa membedakan file hasil restore dari file yang baru dibuat — dan bisa salah melaporkan FAIL.

2. **`adb backup` yang mengembalikan arsip kosong ≠ PASS.** Sejak Android 12, `adb backup` mengecualikan data aplikasi kecuali `android:debuggable="true"`. Pada aplikasi release yang benar, ini akan selalu kosong. Statusnya **Inconclusive untuk metode itu** — gunakan `bmgr` (Metode A). Justru sebaliknya: bila `adb backup` **berhasil** menarik data dari APK release, itu berarti aplikasi debuggable → temuan tambahan (F13).

3. **Sertakan kontrol positif.** Seperti pada demo, pastikan setidaknya satu file yang kamu tahu dikecualikan memang hilang setelah restore. Bila semua file hilang, mungkin backup-nya gagal total (transport salah, `bmgr` tidak aktif, kuota terlampaui) — bukan aturannya bekerja. Periksa output `bmgr backupnow` untuk `result: Success`.

4. **Saring file yang dibuat sistem.** `profileInstalled`, `oat/`, `code_cache/` dan sejenisnya bukan data aplikasi. Fokuskan pada `files/`, `shared_prefs/`, `databases/`, dan `app_webview/`.

5. **Periksa SELURUH sandbox, bukan hanya `files/`.** Script demo membatasi diri ke `filesDir` untuk kesederhanaan, tetapi **token paling sering berada di `shared_prefs/`** dan data user di `databases/`. Gunakan script §3.9.

6. **Jangan lupa WAL/journal SQLite.** `app.db` yang dikecualikan tetapi `app.db-wal` tidak akan membocorkan data melalui backup. Aturan `<exclude>` harus mencakup ketiganya.

7. **Verifikasi kecocokan atribut dengan rentang SDK aplikasi.** Ini kesalahan yang sering lolos:
   - `minSdkVersion ≤ 30` → **wajib** ada `fullBackupContent`
   - `targetSdkVersion ≥ 31` → **wajib** ada `dataExtractionRules`
   - Aplikasi dengan rentang `minSdk 24`–`targetSdk 34` → **butuh keduanya**

8. **Enkripsi dengan kunci KeyStore adalah mitigasi yang kuat di sini.** Kunci Android KeyStore **tidak ikut ter-backup** (tidak dapat diekspor dari secure hardware). Jadi file ter-enkripsi yang ikut backup tetap tidak dapat didekripsi di perangkat lain. Ini jalur PASS yang sah (P6) — tetapi verifikasi bahwa kuncinya benar-benar dari KeyStore, bukan hardcoded (MASTG-TEST-0212).

9. **Celah rule semgrep MASTG.** Rule mencocokkan nama file literal `@xml/backup_rules` / `@xml/data_extraction_rules`. Nama lain — termasuk **contoh dari dokumentasi Android sendiri** (`@xml/backup_rules_extraction`) — akan terlewat dan dilaporkan sebagai "aturan tidak ada". Gunakan Metode E1 (apktool+grep) atau rule perluasan §3.9 untuk verifikasi.

10. **Severity dimodulasi oleh beberapa faktor:**

    | Faktor | Severity |
    |---|---|
    | Kredensial/token/private key ter-restore | **Kritis** — memungkinkan account takeover dari perangkat lain |
    | Data finansial/kesehatan ter-restore | **Kritis** |
    | PII ter-restore | **Tinggi** (+ dimensi privasi, profile `P`) |
    | `allowBackup` tidak dideklarasikan sama sekali + data sensitif ada | **Tinggi** — kelalaian, bukan keputusan |
    | Data dapat ditarik **tanpa root** (`adb backup` berhasil / app debuggable) | **Naik signifikan** |
    | `<exclude>` hanya di `cloud-backup`, bukan `device-transfer` | **Tinggi** — jalur D2D sering dipakai user |
    | Atribut tidak cocok rentang SDK (F9/F10) | **Tinggi** — sebagian basis pengguna tidak terlindungi |
    | Tanpa `requireFlags`/`disableIfNoEncryptionCapabilities` untuk data sangat sensitif | Menengah |
    | Data sensitif ter-backup tetapi **ter-enkripsi dengan kunci KeyStore** | Rendah / informational |
    | Hanya preferensi UI non-sensitif ter-restore | **Bukan temuan** |

11. **Dokumentasikan bukti lengkap:** daftar file sebelum & sesudah restore, isi file sensitif yang ter-restore (redaksi sebagian), **file yang berhasil dikecualikan** (sebagai kontrol positif), metode backup yang dipakai (bmgr/adb/cloud), isi `AndroidManifest.xml` dan **kedua** file aturan secara verbatim, `minSdkVersion`/`targetSdkVersion`, status `debuggable`, hasil `bmgr backupnow` (`result: Success`), dan langkah reproduksi dengan canary value. Cantumkan juga batasan (mis. `device-transfer` tidak diverifikasi karena hanya satu perangkat tersedia).

---

## 4. Rekomendasi Perbaikan

### 4.1 Prinsip Utama (urutan prioritas)

**Prioritas 1 — Jangan simpan data sensitif yang tidak perlu.** Remediasi terkuat: bila datanya tidak ada di sandbox, ia tidak bisa ikut backup. Token sesi sebaiknya hanya di memori. Ini sekaligus menyelesaikan MASTG-TEST-0207.

**Prioritas 2 — Kecualikan data sensitif dari backup (MASTG-BEST-0004).**

MASTG-BEST-0004 menyatakan:

> *"For the sensitive files found, instruct the system to exclude them from the backup:*
> - *If you are using Auto Backup, mark them with the `exclude` tag in `backup_rules.xml` (for Android 11 or lower using `android:fullBackupContent`) or `data_extraction_rules.xml` (for Android 12 and higher using `android:dataExtractionRules`), depending on the target API. **Make sure to use both the `cloud-backup` and `device-transfer` parameters.***
> - *If you are using the key-value approach, set up your `BackupAgent` accordingly."*

Checklist konfigurasi yang benar:
- Deklarasikan **kedua** atribut bila rentang SDK mencakup keduanya
- Cerminkan **setiap** `<exclude>` di `<cloud-backup>` **dan** `<device-transfer>`
- Cakup **semua domain**: `file`, `sharedpref`, `database`, `external`, plus varian `device_*` bila memakai Direct Boot
- Sertakan **file turunan SQLite**: `-wal`, `-shm`, `-journal`
- Gunakan pola direktori (`path="vault/"`) alih-alih daftar file individual agar file baru otomatis tercakup

**Prioritas 3 — Matikan backup sepenuhnya bila aplikasi tidak butuh.**

```xml
<application android:allowBackup="false" ... >
```

Ini opsi paling aman dan paling sederhana. Trade-off-nya: user kehilangan kenyamanan restore. Untuk aplikasi finansial/kesehatan yang datanya toh harus di-sync dari server setelah login, ini biasanya pilihan yang tepat.

> Catat: **jangan mengandalkan ketiadaan atribut**. Bila `allowBackup` tidak dideklarasikan, nilainya **`true`**. Harus dinyatakan eksplisit `false`.

**Prioritas 4 — Gunakan `no_backup/` untuk file yang tidak boleh di-backup.** Android menyediakan direktori khusus yang **otomatis dikecualikan** dari backup — tidak perlu aturan XML:

```kotlin
// ✅ Otomatis tidak ikut backup, tanpa perlu konfigurasi apa pun
val f = File(context.noBackupFilesDir, "session.bin")
f.writeBytes(sessionData)
```

Ini pendekatan yang lebih tahan kesalahan daripada mengandalkan `<exclude>` yang bisa typo atau terlewat saat file baru ditambahkan.

**Prioritas 5 — Enkripsi dengan kunci dari Android KeyStore.** Ini mitigasi paling kuat karena bersifat *fail-safe*: kunci KeyStore **tidak ikut ter-backup** dan tidak dapat diekspor dari secure hardware. Jadi meskipun file ter-enkripsi ikut masuk backup, ia **tidak dapat didekripsi** di perangkat lain.

```kotlin
val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build()
// data ter-enkripsi; kunci tetap di KeyStore dan tidak ikut backup
```

Kombinasikan dengan Prioritas 2 sebagai pertahanan berlapis — jangan andalkan salah satu saja.

**Prioritas 6 — Wajibkan enkripsi end-to-end untuk data sangat sensitif.**

```xml
<!-- Android 12+ : backup hanya terjadi bila perangkat mendukung E2E encryption -->
<cloud-backup disableIfNoEncryptionCapabilities="true"> ... </cloud-backup>

<!-- Android 11 ke bawah -->
<full-backup-content requireFlags="clientSideEncryption"> ... </full-backup-content>
```

Dokumentasi Android menjelaskan bahwa pada Android 9+ dengan lock screen aktif, data backup dienkripsi dengan kunci yang **tidak diketahui Google**. Atribut di atas memastikan backup tidak terjadi bila jaminan itu tidak tersedia.

**Prioritas 7 — Konfigurasikan `BackupAgent` dengan benar bila memakai key-value backup.** Bila aplikasi memakai `BackupAgent`/`BackupAgentHelper`, `<exclude>` XML tidak berlaku — kontrolnya ada di kode:

```kotlin
class MyBackupAgent : BackupAgent() {
    override fun onBackup(oldState: ParcelFileDescriptor?, data: BackupDataOutput,
                          newState: ParcelFileDescriptor) {
        // Tulis HANYA data non-sensitif; jangan sertakan token/kredensial
    }
    override fun onRestore(data: BackupDataInput, appVersionCode: Int,
                           newState: ParcelFileDescriptor) {
        // VALIDASI data hasil restore — perlakukan sebagai untrusted input
    }
}
```

**Prioritas 8 — Validasi data hasil restore.** Terkait Metode G (§3.8): data backup dapat dimodifikasi penyerang. Jangan percaya nilai hasil restore untuk keputusan keamanan (status premium, kuota, peran user) — validasi ulang dengan server. Dan hindari `android:restoreAnyVersion="true"` yang mengizinkan restore dari versi aplikasi lama.

**Prioritas 9 — Pastikan `debuggable=false` pada build release.** Bila `true`, `adb backup` dapat menarik seluruh data sandbox tanpa root — membatalkan semua restriksi Android 12. Verifikasi pada **APK release**, bukan hanya di `build.gradle`.

**Prioritas 10 — Tegakkan secara berkelanjutan.**
- Tambahkan pemeriksaan statis (semgrep rule perluasan §3.9 atau mobsfscan) ke CI/CD
- **Jalankan test dinamis ini sebagai regression test** setelah setiap perubahan pada penyimpanan lokal — penambahan file baru tidak otomatis tercakup `<exclude>` yang sudah ada
- Buat kebijakan: setiap file baru yang menyimpan data sensitif harus diletakkan di `noBackupFilesDir` **atau** ditambahkan ke kedua file aturan dalam PR yang sama
- Dokumentasi Android menekankan: *"**Test Regularly** — Verify backup behavior hasn't changed unexpectedly."*

### 4.2 Checklist Remediasi

- [ ] Inventaris file sandbox lengkap (dari MASTG-TEST-0207) tersedia sebagai daftar yang harus dicek
- [ ] Setiap file sensitif terbukti **tidak ter-restore** setelah backup+restore nyata
- [ ] `android:allowBackup` dideklarasikan **eksplisit** (tidak mengandalkan default `true`)
- [ ] Bila backup tidak dibutuhkan: `android:allowBackup="false"`
- [ ] Bila backup dibutuhkan: **kedua** atribut dideklarasikan sesuai rentang `minSdk`–`targetSdk`
- [ ] File `backup_rules.xml` **dan** `data_extraction_rules.xml` ada di APK dan sesuai dengan referensinya di manifest
- [ ] Setiap `<exclude>` dicerminkan di **`cloud-backup`** dan **`device-transfer`**
- [ ] Semua domain relevan dicakup: `file`, `sharedpref`, `database`, `external`, dan varian `device_*` bila memakai Direct Boot
- [ ] File turunan SQLite (`-wal`, `-shm`, `-journal`) ikut dikecualikan
- [ ] Pola direktori dipakai (`path="vault/"`) agar file baru otomatis tercakup
- [ ] File sensitif diletakkan di **`context.noBackupFilesDir`** bila memungkinkan
- [ ] Data sensitif yang tetap persisten **ter-enkripsi dengan kunci dari Android KeyStore**
- [ ] `disableIfNoEncryptionCapabilities="true"` / `requireFlags="clientSideEncryption"` diterapkan untuk data sangat sensitif
- [ ] `BackupAgent` kustom (bila ada) tidak menyertakan data sensitif, dan `onRestore()` memvalidasi input
- [ ] `android:restoreAnyVersion="true"` tidak dipakai
- [ ] Data hasil restore tidak dipercaya untuk keputusan keamanan; divalidasi ulang dengan server
- [ ] `android:debuggable="false"` diverifikasi pada **APK release**
- [ ] Token sesi hanya di memori; dihapus saat logout
- [ ] Pemeriksaan statis backup terintegrasi di CI/CD
- [ ] **Regression test dinamis** dijalankan setelah setiap perubahan pada penyimpanan lokal
- [ ] Kebijakan PR: file penyimpanan baru wajib masuk `noBackupFilesDir` atau kedua file aturan
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0216 (Metode A) → tidak ada file sensitif ter-restore, dan kontrol positif terbukti dikecualikan
- [ ] **Verifikasi silang:** MASTG-TEST-0262 (statis), MASTG-TEST-0207 (data sandbox), MASTG-TEST-0212 (kunci tidak hardcoded)

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0216: Sensitive Data Not Excluded From Backup](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0216/)
- [MASTG-TEST-0262: References to Backup Configurations Not Excluding Sensitive Data](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0262/)
- [MASWE-0006: Sensitive Data Not Excluded From Backup](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0006/)
- [MASTG-DEMO-0020: Data Exclusion using backup_rules.xml with Backup Manager](https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0020/MASTG-DEMO-0020/)
- [MASTG-DEMO-0035: Data Exclusion using backup_rules.xml with adb backup](https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0035/MASTG-DEMO-0035/)
- [MASTG-DEMO-0034: Backup and Restore App Data with semgrep](https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0034/MASTG-DEMO-0034/)
- [MASTG-KNOW-0050: Backups](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0050/)
- [MASTG-BEST-0004: Exclude Sensitive Data from Backups](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0004/)
- [MASTG-TECH-0128: Performing a Backup and Restore of App Data](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0128/)
- [MASTG-TECH-0127: Inspecting an App's Backup Data](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0127/)
- [MASTG-TECH-0117: Obtaining Information from the AndroidManifest](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0117/)
- [MASTG-TECH-0150: Analyzing the AndroidManifest](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0150/)
- [MASTG-TECH-0007: Obtaining Information from the App Package](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0007/)
- [MASTG-TEST-0207: Runtime Storage of Unencrypted Data in the App Sandbox](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0207/)
- [MASTG Rules — `mastg-android-backup-manifest.yml`](https://github.com/OWASP/mastg/blob/master/rules/mastg-android-backup-manifest.yml)
- [MASTG Utils — `mastg-android-backup-bmgr.sh`](https://github.com/OWASP/mastg/blob/master/utils/mastg-android-backup-bmgr.sh)
- [MASTG Utils — `mastg-android-backup-adb.sh`](https://github.com/OWASP/mastg/blob/master/utils/mastg-android-backup-adb.sh)
- [MASVS-STORAGE: Storage](https://mas.owasp.org/MASVS/05-MASVS-STORAGE/)
- [OWASP Mobile Top 10 2024 — M9: Insecure Data Storage](https://owasp.org/www-project-mobile-top-10/2023-risks/m9-insecure-data-storage)

### 5.2 Dokumentasi Resmi Android / Google

- [Security recommendations for backups — Android Security Risks](https://developer.android.com/privacy-and-security/risks/backup-best-practices)
- [Back up user data with Auto Backup](https://developer.android.com/identity/data/autobackup)
- [Back up key-value pairs with Android Backup Service](https://developer.android.com/identity/data/keyvaluebackup)
- [Data backup overview](https://developer.android.com/identity/data/backup)
- [Test backup and restore (`bmgr`)](https://developer.android.com/identity/data/testingbackup)
- [`<application>` element — `allowBackup` attribute](https://developer.android.com/guide/topics/manifest/application-element#allowbackup)
- [`<application>` element — `fullBackupContent`, `dataExtractionRules`, `backupAgent`, `restoreAnyVersion`](https://developer.android.com/guide/topics/manifest/application-element)
- [Android 12 behavior changes — `adb backup` restrictions](https://developer.android.com/about/versions/12/behavior-changes-12#adb-backup-restrictions)
- [`BackupAgent` — API reference](https://developer.android.com/reference/android/app/backup/BackupAgent)
- [`BackupAgentHelper` — API reference](https://developer.android.com/reference/android/app/backup/BackupAgentHelper)
- [`Context.getNoBackupFilesDir()` — API reference](https://developer.android.com/reference/android/content/Context#getNoBackupFilesDir())
- [Android Keystore system](https://developer.android.com/privacy-and-security/keystore)
- [Support Direct Boot mode (device-protected storage)](https://developer.android.com/privacy-and-security/direct-boot)
- [File-Based Encryption (AOSP)](https://source.android.com/docs/security/features/encryption/file-based)
- [Data storage guidelines](https://developer.android.com/training/data-storage)

### 5.3 Standar & Taksonomi Kelemahan

- [CWE-530: Exposure of Backup File to an Unauthorized Control Sphere](https://cwe.mitre.org/data/definitions/530.html)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
- [CWE-359: Exposure of Private Personal Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/359.html)
- [CWE-16: Configuration](https://cwe.mitre.org/data/definitions/16.html)
- [SEI CERT Android — DRD10-J: Do not release apps that are debuggable](https://wiki.sei.cmu.edu/confluence/display/android/DRD10-J.+Do+not+release+apps+that+are+debuggable)
- [NIST SP 800-163 Rev.1 — Vetting the Security of Mobile Applications](https://csrc.nist.gov/publications/detail/sp/800-163/rev-1/final)
- [NIST SP 800-124 Rev.2 — Guidelines for Managing the Security of Mobile Devices](https://csrc.nist.gov/publications/detail/sp/800-124/rev-2/final)
- [MITRE ATT&CK Mobile — T1409: Stored Application Data](https://attack.mitre.org/techniques/T1409/)
- [OWASP ASVS — V14 Configuration](https://owasp.org/www-project-application-security-verification-standard/)

### 5.4 Riset Keamanan & Artikel Teknis

- [Pen Test Partners — How to subvert Android backups to export sandboxed app files](https://www.pentestpartners.com/security-blog/how-to-subvert-android-backups-to-export-sandboxed-app-files/)
- [Security Café — Mobile Pentesting 101: The Death of ADB Backup: Modern Data Extraction](https://securitycafe.ro/2026/02/02/mobile-pentesting-101-the-death-of-adb-backup-modern-data-extraction-in-2026/)
- [Ed Holloway-George — Unpacking Android Security Part 2: Insecure Data Storage](https://www.spght.dev/articles/04-06-2022/owasp-m2)
- [Medium — Android's Attribute `android:allowBackup` Demystified](https://medium.com/better-programming/androids-attribute-android-allowbackup-demystified-114b88087e3b)
- [Medium (The Startup) — Android 12 Changelog: Google Finally Restricts the Power of "adb backup"](https://medium.com/swlh/android-12-changelog-google-finally-restricts-the-power-of-adb-backup-44f2216c219)
- [Valency Networks — Backups enabled in AndroidManifest.xml: risk, impact and fix](https://valencynetworks.com/kb/android-allow-backup-enabled-vulnerability-risk-impact-and-fix.html)
- [Fluid Attacks — Insecure service configuration: ADB Backups](https://help.fluidattacks.com/portal/en/kb/articles/criteria-vulnerabilities-055)
- [Mozilla Bugzilla #1021742 — Fennec manifest allows for ADB backup attack](https://bugzilla.mozilla.org/show_bug.cgi?id=1021742)
- [adb-backup-apk-injection — PoC injeksi APK ke arsip backup](https://github.com/alsan/adb-backup-apk-injection)
- [Oxygen Forensics — Sandboxing in Android: implications for extraction of data via ADB](https://www.oxygenforensics.com/resources/android-sandboxing/)
- [HackTricks — Android Applications Pentesting](https://book.hacktricks.wiki/en/mobile-pentesting/android-app-pentesting/index.html)

### 5.5 Dokumentasi Tools

- [Android Backup Extractor (`abe`)](https://github.com/nelenkov/android-backup-extractor)
- [adb — Android Debug Bridge](https://developer.android.com/tools/adb)
- [`bmgr` — Backup Manager (via testing backup docs)](https://developer.android.com/identity/data/testingbackup)
- [apktool — Reverse engineering Android APK files](https://apktool.org/)
- [aapt2 — Android Asset Packaging Tool](https://developer.android.com/tools/aapt2)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
- [mobsfscan — static analysis untuk Android/iOS](https://github.com/MobSF/mobsfscan)
- [drozer — Android security assessment framework](https://github.com/WithSecureLabs/drozer)
- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [Frida — Documentation Home](https://frida.re/docs/home/)
- [sqlite3 CLI](https://www.sqlite.org/cli.html)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026), dokumentasi resmi Android Developers, standar CWE/NIST/SEI CERT, serta riset keamanan dan artikel teknis pihak ketiga.*
