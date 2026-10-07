# MASTG-TEST-0200 Files Written to External Storage

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0200 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-STORAGE (MASVS-STORAGE-1: Aplikasi menyimpan data sensitif secara aman) |
| **Weakness** | MASWE-0002 — *Sensitive Data Stored Unencrypted Outside of Private Storage* |
| **Tipe Pengujian** | Dynamic, Filesystem, Manual |
| **Profile** | L1, L2 |
| **CWE terkait** | CWE-312 (Cleartext Storage of Sensitive Information), CWE-921 (Storage of Sensitive Data in a Mechanism without Access Control), CWE-200 (Exposure of Sensitive Information) |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Tujuan test ini adalah **mengambil (retrieve) seluruh file yang ditulis aplikasi ke external storage lalu menginspeksi isinya**, terlepas dari API apa pun yang dipakai untuk menulis file tersebut.

Pendekatannya sengaja dibuat "API-agnostic": tester tidak peduli apakah aplikasi memakai `getExternalFilesDir()`, `Environment.getExternalStorageDirectory()`, `MediaStore`, Storage Access Framework, `DownloadManager`, atau bahkan native code (JNI/NDK). Yang dilakukan adalah **membandingkan snapshot filesystem external storage sebelum dan sesudah aplikasi dijalankan/di-exercise**, lalu mengambil selisihnya (file baru/termodifikasi) dan memeriksa isinya.

> Ini berbeda dengan test bersaudaranya:
> - **MASTG-TEST-0200** (test ini) → pendekatan **dinamis berbasis filesystem diffing**. Menjawab: *"File apa yang benar-benar muncul di external storage?"*
> - **MASTG-TEST-0201** — *Runtime Use of External Storage APIs* → pendekatan **dinamis berbasis hooking/tracing API** (Frida). Menjawab: *"API storage apa yang dipanggil saat runtime?"*
> - **MASTG-TEST-0202** — *References to APIs and Permissions for Accessing External Storage* → pendekatan **statis** (reverse engineering + scanning permission & API references). Menjawab: *"API dan permission apa yang direferensikan di dalam binary/manifest?"*
>
> Praktik terbaik: jalankan ketiganya sebagai satu rangkaian. TEST-0202 memberi peta area yang perlu diuji, TEST-0201 membuktikan API mana yang aktif dipanggil, dan TEST-0200 membuktikan dampak nyatanya di disk.

### 1.2 Mengapa External Storage Berbahaya

External storage di Android adalah penyimpanan **shared** — bisa berupa media removable (SD card) atau emulated (partisi internal yang di-mount sebagai `/sdcard`). Karakteristik keamanannya:

| Aspek | Internal Storage (`/data/data/<pkg>/`) | External Storage (`/sdcard/...`) |
|---|---|---|
| Sandbox UID Linux | Ya, diproteksi penuh | Tidak / lemah (FUSE + emulated permission) |
| Bisa dibaca app lain | Tidak (kecuali root) | Ya, tergantung API level & permission |
| Bisa dimodifikasi user via USB/MTP | Tidak | Ya |
| Hilang saat uninstall | Ya | Tergantung lokasi (app-specific: ya; shared/MediaStore: **tidak**) |
| Bisa dibaca setelah reinstall app lain | Tidak | Ya (untuk lokasi shared) |

Risiko konkret:

1. **Pembacaan data oleh aplikasi lain (information disclosure).** Pada aplikasi yang menargetkan Android 9 (API 28) ke bawah — atau yang opt-out scoped storage lewat `android:requestLegacyExternalStorage="true"` — aplikasi jahat dengan `READ_EXTERNAL_STORAGE` dapat membaca *app-specific directory* aplikasi lain.
2. **Manipulasi data (integrity violation) → "Man-in-the-Disk".** Riset Check Point (DEF CON 2018) menunjukkan aplikasi jahat dengan akses external storage dapat memonitor dan **menimpa** data yang ditransfer aplikasi lain ke external storage. Akibatnya: instalasi aplikasi tanpa persetujuan, DoS, crash, hingga **code injection dalam konteks privileged aplikasi target**. Aplikasi terdampak saat itu antara lain Google Translate, Yandex Translate, Google Voice Typing, Google Text-to-Speech, dan Xiaomi Browser — sekitar setengah dari aplikasi Google Play yang diteliti tidak mematuhi guideline Android.
3. **Data persistence pasca-uninstall.** File yang ditulis via `MediaStore` ke `Downloads/`, `Pictures/`, dsb. **tidak dihapus** saat aplikasi di-uninstall, sehingga kredensial bisa bertahan di device selamanya.
4. **Eksfiltrasi via backup cloud / MTP / adb backup.** File di `/sdcard` umumnya ikut tersinkronisasi ke layanan backup pihak ketiga dan mudah ditarik lewat USB tanpa root.
5. **Akses pada device yang di-root atau lewat forensik fisik.** External storage yang emulated pun ter-enkripsi FBE, tapi sekali device unlocked / rooted, file plaintext langsung terbaca.

### 1.3 Landasan Teknis: Scoped Storage & Matriks Permission

Memahami scoped storage wajib untuk menilai severity temuan dengan benar.

**Scoped Storage** (Android 10 / API 29 ke atas): aplikasi hanya punya akses ke (a) app-specific directory miliknya sendiri di external storage, dan (b) file media yang dibuat oleh aplikasi itu sendiri (atribusi `owner_package_name` di MediaStore). Aplikasi tidak lagi bisa mengakses app-specific directory milik aplikasi lain.

- Aplikasi yang menargetkan API ≤ 29 dapat **opt out sementara** dengan `android:requestLegacyExternalStorage="true"`.
- Begitu aplikasi menargetkan **Android 11 (API 30)**, sistem **mengabaikan** atribut tersebut — scoped storage dipaksa aktif.

**Matriks permission external storage:**

| Permission | Perilaku per API level |
|---|---|
| `READ_EXTERNAL_STORAGE` | < API 19: tidak di-enforce, semua app bisa baca seluruh external storage. API 19+: tidak perlu untuk app-specific dir sendiri. API 29+: tidak bisa baca app-specific dir app lain (scoped storage). **API 33+: tidak berefek apa pun.** |
| `WRITE_EXTERNAL_STORAGE` | API 19+: tidak perlu untuk app-specific dir sendiri. API 29+: tidak bisa tulis ke app-specific dir app lain. **API 30+: deprecated & tidak berefek** (hanya setara READ), kecuali `requestLegacyExternalStorage` / `preserveLegacyExternalStorage`. |
| `MANAGE_EXTERNAL_STORAGE` | Hanya untuk target API 30+. Memberi "All files access" — **bypass scoped storage**. Penggunaannya dibatasi kebijakan Google Play dan butuh justifikasi. Kehadiran permission ini adalah red flag tersendiri. |
| `READ_MEDIA_IMAGES` / `READ_MEDIA_VIDEO` / `READ_MEDIA_AUDIO` | Wajib mulai API 33 untuk mengakses koleksi MediaStore milik app lain, menggantikan `READ_EXTERNAL_STORAGE`. |

**Lokasi yang perlu diperiksa saat testing:**

| Path | API pemanggil | Sifat |
|---|---|---|
| `/sdcard/Android/data/<package>/files/` | `getExternalFilesDir()` | App-specific external. Terlindungi scoped storage (API 29+), **tidak** terlindungi sebelumnya. Hilang saat uninstall. |
| `/sdcard/Android/data/<package>/cache/` | `getExternalCacheDir()` | Sama seperti di atas. |
| `/sdcard/Download/`, `/sdcard/Documents/`, `/sdcard/DCIM/`, `/sdcard/Pictures/`, `/sdcard/Music/` | `MediaStore`, `getExternalStoragePublicDirectory()` | **Shared storage.** Dapat diakses aplikasi lain dengan permission media yang sesuai. **Bertahan setelah uninstall.** |
| `/sdcard/<custom_dir>/` | `Environment.getExternalStorageDirectory()` + `File()` | Shared, paling berisiko. Umum pada aplikasi legacy. |
| `/mnt/media_rw/<uuid>/`, `/storage/<uuid>/` | Secondary/removable storage | SD card fisik — bisa dilepas dan dibaca di device lain. |

### 1.4 Jenis Data yang Dianggap Sensitif

Saat menginspeksi file hasil diff, yang dianggap sebagai temuan antara lain:

- Kredensial: password, PIN, API key, client secret, access/refresh token, session ID, JWT
- Material kriptografi: private key, keystore, certificate + password, seed phrase/mnemonic
- PII: NIK/ID nasional, nomor telepon, alamat, email, tanggal lahir, data biometrik
- Data finansial/kesehatan: nomor kartu, rekening, mutasi transaksi, rekam medis
- Data operasional aplikasi: database SQLite/Realm tanpa enkripsi, shared_prefs yang dicopy keluar, cache respons API berisi data user, log debug verbose, crash dump
- File konfigurasi/kode yang dimuat kembali oleh aplikasi (DEX, SO, JS bundle, template) → risiko **code injection**, bukan hanya disclosure

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | MASTG ID | Fungsi dalam test ini |
|---|---|---|
| **adb** (Android Debug Bridge) | MASTG-TOOL-0004 | Instalasi APK, enumerasi file (`adb shell find`), penarikan file (`adb pull`), query MediaStore, manajemen permission. Tool utama test ini. |
| **Android device / emulator** | MASTG-TOOL-0003 (AVD) | Target pengujian. Disarankan tersedia beberapa API level (28, 30, 33+) untuk menilai perbedaan perilaku scoped storage. |
| **Objection** | MASTG-TOOL-0038 | Eksplorasi filesystem dan download file dari sandbox app tanpa perlu app debuggable (`filesystem download <file>`, `... --folder`). |
| **Frida** | MASTG-TOOL-0001 | Pelengkap (untuk MASTG-TEST-0201): tracing panggilan API external storage saat runtime, memastikan tidak ada penulisan yang terlewat. |

### 2.2 Tools Pendukung

| Tool | Fungsi |
|---|---|
| **Android Studio Device File Explorer** | Browsing filesystem visual (View → Tool Windows → Device File Explorer). Terbatas pada sandbox app jika device non-rooted dan app debuggable. |
| **MASTestApp / MASTG demo app** | Aplikasi rujukan untuk memvalidasi metodologi & tooling sebelum diterapkan ke aplikasi target. |
| **`file`, `strings`, `xxd`, `hexdump`, `binwalk`, `jq`** | Identifikasi tipe file dan ekstraksi string dari file hasil pull. Krusial untuk menilai apakah file ter-enkripsi atau plaintext. |
| **`sqlite3` / DB Browser for SQLite** | Membuka database SQLite yang ditemukan di external storage. |
| **`ent` / analisis entropi** | Membedakan file ter-enkripsi (entropi tinggi ~7.9 bit/byte) dari plaintext/obfuscated (entropi rendah). Mencegah false pass akibat data yang hanya di-Base64/XOR. |
| **grep dengan pola sensitif / TruffleHog / gitleaks** | Pemindaian otomatis file hasil pull untuk pola secret (API key, token, private key). |
| **jadx / apktool** (MASTG-TOOL-0018 / 0011) | Reverse engineering untuk mengonfirmasi lokasi kode penulis file dan memastikan klaim enkripsi. |
| **semgrep** (dengan MASTG rules) | Analisis statis pendukung (lebih relevan untuk MASTG-TEST-0202). |

### 2.3 Prasyarat Lingkungan

- Device/emulator dengan USB debugging aktif. **Root tidak wajib** untuk test ini karena `/sdcard` umumnya dapat dibaca via adb shell.
- Aplikasi terinstall via `adb install` (bila perlu dengan `-g` untuk auto-grant runtime permission agar semua alur bisa di-exercise).
- Disarankan menguji pada **minimal dua API level**: satu di bawah 29 (untuk membuktikan eksposur legacy ke app lain) dan satu di 33+ (untuk perilaku terkini).
- Device dalam kondisi bersih (fresh wipe / snapshot emulator) agar diff tidak tercemar file sisa pengujian sebelumnya.
- Akun uji dengan data sensitif yang **dikenali dan unik** (mis. password `MASTG_Pa55w0rd_UNIQ`, email `tester+mastg@example.com`) sehingga mudah di-grep di hasil diff. Ini teknik kunci: gunakan *canary value*.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0005** (*Installing Apps*) untuk menginstall aplikasi.
2. Gunakan **MASTG-TECH-0002** (*Host-Device Data Transfer*) untuk mengambil daftar file yang ada di external storage saat ini (snapshot **sebelum**).
3. **Exercise aplikasi secara ekstensif** — picu sebanyak mungkin alur dan masukkan data sensitif di setiap tempat yang memungkinkan.
4. Gunakan MASTG-TECH-0002 lagi untuk mengambil daftar file di external storage (snapshot **sesudah**).
5. Hitung **selisih (difference)** antara kedua daftar tersebut.

### 3.2 Implementasi Praktis — Metode Timestamp Marker (rekomendasi MASTG-DEMO-0001)

Metode ini lebih akurat dan ringkas daripada membandingkan dua listing besar, karena memakai satu file penanda waktu.

**Langkah 0 — Persiapan**

```bash
# Verifikasi device terhubung
adb devices

# Install aplikasi target (auto-grant semua runtime permission)
adb install -g ./target-app.apk

# Catat package name
adb shell pm list packages | grep -i <nama_app>

# (Opsional) Cek konfigurasi storage di manifest terlebih dahulu
# targetSdkVersion, requestLegacyExternalStorage, permission storage
```

**Langkah 1 — Buat penanda waktu (`run_before.sh`)**

```bash
#!/bin/bash
# SUMMARY: Membuat dummy file sebagai penanda timestamp,
# untuk mengidentifikasi file yang dibuat selama aplikasi di-exercise
adb shell "touch /data/local/tmp/test_start"
```

**Langkah 2 — Exercise aplikasi**

Buka aplikasi dan lakukan sebanyak mungkin alur secara sadar dan sistematis:

- Registrasi, login, logout, login ulang, "remember me"
- Reset password, verifikasi OTP, setup 2FA/biometrik
- Lengkapi profil (nama, NIK, alamat, telepon, upload KTP/foto)
- Tambah metode pembayaran, lakukan transaksi, unduh invoice/statement
- Upload dan download file/attachment, export data, share/print
- Fitur kamera, galeri, scanner dokumen, voice note
- Chat/pesan, riwayat pencarian, draft
- Mode offline (matikan jaringan → picu caching lokal), lalu online kembali
- Background/foreground berulang, rotasi layar, force-stop, buka ulang
- Trigger error/crash bila mungkin (untuk memicu crash dump ke disk)
- Aktifkan semua opsi di Settings, termasuk "debug"/"developer" bila ada

> Gunakan **canary value** yang unik di setiap input agar mudah ditemukan lewat `grep` nanti.

**Langkah 3 — Ambil selisih dan tarik file (`run_after.sh`)**

```bash
#!/bin/bash
# SUMMARY: List semua file yang dibuat setelah timestamp penanda dari run_before

adb shell "find /sdcard/ -type f -newer /data/local/tmp/test_start" > output.txt
adb shell "rm /data/local/tmp/test_start"
mkdir -p new_files
while read -r line; do
  adb pull "$line" ./new_files/
done < output.txt
```

**Langkah 4 — Inspeksi isi file**

```bash
# Identifikasi tipe setiap file
file ./new_files/*

# Cari canary value dan pola sensitif
grep -riE "MASTG_Pa55w0rd_UNIQ|password|passwd|secret|token|api[_-]?key|bearer|authorization|BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY|[0-9]{16}" ./new_files/

# Lihat string pada file biner
strings -n 6 ./new_files/<file> | less

# Uji apakah benar-benar ter-enkripsi (entropi mendekati 8.0 = kemungkinan terenkripsi)
ent ./new_files/<file>

# Buka database bila ada
sqlite3 ./new_files/<db_file> ".tables" ".dump"
```

### 3.3 Implementasi Alternatif — Metode Dua Snapshot

Berguna bila `find -newer` tidak tersedia atau ingin mendeteksi file yang **dimodifikasi** (bukan hanya dibuat) beserta hash-nya.

```bash
# --- SEBELUM ---
adb shell "find /sdcard/ -type f -exec md5sum {} \;" | sort > before.txt

# --- Exercise aplikasi ---

# --- SESUDAH ---
adb shell "find /sdcard/ -type f -exec md5sum {} \;" | sort > after.txt

# Selisih: file baru maupun yang berubah isinya
diff before.txt after.txt | grep '^>' | sed 's/^> //'

# Hanya nama file baru
comm -13 <(awk '{$1="";print}' before.txt | sort) <(awk '{$1="";print}' after.txt | sort)
```

### 3.4 Pemeriksaan Tambahan yang Direkomendasikan

```bash
# 1. Enumerasi app-specific external directory secara spesifik
adb shell "ls -laR /sdcard/Android/data/<package>/"
adb shell "ls -laR /sdcard/Android/media/<package>/"

# 2. Query MediaStore — file MediaStore mungkin tidak muncul jelas di find
adb shell content query --uri content://media/external_primary/file \
  --projection _display_name:relative_path:owner_package_name:mime_type
adb shell content query --uri content://media/external_primary/downloads
adb shell content query --uri content://media/external_primary/images/media

# 3. Cek konfigurasi scoped storage aplikasi
adb shell dumpsys package <package> | grep -iE "targetSdk|versionName"
# atau dari manifest hasil apktool:
#   grep -E "requestLegacyExternalStorage|preserveLegacyExternalStorage|targetSdkVersion" AndroidManifest.xml

# 4. Cek permission storage yang di-grant
adb shell dumpsys package <package> | grep -iE "EXTERNAL_STORAGE|READ_MEDIA"

# 5. UJI EKSPLOITABILITAS: baca file target dari konteks app lain
#    (simulasikan aplikasi jahat — berhasil membaca = konfirmasi eksposur lintas-app)
adb shell run-as <paket_app_uji_lain> cat /sdcard/Android/data/<package_target>/files/secret.txt

# 6. Verifikasi persistensi pasca-uninstall
adb uninstall <package>
adb shell "ls -la /sdcard/Download/ /sdcard/Documents/"   # file MediaStore harusnya masih ada → temuan
```

### 3.5 Metode Pengujian Alternatif (Multi-Tool)

Metode diffing `adb` + `find` (§3.2/§3.3) punya satu kelemahan struktural: ia hanya melihat **keadaan akhir**, sehingga melewatkan file yang ditulis lalu segera dihapus. Metode alternatif di bawah menutup celah itu dan menawarkan jalur yang tidak butuh root.

#### Metode B — Objection *(tanpa root, eksplorasi interaktif)*

Objection bekerja lewat Frida, sehingga **tidak memerlukan aplikasi debuggable maupun root** — keunggulan nyata dibanding `adb shell find` di sandbox.

```bash
objection -g com.example.target explore

# Di dalam shell objection:
env                                                    # petakan semua path storage app
cd /sdcard/Android/data/com.example.target/files
ls
filesystem download secret.txt                         # tarik satu file
filesystem download . ./dump --folder                  # tarik seluruh direktori
filesystem ls /sdcard/Download

# Monitor penulisan file secara real-time (sambil exercise app)
android hooking watch class_method java.io.FileOutputStream.$init --dump-args --dump-backtrace
```

Keunggulan tambahan: `env` langsung memberi daftar lengkap `externalCacheDirectory`, `filesDirectory`, `obbDir` — menghemat waktu memetakan path.

#### Metode C — Frida: hooking file I/O *(menangkap file temporer yang dihapus)*

Ini menutup celah terbesar metode diffing. File yang ditulis lalu dihapus **tidak akan muncul** di snapshot, tetapi tetap sempat mengekspos data ke aplikasi lain.

```javascript
// catch_temp_writes.js — mencatat SEMUA penulisan, termasuk yang lalu dihapus
const EXT = ['/sdcard', '/storage/emulated', '/storage/self/primary', '/mnt/sdcard'];
function isExt(p) { return p && EXT.some(e => p.indexOf(e) === 0); }

function bt(max = 10) {
    const E = Java.use("java.lang.Exception");
    const st = E.$new().getStackTrace();
    return Array.from({length: Math.min(max, st.length)}, (_, i) => "    " + st[i]).join("\n");
}

['open', 'openat', 'creat', 'unlink', 'rename'].forEach(fn => {
    const a = Process.getModuleByName('libc.so').findExportByName(fn);
    if (!a) return;
    Interceptor.attach(a, {
        onEnter(args) {
            const p = (fn === 'openat' ? args[1] : args[0]).readCString();
            if (isExt(p)) {
                console.log(`\n[${fn}] ${p}`);
                Java.perform(() => console.log(bt()));
            }
        }
    });
});

// Intip ISI yang ditulis — mendeteksi plaintext tanpa perlu menarik file
Java.perform(() => {
    const FOS = Java.use("java.io.FileOutputStream");
    FOS.write.overload('[B', 'int', 'int').implementation = function (b, off, len) {
        try {
            const prev = Java.use("java.lang.String").$new(b, off, Math.min(len, 200));
            console.log(`[write] ${len}B  preview: ${prev}`);
        } catch (e) {}
        return this.write(b, off, len);
    };
});
```

```bash
frida -U -f com.example.target -l catch_temp_writes.js -o writes.log
# Cari canary value langsung di log, tanpa perlu file masih ada di disk
grep -i "MASTG_CANARY" writes.log
```

> Hook `unlink` penting: bila kamu melihat pasangan `open(...O_CREAT)` → `write` → `unlink` pada path yang sama, itu **file temporer** yang lolos dari metode diffing. Lihat juga MASTG-TEST-0201 untuk pendekatan hooking yang lebih lengkap.

#### Metode D — fsmon *(monitoring filesystem real-time, tanpa instrumentasi app)*

Alternatif yang tidak menyentuh aplikasi sama sekali — memantau di level kernel/inotify.

```bash
# fsmon (NowSecure) — FileSystem monitor untuk Android
adb push fsmon-arm64 /data/local/tmp/fsmon
adb shell "chmod 755 /data/local/tmp/fsmon"
adb shell "su -c '/data/local/tmp/fsmon /sdcard'" | tee fsmon.log

# Filter hanya event dari proses aplikasi target
adb shell "su -c '/data/local/tmp/fsmon -P com.example.target /sdcard'"

# Alternatif bawaan: inotifywait (bila tersedia di ROM/BusyBox)
adb shell "su -c 'inotifywait -m -r -e create,modify,delete,moved_to /sdcard'"
```

Keunggulan: menangkap **seluruh** aktivitas filesystem termasuk dari kode native dan proses terpisah, tanpa risiko terdeteksi oleh anti-instrumentation.

#### Metode E — strace *(pembanding independen bila aplikasi punya anti-Frida)*

```bash
PID=$(adb shell pidof -s com.example.target)
adb shell "su -c 'strace -f -e trace=openat,write,unlink -p $PID'" 2>&1 \
  | grep -E "/sdcard|/storage/emulated" | tee strace.log
```

Berguna ketika aplikasi mendeteksi Frida dan mengubah perilaku — strace bekerja di level syscall dan jauh lebih sulit dideteksi.

#### Metode F — MediaStore query *(menangkap file yang tidak terlihat `find`)*

File yang ditulis via `MediaStore` dikelola content provider dan bisa luput dari enumerasi path biasa.

```bash
# Seluruh entri MediaStore beserta pemiliknya — kolom owner_package_name kuncinya
adb shell content query --uri content://media/external_primary/file \
  --projection _id:_display_name:relative_path:owner_package_name:mime_type:_data

# Per koleksi
adb shell content query --uri content://media/external_primary/downloads \
  --projection _display_name:relative_path:owner_package_name
adb shell content query --uri content://media/external_primary/images/media \
  --projection _display_name:relative_path:owner_package_name

# Saring hanya milik aplikasi target
adb shell content query --uri content://media/external_primary/file \
  --projection _display_name:relative_path:owner_package_name \
  | grep "com.example.target"
```

#### Metode G — Snapshot penuh berbasis hash *(mendeteksi file yang DIMODIFIKASI)*

Metode `find -newer` melewatkan file yang sudah ada sebelumnya dan hanya berubah isinya.

```bash
# --- SEBELUM ---
adb shell "find /sdcard/ -type f -exec md5sum {} \;" 2>/dev/null | sort > before.txt

# --- exercise aplikasi ---

# --- SESUDAH ---
adb shell "find /sdcard/ -type f -exec md5sum {} \;" 2>/dev/null | sort > after.txt

# File baru MAUPUN yang berubah isinya
comm -13 before.txt after.txt

# Tarik semuanya dengan struktur direktori dipertahankan
comm -13 before.txt after.txt | awk '{$1=""; sub(/^ /,""); print}' | while read -r p; do
  mkdir -p "./diff_files/$(dirname "${p#/sdcard/}")"
  adb pull "$p" "./diff_files/${p#/sdcard/}" >/dev/null 2>&1
done
```

#### Metode H — MobSF Dynamic Analyzer *(otomatis, laporan siap kutip)*

```bash
docker run -it --rm -p 8000:8000 -p 1337:1337 \
  opensecurity/mobile-security-framework-mobsf:latest
```

Alurnya: upload APK → **Start Dynamic Analysis** → MobSF menjalankan aplikasi di emulator terkelola, meng-exercise activity secara otomatis, lalu menghasilkan bagian **Files Analysis** / **Dumped Files** berisi file yang dibuat aplikasi beserta isinya. Keunggulan: ia sekaligus menangkap logcat, trafik jaringan, dan SQLite dump dalam satu sesi — berguna untuk pass awal yang luas.

Keterbatasan: exercise otomatisnya dangkal (tidak bisa login), jadi ini **pelengkap**, bukan pengganti exercise manual.

#### Metode I — Android Studio Device File Explorer *(visual, tanpa CLI)*

**View → Tool Windows → Device File Explorer**. Navigasi ke `/sdcard/Android/data/<pkg>/`, klik kanan → Save As. Kolom timestamp membantu mengidentifikasi file yang baru dibuat. Cocok untuk verifikasi cepat atau saat mendemokan temuan ke developer.

#### Metode J — Tooling forensik *(analisis mendalam & timeline)*

```bash
# Tarik seluruh external storage untuk analisis offline
adb pull /sdcard ./sdcard_dump

# ALEAPP — Android Logs Events And Protobuf Parser (artefak terstruktur + timeline)
python3 aleapp.py -t fs -i ./sdcard_dump -o ./aleapp_out

# Autopsy / Sleuth Kit — timeline analysis & pencarian keyword lintas file
fls -r -m / ./image.dd > bodyfile
mactime -b bodyfile -d > timeline.csv
```

Berguna bila kamu perlu **merekonstruksi urutan waktu** penulisan file, atau memeriksa sisa data pada file yang sudah dihapus.

---

### 3.6 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Butuh root? | Menangkap file temporer? | Menangkap file dimodifikasi? | Menangkap MediaStore? | Kapan dipakai |
|---|---|---|---|---|---|---|
| **A** | `adb` + `find -newer` (MASTG) | Tidak (untuk `/sdcard`) | ❌ | ❌ | Sebagian | Baseline resmi — cepat & sederhana |
| **B** | Objection | Tidak | Sebagian (via watch) | Manual | Sebagian | **Tanpa root & tanpa app debuggable**; `env` memetakan path |
| **C** | Frida hook file I/O | Ya/gadget | ✅ **(keunggulan utama)** | ✅ | ✅ (via ContentResolver) | Menutup celah terbesar metode diffing |
| **D** | fsmon / inotifywait | Ya | ✅ | ✅ | ✅ | **Tanpa menyentuh aplikasi** — tahan anti-instrumentation |
| **E** | strace | Ya | ✅ | ✅ | ✅ | Pembanding independen bila ada anti-Frida |
| **F** | `content query` | Tidak | ❌ | ❌ | ✅ **(khusus)** | File MediaStore yang luput dari `find` |
| **G** | Snapshot hash (md5sum) | Tidak | ❌ | ✅ **(keunggulan utama)** | Sebagian | File lama yang berubah isinya |
| **H** | MobSF Dynamic | Tidak | ❌ | ❌ | Sebagian | Pass awal luas + laporan siap kutip |
| **I** | Device File Explorer | Tidak | ❌ | Manual | Sebagian | Verifikasi visual / demo ke developer |
| **J** | ALEAPP / Autopsy | Ya | ❌ | ✅ | ✅ | Rekonstruksi timeline, analisis forensik mendalam |

**Kombinasi minimum yang aku rekomendasikan:** **A (find -newer) → G (snapshot hash) → C atau D**.
A cepat untuk gambaran awal, G menangkap file yang dimodifikasi, dan C/D menangkap file temporer yang hilang sebelum snapshot. Tambahkan **F** selalu — file MediaStore adalah kategori yang paling berisiko (bertahan pasca-uninstall) dan paling sering luput. Gunakan **B** bila tidak tersedia root.

---

### 3.7 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> *"The test case **fails** if the files found above are not encrypted and leak sensitive data."*
>
> **Further Validation Required** — inspeksi isi setiap file yang dilaporkan untuk menentukan apakah datanya sensitif:
> - Tentukan apakah file mengandung informasi sensitif (mis. data pribadi, kredensial, atau token).
> - Tentukan apakah data disimpan tanpa enkripsi.

Kedua kondisi harus **AND**: file sensitif **DAN** tidak ter-enkripsi → FAIL.

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi | Contoh bukti |
|---|---|---|
| F1 | Ditemukan file baru di external storage yang berisi **data sensitif dalam bentuk plaintext** | `/sdcard/Android/data/org.owasp.mastestapp/files/secret.txt` berisi `secr3tPa$$W0rd` |
| F2 | File sensitif ditulis ke **shared storage** via MediaStore/public directory | `/sdcard/Download/secretFile75.txt` berisi `MAS_API_KEY=8767086b9f6f976g-a8df76` |
| F3 | Database (SQLite/Realm) tak ter-enkripsi berisi data user ditemukan di external storage | `/sdcard/MyApp/app.db` → `sqlite3 ... .dump` menampilkan tabel `users` dengan kolom `password` |
| F4 | "Enkripsi" yang ditemukan sebenarnya hanya **encoding/obfuscation** (Base64, hex, ROT13, XOR dengan key hardcoded) | `echo '<isi>' \| base64 -d` langsung menghasilkan plaintext; entropi rendah (< 6.0 bit/byte) |
| F5 | Ter-enkripsi, tetapi **kunci ikut tersimpan** di external storage atau hardcoded di APK | `key.pem` / `keystore.jks` + password ada di direktori yang sama, atau key ditemukan via `strings classes.dex` |
| F6 | Log / crash dump / cache respons API berisi data sensitif ditulis ke external storage | `/sdcard/MyApp/logs/debug.log` berisi `Authorization: Bearer eyJ...` |
| F7 | File **tetap ada dan terbaca setelah aplikasi di-uninstall** dan masih mengandung data sensitif | File di `/sdcard/Download/` masih berisi token setelah `adb uninstall` |
| F8 | Data sensitif berhasil **dibaca dari konteks aplikasi lain** (uji eksploitabilitas berhasil) | `run-as <other_app> cat <path>` mengembalikan isi plaintext |
| F9 | Aplikasi memuat **kode/konfigurasi eksekutabel** dari external storage tanpa integrity check | DEX/SO/JS bundle di `/sdcard/...` dapat ditimpa, aplikasi tetap memuatnya → Man-in-the-Disk / code injection |
| F10 | Aplikasi opt-out scoped storage (`requestLegacyExternalStorage="true"` dengan target ≤ API 29) **dan** menulis data sensitif ke external storage | Manifest + temuan F1/F2 |

**Contoh output yang menandakan FAIL** (hasil MASTG-DEMO-0001):

```
# output.txt
/sdcard/Android/data/org.owasp.mastestapp/files/secret.txt
/sdcard/Download/secretFile75.txt
```

```
# ./new_files/secret.txt
secr3tPa$$W0rd

# ./new_files/secretFile75.txt
MAS_API_KEY=8767086b9f6f976g-a8df76
```

Evaluasi MASTG: *"This test **fails** because the files are not encrypted and contain sensitive data (a password and an API key)."*

Kode yang bertanggung jawab (sampel demo):

```kotlin
// Penulisan via API external storage — plaintext
fun mastgTestApi() {
    val externalStorageDir = context.getExternalFilesDir(null)
    val fileName = File(externalStorageDir, "secret.txt")
    val fileContent = "secr3tPa\$\$W0rd\n"
    FileOutputStream(fileName).use { output ->
        output.write(fileContent.toByteArray())
    }
}

// Penulisan via MediaStore ke Downloads — plaintext & bertahan pasca-uninstall
fun mastgTestMediaStore() {
    val resolver = context.contentResolver
    val contentValues = ContentValues().apply {
        put(MediaStore.MediaColumns.DISPLAY_NAME, "secretFile75.txt")
        put(MediaStore.MediaColumns.MIME_TYPE, "text/plain")
        put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
    }
    val textUri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, contentValues)
    textUri?.let {
        resolver.openOutputStream(it)?.use { os ->
            os.write("MAS_API_KEY=8767086b9f6f976g-a8df76\n".toByteArray())
        }
    }
}
```

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi | Contoh bukti |
|---|---|---|
| P1 | **Tidak ada file baru sama sekali** yang muncul di external storage selama aplikasi di-exercise secara ekstensif | `output.txt` kosong; `wc -l output.txt` → `0` |
| P2 | Ada file baru, tetapi **isinya tidak sensitif** — murni data non-personal | Asset gambar publik, ikon, font, file `.nomedia`, tile peta, cache thumbnail konten publik |
| P3 | Ada file sensitif, tetapi **ter-enkripsi dengan benar** menggunakan algoritma kuat, dan **kunci disimpan di Android KeyStore** (bukan di external storage / hardcoded) | `file` → `data`; `strings` tidak menampilkan canary value; entropi ≈ 7.9+ bit/byte; kode menunjukkan `EncryptedFile` / AES-GCM dengan key dari KeyStore |
| P4 | File yang dibuat adalah hasil **aksi eksplisit user** (mis. user menekan "Export PDF" / "Save photo"), berupa data yang memang ditujukan untuk dibagikan, dan tidak memuat kredensial/token | Invoice PDF hasil klik tombol Download oleh user — dengan catatan: sebaiknya tetap didokumentasikan sebagai informational risk |
| P5 | Semua data sensitif hanya ditemukan di **internal storage** (`/data/data/<pkg>/`), tidak ada jejak di `/sdcard` | `find /sdcard -newer ...` bersih; data ada di internal storage saja |
| P6 | Uji eksploitabilitas **gagal** — aplikasi lain tidak dapat membaca file tersebut, dan file yang ada tidak sensitif | `run-as <other_app> cat <path>` → `Permission denied` + tidak ada temuan plaintext |

**Contoh output yang menandakan PASS:**

```bash
$ cat output.txt
$ wc -l output.txt
0 output.txt
# → Tidak ada file yang ditulis ke external storage
```

atau:

```bash
$ cat output.txt
/sdcard/Android/data/com.example.app/files/vault.bin

$ file ./new_files/vault.bin
./new_files/vault.bin: data

$ grep -riE "MASTG_Pa55w0rd_UNIQ|password|token|api_key" ./new_files/
# (tidak ada hasil)

$ strings -n 6 ./new_files/vault.bin | head
# hanya byte acak, tidak ada string bermakna

$ ent ./new_files/vault.bin
Entropy = 7.998432 bits per byte.
# → konsisten dengan data ter-enkripsi
```

Dikonfirmasi lewat reverse engineering bahwa enkripsi memakai `EncryptedFile` dengan MasterKey dari Android KeyStore:

```kotlin
val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build()

val encryptedFile = EncryptedFile.Builder(
    context,
    File(context.getExternalFilesDir(null), "vault.bin"),
    masterKey,
    EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
).build()
```

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Jangan berhenti di listing file — wajib inspeksi isi.** MASTG secara eksplisit menandai test ini butuh *Further Validation*. Nama file yang tampak tidak berbahaya (`cache.dat`, `tmp_001`) sering berisi token.
2. **Jangan menyimpulkan PASS hanya karena `output.txt` kosong pada satu sesi.** File mungkin baru ditulis pada alur yang belum di-exercise. Korelasikan dengan **MASTG-TEST-0201** (Frida tracing API) dan **MASTG-TEST-0202** (analisis statis) — jika analisis statis menunjukkan referensi ke `getExternalFilesDir` tetapi diff kosong, berarti alur pemicunya belum tersentuh.
3. **Waspadai false pass akibat enkripsi palsu.** Selalu uji dengan `strings`, `base64 -d`, dan analisis entropi.
4. **Severity dimodulasi oleh API level dan lokasi**, tetapi **tidak menghilangkan temuan**:
   - Data sensitif plaintext di **shared storage** (Download/Documents/DCIM) → severity tertinggi (terbaca app lain + bertahan pasca-uninstall).
   - Data sensitif plaintext di **app-specific external dir** pada target API ≥ 30 → severity lebih rendah (dilindungi scoped storage dari app lain), namun **tetap FAIL** karena masih terbaca oleh user via MTP/USB, oleh device yang di-root, oleh backup pihak ketiga, dan oleh malware dengan `MANAGE_EXTERNAL_STORAGE`.
   - Adanya `requestLegacyExternalStorage="true"` atau `MANAGE_EXTERNAL_STORAGE` → naikkan severity.
5. **Dokumentasikan bukti secara lengkap** untuk setiap temuan: path file, isi (redacted bila perlu), API level device, target SDK aplikasi, permission yang di-grant, langkah reproduksi, dan hasil uji cross-app read.

---

## 4. Rekomendasi Perbaikan

### 4.1 Prinsip Utama (urutan prioritas)

**Prioritas 1 — Jangan simpan data sensitif di external storage.** Ini satu-satunya remediasi yang menghilangkan akar masalah. Android Security Guidelines dan SEI CERT Android (DRD00) sama-sama menegaskan hal ini. Pindahkan ke internal storage yang dilindungi sandbox UID Linux.

```kotlin
// ❌ SALAH — external storage
val file = File(context.getExternalFilesDir(null), "secret.txt")
file.writeText(password)

// ✅ BENAR — internal storage (private, dihapus saat uninstall)
context.openFileOutput("secret.txt", Context.MODE_PRIVATE).use { it.write(data) }
// atau
val file = File(context.filesDir, "secret.txt")
```

Jangan pernah gunakan `MODE_WORLD_READABLE` / `MODE_WORLD_WRITEABLE` (sudah deprecated sejak API 17 dan melempar `SecurityException` sejak API 24).

**Prioritas 2 — Gunakan mekanisme penyimpanan yang tepat sesuai jenis data.**

| Jenis data | Mekanisme yang benar |
|---|---|
| Kunci kriptografi, material kripto | **Android KeyStore** (dengan `setUserAuthenticationRequired`, StrongBox bila tersedia). Kunci tidak pernah keluar dari secure hardware. |
| Password, token, API key | Jangan disimpan bila bisa dihindari. Bila perlu: enkripsi dengan kunci dari KeyStore, simpan di internal storage. |
| Key-value preferences sensitif | Internal storage + enkripsi (`EncryptedSharedPreferences` / penggantinya; catat bahwa Jetpack Security `androidx.security:security-crypto` kini deprecated — pertimbangkan implementasi AES-GCM sendiri dengan kunci KeyStore, atau Google Tink). |
| Data terstruktur | Room + **SQLCipher** / SQLite ter-enkripsi, di internal storage. |
| File besar milik app | Internal storage; jika ukuran memaksa external, wajib enkripsi (Prioritas 3). |
| File yang memang untuk dibagikan | MediaStore / Storage Access Framework, **hanya untuk data non-sensitif**, dan idealnya atas aksi eksplisit user. |
| Berbagi file ke app lain | **FileProvider** dengan `content://` URI dan grant permission temporer — bukan menaruh file di `/sdcard`. |

**Prioritas 3 — Jika external storage benar-benar tak terhindarkan: enkripsi dengan kunci dari KeyStore.**

```kotlin
// Enkripsi file di external storage, kunci di Android KeyStore
val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build()

val targetFile = File(context.getExternalFilesDir(null), "data.enc")
val encryptedFile = EncryptedFile.Builder(
    context,
    targetFile,
    masterKey,
    EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
).build()

encryptedFile.openFileOutput().use { it.write(sensitiveBytes) }
```

Syarat agar dianggap memadai:
- Algoritma modern dengan authenticated encryption: **AES-256-GCM** atau ChaCha20-Poly1305. Jangan ECB, jangan DES/3DES/RC4, jangan CBC tanpa MAC.
- IV/nonce acak per operasi, tidak pernah diulang.
- Kunci **dihasilkan dan disimpan di Android KeyStore** — bukan hardcoded di kode, bukan diturunkan dari nilai statis (IMEI, package name, string konstan), bukan diletakkan di external storage.
- Bila kunci diturunkan dari password user: KDF kuat (PBKDF2 iterasi tinggi / **Argon2id** / scrypt) dengan salt acak.

**Prioritas 4 — Aktifkan dan pertahankan scoped storage.**

```xml
<!-- AndroidManifest.xml -->
<application
    android:requestLegacyExternalStorage="false"
    ... >
```

- Target **Android 11 (API 30) ke atas** — scoped storage dipaksa aktif oleh OS.
- **Hapus** `android:requestLegacyExternalStorage="true"` dan `preserveLegacyExternalStorage`.
- Hindari `MANAGE_EXTERNAL_STORAGE` kecuali benar-benar wajib (file manager, antivirus, backup app) — penggunaannya dibatasi kebijakan Google Play.
- Deklarasikan permission storage secara minimal; gunakan `READ_MEDIA_IMAGES`/`VIDEO`/`AUDIO` yang granular (API 33+), atau lebih baik **Photo Picker** yang tidak butuh permission sama sekali.

**Prioritas 5 — Validasi input dan integritas untuk semua data yang dibaca dari external storage.** Ini mitigasi khusus terhadap Man-in-the-Disk. Perlakukan semua file dari external storage sebagai **untrusted input**.

- **Jangan pernah** memuat kode eksekutabel (DEX, SO, APK, JS bundle, script) dari external storage.
- Validasi ketat: cek ukuran, tipe MIME, magic bytes, skema/struktur, batas nilai. Jangan deserialisasi objek Java/Kotlin dari file external storage.
- Cegah path traversal dan symlink attack: kanonikalisasi path (`File.canonicalPath`) dan pastikan masih di dalam direktori yang diizinkan.
- Verifikasi integritas dengan hash SHA-256 yang **disimpan di internal storage** (bukan di sebelah file), atau lebih baik dengan HMAC/signature:

```kotlin
object FileIntegrityChecker {
    @Throws(IOException::class, NoSuchAlgorithmException::class)
    fun getIntegrityHash(filePath: String?): String {
        val md = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(8192)
        var bytesRead: Int
        BufferedInputStream(FileInputStream(filePath)).use { fis ->
            while (fis.read(buffer).also { bytesRead = it } != -1) {
                md.update(buffer, 0, bytesRead)
            }
        }
        return md.digest().joinToString("") { "%02x".format(it) }
    }

    fun verifyIntegrity(filePath: String?, expectedHash: String): Boolean =
        getIntegrityHash(filePath) == expectedHash
}
```

> Catatan: hash SHA-256 saja hanya mendeteksi korupsi/tampering oleh penyerang yang tidak tahu nilai hash. Untuk proteksi yang benar terhadap penyerang aktif, gunakan **HMAC-SHA256** dengan kunci dari KeyStore, atau enkripsi authenticated (AES-GCM) yang sekaligus menjamin integritas.

### 4.2 Perbaikan Praktik Tambahan

- **Data minimization:** jangan simpan apa yang tidak perlu disimpan. Token sesi sebaiknya hanya di memori; gunakan refresh token berumur pendek.
- **Hapus file temporer & cache** segera setelah dipakai; jangan biarkan file sementara di `/sdcard`. Gunakan `File.deleteOnExit()` atau hapus eksplisit di `finally`.
- **Matikan logging verbose di build release** (`BuildConfig.DEBUG`), dan pastikan crash handler tidak menulis dump berisi PII/kredensial ke external storage.
- **Audit SDK/library pihak ketiga.** Analytics, crash reporter, map SDK, dan image loader sering menulis cache ke external storage tanpa sepengetahuan developer. Test ini sering menemukan file dari SDK, bukan dari kode aplikasi sendiri.
- **Exclude dari backup:** gunakan `android:allowBackup="false"` atau `dataExtractionRules` / `fullBackupContent` untuk mengecualikan file sensitif (lihat MASWE-0006).
- **Integrasikan ke CI/CD:** jadikan pemeriksaan ini bagian dari regression test — jalankan skrip diff pada emulator di pipeline dan gagalkan build bila ada file baru tak terduga di `/sdcard`.
- **Threat model eksplisit:** dokumentasikan setiap penulisan ke external storage yang disengaja beserta justifikasinya, agar reviewer bisa membedakan keputusan desain dari kebocoran tak sengaja.

### 4.3 Checklist Remediasi

- [ ] Tidak ada data sensitif (kredensial, token, PII, data finansial) yang ditulis ke external storage
- [ ] Data sensitif disimpan di internal storage (`context.filesDir`, `openFileOutput(..., MODE_PRIVATE)`)
- [ ] Tidak ada penggunaan `MODE_WORLD_READABLE` / `MODE_WORLD_WRITEABLE`
- [ ] Bila external storage tetap dipakai: data ter-enkripsi AES-256-GCM dengan kunci di Android KeyStore
- [ ] Tidak ada kunci/secret yang hardcoded di kode atau ikut disimpan di external storage
- [ ] `targetSdkVersion` ≥ 30 dan `requestLegacyExternalStorage` tidak di-set `true`
- [ ] `MANAGE_EXTERNAL_STORAGE` tidak dideklarasikan (kecuali dengan justifikasi kuat dan approval Play)
- [ ] Permission storage minimal; gunakan Photo Picker / SAF / granular `READ_MEDIA_*`
- [ ] Semua data yang dibaca dari external storage divalidasi dan diverifikasi integritasnya (HMAC/AEAD)
- [ ] Tidak ada kode eksekutabel yang dimuat dari external storage
- [ ] File temporer/cache di external storage dibersihkan setelah dipakai
- [ ] Logging verbose dan crash dump ke external storage dimatikan pada build release
- [ ] Library pihak ketiga diaudit untuk penulisan ke external storage
- [ ] File sensitif dikecualikan dari backup
- [ ] Verifikasi ulang: ulangi MASTG-TEST-0200 setelah perbaikan → `output.txt` bersih atau semua file terbukti ter-enkripsi

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0200: Files Written to External Storage](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0200/)
- [MASTG-TEST-0201: Runtime Use of External Storage APIs](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0201/)
- [MASTG-TEST-0202: References to APIs and Permissions for Accessing External Storage](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0202/)
- [MASTG-TEST-0001: Testing Local Storage for Sensitive Data](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0001/)
- [MASWE-0002: Sensitive Data Stored Unencrypted Outside of Private Storage](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0002/)
- [MASTG-DEMO-0001: File System Snapshots from External Storage](https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0001/MASTG-DEMO-0001/)
- [MASTG-DEMO-0002: External Storage APIs Tracing with Frida](https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0002/MASTG-DEMO-0002/)
- [MASTG-DEMO-0003: App Writing to External Storage without Scoped Storage Restrictions](https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0003/MASTG-DEMO-0003/)
- [MASTG-DEMO-0004: App Writing to External Storage with Scoped Storage Restrictions](https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0004/MASTG-DEMO-0004/)
- [MASTG-DEMO-0005: App Writing to External Storage via the MediaStore API](https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0005/MASTG-DEMO-0005/)
- [MASTG-KNOW-0042: External Storage](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0042/)
- [MASTG-TECH-0002: Host-Device Data Transfer](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0002/)
- [MASTG-TECH-0005: Installing Apps](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0005/)
- [MASVS-STORAGE: Storage](https://mas.owasp.org/MASVS/05-MASVS-STORAGE/)
- [OWASP MASTG Repository (GitHub)](https://github.com/OWASP/mastg)
- [OWASP Mobile Top 10 2024 — M9: Insecure Data Storage](https://owasp.org/www-project-mobile-top-10/2023-risks/m9-insecure-data-storage)

### 5.2 Dokumentasi Resmi Android / Google

- [Sensitive Data Stored in External Storage — Android Security Risks](https://developer.android.com/privacy-and-security/risks/sensitive-data-external-storage)
- [Data and file storage overview](https://developer.android.com/training/data-storage)
- [Access app-specific files](https://developer.android.com/training/data-storage/app-specific)
- [Scoped storage](https://developer.android.com/training/data-storage#scoped-storage)
- [Storage use cases and best practices](https://developer.android.com/training/data-storage/use-cases)
- [Access media files from shared storage (MediaStore)](https://developer.android.com/training/data-storage/shared/media)
- [Access documents and other files (Storage Access Framework)](https://developer.android.com/training/data-storage/shared/documents-files)
- [Manage all files on a storage device (MANAGE_EXTERNAL_STORAGE)](https://developer.android.com/training/data-storage/manage-all-files)
- [App security best practices — Store data safely](https://developer.android.com/privacy-and-security/security-best-practices#external-storage)
- [Security tips — Using external storage](https://developer.android.com/privacy-and-security/security-tips#external-storage)
- [Android Keystore system](https://developer.android.com/privacy-and-security/keystore)
- [Cryptography best practices](https://developer.android.com/privacy-and-security/cryptography)
- [FileProvider](https://developer.android.com/reference/androidx/core/content/FileProvider)
- [Photo picker](https://developer.android.com/training/data-storage/shared/photopicker)
- [adb — Copy files to/from a device](https://developer.android.com/studio/command-line/adb#copyfiles)
- [Device File Explorer (Android Studio)](https://developer.android.com/studio/debug/device-file-explorer)
- [File-Based Encryption (AOSP)](https://source.android.com/docs/security/features/encryption/file-based)
- [Google Play — Use of the All files access permission](https://support.google.com/googleplay/android-developer/answer/10467955)

### 5.3 Standar, Taksonomi, dan Guideline Lain

- [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
- [CWE-921: Storage of Sensitive Data in a Mechanism without Access Control](https://cwe.mitre.org/data/definitions/921.html)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [SEI CERT Android — DRD00: Do not store sensitive information on external storage (SD card) unless encrypted first](https://wiki.sei.cmu.edu/confluence/display/android/DRD00.+Do+not+store+sensitive+information+on+external+storage+%28SD+card%29+unless+encrypted+first)
- [NIST SP 800-163 Rev.1 — Vetting the Security of Mobile Applications](https://csrc.nist.gov/publications/detail/sp/800-163/rev-1/final)
- [NIST SP 800-124 Rev.2 — Guidelines for Managing the Security of Mobile Devices](https://csrc.nist.gov/publications/detail/sp/800-124/rev-2/final)
- [SonarQube Rule java:S5324 — Accessing Android external storage is security-sensitive](https://rules.sonarsource.com/java/RSPEC-5324/)
- [CodeQL — Cleartext storage of sensitive information in the Android filesystem](https://codeql.github.com/codeql-query-help/java/java-android-cleartext-storage-filesystem/)
- [MITRE ATT&CK Mobile — T1533: Data from Local System](https://attack.mitre.org/techniques/T1533/)
- [MITRE ATT&CK Mobile — T1409: Stored Application Data](https://attack.mitre.org/techniques/T1409/)

### 5.4 Riset Keamanan & Artikel Teknis

- [Check Point Research — Man-in-the-Disk: Android Apps Exposed via External Storage](https://research.checkpoint.com/2018/androids-man-in-the-disk/)
- [Check Point Blog — Man-in-the-Disk: A New Attack Surface for Android Apps](https://blog.checkpoint.com/security/man-in-the-disk-a-new-attack-surface-for-android-apps/)
- [Threatpost — DEF CON 2018: 'Man in the Disk' Attack Surface Affects All Android Phones](https://threatpost.com/def-con-2018-man-in-the-disk-attack-surface-affects-all-android-phones/134993/)
- [The Hacker News — New Man-in-the-Disk attack leaves millions of Android phones vulnerable](https://thehackernews.com/2018/08/man-in-the-disk-android-hack.html)
- [NDSS 2025 — ScopeVerif: Analyzing the Security of Android's Scoped Storage via Differential Analysis](https://www.ndss-symposium.org/wp-content/uploads/2025-340-paper.pdf)
- [PolyScope: Multi-Policy Access Control Analysis to Triage Android Scoped Storage (arXiv)](https://arxiv.org/pdf/2302.13506)
- [Security Smells in Android (arXiv)](https://arxiv.org/pdf/2006.01181)
- [HackTricks — Android Applications Basics & Local Storage](https://book.hacktricks.wiki/en/mobile-pentesting/android-app-pentesting/index.html)
- [Google Tink — Cryptographic library](https://developers.google.com/tink)

### 5.5 Dokumentasi Tools

- [Frida — Dynamic instrumentation toolkit](https://frida.re/docs/home/)
- [Objection — Runtime mobile exploration](https://github.com/sensepost/objection)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [apktool — Reverse engineering Android APK files](https://apktool.org/)
- [Semgrep — Static analysis](https://semgrep.dev/docs/)
- [sqlite3 CLI](https://www.sqlite.org/cli.html)
- [ent — Pseudorandom number sequence test (entropy)](https://www.fourmilab.ch/random/)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026), dokumentasi resmi Android Developers, standar CWE/SEI CERT/NIST, serta riset keamanan pihak ketiga.*
