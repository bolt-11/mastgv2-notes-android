# MASTG-TEST-0201 Runtime Use of APIs to Access External Storage

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0201 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-STORAGE (MASVS-STORAGE-1: Aplikasi menyimpan data sensitif secara aman) |
| **Weakness** | MASWE-0002 — *Sensitive Data Stored Unencrypted Outside of Private Storage* |
| **Tipe Pengujian** | Dynamic, **Hooks**, Manual |
| **Profile** | L1, L2 |
| **Knowledge** | MASTG-KNOW-0042 (External Storage) |
| **APIs yang disorot** | `Environment#getExternalStorageDirectory`, `Environment#getExternalStoragePublicDirectory`, `Environment#getExternalFilesDir`, `Environment#getExternalCacheDir`, `FileOutputStream` |
| **Teknik terkait** | MASTG-TECH-0005 (Installing Apps), MASTG-TECH-0043 (Method Hooking), MASTG-TECH-0023 (Reviewing Decompiled Java Code) |
| **Demo terkait** | MASTG-DEMO-0002 (External Storage APIs Tracing with Frida) |
| **CWE terkait** | CWE-312 (Cleartext Storage of Sensitive Information), CWE-921 (Storage of Sensitive Data in a Mechanism without Access Control), CWE-200 (Exposure of Sensitive Information) |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Test ini bertujuan **mengidentifikasi API mana yang benar-benar dipanggil aplikasi saat runtime untuk mengakses/menulis ke external storage**, beserta **file apa yang dihasilkan**, **siapa pemanggilnya** (backtrace / stack trace), dan **di baris kode mana** penulisan itu terjadi.

Kutipan langsung dari overview MASTG:

> *"Android apps use a variety of APIs to access the external storage. Collecting a comprehensive list of these APIs can be challenging, especially if an app uses a third-party framework, loads code at runtime, or includes native code."*
>
> *"The most effective approach to testing applications that write to device storage is usually dynamic analysis, and specifically method hooking. You can use it to hook into the relevant APIs such as `getExternalStorageDirectory`, `getExternalStoragePublicDirectory`, `getExternalFilesDir` or `FileOutputStream`. You could also use `open` as a catch-all for file interactions. However, this won't catch all file interactions, such as those that use the `MediaStore` API and should be done with additional filtering as it can generate a lot of noise."*

Jadi, ada tiga poin kunci dari overview tersebut yang wajib dipahami sebelum menguji:

1. **Daftar API tidak mungkin dikumpulkan secara lengkap secara statis.** Framework pihak ketiga (React Native, Flutter, Unity, Cordova), kode yang dimuat saat runtime (DexClassLoader, dynamic feature module), dan kode native (JNI/NDK) membuat analisis statis selalu punya titik buta. Karena itu pendekatannya harus **dinamis**.
2. **`open()` dari libc dipakai sebagai *catch-all*.** Hampir semua API file I/O Java/Kotlin (`FileOutputStream`, `FileWriter`, `RandomAccessFile`, `Files.write`) pada akhirnya turun ke syscall `open()` di libc — termasuk kode native. Dengan hook di satu titik ini, kita menangkap operasi file dari lapisan mana pun.
3. **`open()` punya blind spot besar: MediaStore.** Dan `open()` juga menghasilkan **noise sangat banyak**, sehingga wajib difilter berdasarkan prefix path external storage.

### 1.2 Posisi Test Ini dalam Rangkaian MASVS-STORAGE

Tiga test bersaudara ini saling melengkapi dan sebaiknya dijalankan bersama:

| Test | Pendekatan | Menjawab pertanyaan | Kekuatan | Kelemahan |
|---|---|---|---|---|
| **MASTG-TEST-0200** | Dinamis — *filesystem diffing* (snapshot before/after) | "File apa yang **benar-benar muncul** di disk?" | Bukti nyata & API-agnostic total; tidak bisa dibohongi | Tidak tahu **siapa** yang menulis dan **di baris kode mana**; tidak menangkap file yang langsung dihapus |
| **MASTG-TEST-0201** *(dokumen ini)* | Dinamis — **method hooking / instrumentasi** | "**API apa** yang dipanggil, oleh **kode mana**?" | Atribusi presisi ke baris kode & library; menangkap file sementara (write→delete); menangkap kode native | Butuh Frida/root; bisa dihalangi anti-instrumentation; hanya menangkap alur yang di-*exercise* |
| **MASTG-TEST-0202** | Statis — reverse engineering manifest & referensi API | "API & permission apa yang **direferensikan**?" | Cakupan 100% dari kode yang ada, tanpa perlu menjalankan app | Banyak false positive (dead code, library tak terpakai); buta terhadap kode dinamis/native/obfuscated |

**Nilai unik TEST-0201** dibanding TEST-0200: TEST-0200 hanya memberi daftar path. TEST-0201 memberi **backtrace** — sehingga kamu bisa membedakan apakah file ditulis oleh kode aplikasi sendiri atau oleh **SDK pihak ketiga** (analytics, crash reporter, image loader), dan bisa langsung menunjuk baris kode yang harus diperbaiki developer. Ini yang membuat temuan test ini sangat *actionable*.

Selain itu, TEST-0201 menangkap kasus yang **lolos** dari TEST-0200:
- File yang ditulis lalu **segera dihapus** (temp file) — tidak muncul di diff filesystem, tapi tetap sempat mengekspos data ke aplikasi lain selama jendela waktu tersebut.
- File yang ditulis ke path yang tidak terjangkau `find /sdcard/` (secondary storage, path tak lazim).
- Operasi **baca** (read) dari external storage — relevan untuk risiko Man-in-the-Disk, di mana aplikasi memuat data/kode tak terpercaya.

### 1.3 Peta API External Storage yang Perlu Di-hook

Memahami lapisan-lapisan API sangat penting agar hooking tidak bocor.

**Lapisan A — API resolusi path (memberi tahu *ke mana* aplikasi akan menulis):**

| API | Path yang dikembalikan | Catatan keamanan |
|---|---|---|
| `Context.getExternalFilesDir(String type)` | `/sdcard/Android/data/<pkg>/files/...` | App-specific external. Dilindungi scoped storage (API 29+), **tidak** sebelum itu. Hilang saat uninstall. |
| `Context.getExternalCacheDir()` | `/sdcard/Android/data/<pkg>/cache/` | Sama seperti di atas. |
| `Context.getExternalMediaDirs()` | `/sdcard/Android/media/<pkg>/` | Terlihat di MediaStore → bisa diakses app lain dengan permission media. |
| `Environment.getExternalStorageDirectory()` | `/sdcard/` | **Deprecated (API 29)**. Shared storage — paling berisiko. Indikator kode legacy. |
| `Environment.getExternalStoragePublicDirectory(String type)` | `/sdcard/Download/`, `/sdcard/Documents/`, `/sdcard/DCIM/` | **Deprecated (API 29)**. Shared, dapat diakses app lain, **bertahan pasca-uninstall**. |
| `Context.getExternalFilesDirs()` / `ContextCompat.getExternalFilesDirs()` | Termasuk SD card sekunder | SD card fisik bisa dilepas dan dibaca di device lain. |

> **Penting:** memanggil API resolusi path saja **belum berarti** ada penulisan. Hook di lapisan ini berguna untuk memetakan *niat*, tetapi bukti penulisan harus datang dari Lapisan B/C. Jangan langsung menyimpulkan FAIL hanya karena `getExternalFilesDir` terpanggil.

**Lapisan B — API penulisan Java/Kotlin (yang melakukan I/O aktual):**

- `java.io.FileOutputStream` (konstruktor), `java.io.FileWriter`, `java.io.RandomAccessFile`
- `java.io.File.createNewFile()`, `File.mkdirs()`, `File.delete()`
- `java.nio.file.Files.write()` / `newOutputStream()` / `copy()`
- Kotlin: `File.writeText()`, `File.writeBytes()`, `File.appendText()` (semuanya wrapper atas `FileOutputStream`)
- `android.content.ContentResolver.openOutputStream()` / `openFileDescriptor()`
- Serialisasi tingkat tinggi: `ObjectOutputStream`, `Properties.store()`, `Bitmap.compress()`, `ZipOutputStream`
- `android.app.DownloadManager.enqueue()` — mengunduh langsung ke shared storage

**Lapisan C — Lapisan native/libc (catch-all):**

- `open()`, `openat()`, `creat()` — titik konvergensi semua I/O file, termasuk dari kode NDK
- `fopen()`, `rename()`, `unlink()`, `mkdir()`
- Hook di sini menangkap **semua** yang lolos dari Lapisan B, termasuk library native pihak ketiga

**Lapisan D — MediaStore / ContentResolver (blind spot `open()`):**

Catatan resmi MASTG-DEMO-0002:

> *"When apps write files using the `ContentResolver.insert()` method, the files are managed by Android's MediaStore and are identified by `content://` URIs, not direct file system paths. This design abstracts the actual file locations, making them inaccessible through standard file system operations like the `open` function in libc. Consequently, when using Frida to hook into file operations, intercepting calls to `open` won't reveal these files."*

Artinya: **hook `open()` saja TIDAK CUKUP.** Kamu wajib juga meng-hook:
- `ContentResolver.insert(Uri, ContentValues)` — untuk menangkap pembuatan entri MediaStore
- `ContentResolver.openOutputStream(Uri)` — untuk menangkap penulisan isi file
- `MediaStore.createWriteRequest()` (API 30+), `MediaSessionManager`

Path final harus **direkonstruksi** dari `ContentValues`: kombinasi `relative_path` + `_display_name`. Contoh dari demo: `relative_path: Download` + `_display_name: secretFile55.txt` → `/storage/emulated/0/Download/secretFile55.txt`.

**Lapisan E — Storage Access Framework & lainnya:**
- `Intent.ACTION_CREATE_DOCUMENT` / `ACTION_OPEN_DOCUMENT` → `ContentResolver.openOutputStream()`
- `DocumentFile.createFile()` (androidx.documentfile)
- `MANAGE_EXTERNAL_STORAGE` + `File` API langsung ke path arbitrer

### 1.4 Risiko yang Dikonfirmasi oleh Test Ini

Test ini memvalidasi eksposur yang sama dengan MASTG-TEST-0200 (lihat dokumen tersebut untuk detail), tetapi dengan sudut pandang atribusi kode:

1. **Information disclosure lintas-aplikasi** — file plaintext di external storage terbaca app lain (terutama target API ≤ 29 atau `requestLegacyExternalStorage="true"`).
2. **Man-in-the-Disk** (Check Point, DEF CON 2018) — penyerang menimpa data yang ditulis/dibaca aplikasi di external storage; berpotensi DoS, crash, hingga **code injection dalam konteks privileged aplikasi target**. Test ini sangat efektif mendeteksi risiko ini karena hook pada `open()` juga menangkap operasi **baca**, sehingga kamu bisa melihat aplikasi memuat file dari `/sdcard` dan melacak ke baris kode yang memprosesnya.
3. **Kebocoran via SDK pihak ketiga** — ini keunggulan khas test ini. Backtrace akan menunjukkan paket seperti `com.google.firebase.crashlytics.*`, `com.squareup.picasso.*`, atau `io.branch.*` sebagai pemanggil, yang sering tidak disadari developer.
4. **Persistensi pasca-uninstall** — file yang ditulis via MediaStore ke `Download/`, `Documents/` tidak dihapus saat aplikasi di-uninstall.
5. **Kebocoran dari kode native** — hook libc menangkap penulisan dari `.so` yang tidak terlihat di analisis DEX.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | MASTG ID | Fungsi dalam test ini |
|---|---|---|
| **Frida** | MASTG-TOOL-0001 | **Tool utama.** Dynamic instrumentation: hook `libc!open`, `ContentResolver.insert`, `FileOutputStream`, cetak backtrace. `frida` CLI untuk spawn + inject script. |
| **frida-server** | — | Daemon yang harus berjalan di device (butuh root) — atau gunakan **frida-gadget** yang di-inject ke APK untuk device non-root. |
| **adb** | MASTG-TOOL-0004 | Instalasi APK, push frida-server, port forwarding, verifikasi file hasil temuan. |
| **Android device / emulator (rooted)** | MASTG-TOOL-0003 | Target. Disarankan emulator AVD dengan image *Google APIs* (bukan Google Play) agar mudah di-root via `adb root`. |
| **jadx** | MASTG-TOOL-0018 | **Wajib untuk langkah evaluasi.** MASTG-TECH-0023 mengarahkan kita meninjau lokasi kode dari backtrace untuk menentukan apakah code path-nya security-relevant. |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **frida-trace** | Alternatif cepat tanpa menulis script. `-i "open"` untuk fungsi native, `-j '<Class>!<method>'` untuk metode Java (mendukung modifier `/isu`: `s`=include signature, `i`=case-insensitive, `u`=user-defined classes only). Unggul saat ingin meng-hook ribuan fungsi sekaligus dengan wildcard `*`. |
| **Objection** | MASTG-TOOL-0038. Wrapper Frida siap pakai: `android hooking watch class_method java.io.FileOutputStream.$init --dump-args --dump-backtrace`, plus `filesystem download` untuk menarik file temuan. Cocok untuk pengujian cepat. |
| **jnitrace** | Tracing JNI API calls — penting bila aplikasi menulis file dari kode native via JNI. |
| **frida-gadget** | Untuk device **non-rooted**: inject gadget ke APK (repackaging dengan objection/apktool + apksigner), lalu instrumentasi tanpa root. |
| **Xposed / LSPosed** | Alternatif method hooking (MASTG-TECH-0043). Lebih persisten tapi kurang fleksibel untuk tracing ad-hoc dibanding Frida. |
| **strace** | Tracing syscall level-OS (`strace -f -e trace=openat,write -p <pid>`). Berguna sebagai pembanding independen bila aplikasi punya anti-Frida. |
| **apktool** | MASTG-TOOL-0011. Decode manifest untuk cek `targetSdkVersion`, `requestLegacyExternalStorage`, permission storage. |
| **`file`, `strings`, `xxd`, `ent`, `sqlite3`** | Inspeksi isi file yang ditemukan — termasuk analisis entropi untuk membedakan enkripsi asli dari encoding. |
| **MASTestApp** | Aplikasi rujukan MASTG untuk memvalidasi script & tooling sebelum diterapkan ke target. |

### 2.3 Prasyarat Lingkungan

- **Root atau frida-gadget.** Ini prasyarat keras; tanpa salah satunya, method hooking tidak mungkin. Ini pembeda utama dengan MASTG-TEST-0200 yang bisa jalan tanpa root.
- **Versi frida-server harus cocok dengan versi frida CLI** di host (mismatch versi adalah penyebab error paling umum). Arsitektur juga harus tepat (`arm64`, `x86_64`).
- Aplikasi terinstall (`adb install -g` agar semua runtime permission ter-grant dan seluruh alur bisa dijangkau).
- **Canary value** yang unik untuk setiap input (mis. `MASTG_Pa55w0rd_UNIQ`) — memudahkan grep pada isi file dan korelasi dengan output trace.
- **Antisipasi anti-instrumentation.** Banyak aplikasi produksi (terutama finansial) mendeteksi Frida/root dan akan keluar. Bila ini terjadi, bypass detection dulu (rujuk MASVS-RESILIENCE / MASTG-TECH-0043) — dan **dokumentasikan sebagai temuan terpisah**, bukan sebagai alasan test ini di-skip. Alternatifnya, andalkan MASTG-TEST-0200 yang tidak butuh instrumentasi.
- Device bersih / snapshot emulator agar baseline noise minimal.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0005** (*Installing Apps*) untuk menginstall aplikasi.
2. Gunakan **MASTG-TECH-0043** (*Method Hooking*) untuk meng-hook panggilan API yang relevan.
3. **Exercise aplikasi secara ekstensif** untuk memicu sebanyak mungkin alur, dan masukkan data sensitif di setiap tempat yang memungkinkan.

Lalu untuk evaluasi, gunakan **MASTG-TECH-0023** (*Reviewing Decompiled Java Code*) untuk menginspeksi lokasi kode dari backtrace, guna menentukan code path persis yang menghasilkan file tersebut dan apakah code path itu security-relevant.

### 3.2 Implementasi Praktis (MASTG-DEMO-0002)

**Langkah 0 — Setup Frida**

```bash
# Cek versi frida di host
frida --version

# Unduh frida-server sesuai versi & arsitektur device
adb shell getprop ro.product.cpu.abi      # -> mis. x86_64 / arm64-v8a

# Push dan jalankan frida-server di device
adb push frida-server-<versi>-android-<arch> /data/local/tmp/frida-server
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "su -c /data/local/tmp/frida-server &"

# Verifikasi koneksi
frida-ps -U | head

# Install aplikasi target dengan semua permission ter-grant
adb install -g ./target-app.apk
```

**Langkah 1 — Script hooking (`script.js`)**

Ini script resmi dari MASTG-DEMO-0002:

```javascript
function printBacktrace(maxLines = 8) {
    Java.perform(() => {
        let Exception = Java.use("java.lang.Exception");
        let stackTrace = Exception.$new().getStackTrace().toString().split(",");
        console.log("\nBacktrace:");
        for (let i = 0; i < Math.min(maxLines, stackTrace.length); i++) {
            console.log(stackTrace[i]);
        }
    });
};

// Intercept libc's open to make sure we cover all Java I/O APIs
Interceptor.attach(
    Process.getModuleByName('libc.so').getExportByName('open'),
    {
        onEnter: function(args) {
            const external_paths = ['/sdcard', '/storage/emulated'];
            const path = args[0].readCString();
            external_paths.forEach(external_path => {
                if (path.indexOf(external_path) === 0) {
                    console.log(`\n[*] open called to open a file from external storage at: ${path}`);
                    printBacktrace(15);
                }
            });
        }
    }
);

// Hook ContentResolver.insert to log ContentValues (including keys like
// _display_name, mime_type, and relative_path) and returned URI
Java.perform(() => {
    let ContentResolver = Java.use("android.content.ContentResolver");
    ContentResolver.insert.overload('android.net.Uri', 'android.content.ContentValues')
      .implementation = function(uri, values) {
        console.log(`\n[*] ContentResolver.insert called with ContentValues:`);
        console.log(`\t_display_name: ${values.get("_display_name").toString()}`);
        console.log(`\tmime_type: ${values.get("mime_type").toString()}`);
        console.log(`\trelative_path: ${values.get("relative_path").toString()}`);

        let result = this.insert(uri, values);
        console.log(`\n[*] ContentResolver.insert returned URI: ${result.toString()}`);
        printBacktrace();
        return result;
    };
});
```

Perhatikan dua pilihan desain penting dalam script ini:
- **Filter path** (`['/sdcard', '/storage/emulated']`) diterapkan langsung di `onEnter` — inilah "additional filtering" yang diwajibkan MASTG untuk mengatasi noise dari `open()`.
- **`ContentResolver.insert` di-hook terpisah** — karena MediaStore tidak terlihat oleh hook `open()`.

**Langkah 2 — Jalankan (`run.sh`)**

```bash
#!/bin/bash

# SUMMARY: This script uses frida to trace files that an app has opened since it spawned.
# The script filters the output of frida-trace to print only the paths belonging to external
# storage but the predefined list of external storage paths might not be complete.
# A sample output is shown in "output.txt". If the output is empty, it indicates that no
# external storage is used.

frida \
    -U \
    -f org.owasp.mastestapp \
    -l script.js \
    -o output.txt
```

**Langkah 3 — Exercise aplikasi**

Buka aplikasi dan jalankan alur sebanyak mungkin secara sistematis, dengan canary value di setiap input:

- Registrasi, login, logout, login ulang, "remember me", biometrik/2FA, reset password, OTP
- Lengkapi profil (nama, NIK, alamat, telepon, upload dokumen identitas/foto)
- Tambah metode pembayaran, lakukan transaksi, unduh invoice/e-statement
- Upload & download attachment, export data, share, print
- Kamera, galeri, document scanner, voice note
- Chat/pesan, riwayat pencarian, draft
- Mode offline (matikan jaringan → picu caching lokal), lalu online kembali
- Background/foreground berulang, rotasi layar, force-stop lalu buka ulang
- Picu error/crash bila mungkin (memicu crash dump ke disk)
- Aktifkan semua toggle di Settings, termasuk opsi debug/developer bila ada

**Langkah 4 — Hentikan dan analisis**

Tekan `Ctrl+C` untuk mengakhiri, lalu analisis `output.txt`.

### 3.3 Perluasan Script yang Direkomendasikan

Script demo MASTG sengaja minimalis untuk tujuan edukasi. Untuk pengujian nyata, script tersebut punya beberapa keterbatasan praktis yang sebaiknya ditutup:

1. **`values.get("...")` bisa mengembalikan `null`** jika key tidak ada, lalu `.toString()` akan crash dan menggagalkan hook. Perlu null-check.
2. **Hanya `open` yang di-hook**, bukan `openat` — padahal Android/bionic modern banyak memakai `openat`.
3. **Filter path belum mencakup** secondary/removable storage (`/storage/XXXX-XXXX`) dan `/mnt/media_rw`.
4. **`ContentResolver.openOutputStream` tidak di-hook**, padahal itu titik penulisan isi file MediaStore.
5. **Operasi baca tidak dibedakan dari tulis** — padahal untuk Man-in-the-Disk, operasi baca justru yang penting.

Versi yang diperluas:

```javascript
function printBacktrace(maxLines = 12) {
    Java.perform(() => {
        const Exception = Java.use("java.lang.Exception");
        const stackTrace = Exception.$new().getStackTrace();
        console.log("\nBacktrace:");
        for (let i = 0; i < Math.min(maxLines, stackTrace.length); i++) {
            console.log("  " + stackTrace[i].toString());
        }
    });
}

const EXTERNAL_PREFIXES = [
    '/sdcard',
    '/storage/emulated',
    '/storage/self/primary',
    '/mnt/sdcard',
    '/mnt/media_rw',
    '/storage/'            // menangkap removable storage /storage/XXXX-XXXX
];

function isExternal(path) {
    if (!path) return false;
    return EXTERNAL_PREFIXES.some(p => path.indexOf(p) === 0);
}

// Decode flags O_WRONLY/O_RDWR/O_CREAT agar bisa membedakan baca vs tulis
function decodeFlags(flags) {
    const acc = flags & 3;                       // O_ACCMODE
    let s = (acc === 0) ? "O_RDONLY" : (acc === 1) ? "O_WRONLY" : "O_RDWR";
    if (flags & 0x40)  s += "|O_CREAT";
    if (flags & 0x400) s += "|O_APPEND";
    if (flags & 0x200) s += "|O_TRUNC";
    return s;
}

// --- Lapisan C: catch-all native (open DAN openat) ---
['open', 'openat'].forEach(fn => {
    const addr = Process.getModuleByName('libc.so').findExportByName(fn);
    if (!addr) return;
    Interceptor.attach(addr, {
        onEnter(args) {
            // open(path, flags) | openat(dirfd, path, flags)
            const pathArg  = (fn === 'open') ? args[0] : args[1];
            const flagsArg = (fn === 'open') ? args[1] : args[2];
            const path = pathArg.readCString();
            if (isExternal(path)) {
                console.log(`\n[*] ${fn}() on external storage: ${path}` +
                            `  [${decodeFlags(flagsArg.toInt32())}]`);
                printBacktrace(15);
            }
        }
    });
});

// --- Lapisan D: MediaStore / ContentResolver ---
Java.perform(() => {
    const ContentResolver = Java.use("android.content.ContentResolver");

    // Ambil nilai ContentValues dengan aman (null-safe)
    function safeGet(values, key) {
        try {
            const v = values.get(key);
            return (v === null) ? "<null>" : v.toString();
        } catch (e) { return "<n/a>"; }
    }

    ContentResolver.insert.overload('android.net.Uri', 'android.content.ContentValues')
      .implementation = function (uri, values) {
        const name = safeGet(values, "_display_name");
        const mime = safeGet(values, "mime_type");
        const rel  = safeGet(values, "relative_path");
        console.log(`\n[*] ContentResolver.insert()`);
        console.log(`\ttarget uri     : ${uri}`);
        console.log(`\t_display_name  : ${name}`);
        console.log(`\tmime_type      : ${mime}`);
        console.log(`\trelative_path  : ${rel}`);
        // Rekonstruksi path yang diperkirakan
        console.log(`\t=> inferred path: /storage/emulated/0/${rel}/${name}`);
        const result = this.insert(uri, values);
        console.log(`\treturned URI   : ${result}`);
        printBacktrace();
        return result;
      };

    // Titik penulisan isi file MediaStore / SAF
    ContentResolver.openOutputStream.overload('android.net.Uri')
      .implementation = function (uri) {
        console.log(`\n[*] ContentResolver.openOutputStream(): ${uri}`);
        printBacktrace();
        return this.openOutputStream(uri);
      };
});

// --- Lapisan A: API resolusi path (memetakan "niat") ---
Java.perform(() => {
    const Ctx = Java.use("android.content.ContextWrapper");
    Ctx.getExternalFilesDir.implementation = function (type) {
        const r = this.getExternalFilesDir(type);
        console.log(`\n[*] getExternalFilesDir("${type}") -> ${r}`);
        printBacktrace(10);
        return r;
    };
    Ctx.getExternalCacheDir.implementation = function () {
        const r = this.getExternalCacheDir();
        console.log(`\n[*] getExternalCacheDir() -> ${r}`);
        printBacktrace(10);
        return r;
    };

    const Env = Java.use("android.os.Environment");
    Env.getExternalStorageDirectory.implementation = function () {
        const r = this.getExternalStorageDirectory();
        console.log(`\n[!] DEPRECATED getExternalStorageDirectory() -> ${r}`);
        printBacktrace(10);
        return r;
    };
    Env.getExternalStoragePublicDirectory.implementation = function (type) {
        const r = this.getExternalStoragePublicDirectory(type);
        console.log(`\n[!] DEPRECATED getExternalStoragePublicDirectory("${type}") -> ${r}`);
        printBacktrace(10);
        return r;
    };
});

// --- Bonus: intip isi yang ditulis, untuk mendeteksi plaintext langsung ---
Java.perform(() => {
    const FOS = Java.use("java.io.FileOutputStream");
    FOS.write.overload('[B', 'int', 'int').implementation = function (b, off, len) {
        try {
            const preview = Java.use("java.lang.String").$new(b, off, Math.min(len, 200));
            console.log(`\n[*] FileOutputStream.write() ${len} bytes, preview: ${preview}`);
        } catch (e) { /* data biner, abaikan */ }
        return this.write(b, off, len);
    };
});
```

> Hook `FileOutputStream.write()` di atas sangat membantu: ia memperlihatkan **isi** yang ditulis secara langsung, sehingga kamu bisa mendeteksi plaintext tanpa harus menarik file dari device. Tapi ia juga sumber noise besar — aktifkan hanya bila diperlukan.

### 3.4 Alternatif Cepat dengan frida-trace dan Objection

**frida-trace** (tanpa menulis script):

```bash
# Trace fungsi native open (catch-all, noise tinggi)
frida-trace -U -f org.owasp.mastestapp -i "open" -i "openat" -o trace.txt

# Trace metode Java terkait storage; modifier /isu:
#   i = case-insensitive, s = include signature, u = user-defined classes only
frida-trace -U -f org.owasp.mastestapp --runtime=v8 \
  -j 'java.io.FileOutputStream!*' \
  -j 'android.content.ContentResolver!insert*' \
  -j '*!*ExternalStorage*/isu' \
  -j '*!*ExternalFilesDir*/isu' \
  -o trace.txt
```

**Objection** (paling cepat untuk pengujian eksploratif):

```bash
objection -g org.owasp.mastestapp explore

# Di dalam shell objection:
android hooking watch class_method java.io.FileOutputStream.$init --dump-args --dump-backtrace
android hooking watch class_method android.content.ContentResolver.insert --dump-args --dump-backtrace
android hooking watch class_method android.os.Environment.getExternalStorageDirectory --dump-backtrace

# Tarik file temuan langsung
ls /sdcard/Android/data/org.owasp.mastestapp/files
filesystem download /sdcard/Android/data/org.owasp.mastestapp/files/secret.txt
```

**strace** sebagai pembanding independen (berguna bila ada anti-Frida):

```bash
adb shell "su -c 'strace -f -e trace=openat,write -p $(pidof org.owasp.mastestapp)'" \
  | grep -E "/sdcard|/storage/emulated"
```

### 3.5 Langkah Konfirmasi Wajib (Evaluasi Lanjutan)

MASTG secara eksplisit meminta langkah ini — jangan berhenti di output trace.

```bash
# 1. Tarik file yang teridentifikasi dari trace, lalu inspeksi isinya
adb pull /storage/emulated/0/Android/data/org.owasp.mastestapp/files/secret.txt
adb pull /storage/emulated/0/Download/secretFile55.txt

file secret.txt secretFile55.txt
cat secret.txt

# 2. Cari canary value & pola sensitif
grep -riE "MASTG_Pa55w0rd_UNIQ|password|passwd|secret|token|api[_-]?key|bearer|authorization|BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY|[0-9]{16}" .

# 3. Uji apakah benar-benar ter-enkripsi (bukan hanya encoding)
ent secret.txt                 # entropi ~7.9+ bit/byte => kemungkinan terenkripsi
strings -n 6 secret.txt
base64 -d secret.txt 2>/dev/null | head   # cek apakah cuma Base64

# 4. Verifikasi path MediaStore yang direkonstruksi dari ContentValues
adb shell content query --uri content://media/external/downloads \
  --projection _id:_display_name:relative_path:owner_package_name:_data

# 5. MASTG-TECH-0023 — telusuri lokasi kode dari backtrace
#    Buka APK di jadx, navigasi ke kelas & baris yang disebut backtrace
jadx -d ./decompiled ./target-app.apk
grep -rn "getExternalFilesDir\|MediaStore\|getExternalStoragePublicDirectory" ./decompiled/sources/

# 6. Cek konfigurasi scoped storage untuk menentukan severity
grep -E "targetSdkVersion|requestLegacyExternalStorage|preserveLegacyExternalStorage" \
  ./decoded/AndroidManifest.xml
adb shell dumpsys package org.owasp.mastestapp | grep -iE "targetSdk|EXTERNAL_STORAGE|READ_MEDIA"

# 7. Uji eksploitabilitas: baca dari konteks aplikasi lain
adb shell run-as <paket_app_uji_lain> cat \
  /sdcard/Android/data/org.owasp.mastestapp/files/secret.txt
```

### 3.6 Metode Pengujian Alternatif Lanjutan (Multi-Tool)

§3.4 sudah mencakup frida-trace, Objection, dan strace. Berikut jalur tambahan untuk situasi yang lebih sulit — terutama **device non-root**, **anti-instrumentation**, dan **kode native**.

#### Metode E — frida-gadget *(instrumentasi tanpa root)*

Ini jalur terpenting bila kamu tidak punya device rooted. `frida-gadget` disuntikkan ke dalam APK sehingga aplikasi "membawa" Frida-nya sendiri.

```bash
# Cara termudah: objection melakukan repackaging otomatis
pip install objection
objection patchapk --source ./target-app.apk
#   -> menghasilkan target-app.objection.apk dengan gadget tertanam

adb install ./target-app.objection.apk
# Aplikasi akan PAUSE saat startup menunggu koneksi:
frida -U Gadget -l script.js

# Cara manual (kendali lebih besar):
apktool d -f -o ./app ./target-app.apk
cp frida-gadget-<ver>-android-arm64.so ./app/lib/arm64-v8a/libgadget.so
#   lalu tambahkan System.loadLibrary("gadget") di <clinit> Application class (smali)
apktool b -o repacked.apk ./app
apksigner sign --ks debug.keystore repacked.apk
```

> **Catat sebagai temuan tersendiri:** bila repackaging + instalasi berhasil, itu berarti aplikasi tidak punya integrity/signature check — kelemahan MASVS-RESILIENCE (MASTG-TEST-0224 dan sekitarnya).

#### Metode F — Xposed / LSPosed module *(alternatif hooking yang lebih sulit dideteksi)*

MASTG-TECH-0043 menyebut Xposed sebagai metode hooking yang sah. LSPosed (implementasi modern berbasis Zygisk/Riru) sering lolos dari deteksi yang menargetkan Frida secara spesifik.

```java
// ExternalStorageMonitor.java — modul LSPosed
public class ExternalStorageMonitor implements IXposedHookLoadPackage {
    @Override
    public void handleLoadPackage(final LoadPackageParam lpparam) throws Throwable {
        if (!lpparam.packageName.equals("com.example.target")) return;

        // Hook getExternalFilesDir
        findAndHookMethod("android.content.ContextWrapper", lpparam.classLoader,
            "getExternalFilesDir", String.class, new XC_MethodHook() {
                @Override protected void afterHookedMethod(MethodHookParam param) {
                    XposedBridge.log("[ExtStorage] getExternalFilesDir -> " + param.getResult());
                    XposedBridge.log(android.util.Log.getStackTraceString(new Throwable()));
                }
            });

        // Hook FileOutputStream constructor
        findAndHookConstructor("java.io.FileOutputStream", lpparam.classLoader,
            java.io.File.class, new XC_MethodHook() {
                @Override protected void beforeHookedMethod(MethodHookParam param) {
                    String p = param.args[0].toString();
                    if (p.startsWith("/sdcard") || p.startsWith("/storage/emulated")) {
                        XposedBridge.log("[ExtStorage] write -> " + p);
                        XposedBridge.log(android.util.Log.getStackTraceString(new Throwable()));
                    }
                }
            });
    }
}
```

```bash
# Output modul muncul di logcat dengan tag LSPosed
adb logcat -s LSPosed:V | grep ExtStorage
```

Keunggulan: persisten lintas restart aplikasi, dan tidak ada proses `frida-server` yang berjalan untuk dideteksi. Kelemahan: perlu kompilasi APK modul dan reboot untuk mengaktifkan.

#### Metode G — jnitrace *(penulisan file dari kode native via JNI)*

Bila aplikasi memanggil API Java dari kode native, hook Java biasa akan melihat pemanggilannya tetapi backtrace-nya tidak informatif. `jnitrace` menampilkan seluruh interaksi JNI.

```bash
pip install jnitrace
jnitrace -m libnative.so com.example.target | tee jnitrace.log

# Saring pemanggilan yang relevan
grep -A5 -iE "getExternalFilesDir|FileOutputStream|MediaStore" jnitrace.log
```

#### Metode H — r2frida *(analisis native + hooking dalam satu sesi)*

```bash
r2 frida://usb//com.example.target

# Di dalam r2:
\i                                   # info proses
\il                                  # daftar modul yang dimuat
\iE libnative.so                     # export dari library native
\dt libc.so!openat                   # trace openat
\dtf libc.so!openat "^z i"           # trace dengan argumen (string, int)
\is~open                             # cari simbol yang mengandung "open"
```

Berguna ketika penulisan file berasal dari `.so` dan kamu perlu menganalisis fungsi native-nya sekaligus.

#### Metode I — fsmon / inotifywait *(monitoring tanpa instrumentasi aplikasi)*

Ini jalur yang **sepenuhnya menghindari anti-instrumentation** karena tidak menyentuh aplikasi sama sekali.

```bash
# fsmon (NowSecure) — memantau di level kernel
adb push fsmon-arm64 /data/local/tmp/fsmon && adb shell "chmod 755 /data/local/tmp/fsmon"
adb shell "su -c '/data/local/tmp/fsmon -P com.example.target /sdcard'" | tee fsmon.log

# inotifywait (bila tersedia di ROM/BusyBox)
adb shell "su -c 'inotifywait -m -r -e create,modify,delete,moved_to /sdcard'"
```

Keterbatasan: tidak memberi backtrace, sehingga tidak bisa mengatribusikan penulisan ke baris kode. Pakai sebagai **konfirmasi independen** bahwa penulisan memang terjadi.

#### Metode J — MobSF Dynamic Analyzer *(otomatis, laporan siap kutip)*

```bash
docker run -it --rm -p 8000:8000 -p 1337:1337 \
  opensecurity/mobile-security-framework-mobsf:latest
```

MobSF menjalankan Frida di belakang layar dan menyediakan bagian **Runtime Dependency Check** serta **API Monitor** yang mencatat pemanggilan API sensitif — termasuk file I/O. Keunggulan: tidak perlu menulis script, dan hasilnya langsung dalam format laporan. Keterbatasan: exercise otomatisnya dangkal dan hook-nya generik, jadi ini pass awal — bukan pengganti script kustom.

#### Metode K — Korelasi dengan analisis statis *(menentukan cakupan pengujian)*

Ini bukan tool baru, tetapi langkah metodologis yang sering dilewatkan dan menentukan validitas kesimpulan PASS.

```bash
# 1. Dapatkan daftar LENGKAP referensi API dari analisis statis (MASTG-TEST-0202)
jadx -d ./decompiled ./target-app.apk
rg -n --no-heading "getExternalFilesDir|getExternalStorageDirectory|getExternalCacheDir|MediaStore" \
  ./decompiled/sources/ | awk -F: '{print $1}' | sort -u > static_refs.txt

# 2. Dapatkan daftar API yang BENAR-BENAR terpanggil dari trace runtime
grep -oE "org\.owasp\.[A-Za-z0-9.$]+" output.txt | sort -u > runtime_hits.txt

# 3. Selisihnya = jalur kode yang BELUM di-exercise
#    -> status INKONKLUSIF untuk jalur ini, bukan PASS
comm -23 static_refs.txt runtime_hits.txt
```

Bila selisihnya tidak kosong, kamu belum meng-exercise seluruh permukaan — dan tidak boleh menyimpulkan PASS. Ini cara konkret menjalankan catatan penilaian nomor 1 di §3.8.

---

### 3.7 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Butuh root? | Memberi backtrace? | Menangkap kode native? | Tahan anti-Frida? | Kapan dipakai |
|---|---|---|---|---|---|---|
| **A** | Frida script kustom (§3.2/§3.3) | Ya/gadget | ✅ | ✅ (hook libc) | ❌ | **Baseline resmi** — kendali penuh |
| **B** | frida-trace (§3.4) | Ya/gadget | Sebagian | ✅ | ❌ | Cepat, tanpa menulis script |
| **C** | Objection (§3.4) | Tidak¹ | ✅ | ❌ | ❌ | Eksploratif cepat; `filesystem download` |
| **D** | strace (§3.4) | Ya | ❌ | ✅ | ✅ | Pembanding independen bila ada anti-Frida |
| **E** | frida-gadget | **Tidak** | ✅ | ✅ | ❌ | **Device non-root**; repackaging berhasil = temuan MASVS-RESILIENCE |
| **F** | Xposed / LSPosed | Ya | ✅ | ❌ | ✅ (lebih sulit dideteksi) | Anti-Frida aktif; butuh persistensi |
| **G** | jnitrace | Ya | ✅ (JNI) | ✅ **(khusus)** | ❌ | Penulisan file dari `.so` via JNI |
| **H** | r2frida | Ya | Sebagian | ✅ **(khusus)** | ❌ | Analisis native + hooking sekaligus |
| **I** | fsmon / inotifywait | Ya | ❌ | ✅ | ✅ **(tidak menyentuh app)** | Konfirmasi independen; anti-instrumentation kuat |
| **J** | MobSF Dynamic | Tidak | Sebagian | ❌ | ❌ | Pass awal + laporan siap kutip |
| **K** | Korelasi statis–dinamis | Tidak | — | — | — | **Menentukan apakah PASS valid** — wajib dilakukan |

¹ Objection memakai Frida; tanpa root ia butuh frida-gadget (Metode E) atau device dengan frida-server.

**Kombinasi minimum yang aku rekomendasikan:** **A (Frida kustom) → K (korelasi statis-dinamis)**.
A memberi backtrace dan nilai runtime yang menjadi inti test ini; K memastikan kesimpulanmu valid dengan membuktikan seluruh permukaan sudah di-exercise. Tambahkan **E (frida-gadget)** bila tidak ada root, **D atau I** bila aplikasi punya anti-instrumentation, dan **G/H** bila APK memuat `.so` yang menulis file.

> **Bila semua jalur instrumentasi terhalang:** jangan laporkan PASS. Statusnya **Inconclusive**, dan selesaikan penilaian lewat **MASTG-TEST-0200** (diffing filesystem, tidak butuh instrumentasi) dan **MASTG-TEST-0202** (statis).

---

### 3.8 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Observation:** *"The output should contain a list of files that the app wrote to the external storage during execution and the APIs used to write them including function names and backtraces."*
>
> **Evaluation:** *"The test case **fails** if the files found above are not encrypted and leak sensitive data."*
>
> **Further Validation Required** — inspeksi isi setiap file yang dilaporkan:
> - Tentukan apakah file mengandung informasi sensitif (mis. data pribadi, kredensial, atau token).
> - Tentukan apakah data disimpan tanpa enkripsi.
>
> Gunakan MASTG-TECH-0023 untuk menginspeksi lokasi kode dari backtrace bila ingin menentukan code path persis yang menghasilkan file dan apakah code path tersebut security-relevant.

Kedua kondisi bersifat **AND**: file sensitif **DAN** tidak ter-enkripsi → FAIL.

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi | Contoh bukti dari output trace |
|---|---|---|
| F1 | Trace menunjukkan penulisan ke external storage, dan file hasilnya berisi **data sensitif plaintext** | `[*] open called ... /storage/emulated/0/Android/data/<pkg>/files/secret.txt` + backtrace `FileOutputStream.<init>` → isi file = `secr3tPa$$W0rd` |
| F2 | Trace `ContentResolver.insert` menunjukkan penulisan file sensitif ke **shared storage** | `_display_name: secretFile55.txt`, `relative_path: Download` → `/storage/emulated/0/Download/secretFile55.txt` berisi `MAS_API_KEY=8767086b9f6f976g-a8df76` |
| F3 | Hook `FileOutputStream.write()` memperlihatkan **canary value / kredensial** langsung di buffer yang ditulis | `preview: {"user":"tester","password":"MASTG_Pa55w0rd_UNIQ"}` |
| F4 | Backtrace menunjuk ke **kode aplikasi sendiri** yang menulis data sensitif tanpa enkripsi | `org.owasp.mastestapp.MastgTest.mastgTestApi(MastgTest.kt:26)` |
| F5 | Backtrace menunjuk ke **SDK pihak ketiga** yang menulis data sensitif/PII ke external storage | Backtrace berisi `com.<vendor>.crashlytics.*` / `com.<vendor>.analytics.*` menulis `/sdcard/.../crash_<ts>.log` berisi token |
| F6 | Terdeteksi pemanggilan API **deprecated & berisiko tinggi** yang diikuti penulisan data sensitif | `[!] DEPRECATED getExternalStoragePublicDirectory("Documents")` + backtrace + file plaintext |
| F7 | "Enkripsi" yang terlihat hanyalah **encoding/obfuscation** (Base64, hex, XOR key hardcoded) | `base64 -d` langsung menghasilkan plaintext; `ent` → entropi < 6.0 bit/byte |
| F8 | File ter-enkripsi tetapi **kunci ikut ditulis** ke external storage, atau hardcoded (terlihat dari trace/decompile) | Trace menunjukkan penulisan `key.bin` di direktori yang sama; atau jadx menampilkan `SecretKeySpec("hardcodedkey".getBytes(), "AES")` |
| F9 | Trace menunjukkan aplikasi **membaca** file dari external storage lalu memuatnya sebagai kode/konfigurasi eksekutabel tanpa integrity check | `openat() ... /sdcard/MyApp/plugin.dex [O_RDONLY]` + backtrace `DexClassLoader.<init>` → **Man-in-the-Disk / code injection** |
| F10 | Trace menunjukkan penulisan **file sementara** berisi data sensitif ke external storage (meski lalu dihapus) | `open() ... /sdcard/tmp_upload_ktp.jpg [O_WRONLY\|O_CREAT]` — lolos dari TEST-0200 tapi tetap FAIL |
| F11 | Penulisan data sensitif terjadi pada aplikasi yang **opt-out scoped storage** (`requestLegacyExternalStorage="true"` dengan target ≤ API 29) | Manifest + temuan F1/F2 → severity dinaikkan |

**Contoh output yang menandakan FAIL** (hasil resmi MASTG-DEMO-0002, `output.txt`):

```
[*] open called to open a file from external storage at: /storage/emulated/0/Android/data/org.owasp.mastestapp/files/secret.txt

Backtrace:
libcore.io.Linux.open(Native Method)
libcore.io.ForwardingOs.open(ForwardingOs.java:563)
libcore.io.BlockGuardOs.open(BlockGuardOs.java:274)
libcore.io.ForwardingOs.open(ForwardingOs.java:563)
android.app.ActivityThread$AndroidOs.open(ActivityThread.java:8063)
libcore.io.IoBridge.open(IoBridge.java:560)
java.io.FileOutputStream.<init>(FileOutputStream.java:236)
java.io.FileOutputStream.<init>(FileOutputStream.java:186)
org.owasp.mastestapp.MastgTest.mastgTestApi(MastgTest.kt:26)
org.owasp.mastestapp.MastgTest.mastgTest(MastgTest.kt:16)
org.owasp.mastestapp.MainActivityKt.MainScreen$lambda$9$lambda$8(MainActivity.kt:53)
...
java.lang.Thread.run(Thread.java:1012)

[*] ContentResolver.insert called with ContentValues:
        _display_name: secretFile59.txt
        mime_type: text/plain
        relative_path: Download

[*] ContentResolver.insert returned URI: content://media/external/downloads/1000000143

Backtrace:
android.content.ContentResolver.insert(Native Method)
org.owasp.mastestapp.MastgTest.mastgTestMediaStore(MastgTest.kt:44)
org.owasp.mastestapp.MastgTest.mastgTest(MastgTest.kt:17)
org.owasp.mastestapp.MainActivityKt.MainScreen$lambda$9$lambda$8(MainActivity.kt:53)
...
java.lang.Thread.run(Thread.java:1012)
```

**Cara membaca output di atas** — inilah inti nilai test ini:

| Temuan | Path | API yang dipakai | Lokasi kode (dari backtrace) |
|---|---|---|---|
| 1 | `/storage/emulated/0/Android/data/org.owasp.mastestapp/files/secret.txt` | `java.io.FileOutputStream` | `MastgTest.mastgTestApi(MastgTest.kt:26)` |
| 2 | `secretFile59.txt` → URI `content://media/external/downloads/1000000143`, **path diperkirakan** `/storage/emulated/0/Download/secretFile59.txt` | `android.content.ContentResolver.insert` | `MastgTest.mastgTestMediaStore(MastgTest.kt:44)` |

Perhatikan pola diagnostik pada backtrace pertama: rantai `Linux.open → BlockGuardOs.open → IoBridge.open → FileOutputStream.<init>` adalah **sidik jari khas** penulisan file via Java I/O. Frame terakhir sebelum masuk ke framework (`MastgTest.kt:26`) adalah **lokasi kode yang harus diperbaiki**.

Perhatikan juga bahwa temuan kedua **tidak muncul di hook `open()`** — hanya tertangkap oleh hook `ContentResolver.insert`. Ini bukti konkret dari blind spot MediaStore yang disebut MASTG.

Kode yang bertanggung jawab (sampel demo, sama dengan MASTG-DEMO-0001):

```kotlin
fun mastgTestApi() {
    val externalStorageDir = context.getExternalFilesDir(null)
    val fileName = File(externalStorageDir, "secret.txt")
    val fileContent = "secr3tPa\$\$W0rd\n"
    FileOutputStream(fileName).use { output ->          // <-- MastgTest.kt:26
        output.write(fileContent.toByteArray())
    }
}

fun mastgTestMediaStore() {
    val resolver = context.contentResolver
    val contentValues = ContentValues().apply {
        put(MediaStore.MediaColumns.DISPLAY_NAME, "secretFile59.txt")
        put(MediaStore.MediaColumns.MIME_TYPE, "text/plain")
        put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
    }
    val textUri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, contentValues)  // <-- :44
    textUri?.let {
        resolver.openOutputStream(it)?.use { os ->
            os.write("MAS_API_KEY=8767086b9f6f976g-a8df76\n".toByteArray())
        }
    }
}
```

Evaluasi MASTG untuk demo ini: *"This test **fails** because the files are not encrypted and contain sensitive data (such as a password and an API key). This can be further confirmed by reverse-engineering the app to inspect its code and retrieving the files from the device."*

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi | Contoh bukti |
|---|---|---|
| P1 | **Output trace kosong** setelah aplikasi di-exercise secara ekstensif — tidak ada API external storage yang terpanggil sama sekali | `wc -c output.txt` → `0`. Sesuai catatan resmi `run.sh`: *"If the output is empty, it indicates that no external storage is used."* |
| P2 | Ada pemanggilan API external storage, tetapi **hanya untuk data non-sensitif** | `open() ... /sdcard/Android/data/<pkg>/cache/map_tile_1842.png [O_WRONLY\|O_CREAT]` — tile peta publik, tidak ada PII |
| P3 | Ada penulisan data sensitif, tetapi trace + decompile membuktikan data **ter-enkripsi dengan benar** (AES-256-GCM) dan **kunci berada di Android KeyStore** | Backtrace memperlihatkan frame `androidx.security.crypto.EncryptedFile` / `javax.crypto.CipherOutputStream`; file hasil → `file` = `data`, `ent` ≈ 7.99 bit/byte, `strings` bersih dari canary |
| P4 | Hook `FileOutputStream.write()` hanya menunjukkan **ciphertext**, tidak ada canary value | `preview:` menampilkan byte acak/tak terbaca, bukan plaintext |
| P5 | Penulisan hanya terjadi sebagai hasil **aksi eksplisit user** atas data yang memang ditujukan untuk dibagikan, tanpa kredensial/token | Backtrace dipicu dari handler tombol "Export PDF"; isi PDF = invoice tanpa token. *(Tetap catat sebagai informational.)* |
| P6 | Semua trace penulisan data sensitif menunjuk ke **internal storage**, bukan external | Path pada trace seluruhnya `/data/user/0/<pkg>/...`, sehingga terfilter keluar oleh `isExternal()` |
| P7 | Trace membuktikan setiap **baca** dari external storage melewati **verifikasi integritas** sebelum data dipakai | Backtrace menunjukkan frame `Mac.doFinal` / `MessageDigest.digest` tepat setelah pembacaan file, dan `DexClassLoader` tidak pernah muncul |

**Contoh output yang menandakan PASS:**

```bash
$ frida -U -f com.example.secureapp -l script.js -o output.txt
# ... exercise aplikasi secara ekstensif ...
$ wc -c output.txt
0 output.txt
# => Tidak ada API external storage yang dipanggil
```

atau — ada penulisan, tetapi terbukti ter-enkripsi dengan benar:

```
[*] getExternalFilesDir("null") -> /storage/emulated/0/Android/data/com.example.secureapp/files

Backtrace:
  com.example.secureapp.storage.SecureVault.write(SecureVault.kt:41)
  ...

[*] open() on external storage: /storage/emulated/0/Android/data/com.example.secureapp/files/vault.bin  [O_WRONLY|O_CREAT|O_TRUNC]

Backtrace:
  libcore.io.Linux.open(Native Method)
  ...
  java.io.FileOutputStream.<init>(FileOutputStream.java:236)
  com.google.crypto.tink.subtle.StreamingAeadEncryptingStream.<init>(...)
  androidx.security.crypto.EncryptedFile.openFileOutput(EncryptedFile.java:212)
  com.example.secureapp.storage.SecureVault.write(SecureVault.kt:43)
  ...
```

```bash
$ adb pull /sdcard/Android/data/com.example.secureapp/files/vault.bin
$ file vault.bin
vault.bin: data
$ grep -aiE "MASTG_Pa55w0rd_UNIQ|password|token|api_key" vault.bin
# (tidak ada hasil)
$ ent vault.bin
Entropy = 7.998211 bits per byte.
```

Dikonfirmasi via jadx (MASTG-TECH-0023) bahwa kunci berasal dari Android KeyStore:

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

encryptedFile.openFileOutput().use { it.write(sensitiveBytes) }
```

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Output trace kosong ≠ otomatis PASS.** Ini jebakan terbesar test ini. Trace hanya merekam alur yang benar-benar kamu jalankan. Penyebab false pass:
   - Alur pemicu belum di-*exercise* (mis. fitur export hanya aktif untuk akun premium).
   - Aplikasi mendeteksi Frida dan **diam-diam menonaktifkan** fitur tersebut.
   - Hook gagal terpasang (versi frida mismatch, nama export berbeda, aplikasi memakai `openat` bukan `open`).
   - Penulisan terjadi di **proses terpisah** (`:remote` service) yang tidak di-attach.
   
   **Mitigasi:** validasi dulu script-mu pada aplikasi yang sudah diketahui gagal (MASTestApp) untuk membuktikan hook berfungsi, lalu korelasikan hasilnya dengan **MASTG-TEST-0200** (diff filesystem) dan **MASTG-TEST-0202** (analisis statis). Jika TEST-0202 menemukan referensi ke `getExternalFilesDir` tetapi trace kosong, itu **inkonklusif — bukan PASS**; berarti alur pemicunya belum tersentuh.

2. **Hook `open()` saja tidak cukup — MediaStore invisible.** Ini ditegaskan eksplisit oleh MASTG. Tanpa hook `ContentResolver.insert`, kamu akan melewatkan seluruh kategori penulisan ke shared storage yang justru paling berisiko (bertahan pasca-uninstall).

3. **Path MediaStore bersifat *inferred*, bukan hasil observasi langsung.** Rekonstruksi `relative_path` + `_display_name` adalah perkiraan. Selalu verifikasi dengan `adb shell content query --uri content://media/external/downloads` atau `adb shell ls`, karena Android dapat menambahkan suffix bila nama file bentrok (`secretFile55(1).txt`).

4. **Pemanggilan API resolusi path ≠ bukti penulisan.** `getExternalFilesDir()` terpanggil tidak berarti ada file sensitif ditulis — bisa jadi hanya pengecekan ketersediaan storage. Wajib dikorelasikan dengan `open(..., O_WRONLY|O_CREAT)` atau `FileOutputStream`. Melaporkan ini sebagai FAIL tanpa korelasi adalah false positive.

5. **Waspadai enkripsi palsu.** Selalu uji dengan `strings`, `base64 -d`, dan analisis entropi. Backtrace yang memperlihatkan frame `javax.crypto.*` juga belum menjamin — periksa mode cipher (tolak ECB) dan **asal kunci** via jadx.

6. **Perhatikan asal-usul pemanggil.** Bedakan dengan jelas antara:
   - Kode aplikasi sendiri → developer dapat memperbaiki langsung.
   - SDK pihak ketiga → perlu update SDK, konfigurasi ulang, atau penggantian vendor. **Tetap tanggung jawab developer aplikasi** dan tetap dilaporkan sebagai temuan.
   - Framework Android itu sendiri (mis. WebView cache) → evaluasi apakah memang dikonfigurasi ke external storage oleh aplikasi.

7. **Severity dimodulasi oleh lokasi & API level, tetapi tidak menghilangkan temuan:**
   - Data sensitif plaintext di **shared storage** (Download/Documents/DCIM/MediaStore) → severity tertinggi: terbaca app lain **dan** bertahan setelah uninstall.
   - Data sensitif plaintext di **app-specific external dir** dengan target API ≥ 30 → severity lebih rendah (terlindungi scoped storage dari app lain), namun **tetap FAIL** karena masih terbaca via MTP/USB oleh user, pada device rooted, oleh backup pihak ketiga, dan oleh app dengan `MANAGE_EXTERNAL_STORAGE`.
   - Adanya `requestLegacyExternalStorage="true"` atau `MANAGE_EXTERNAL_STORAGE` → naikkan severity.
   - Pemuatan kode dari external storage (F9) → severity kritis, terlepas dari sensitivitas data.

8. **Anti-instrumentation adalah temuan terpisah, bukan alasan skip.** Jika aplikasi menolak berjalan di bawah Frida, catat sebagai kontrol MASVS-RESILIENCE yang berfungsi, lalu **tetap selesaikan penilaian storage** lewat MASTG-TEST-0200 (tidak butuh instrumentasi) dan MASTG-TEST-0202 (statis). Jangan laporkan test ini sebagai PASS hanya karena tidak bisa dijalankan — statusnya **Inconclusive / Not Applicable**, disertai alasan.

9. **Dokumentasikan bukti lengkap per temuan:** path file (dan URI untuk MediaStore), API yang dipakai, **backtrace lengkap**, lokasi kode hasil MASTG-TECH-0023 (`File.kt:baris`), isi file (redacted bila perlu), API level device, `targetSdkVersion`, permission ter-grant, langkah reproduksi, dan hasil uji cross-app read.

---

## 4. Rekomendasi Perbaikan

Akar masalah test ini identik dengan MASTG-TEST-0200 (MASWE-0002), sehingga remediasinya sama. Yang membedakan: temuan test ini datang **dengan lokasi kode persisnya**, jadi perbaikan bisa langsung ditargetkan.

### 4.1 Prinsip Utama (urutan prioritas)

**Prioritas 1 — Hilangkan pemanggilan API external storage untuk data sensitif.** Gunakan backtrace dari trace sebagai daftar kerja (worklist) yang konkret: setiap frame `<Class>.<method>(File.kt:N)` adalah satu titik yang harus diperbaiki.

```kotlin
// ❌ SALAH — terdeteksi sebagai FileOutputStream.<init> + path /sdcard di trace
val file = File(context.getExternalFilesDir(null), "secret.txt")
FileOutputStream(file).use { it.write(password.toByteArray()) }

// ❌ SALAH — terdeteksi sebagai ContentResolver.insert ke relative_path: Download
val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, contentValues)
resolver.openOutputStream(uri!!)?.use { it.write(apiKey.toByteArray()) }

// ✅ BENAR — internal storage, tidak akan muncul dalam trace external storage
context.openFileOutput("secret.txt", Context.MODE_PRIVATE).use { it.write(data) }
// atau
File(context.filesDir, "secret.txt").writeBytes(data)
```

Jangan pernah gunakan `MODE_WORLD_READABLE` / `MODE_WORLD_WRITEABLE` (deprecated sejak API 17, melempar `SecurityException` sejak API 24).

**Prioritas 2 — Ganti API deprecated yang terdeteksi di trace.**

| API terdeteksi di trace | Pengganti yang benar |
|---|---|
| `Environment.getExternalStorageDirectory()` | `context.filesDir` (sensitif) atau `context.getExternalFilesDir()` (non-sensitif besar) |
| `Environment.getExternalStoragePublicDirectory()` | MediaStore API / Storage Access Framework, **hanya untuk data non-sensitif** |
| `WRITE_EXTERNAL_STORAGE` + `File` API langsung | MediaStore (media) / SAF (dokumen) / internal storage (sensitif) |
| Menaruh file di `/sdcard` untuk dibagikan ke app lain | **FileProvider** + `content://` URI dengan grant permission temporer |
| Meminta `READ_EXTERNAL_STORAGE` untuk memilih foto | **Photo Picker** (tanpa permission sama sekali) |

**Prioritas 3 — Gunakan mekanisme penyimpanan yang tepat sesuai jenis data.**

| Jenis data | Mekanisme yang benar |
|---|---|
| Kunci kriptografi | **Android KeyStore** (dengan `setUserAuthenticationRequired`, StrongBox bila tersedia) — kunci tidak pernah keluar dari secure hardware |
| Password, token, API key | Hindari penyimpanan bila mungkin (token sesi cukup di memori). Bila perlu: enkripsi dengan kunci KeyStore, simpan di internal storage |
| Key-value preferences sensitif | Internal storage + enkripsi. Catat bahwa Jetpack Security `androidx.security:security-crypto` kini **deprecated** — pertimbangkan AES-GCM sendiri dengan kunci KeyStore, atau **Google Tink** |
| Data terstruktur | Room + **SQLCipher**, di internal storage |
| File besar milik aplikasi | Internal storage; bila ukuran memaksa external, wajib enkripsi (Prioritas 4) |
| File yang memang untuk dibagikan | MediaStore / SAF — **hanya data non-sensitif**, idealnya atas aksi eksplisit user |

**Prioritas 4 — Jika external storage tak terhindarkan: enkripsi dengan kunci dari KeyStore.**

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
- **AES-256-GCM** atau ChaCha20-Poly1305 (authenticated encryption). Tolak ECB, DES/3DES/RC4, dan CBC tanpa MAC.
- IV/nonce acak per operasi, tidak pernah diulang.
- Kunci **dihasilkan & disimpan di Android KeyStore** — bukan hardcoded, bukan diturunkan dari nilai statis (IMEI, package name, konstanta), bukan ditulis ke external storage.
- Bila kunci diturunkan dari password user: KDF kuat (PBKDF2 iterasi tinggi / **Argon2id** / scrypt) dengan salt acak.

> **Verifikasi remediasi lewat test ini sendiri:** setelah perbaikan, jalankan ulang MASTG-TEST-0201. Backtrace yang benar akan memperlihatkan frame `EncryptedFile.openFileOutput` / `CipherOutputStream` di antara kode aplikasi dan `FileOutputStream.<init>`. Ketiadaan frame kripto pada jalur penulisan adalah indikator kuat bahwa data masih plaintext.

**Prioritas 5 — Aktifkan dan pertahankan scoped storage.**

```xml
<application
    android:requestLegacyExternalStorage="false"
    ... >
```

- Target **Android 11 (API 30) ke atas** — scoped storage dipaksa aktif oleh OS.
- **Hapus** `requestLegacyExternalStorage="true"` dan `preserveLegacyExternalStorage`.
- Hindari `MANAGE_EXTERNAL_STORAGE` kecuali benar-benar wajib (file manager, antivirus, backup app) — dibatasi kebijakan Google Play.
- Deklarasikan permission storage seminimal mungkin; gunakan `READ_MEDIA_IMAGES`/`VIDEO`/`AUDIO` granular (API 33+), atau Photo Picker yang tak butuh permission.

**Prioritas 6 — Validasi input & integritas untuk semua data yang DIBACA dari external storage** (mitigasi Man-in-the-Disk; relevan untuk temuan F9). Perlakukan setiap file dari external storage sebagai **untrusted input**.

- **Jangan pernah** memuat kode eksekutabel (DEX, SO, APK, JS bundle, script) dari external storage. Jika trace menunjukkan `DexClassLoader` / `System.load()` pada path `/sdcard`, ini harus dihapus total.
- Validasi ketat: ukuran, tipe MIME, magic bytes, struktur skema, batas nilai. Jangan deserialisasi objek Java/Kotlin dari file external storage.
- Cegah path traversal & symlink attack: kanonikalisasi path (`File.canonicalPath`) dan pastikan tetap di dalam direktori yang diizinkan.
- Verifikasi integritas dengan **HMAC-SHA256** berkunci KeyStore atau AEAD (AES-GCM), bukan hash telanjang:

```kotlin
// Verifikasi integritas berkunci — tahan terhadap penyerang aktif
fun verify(file: File, expectedTag: ByteArray, keyAlias: String): Boolean {
    val key = (KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        .getEntry(keyAlias, null) as KeyStore.SecretKeyEntry).secretKey
    val mac = Mac.getInstance("HmacSHA256").apply { init(key) }
    file.inputStream().buffered().use { input ->
        val buf = ByteArray(8192)
        var n: Int
        while (input.read(buf).also { n = it } != -1) mac.update(buf, 0, n)
    }
    return MessageDigest.isEqual(mac.doFinal(), expectedTag)   // constant-time
}
```

> Hash SHA-256 telanjang **tidak memadai** bila hash-nya disimpan di sebelah file — penyerang cukup menimpa keduanya. Simpan tag di internal storage, dan lebih baik gunakan HMAC berkunci seperti di atas.

### 4.2 Perbaikan Praktik Tambahan

- **Audit SDK pihak ketiga secara khusus.** Ini nilai unik test ini: backtrace menunjuk vendor penyebab. Untuk setiap SDK yang terdeteksi menulis ke external storage — matikan fiturnya, konfigurasikan ulang ke internal storage bila didukung, update ke versi terbaru, atau ganti vendor.
- **Data minimization.** Jangan simpan apa yang tidak perlu. Token sesi sebaiknya hanya di memori; gunakan refresh token berumur pendek.
- **Hapus file temporer segera** setelah dipakai, dan jangan letakkan temp file di `/sdcard` sejak awal (gunakan `context.cacheDir`). Ini menutup temuan F10.
- **Matikan logging verbose di build release** (`BuildConfig.DEBUG`); pastikan crash handler tidak menulis dump berisi PII/kredensial ke external storage.
- **Exclude file sensitif dari backup** (`android:allowBackup="false"` atau `dataExtractionRules`/`fullBackupContent`) — lihat MASWE-0006.
- **Integrasikan ke CI/CD.** Script Frida ini dapat dijalankan di emulator pada pipeline bersama UI test (Espresso/Appium) sebagai regression test: gagalkan build bila muncul panggilan API external storage yang tak terdaftar di allowlist. Ini mencegah regresi saat SDK di-update.
- **Threat model eksplisit.** Dokumentasikan setiap penulisan ke external storage yang memang disengaja beserta justifikasinya, agar reviewer bisa membedakan keputusan desain dari kebocoran tak sengaja.

### 4.3 Checklist Remediasi

- [ ] Setiap lokasi kode dari backtrace temuan sudah ditinjau dan diperbaiki
- [ ] Tidak ada data sensitif (kredensial, token, PII, data finansial) yang ditulis ke external storage
- [ ] `Environment.getExternalStorageDirectory()` dan `getExternalStoragePublicDirectory()` (deprecated) sudah dihapus dari kode
- [ ] Data sensitif disimpan di internal storage (`context.filesDir`, `openFileOutput(..., MODE_PRIVATE)`)
- [ ] Tidak ada penggunaan `MODE_WORLD_READABLE` / `MODE_WORLD_WRITEABLE`
- [ ] Bila external storage tetap dipakai: data ter-enkripsi AES-256-GCM dengan kunci di Android KeyStore
- [ ] Tidak ada kunci/secret hardcoded atau ikut disimpan di external storage
- [ ] Penulisan via `ContentResolver.insert` / MediaStore hanya untuk data non-sensitif
- [ ] `targetSdkVersion` ≥ 30 dan `requestLegacyExternalStorage` tidak di-set `true`
- [ ] `MANAGE_EXTERNAL_STORAGE` tidak dideklarasikan (kecuali dengan justifikasi kuat dan approval Play)
- [ ] Permission storage minimal; gunakan Photo Picker / SAF / `READ_MEDIA_*` granular
- [ ] Tidak ada kode eksekutabel (DEX/SO/APK/JS) yang dimuat dari external storage
- [ ] Semua data yang dibaca dari external storage divalidasi dan diverifikasi integritasnya (HMAC/AEAD berkunci KeyStore)
- [ ] File temporer tidak lagi ditulis ke external storage; cache diarahkan ke `context.cacheDir`
- [ ] Logging verbose & crash dump ke external storage dimatikan pada build release
- [ ] SDK pihak ketiga yang terdeteksi menulis ke external storage sudah diaudit dan ditangani
- [ ] File sensitif dikecualikan dari backup
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0201 → output trace bersih, atau backtrace memperlihatkan frame enkripsi pada setiap jalur penulisan
- [ ] **Verifikasi silang:** jalankan MASTG-TEST-0200 (diff filesystem) dan MASTG-TEST-0202 (statis) untuk memastikan tidak ada jalur yang terlewat

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0201: Runtime Use of APIs to Access External Storage](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0201/)
- [MASTG-TEST-0200: Files Written to External Storage](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0200/)
- [MASTG-TEST-0202: References to APIs and Permissions for Accessing External Storage](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0202/)
- [MASTG-TEST-0001: Testing Local Storage for Sensitive Data](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0001/)
- [MASWE-0002: Sensitive Data Stored Unencrypted Outside of Private Storage](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0002/)
- [MASTG-DEMO-0002: External Storage APIs Tracing with Frida](https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0002/MASTG-DEMO-0002/)
- [MASTG-DEMO-0001: File System Snapshots from External Storage](https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0001/MASTG-DEMO-0001/)
- [MASTG-DEMO-0003: App Writing to External Storage without Scoped Storage Restrictions](https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0003/MASTG-DEMO-0003/)
- [MASTG-DEMO-0004: App Writing to External Storage with Scoped Storage Restrictions](https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0004/MASTG-DEMO-0004/)
- [MASTG-DEMO-0005: App Writing to External Storage via the MediaStore API](https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0005/MASTG-DEMO-0005/)
- [MASTG-KNOW-0042: External Storage](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0042/)
- [MASTG-TECH-0043: Method Hooking](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/)
- [MASTG-TECH-0023: Reviewing Decompiled Java Code](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/)
- [MASTG-TECH-0005: Installing Apps](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0005/)
- [MASTG-TECH-0002: Host-Device Data Transfer](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0002/)
- [MASTG-TOOL-0001: Frida](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0001/)
- [MASTG-TOOL-0038: Objection](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0038/)
- [MASTG-TOOL-0018: jadx](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0018/)
- [MASVS-STORAGE: Storage](https://mas.owasp.org/MASVS/05-MASVS-STORAGE/)
- [OWASP MASTG Repository (GitHub)](https://github.com/OWASP/mastg)
- [OWASP Mobile Top 10 2024 — M9: Insecure Data Storage](https://owasp.org/www-project-mobile-top-10/2023-risks/m9-insecure-data-storage)

### 5.2 Dokumentasi Frida & Tooling Instrumentasi

- [Frida — Documentation Home](https://frida.re/docs/home/)
- [Frida — `frida-trace` CLI reference](https://frida.re/docs/frida-trace/)
- [Frida — JavaScript API: `Interceptor`](https://frida.re/docs/javascript-api/#interceptor)
- [Frida — JavaScript API: `Java` (Android runtime)](https://frida.re/docs/javascript-api/#java)
- [Frida — Android instrumentation guide](https://frida.re/docs/android/)
- [Frida — `frida-gadget` (instrumentasi tanpa root)](https://frida.re/docs/gadget/)
- [Frida Handbook — Hooks and the Interceptor API](https://learnfrida.info/basic_usage/)
- [Frida CodeShare — kumpulan script komunitas](https://codeshare.frida.re/)
- [SensePost — Using & improving frida-trace (2025)](https://sensepost.com/blog/2025/using-improving-frida-trace/)
- [iddoeldor/frida-snippets — hand-crafted Frida examples](https://github.com/iddoeldor/frida-snippets)
- [FrenchYeti/frida-trick — koleksi script & trik Frida](https://github.com/FrenchYeti/frida-trick)
- [jnitrace — tracing JNI API usage in Android apps](https://github.com/chame1eon/jnitrace)
- [Objection — runtime mobile exploration](https://github.com/sensepost/objection)
- [Frida cheat sheet (awakened1712)](https://awakened1712.github.io/hacking/hacking-frida/)
- [awesome-frida — kurasi resource Frida](https://github.com/DevenLu/awesome-frida)
- [rovo89/XposedTools — membangun & memasang modul Xposed](https://github.com/rovo89/XposedTools)
- [LSPosed — implementasi Xposed modern (Zygisk/Riru)](https://github.com/LSPosed/LSPosed)

### 5.3 Dokumentasi Resmi Android / Google

- [Sensitive Data Stored in External Storage — Android Security Risks](https://developer.android.com/privacy-and-security/risks/sensitive-data-external-storage)
- [Data and file storage overview](https://developer.android.com/training/data-storage)
- [Access app-specific files](https://developer.android.com/training/data-storage/app-specific)
- [Scoped storage](https://developer.android.com/training/data-storage#scoped-storage)
- [Storage use cases and best practices](https://developer.android.com/training/data-storage/use-cases)
- [Access media files from shared storage (MediaStore)](https://developer.android.com/training/data-storage/shared/media)
- [Access documents and other files (Storage Access Framework)](https://developer.android.com/training/data-storage/shared/documents-files)
- [Manage all files on a storage device (`MANAGE_EXTERNAL_STORAGE`)](https://developer.android.com/training/data-storage/manage-all-files)
- [`ContentResolver` — API reference](https://developer.android.com/reference/android/content/ContentResolver)
- [`Environment` — API reference](https://developer.android.com/reference/android/os/Environment)
- [`MediaStore.MediaColumns` — API reference](https://developer.android.com/reference/android/provider/MediaStore.MediaColumns)
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
- [SEI CERT Android — DRD00: Do not store sensitive information on external storage (SD card) unless encrypted first](https://wiki.sei.cmu.edu/confluence/display/android/DRD00.+Do+not+store+sensitive+information+on+external+storage+%28SD+card%29+unless+encrypted+first)
- [NIST SP 800-163 Rev.1 — Vetting the Security of Mobile Applications](https://csrc.nist.gov/publications/detail/sp/800-163/rev-1/final)
- [NIST SP 800-124 Rev.2 — Guidelines for Managing the Security of Mobile Devices](https://csrc.nist.gov/publications/detail/sp/800-124/rev-2/final)
- [SonarQube Rule java:S5324 — Accessing Android external storage is security-sensitive](https://rules.sonarsource.com/java/RSPEC-5324/)
- [CodeQL — Cleartext storage of sensitive information in the Android filesystem](https://codeql.github.com/codeql-query-help/java/java-android-cleartext-storage-filesystem/)
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
- [Linux `open(2)` man page — flags O_WRONLY/O_CREAT/O_APPEND](https://man7.org/linux/man-pages/man2/open.2.html)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026), dokumentasi resmi Frida dan Android Developers, standar CWE/SEI CERT/NIST, serta riset keamanan pihak ketiga.*
