# MASTG-TEST-0203 Runtime Use of Logging APIs

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0203 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-STORAGE (MASVS-STORAGE-2: Aplikasi mencegah kebocoran data sensitif yang tidak diperlukan) |
| **Weakness** | MASWE-0005 — *Insertion of Sensitive Data into Logs* |
| **Tipe Pengujian** | Dynamic, **Hooks** |
| **Profile** | L1, L2, **P** (Privacy) |
| **Knowledge** | MASTG-KNOW-0049 (Logs) |
| **Best Practice** | MASTG-BEST-0002 (Remove Logging Code) |
| **APIs yang disorot** | `Log`, `Logger`, `System.out.print`, `System.err.print`, `java.lang.Throwable#printStackTrace` |
| **Teknik terkait** | MASTG-TECH-0005 (Installing Apps), MASTG-TECH-0043 (Method Hooking) |
| **Demo terkait** | MASTG-DEMO-0006 (Tracing Common Logging APIs Looking for Secrets) |
| **Test bersaudara** | MASTG-TEST-0231 (References to Logging APIs — pendekatan statis) |
| **Menggantikan** | MASTG-TEST-0003 (*Testing Logs for Sensitive Data* — status **deprecated**, digantikan oleh MASTG-TEST-0203 + MASTG-TEST-0231) |
| **CWE terkait** | CWE-532 (Insertion of Sensitive Information into Log File), CWE-200 (Exposure of Sensitive Information), CWE-312 (Cleartext Storage of Sensitive Information), CWE-359 (Exposure of Private Personal Information) |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Test ini bertujuan **mengidentifikasi pemanggilan API logging saat runtime dan memeriksa apakah data sensitif ikut tercatat ke dalam log**.

Kutipan langsung dari overview MASTG:

> *"On Android platforms, logging APIs like `Log`, `Logger`, `System.out.print`, `System.err.print`, and `java.lang.Throwable#printStackTrace` can inadvertently lead to the leakage of sensitive information. Log messages are recorded in logcat, a shared memory buffer, accessible since Android 4.1 (API level 16) only to privileged system applications that declare the `READ_LOGS` permission. Nonetheless, the vast ecosystem of Android devices includes pre-loaded apps with the `READ_LOGS` privilege, increasing the risk of sensitive data exposure. Therefore, direct logging to logcat is generally advised against due to its susceptibility to data leaks."*

Ada empat fakta teknis penting dalam paragraf itu:

1. **logcat adalah *shared memory buffer*** — bukan penyimpanan privat milik aplikasi. Semua aplikasi di device menulis ke buffer yang sama.
2. **Sejak Android 4.1 (API 16)**, akses baca logcat dibatasi hanya untuk aplikasi sistem *privileged* yang mendeklarasikan `READ_LOGS`. Sebelum API 16, **aplikasi biasa mana pun** dapat membaca seluruh log device hanya dengan meminta permission tersebut.
3. **Pembatasan itu tidak setuntas yang terlihat.** Ekosistem Android sangat beragam, dan banyak **aplikasi pre-installed** dari vendor/operator memiliki privilege `READ_LOGS` — yang di-grant otomatis tanpa persetujuan user. Jadi asumsi "logcat aman karena butuh permission sistem" tidak berlaku di dunia nyata.
4. Karena itu, **logging langsung ke logcat secara umum tidak disarankan**.

### 1.2 Mengapa Logging Berbahaya: Jalur Kebocoran yang Nyata

MASTG-KNOW-0049 mengakui bahwa ada banyak alasan sah untuk membuat log di perangkat mobile — melacak crash, error, dan statistik penggunaan. Log bisa disimpan lokal saat offline lalu dikirim ke endpoint saat online. **Namun**, mencatat data sensitif dapat mengekspos data itu ke penyerang atau aplikasi jahat, dan **berpotensi melanggar kerahasiaan user**.

Perlu dipahami bahwa `READ_LOGS` **bukan satu-satunya** jalur akses ke log. Inilah sebabnya temuan test ini tetap relevan meski aplikasi jahat biasa tidak bisa membaca logcat:

| Jalur akses | Kondisi | Catatan |
|---|---|---|
| **Aplikasi pre-installed dengan `READ_LOGS`** | Vendor/operator, tanpa persetujuan user | Jalur yang secara eksplisit disebut MASTG. Riset menemukan aplikasi pre-installed yang menulis log Android ke external storage saat dipicu lewat Intent — sehingga **aplikasi mana pun dengan `READ_EXTERNAL_STORAGE` dapat membacanya** |
| **`adb logcat` via USB debugging** | Developer options aktif | **Tidak butuh root.** Akses fisik singkat ke device yang unlocked sudah cukup untuk memanen log |
| **Device yang di-root / malware dengan privilege** | Root/exploit | Akses penuh ke buffer logcat |
| **Bug report / `adb bugreport`** | Dipicu user atau sistem | Berisi dump logcat lengkap; sering dikirimkan user ke support, di-upload ke tiket, atau dibagikan di forum publik |
| **Crash reporting SDK** | SDK pihak ketiga | Banyak SDK melampirkan potongan logcat ke laporan crash lalu **mengirimkannya ke server pihak ketiga** — data sensitif keluar dari device |
| **Aplikasi membaca log-nya sendiri** | Tanpa permission | Sebuah proses dapat membaca output log-nya sendiri; bila aplikasi lalu menuliskannya ke file di external storage, kebocoran meluas (bertaut dengan MASTG-TEST-0200) |
| **Log ditulis ke file lokal lalu dikirim** | Desain aplikasi | Riset menemukan aplikasi yang mem-*post* raw log ke internet |
| **Android < 4.1 (API 16)** | Device/target SDK lama | Aplikasi biasa mana pun dengan `READ_LOGS` dapat membaca semua log |

Kategori data yang terbukti bocor lewat log pada riset dan temuan nyata: nama akun, informasi password, data lokasi, serta data perangkat seperti MAC address dan IMEI. Contoh kasus tingkat OS: **CVE-2023-21387** pada komponen User Backup Manager Android, di mana token backup sensitif tertulis ke system log dalam bentuk plaintext sehingga memungkinkan kebocoran token autentikasi.

**Dimensi privasi.** Perhatikan bahwa test ini memiliki profile **P (Privacy)** — bukan hanya L1/L2. Artinya pencatatan PII ke log dinilai sebagai masalah privasi tersendiri, terlepas dari apakah ada penyerang yang mengeksploitasinya. Pencatatan email, nomor telepon, lokasi, atau ID perangkat ke log dapat melanggar kewajiban regulasi (GDPR, UU PDP) sekalipun tidak ada kebocoran yang terbukti.

### 1.3 Posisi Test Ini dalam Rangkaian Logging

Sama seperti rangkaian external storage (TEST-0200/0201/0202), pengujian logging juga terbagi menjadi pendekatan dinamis dan statis:

| Test | Pendekatan | Menjawab | Kekuatan | Kelemahan |
|---|---|---|---|---|
| **MASTG-TEST-0203** *(dokumen ini)* | **Dinamis** — method hooking | "API logging apa yang **benar-benar dipanggil**, dan **nilai apa** yang dicatat?" | **Melihat nilai runtime yang sebenarnya** — inilah keunggulan utamanya; menangkap data yang dibangun dinamis; menangkap log dari library | Hanya alur yang di-*exercise*; butuh Frida; bisa dihalangi anti-instrumentation |
| **MASTG-TEST-0231** | **Statis** — reverse engineering + pattern matching | "Di mana saja API logging **direferensikan** di kode?" | Cakupan menyeluruh atas seluruh kode, cepat, CI-friendly, tanpa device | Tidak tahu nilai runtime; banyak false positive; buta terhadap kode native/dinamis |
| **MASTG-TEST-0003** | — | *(deprecated)* | Digantikan oleh kedua test di atas | — |

> **Catatan versi:** MASTG-TEST-0003 (*Testing Logs for Sensitive Data*) kini berstatus **deprecated** dengan `covered_by: [MASTG-TEST-0203, MASTG-TEST-0231]`. Jika kamu merujuk dokumentasi atau laporan lama yang menyebut MSTG-STORAGE-3 / MASTG-TEST-0003, padanannya di MASTG V2 adalah kedua test ini.

**Nilai unik TEST-0203** dibanding TEST-0231: analisis statis hanya bisa melihat bahwa ada `Log.d(TAG, "token: $token")` — ia tidak tahu apa isi `$token` saat runtime, dan tidak tahu apakah variabel itu berisi data sensitif atau nilai dummy. Test dinamis ini **melihat nilai yang sebenarnya tercatat**, sehingga langsung menjawab pertanyaan evaluasi: apakah ada data sensitif di log?

Sebaliknya, TEST-0231 menangkap yang lolos dari TEST-0203: pemanggilan logging di jalur kode yang tidak pernah dipicu selama pengujian (mis. handler error yang jarang terjadi, fitur premium).

### 1.4 Peta API Logging yang Perlu Diperiksa

**Kelompok A — API yang eksplisit disebut MASTG:**

| API | Keterangan |
|---|---|
| `android.util.Log` — `v()`, `d()`, `i()`, `w()`, `e()`, `wtf()`, `println()` | API logging utama Android. Semuanya menulis ke logcat |
| `java.util.logging.Logger` — `severe()`, `warning()`, `info()`, `config()`, `fine()`, `finer()`, `finest()`, `log()` | Logger standar Java; pada Android diarahkan ke logcat |
| `System.out.print` / `System.out.println` | Pada Android diarahkan ke logcat dengan tag `System.out` |
| `System.err.print` / `System.err.println` | Diarahkan ke logcat dengan tag `System.err` |
| `java.lang.Throwable#printStackTrace()` | **Sering terlupakan.** Mencetak stack trace ke `System.err` → logcat. Exception message kerap memuat data sensitif (mis. URL lengkap dengan token, isi respons API) |

**Kelompok B — Permukaan tambahan yang tidak disebut MASTG tetapi wajib diperiksa dalam pengujian nyata:**

| API / Komponen | Alasan perlu diperiksa |
|---|---|
| **Timber** (`Timber.d/e/i/v/w/wtf`) | Logging library paling populer di Android. Tidak akan tertangkap bila kamu hanya meng-hook `android.util.Log` — kecuali Timber dikonfigurasi dengan `DebugTree` yang mendelegasikan ke `Log` |
| **SLF4J / Logback-android / log4j** | Umum di aplikasi enterprise |
| `android.util.Slog` | Logging sistem (hanya untuk aplikasi platform) |
| **Native logging** — `__android_log_print`, `__android_log_write` (liblog) | Log dari kode NDK/`.so`. **Tidak terlihat** oleh hook Java |
| **OkHttp `HttpLoggingInterceptor`** | Bila di-set `Level.BODY`, mencatat **seluruh header dan body request/response** — termasuk `Authorization: Bearer ...`. Salah satu penyebab kebocoran log terbesar di praktik |
| **Retrofit / Volley / Firebase / analytics SDK** | Sering punya flag debug logging sendiri |
| **WebView console** (`ConsoleMessage` via `WebChromeClient.onConsoleMessage`) | `console.log()` dari JavaScript masuk ke logcat |
| **Crash reporter** (Crashlytics `log()`, Sentry breadcrumbs) | Menambahkan konteks log yang **dikirim ke server pihak ketiga** |
| **Custom logger wrapper** aplikasi sendiri | Mis. `AppLogger.debug()` yang di dalamnya memanggil `Log.d` — hook pada `Log` akan menangkapnya, tapi backtrace-nya akan menunjuk ke wrapper, bukan ke pemanggil asli |

> Rule praktis: hook pada `android.util.Log` menangkap **sebagian besar** kebocoran karena banyak library akhirnya mendelegasikan ke sana. Tapi jangan berasumsi demikian — verifikasi dengan memeriksa dependency aplikasi (`grep -r "timber\|slf4j\|HttpLoggingInterceptor"` pada kode hasil dekompilasi).

### 1.5 Mitos yang Perlu Diluruskan

Beberapa keyakinan umum yang salah dan sering menyebabkan penilaian keliru:

1. **"`Log.v` dan `Log.d` otomatis dihapus di release build."** **Salah.** Android tidak menghapus pemanggilan logging apa pun secara otomatis. Penghapusan hanya terjadi jika kamu mengonfigurasi ProGuard/R8 dengan `-assumenosideeffects` secara eksplisit. Demo MASTG sendiri menunjukkan `Log.v` dan `Log.d` muncul normal di logcat.
2. **"Log level rendah (verbose/debug) tidak muncul di produksi."** **Salah.** Semua level muncul di logcat kecuali disaring saat pembacaan. `Log.isLoggable()` hanya berguna bila developer memang memakainya sebagai gate.
3. **"logcat aman karena butuh `READ_LOGS` yang hanya dimiliki aplikasi sistem."** **Menyesatkan** — lihat tabel §1.2. Aplikasi pre-installed, `adb logcat`, bug report, dan crash reporter semuanya jalur nyata.
4. **"Cukup pasang aturan ProGuard, masalah selesai."** **Tidak cukup.** MASTG-BEST-0002 menjelaskan bahwa `-assumenosideeffects` hanya menjamin *pemanggilan metode* `Log` dihapus. Bila string yang dicatat dibangun secara dinamis, **kode pembangun string bisa tetap ada di bytecode** (lihat §4.1).

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | MASTG ID | Fungsi dalam test ini |
|---|---|---|
| **Frida / frida-trace** | MASTG-TOOL-0001 | **Tool utama.** `frida-trace -j` untuk meng-hook seluruh metode kelas logging sekaligus dan mencatat argumennya |
| **frida-server** | — | Daemon di device (butuh root) — atau **frida-gadget** untuk device non-root |
| **adb** | MASTG-TOOL-0004 | Instalasi APK (`adb install -g`), dan **`adb logcat`** sebagai pembanding independen hasil trace |
| **Android device / emulator (rooted)** | MASTG-TOOL-0003 | Target pengujian |
| **jadx** | MASTG-TOOL-0018 | Menelusuri lokasi kode pemanggil log untuk menentukan konteks dan sumber datanya |

### 2.2 Tools Pendukung

| Tool | Fungsi |
|---|---|
| **`adb logcat` dengan filter** | Pembanding wajib: `adb logcat --pid=$(adb shell pidof -s <pkg>)`. **Tidak butuh root** — cukup USB debugging. Ini sekaligus mendemonstrasikan salah satu jalur eksploitasi |
| **pidcat** | Wrapper logcat yang memfilter per-package dan mewarnai output — jauh lebih terbaca |
| **Objection** | MASTG-TOOL-0038. Alternatif cepat: `android hooking watch class android.util.Log --dump-args --dump-backtrace` |
| **semgrep** | MASTG-TOOL-0110. Untuk MASTG-TEST-0231 (statis) — melengkapi cakupan test ini |
| **ProGuard / R8** | MASTG-TOOL-0022. Bukan tool pengujian, tapi konfigurasinya (`proguard-rules.pro`) harus **diverifikasi** sebagai bagian evaluasi |
| **`strings` / Ghidra** | Memeriksa `.so` untuk pemanggilan `__android_log_print` — titik buta hook Java |
| **grep / ripgrep** | Menyaring output trace untuk canary value dan pola secret |
| **TruffleHog / gitleaks** | Memindai output log yang terkumpul untuk pola secret (token, API key, private key) |
| **Android Studio Logcat** | Tampilan logcat terintegrasi; demo MASTG memakai ini sebagai referensi pembanding |

### 2.3 Prasyarat Lingkungan

- **Root atau frida-gadget** untuk method hooking. Namun catat: bagian **pembanding** (`adb logcat`) bisa jalan tanpa root — dan justru itu yang membuktikan eksploitabilitas.
- **Versi frida-server harus cocok** dengan frida CLI di host; arsitektur juga harus tepat.
- **`--runtime=v8`** diperlukan untuk `frida-trace -j` (tracing metode Java), seperti pada `run.sh` demo MASTG.
- Aplikasi terinstall dengan `adb install -g` agar semua alur dapat dijangkau.
- **Canary value yang unik dan mudah di-grep.** Ini sangat penting untuk test ini dan **direkomendasikan eksplisit oleh MASTG**: *"You could refine the test to input a known secret and then search for it in the logs."* Gunakan pola seperti `MASTG_CANARY_PWD_7f3a`, `canary+mastg@example.com`.
- **Uji build RELEASE, bukan hanya debug.** Ini krusial: banyak aplikasi punya logging berlebih di debug build yang memang sudah dihapus/dimatikan di release. Menguji debug build akan menghasilkan false positive besar-besaran. Bila hanya tersedia debug build, **nyatakan itu sebagai batasan pengujian** di laporan.
- **Antisipasi anti-instrumentation** pada aplikasi produksi (terutama finansial). Bila terhalang, `adb logcat` tetap dapat dipakai sebagai jalur pengujian alternatif.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0005** (*Installing Apps*) untuk menginstall aplikasi.
2. Gunakan **MASTG-TECH-0043** (*Method Hooking*) untuk meng-hook pemanggilan API yang relevan.
3. **Exercise aplikasi secara ekstensif** untuk memicu sebanyak mungkin alur, dan masukkan data sensitif di setiap tempat yang memungkinkan.

### 3.2 Implementasi Praktis (MASTG-DEMO-0006)

**Langkah 0 — Setup**

```bash
# Cek versi & arsitektur
frida --version
adb shell getprop ro.product.cpu.abi

# Jalankan frida-server di device
adb push frida-server-<versi>-android-<arch> /data/local/tmp/frida-server
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "su -c /data/local/tmp/frida-server &"
frida-ps -U | head

# Install aplikasi (idealnya RELEASE build)
adb install -g ./target-app.apk

# Bersihkan buffer logcat agar baseline bersih
adb logcat -c
```

**Langkah 1 — Jalankan frida-trace (`run.sh` resmi MASTG-DEMO-0006)**

```bash
#!/bin/bash

# SUMMARY: This script uses frida-trace to trace logging statements in the specified Android app
# and filters the output to exclude certain log methods.
# The raw output is saved to "output_raw.txt" and then filtered to remove unwanted log entries.
# The final result saved to "output.txt".

frida-trace \
    -U \
    -f org.owasp.mastestapp \
    --runtime=v8 \
    -j 'android.util.Log!*' \
    -j 'java.util.logging.Logger!severe' \
    -o output_raw.txt \
    && cat output_raw.txt | grep -E "(Log|Logger)" | grep -vE "Log\.println|Log\.isLoggable" > output.txt
```

Cara membaca perintah ini:

| Bagian | Arti |
|---|---|
| `-U` | Hubungkan ke device via USB |
| `-f org.owasp.mastestapp` | **Spawn** aplikasi (bukan attach) — penting agar log saat startup ikut tertangkap |
| `--runtime=v8` | Wajib untuk tracing metode Java dengan `-j` |
| `-j 'android.util.Log!*'` | Hook **semua** metode kelas `android.util.Log` (`v`, `d`, `i`, `w`, `e`, `wtf`, `println`, `isLoggable`, ...) |
| `-j 'java.util.logging.Logger!severe'` | Hook metode `severe` dari `Logger` |
| `-o output_raw.txt` | Simpan output mentah |
| `grep -vE "Log\.println\|Log\.isLoggable"` | **Kurangi noise/duplikasi**: `Log.v/d/i/w/e` secara internal memanggil `Log.println`, sehingga setiap satu log akan muncul dua kali. `isLoggable` hanya pengecekan level, bukan pencatatan data |

> Perhatikan bahwa filter `grep` pada demo adalah bagian penting desainnya, bukan kosmetik. Tanpa filter itu, setiap pemanggilan log muncul berulang dan output menjadi sulit dibaca.

**Langkah 2 — Exercise aplikasi dengan canary value**

Jalankan alur sebanyak mungkin, dan di **setiap** input masukkan canary value yang unik:

- Registrasi & login (username, password, OTP) — gunakan password canary `MASTG_CANARY_PWD_7f3a`
- Login gagal, password salah, akun terkunci → memicu jalur error yang sering memuat log verbose
- Reset password, verifikasi email/SMS, setup 2FA/biometrik
- Lengkapi profil: nama, NIK, alamat, telepon, tanggal lahir, upload dokumen
- Tambah metode pembayaran (nomor kartu canary), lakukan transaksi, unduh invoice
- Fitur pencarian, chat, komentar
- **Matikan jaringan di tengah operasi** → memicu exception & `printStackTrace`
- **Picu error server** (input tidak valid, payload besar) → memicu logging respons API
- Background/foreground, rotasi layar, force-stop, buka ulang
- Aktifkan semua toggle di Settings, terutama opsi "debug"/"developer" bila ada
- Deep link / intent eksternal

**Langkah 3 — Hentikan dan analisis**

```bash
# Tekan Ctrl+C untuk mengakhiri frida-trace, lalu:

# Cari canary value di output trace
grep -iE "MASTG_CANARY_PWD_7f3a|canary\+mastg" output.txt

# Cari pola secret umum
grep -inE "password|passwd|pwd|token|bearer|authorization|api[_-]?key|secret|credential|session|cookie|jwt|eyJ[A-Za-z0-9_-]{10,}|BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY" output.txt

# Cari PII
grep -inE "[0-9]{16}|[0-9]{3}-[0-9]{2}-[0-9]{4}|[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,}|\+?62[0-9]{9,}|imei|mac[_ ]?address|latitude|longitude" output.txt

# Cari material kriptografi (IV, key) — seperti pada sampel demo
grep -inE "\biv\b|initialization.?vector|secret_?key|aes|cipher" output.txt
```

**Langkah 4 — Bandingkan dengan logcat**

Demo MASTG menyertakan `logcat_output.txt` sebagai **referensi pembanding**. Ini langkah verifikasi yang penting: ia membuktikan bahwa data yang tertangkap hook benar-benar **sampai ke buffer logcat** dan karenanya dapat diakses pihak lain.

```bash
# Baca logcat hanya untuk proses aplikasi target — TIDAK BUTUH ROOT
adb logcat --pid=$(adb shell pidof -s org.owasp.mastestapp)

# Simpan dan cari canary value
adb logcat -d > logcat_dump.txt
grep -iE "MASTG_CANARY_PWD_7f3a|password|token" logcat_dump.txt

# Alternatif yang lebih terbaca
pidcat org.owasp.mastestapp
```

> Bahwa perintah di atas berjalan **tanpa root**, hanya dengan USB debugging, adalah bukti praktis eksploitabilitas yang layak dicantumkan di laporan.

### 3.3 Perluasan yang Direkomendasikan

Script demo MASTG sengaja minimalis untuk tujuan edukasi dan hanya mencakup `android.util.Log` serta `Logger.severe`. Untuk pengujian nyata, ada beberapa celah yang perlu ditutup:

**Celah 1 — `Logger` hanya di-hook pada `severe`.** Metode lain (`warning`, `info`, `fine`, `log`) terlewat.
**Celah 2 — `System.out` / `System.err` tidak di-hook**, padahal disebut eksplisit di daftar API test ini.
**Celah 3 — `printStackTrace()` tidak di-hook**, padahal juga disebut eksplisit di daftar API.
**Celah 4 — Library logging pihak ketiga** (Timber, OkHttp interceptor) tidak tercakup.
**Celah 5 — Backtrace tidak dicetak**, sehingga sulit menentukan lokasi kode pemanggil.

**Perintah frida-trace yang diperluas:**

```bash
frida-trace \
    -U \
    -f com.example.target \
    --runtime=v8 \
    -j 'android.util.Log!*' \
    -j 'java.util.logging.Logger!*' \
    -j 'java.io.PrintStream!print*' \
    -j 'java.lang.Throwable!printStackTrace*' \
    -j 'timber.log.Timber!*' \
    -j '*!*HttpLoggingInterceptor*/isu' \
    -o output_raw.txt
```

> Catatan: `-j 'java.io.PrintStream!print*'` akan menangkap `System.out.print*` dan `System.err.print*` (keduanya adalah `PrintStream`), tetapi juga sangat **noisy** karena semua penulisan stream ikut tertangkap. Saring hasilnya.

**Script Frida khusus dengan backtrace dan deteksi canary otomatis:**

```javascript
// Pola yang dianggap sensitif — sesuaikan dengan canary value pengujianmu
const SENSITIVE = [
    /MASTG_CANARY_PWD_7f3a/i,
    /canary\+mastg@example\.com/i,
    /password|passwd|pwd/i,
    /token|bearer|authorization/i,
    /api[_-]?key|secret|credential/i,
    /eyJ[A-Za-z0-9_-]{10,}/,                 // JWT
    /BEGIN (RSA|EC|OPENSSH)? ?PRIVATE KEY/,
    /\b\d{16}\b/,                            // nomor kartu
    /\biv\b|secret_?key/i
];

function isSensitive(s) {
    return s && SENSITIVE.some(re => re.test(s));
}

function backtrace(max = 10) {
    const Exception = Java.use("java.lang.Exception");
    const st = Exception.$new().getStackTrace();
    const lines = [];
    for (let i = 0; i < Math.min(max, st.length); i++) {
        const f = st[i].toString();
        // Lewati frame framework logging agar pemanggil asli terlihat
        if (f.indexOf("android.util.Log") === 0) continue;
        if (f.indexOf("java.util.logging") === 0) continue;
        lines.push("    " + f);
    }
    return lines.join("\n");
}

function report(api, tag, msg, thr) {
    const flag = isSensitive(msg) || isSensitive(tag) ? "  [!! SENSITIVE !!]" : "";
    console.log(`\n[*] ${api}${flag}`);
    if (tag !== null) console.log(`    tag : ${tag}`);
    console.log(`    msg : ${msg}`);
    if (thr) console.log(`    thr : ${thr}`);
    console.log("  Caller:");
    console.log(backtrace());
}

Java.perform(() => {
    // --- android.util.Log ---
    const Log = Java.use("android.util.Log");
    ['v', 'd', 'i', 'w', 'e', 'wtf'].forEach(m => {
        Log[m].overloads.forEach(ov => {
            ov.implementation = function (...args) {
                // Overload umum: (String tag, String msg) atau (String tag, String msg, Throwable tr)
                const tag = (args.length > 0 && args[0]) ? args[0].toString() : null;
                const msg = (args.length > 1 && args[1]) ? args[1].toString() : null;
                const thr = (args.length > 2 && args[2]) ? args[2].toString() : null;
                report(`Log.${m}()`, tag, msg, thr);
                return ov.apply(this, args);
            };
        });
    });

    // --- java.util.logging.Logger (semua level, bukan hanya severe) ---
    const Logger = Java.use("java.util.logging.Logger");
    ['severe', 'warning', 'info', 'config', 'fine', 'finer', 'finest'].forEach(m => {
        try {
            Logger[m].overload('java.lang.String').implementation = function (msg) {
                report(`Logger.${m}()`, null, msg, null);
                return this[m](msg);
            };
        } catch (e) { /* metode tidak tersedia */ }
    });

    // --- System.out / System.err (keduanya PrintStream) ---
    const PrintStream = Java.use("java.io.PrintStream");
    ['println', 'print'].forEach(m => {
        try {
            PrintStream[m].overload('java.lang.String').implementation = function (s) {
                report(`PrintStream.${m}()`, null, s, null);
                return this[m](s);
            };
        } catch (e) { /* ignore */ }
    });

    // --- Throwable.printStackTrace() — API yang disebut MASTG tapi tak ada di demo ---
    const Throwable = Java.use("java.lang.Throwable");
    Throwable.printStackTrace.overload().implementation = function () {
        const msg = this.getMessage() ? this.getMessage().toString() : "<no message>";
        report("Throwable.printStackTrace()", this.$className, msg, null);
        return this.printStackTrace();
    };

    // --- Timber (bila dipakai aplikasi) ---
    try {
        const Timber = Java.use("timber.log.Timber");
        ['v', 'd', 'i', 'w', 'e', 'wtf'].forEach(m => {
            Timber[m].overload('java.lang.String', '[Ljava.lang.Object;')
              .implementation = function (msg, args) {
                report(`Timber.${m}()`, null, msg, null);
                return this[m](msg, args);
            };
        });
    } catch (e) { console.log("[i] Timber tidak ditemukan — dilewati"); }
});
```

Jalankan dengan:

```bash
frida -U -f com.example.target -l log_trace.js -o output.txt
```

Keunggulan script ini dibanding `frida-trace`: menandai otomatis baris yang mengandung pola sensitif (`[!! SENSITIVE !!]`), dan mencetak **backtrace dengan frame framework logging disaring** — sehingga pemanggil asli langsung terlihat (berguna saat aplikasi memakai custom logger wrapper).

### 3.4 Pemeriksaan Pelengkap

```bash
# 1. Titik buta hook Java: logging dari kode native
for so in $(find ./extracted -name "*.so"); do
  echo "--- $so"
  strings "$so" | grep -E "__android_log_print|__android_log_write"
done

# 2. Periksa apakah aplikasi menulis log ke FILE (bertaut dengan MASTG-TEST-0200)
adb shell "find /sdcard/ -iname '*.log' -o -iname '*log*.txt'"
adb shell "run-as com.example.target ls -la /data/data/com.example.target/files/"

# 3. Verifikasi konfigurasi ProGuard/R8 (bagian evaluasi remediasi)
apktool d -s -f -o out ./target-app.apk
grep -rn "assumenosideeffects" ./proguard-rules.pro 2>/dev/null
# Bila hanya punya APK: cek apakah pemanggilan Log masih ada di bytecode
jadx -d ./decompiled ./target-app.apk
grep -rcE "Log\.(v|d|i|w|e|wtf)\(" ./decompiled/sources/ | grep -v ":0$" | head

# 4. Cek OkHttp logging interceptor — penyebab kebocoran log terbesar di praktik
grep -rn "HttpLoggingInterceptor\|Level.BODY\|Level.HEADERS" ./decompiled/sources/

# 5. Cek WebView console logging
grep -rn "onConsoleMessage\|ConsoleMessage" ./decompiled/sources/

# 6. Cek apakah crash reporter melampirkan log
grep -rn "Crashlytics.log\|FirebaseCrashlytics\|Sentry.captureMessage\|addBreadcrumb" ./decompiled/sources/

# 7. Bug report — jalur kebocoran yang sering diabaikan
adb bugreport ./bugreport.zip
unzip -p ./bugreport.zip | grep -iE "MASTG_CANARY_PWD_7f3a|password|token" | head
```

### 3.5 Metode Pengujian Alternatif (Multi-Tool)

Test ini punya keuntungan besar dibanding test dinamis lain: **jalur alternatifnya banyak dan sebagian tidak butuh root sama sekali**, karena logcat dapat dibaca lewat `adb` biasa.

#### Metode B — `adb logcat` murni *(tanpa root, tanpa Frida — dan sekaligus bukti eksploitabilitas)*

**Ini metode yang aku rekomendasikan sebagai titik awal**, bukan hanya pembanding. Ia tidak butuh root, tidak butuh instrumentasi, tidak bisa dihalangi anti-Frida — dan keberhasilannya **sekaligus mendemonstrasikan jalur serangan yang nyata**.

```bash
PKG=com.example.target
adb logcat -c                                     # bersihkan buffer

# Opsi 1: filter per PID aplikasi (paling bersih)
adb logcat --pid=$(adb shell pidof -s $PKG) | tee app.log

# Opsi 2: tangkap SEMUA buffer (main, system, crash, events, radio)
adb logcat -b all -v threadtime | tee all.log

# Opsi 3: dump lalu analisis offline
adb logcat -d -b all > dump.log

# Cari canary & pola secret
grep -inE "MASTG_CANARY_PWD_7f3a|password|token|bearer|authorization|api[_-]?key|eyJ[A-Za-z0-9_-]{10,}" all.log

# Filter per level (W/E saja — yang seharusnya tersisa di produksi)
adb logcat --pid=$(adb shell pidof -s $PKG) *:W
```

> **Poin penting untuk laporan:** perintah di atas berjalan **tanpa root**, hanya dengan USB debugging aktif. Itu berarti akses fisik singkat ke perangkat yang unlocked sudah cukup untuk memanen log. Cantumkan ini sebagai bukti eksploitabilitas, bukan sekadar metode pengujian.

#### Metode C — pidcat *(logcat yang jauh lebih terbaca)*

```bash
pip install pidcat        # atau: brew install pidcat
pidcat com.example.target

# Filter level minimum
pidcat -l W com.example.target

# Hanya tag tertentu
pidcat --tag Auth --tag Network com.example.target
```

Output berwarna per level dan otomatis mengikuti PID aplikasi meski aplikasi di-restart — sangat membantu saat exercise manual yang panjang.

#### Metode D — Objection *(hooking cepat tanpa menulis script)*

```bash
objection -g com.example.target explore

# Pantau seluruh kelas Log
android hooking watch class android.util.Log
android hooking watch class_method android.util.Log.d --dump-args --dump-backtrace
android hooking watch class_method android.util.Log.e --dump-args --dump-backtrace
android hooking watch class_method java.util.logging.Logger.severe --dump-args --dump-backtrace

# Throwable.printStackTrace — API yang disebut MASTG tapi tidak ada di demo
android hooking watch class_method java.lang.Throwable.printStackTrace --dump-backtrace
```

Keunggulan: `--dump-args` langsung menampilkan nilai yang dicatat, dan `--dump-backtrace` memberi pemanggilnya — dua hal yang dibutuhkan kriteria evaluasi — tanpa perlu menulis satu baris JavaScript.

#### Metode E — MASTG-TEST-0231: analisis statis *(counterpart resmi)*

MASTG menyediakan test statis terpisah untuk logging. Jalankan berpasangan dengan test ini.

```bash
jadx -d ./decompiled ./target-app.apk
D=./decompiled/sources

# --- API logging yang disebut MASTG ---
rg -n --no-heading "android\.util\.Log|Log\.(v|d|i|w|e|wtf|println)\(" $D
rg -n --no-heading "java\.util\.logging\.Logger|\.severe\(|\.warning\(|\.info\(|\.fine\(" $D
rg -n --no-heading "System\.out\.print|System\.err\.print" $D
rg -n --no-heading "printStackTrace\(\)" $D

# --- Library logging pihak ketiga (TIDAK disebut MASTG) ---
rg -n --no-heading "timber\.log\.Timber|Timber\.(v|d|i|w|e|wtf)\(" $D
rg -n --no-heading "org\.slf4j|LoggerFactory\.getLogger|logback" $D
rg -n --no-heading "HttpLoggingInterceptor|Level\.BODY|Level\.HEADERS" $D   # penyebab terbesar
rg -n --no-heading "Crashlytics\.log|FirebaseCrashlytics|Sentry\.|addBreadcrumb" $D
rg -n --no-heading "onConsoleMessage|ConsoleMessage" $D                     # WebView

# --- Verifikasi apakah Log sudah di-STRIP oleh R8/ProGuard di release ---
rg -c --no-heading "Log\.(v|d|i|w|e|wtf)\(" $D | grep -v ":0$" | head
#   Pada release build yang benar, hitungannya HARUS 0 atau sangat kecil
rg -n "assumenosideeffects" ./proguard-rules.pro 2>/dev/null

# --- Logging dari kode native ---
unzip -o ./target-app.apk -d ./apk_x >/dev/null
for so in $(find ./apk_x -name "*.so"); do
  echo "--- $so"; strings "$so" | grep -E "__android_log_print|__android_log_write"
done
```

#### Metode F — MobSF *(statis + dinamis dalam satu tool)*

```bash
docker run -it --rm -p 8000:8000 -p 1337:1337 \
  opensecurity/mobile-security-framework-mobsf:latest
```

| Bagian | Isinya |
|---|---|
| **Code Analysis** (statis) | *"The App logs information. Sensitive information should never be logged."* — dengan daftar lokasi kode |
| **Logcat** (Dynamic Analysis) | Tangkapan logcat lengkap selama sesi dinamis, siap di-grep |
| **API Monitor** | Pemanggilan API sensitif termasuk logging |

Keunggulan besar untuk test ini: MobSF menggabungkan sisi statis (TEST-0231) dan dinamis (TEST-0203) dalam satu laporan.

#### Metode G — mobsfscan / semgrep *(gate CI/CD)*

```bash
mobsfscan --json -o out.json ./decompiled/sources/
jq '.results | to_entries[] | select(.key | test("log"))' out.json

# Semgrep registry
semgrep --config "r/java.android.security.android-logging.android-logging" ./decompiled/sources/
semgrep --config "p/mobsfscan" ./decompiled/sources/

# Rule kustom untuk pola paling berbahaya: variabel masuk ke Log
cat > log-rules.yml <<'YAML'
rules:
  - id: log-with-variable-interpolation
    severity: WARNING
    languages: [java, kotlin]
    message: "[MASVS-STORAGE-2] Nilai variabel dicatat ke log — periksa sensitivitasnya"
    pattern-either:
      - pattern: android.util.Log.$M($TAG, $X + $Y)
      - pattern: android.util.Log.$M($TAG, String.format(...))
      - pattern: android.util.Log.$M($TAG, new StringBuilder(...).append(...).toString())
  - id: okhttp-body-logging
    severity: ERROR
    languages: [java, kotlin]
    message: "[MASVS-STORAGE-2] HttpLoggingInterceptor mencatat body/header — kebocoran token"
    pattern-either:
      - pattern-regex: 'Level\.BODY'
      - pattern-regex: 'Level\.HEADERS'
YAML
semgrep -c log-rules.yml ./decompiled/sources/
```

> Rule `log-with-variable-interpolation` menyasar pola yang paling sering membocorkan data: `Log.d(TAG, "token: $token")`. Konstanta murni (`Log.d(TAG, "onCreate")`) tidak terpicu.

#### Metode H — Verifikasi jalur kebocoran sekunder *(sering terlewat total)*

Log tidak hanya berakhir di logcat. Tiga jalur ini perlu diperiksa terpisah.

```bash
PKG=com.example.target

# --- 1. Bug report — berisi dump logcat lengkap, sering dikirim user ke support ---
adb bugreport ./bugreport.zip
unzip -o ./bugreport.zip -d ./br >/dev/null
grep -rinE "MASTG_CANARY_PWD_7f3a|password|token" ./br/ | head

# --- 2. Log yang ditulis ke FILE (bertaut MASTG-TEST-0200 & 0207) ---
adb shell "find /sdcard/ -iname '*.log' -o -iname '*log*.txt' -o -iname '*.txt'" | head -30
adb shell "su -c 'find /data/data/$PKG -iname \"*.log\" -o -iname \"*crash*\"'"
adb shell "su -c 'ls -la /data/anr/ /data/tombstones/'"      # ANR trace & tombstone

# --- 3. Crash reporter — log dikirim ke SERVER pihak ketiga ---
rg -n --no-heading "Crashlytics\.log|setCustomKey|Sentry\.captureMessage|addBreadcrumb" \
  ./decompiled/sources/
#   Verifikasi isinya lewat MASTG-TEST-0206 (network capture)
```

Poin ini penting untuk severity: log yang **dikirim ke server pihak ketiga** berarti data keluar dari perangkat, bukan sekadar tersimpan lokal.

#### Metode I — Uji RELEASE vs DEBUG *(langkah metodologis yang menentukan validitas)*

Ini bukan tool baru, tetapi prosedur yang menentukan apakah temuanmu punya bobot produksi.

```bash
# Bandingkan kedua build pada sesi yang setara
for APK in app-debug.apk app-release.apk; do
  echo "=== $APK"
  adb uninstall $PKG 2>/dev/null
  adb install -g "./$APK"
  adb logcat -c
  echo "--> exercise aplikasi sekarang, lalu tekan Enter"; read
  adb logcat -d -b all | grep -icE "MASTG_CANARY_PWD_7f3a|password|token"
done

# Verifikasi apakah Log sudah di-strip di release
jadx -d ./rel ./app-release.apk
rg -c --no-heading "Log\.(v|d|i)\(" ./rel/sources/ | grep -v ":0$" | wc -l
#   Hasil 0 = ProGuard/R8 sudah menghapus pemanggilan Log
```

Bila release build bersih sementara debug build banjir temuan, itu artinya **kontrolnya bekerja** — laporkan sebagai PASS dengan catatan hygiene, bukan sebagai kerentanan.

---

### 3.6 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Butuh root? | Memberi nilai runtime? | Memberi backtrace? | Cakupan library pihak ketiga | Kapan dipakai |
|---|---|---|---|---|---|---|
| **A** | frida-trace / Frida (§3.2–3.3) | Ya/gadget | ✅ | ✅ | ✅ (bila di-hook) | **Baseline resmi** — kendali penuh |
| **B** | `adb logcat` | **Tidak** | ✅ | ❌ | ✅ **(semua, otomatis)** | **Titik awal terbaik** + bukti eksploitabilitas |
| **C** | pidcat | **Tidak** | ✅ | ❌ | ✅ | Sama seperti B, jauh lebih terbaca |
| **D** | Objection | Tidak¹ | ✅ | ✅ | Sebagian | Hooking cepat tanpa menulis script |
| **E** | Analisis statis (TEST-0231) | Tidak | ❌ | — | ✅ | **Cakupan menyeluruh** — jalur kode yang belum di-exercise |
| **F** | MobSF | Tidak | ✅ | Sebagian | ✅ | Statis + dinamis dalam satu laporan |
| **G** | mobsfscan / semgrep | Tidak | ❌ | — | ✅ | Gate CI/CD; rule kustom untuk interpolasi variabel |
| **H** | bugreport / file log / crash reporter | Sebagian | ✅ | ❌ | ✅ | **Jalur kebocoran sekunder** — sering terlewat total |
| **I** | Perbandingan release vs debug | Tidak | ✅ | — | ✅ | **Menentukan bobot produksi temuan** |

¹ Objection memakai Frida; tanpa root butuh frida-gadget.

**Kombinasi minimum yang aku rekomendasikan:** **B (adb logcat) → E (statis) → I (release vs debug)**.
B adalah cara tercepat dan paling representatif — tanpa root, tanpa risiko dihalangi anti-instrumentation, dan hasilnya langsung berupa bukti. E memberi cakupan atas jalur kode yang belum di-exercise. I memastikan temuanmu relevan untuk produksi. Tambahkan **A (Frida)** bila kamu butuh backtrace untuk mengatribusikan kebocoran ke SDK pihak ketiga, dan **H** selalu — bug report serta log-ke-file adalah jalur yang paling sering luput.

> **Catat perbedaan penting dari test dinamis lain:** karena logcat dapat dibaca tanpa root maupun instrumentasi, **anti-Frida tidak membuat test ini Inconclusive**. Selalu ada jalur Metode B yang bisa ditempuh.

---

### 3.7 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Observation:** *"The output should contain a list of locations where logging APIs are used in the app for the current execution."*
>
> **Evaluation:** *"The test case **fails** if you can find sensitive data being logged using those APIs."*

Evaluasi test ini **lebih sederhana** daripada TEST-0200/0201/0202: tidak ada klausa "dan tidak ter-enkripsi". Cukup **ada data sensitif di log → FAIL**. Ini masuk akal karena tujuan log adalah keterbacaan; data sensitif yang dicatat pada praktiknya selalu plaintext.

Panduan review dari MASTG-DEMO-0006:

> *"Review each of the reported instances by using keywords and known secrets (e.g. passwords or usernames or values you keyed into the app)."*
>
> *"Note: You could refine the test to input a known secret and then search for it in the logs."*

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi | Contoh bukti |
|---|---|---|
| F1 | Trace menunjukkan **password / PIN** tercatat lewat API logging | `Log.i("MASTG", "key: MAS-Sensitive-Password")` |
| F2 | Trace menunjukkan **token / API key / session ID / JWT** tercatat | `Log.d("Auth", "Bearer eyJhbGciOiJIUzI1NiIs...")` |
| F3 | Trace menunjukkan **material kriptografi** (kunci, IV, salt, seed phrase) tercatat | `Log.w("MASTG", "test: MAS-Sensitive-Value-IV")`; `Logger.severe("MAS-Sensitive-Key")` |
| F4 | Trace menunjukkan **PII** tercatat (nama, email, NIK, telepon, alamat, tanggal lahir, lokasi, IMEI, MAC address) | `Log.d("Profile", "user=budi@example.com, nik=3201...")` → juga pelanggaran profile **P (Privacy)** |
| F5 | Trace menunjukkan **data finansial/kesehatan** tercatat | `Log.i("Payment", "card=4111111111111111, cvv=123")` |
| F6 | **Canary value** yang kamu masukkan ke aplikasi muncul di output trace atau di logcat | `grep MASTG_CANARY_PWD_7f3a output.txt` → ada hasil |
| F7 | `printStackTrace()` / log exception memuat data sensitif dalam message atau stack trace | `Throwable.printStackTrace()` dengan message `HTTP 401 for https://api/login?token=abc123` |
| F8 | **Full request/response HTTP** tercatat (OkHttp `HttpLoggingInterceptor` pada `Level.BODY`) | Log memuat header `Authorization` dan body berisi kredensial |
| F9 | Data sensitif tercatat pada **RELEASE build** (bukan hanya debug) | Dikonfirmasi dengan menguji APK release; ProGuard tidak dikonfigurasi untuk strip log |
| F10 | Log berisi data sensitif **ditulis ke file** dan/atau dikirim ke server | Bertaut dengan MASTG-TEST-0200; atau `Crashlytics.log()` mengirim konteks sensitif ke pihak ketiga |
| F11 | Log membocorkan **detail internal** yang memudahkan serangan lanjutan | Endpoint staging, feature flag, status SSL pinning, nama kelas internal, versi library, query SQL lengkap |
| F12 | Log dari **kode native** memuat data sensitif | `strings lib.so` → `__android_log_print` + review menunjukkan pencatatan kredensial |

**Contoh output yang menandakan FAIL** (hasil resmi MASTG-DEMO-0006):

Kode sampel (`MastgTest.kt`):

```kotlin
class MastgTest (private val context: Context){

    fun mastgTest(): String {
        val variable = "MAS-Sensitive-Value"
        val password = "MAS-Sensitive-Password"
        val secret_key = "MAS-Sensitive-Key"
        val IV = "MAS-Sensitive-Value-IV"
        val iv = "MAS-Sensitive-Value-IV-2"

        Log.v("MASTG", "key: $variable")
        Log.i("MASTG", "key: $password")
        Log.w("MASTG", "test: $IV")
        Log.d("MASTG", "test: $iv")
        Log.e("MASTG", "test: $variable")
        Log.wtf("MASTG", "test: $variable")

        val x = Logger.getLogger("myLogger")
        x.severe(secret_key)

        return "Done"
    }
}
```

Output `frida-trace` (`output.txt`):

```
Log.v("MASTG", "key: MAS-Sensitive-Value")
Log.i("MASTG", "key: MAS-Sensitive-Password")
Log.w("MASTG", "test: MAS-Sensitive-Value-IV")
Log.d("MASTG", "test: MAS-Sensitive-Value-IV-2")
Log.e("MASTG", "test: MAS-Sensitive-Value")
Log.wtf("MASTG", "test: MAS-Sensitive-Value")
Log.wtf(0, "MASTG", "test: MAS-Sensitive-Value", null, false, false)
Logger.severe("MAS-Sensitive-Key")
```

Logcat pembanding (`logcat_output.txt`) — membuktikan data benar-benar sampai ke buffer bersama:

```
2024-05-14 10:30:06.864  6966-6966  MASTG   org.owasp.mastestapp  V  key: MAS-Sensitive-Value
2024-05-14 10:30:06.866  6966-6966  MASTG   org.owasp.mastestapp  I  key: MAS-Sensitive-Password
2024-05-14 10:30:06.867  6966-6966  MASTG   org.owasp.mastestapp  W  test: MAS-Sensitive-Value-IV
2024-05-14 10:30:06.867  6966-6966  MASTG   org.owasp.mastestapp  D  test: MAS-Sensitive-Value-IV-2
2024-05-14 10:30:06.867  6966-6966  MASTG   org.owasp.mastestapp  E  test: MAS-Sensitive-Value
2024-05-14 10:30:06.869  6966-6966  MASTG   org.owasp.mastestapp  E  test: MAS-Sensitive-Value
2024-05-14 10:30:06.881  6966-6966  myLogger org.owasp.mastestapp  E  MAS-Sensitive-Key
```

Evaluasi MASTG: *"Review each of the reported instances by using keywords and known secrets."* → **FAIL**, karena password, secret key, dan IV semuanya tercatat.

**Empat observasi teknis penting dari output demo ini:**

1. **Semua level muncul, termasuk `Log.v` dan `Log.d`.** Ini bukti langsung bahwa logging verbose/debug **tidak dihapus otomatis** — perlu konfigurasi ProGuard eksplisit.
2. **`Log.wtf` muncul dua kali** — satu sebagai `Log.wtf("MASTG", ...)` (overload publik) dan satu sebagai `Log.wtf(0, "MASTG", "...", null, false, false)` (overload internal yang dipanggil di dalamnya). Ini normal, bukan dua kejadian logging terpisah. Jangan hitung ganda saat melaporkan temuan.
3. **`Log.wtf` muncul di logcat sebagai level `E`**, bukan level khusus.
4. **`Logger.severe()` muncul dengan tag `myLogger`** (nama logger) dan level `E` — memperlihatkan bahwa `java.util.logging.Logger` pada Android diarahkan ke logcat.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi | Contoh bukti |
|---|---|---|
| P1 | **Output trace kosong** — tidak ada API logging yang terpanggil sama sekali selama aplikasi di-exercise | `wc -l output.txt` → `0`. Konsisten dengan MASTG-BEST-0002: *"Ideally, a release build shouldn't use any logging functions"* |
| P2 | Ada pemanggilan logging, tetapi **hanya mencatat pesan operasional non-sensitif** | `Log.e("Net", "Request timeout")`, `Log.i("App", "Cold start completed in 412ms")` — tanpa nilai variabel sensitif |
| P3 | **Canary value tidak ditemukan** di output trace maupun di logcat setelah semua alur di-exercise | `grep -i "MASTG_CANARY_PWD_7f3a" output.txt logcat_dump.txt` → tidak ada hasil |
| P4 | Data sensitif tercatat dalam bentuk **ter-redaksi / ter-masking** | `Log.d("Profile", "email=XX, card=XXXX-XXXX-XXXX-1313")`; atau `toString()` di-override mengembalikan `Credential XX` |
| P5 | Logging **di-gate oleh `BuildConfig.DEBUG`** dan APK release terbukti tidak mencatat apa pun | Trace pada release build kosong; review jadx menunjukkan `if (BuildConfig.DEBUG) Log.d(...)` |
| P6 | Pemanggilan `Log` **sudah di-strip oleh R8/ProGuard** pada release build | `grep -rcE "Log\.(v\|d\|i)\(" ./decompiled/sources/` → 0; `proguard-rules.pro` memuat `-assumenosideeffects class android.util.Log` |
| P7 | Level log dibatasi: hanya `w`/`e` di produksi, dan isinya generik | Sesuai rekomendasi Android: *"Keep only Warning and Error logs in production"* |
| P8 | `HttpLoggingInterceptor` **tidak dipasang** di release, atau di-set `Level.NONE` | `grep "Level.BODY\|Level.HEADERS"` → tidak ada hasil pada build release |

**Contoh output yang menandakan PASS:**

```bash
$ frida-trace -U -f com.example.secureapp --runtime=v8 \
    -j 'android.util.Log!*' -j 'java.util.logging.Logger!*' -o output_raw.txt
# ... exercise aplikasi secara ekstensif dengan canary value ...
$ cat output_raw.txt | grep -E "(Log|Logger)" | grep -vE "Log\.println|Log\.isLoggable" > output.txt
$ wc -l output.txt
0 output.txt
# => Tidak ada pemanggilan API logging pada release build
```

atau — ada logging, tetapi bersih:

```
Log.i("Lifecycle", "onCreate")
Log.e("Network", "Request failed: timeout")
Log.w("Cache", "Cache miss, refetching")
```

```bash
$ grep -iE "MASTG_CANARY_PWD_7f3a|password|token|bearer|api_key|[0-9]{16}" output.txt
# (tidak ada hasil)

$ adb logcat -d | grep -i "MASTG_CANARY_PWD_7f3a"
# (tidak ada hasil)
```

Diperkuat dengan verifikasi konfigurasi build:

```proguard
# proguard-rules.pro — pemanggilan Log di-strip di release
-assumenosideeffects class android.util.Log {
    public static boolean isLoggable(java.lang.String, int);
    public static int v(...);
    public static int d(...);
    public static int i(...);
    public static int w(...);
    public static int e(...);
    public static int wtf(...);
}
```

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Uji RELEASE build — ini yang paling sering salah.** Menguji debug build akan menghasilkan banjir temuan yang tidak mencerminkan risiko sebenarnya, karena logging debug memang wajar ada di build pengembangan dan biasanya sudah di-strip di release. Jika kamu hanya punya debug build, **nyatakan itu sebagai batasan pengujian** dan jangan laporkan temuannya dengan severity produksi.

2. **Output trace kosong ≠ otomatis PASS.** Penyebab false pass:
   - Alur pemicu belum di-*exercise* (log sensitif sering ada di **handler error**, bukan happy path — karena itu penting sengaja memicu error).
   - Aplikasi memakai **Timber atau logger lain** yang tidak di-hook.
   - Logging dari **kode native** (`__android_log_print`) — tidak terlihat oleh hook Java.
   - Aplikasi mendeteksi Frida dan mengubah perilaku.
   - Hook gagal terpasang (versi frida mismatch, lupa `--runtime=v8`).
   
   **Mitigasi:** validasi script pada aplikasi yang diketahui gagal (MASTestApp) untuk membuktikan hook bekerja; korelasikan dengan **MASTG-TEST-0231** (statis) — jika TEST-0231 menemukan banyak referensi `Log.d` tetapi trace kosong, status **inkonklusif, bukan PASS**; dan bandingkan dengan `adb logcat` sebagai jalur independen.

3. **Selalu bandingkan dengan `adb logcat`.** Demo MASTG menyertakan `logcat_output.txt` justru untuk ini. Hook membuktikan API dipanggil; logcat membuktikan data **sampai ke buffer bersama** dan karenanya dapat diakses pihak lain. Dua-duanya perlu.

4. **Gunakan canary value — ini teknik paling efektif untuk test ini.** MASTG merekomendasikannya eksplisit. Tanpa canary, kamu akan sulit membedakan apakah string `"user123"` di log adalah data user sungguhan atau placeholder.

5. **Jangan hitung ganda overload internal.** Seperti `Log.wtf` di demo yang muncul dua kali. Demikian pula `Log.v/d/i/w/e` yang memanggil `Log.println` secara internal — inilah alasan filter `grep -vE "Log\.println"` ada di script demo.

6. **Perhatikan konteks, bukan hanya kata kunci.** Grep dengan pola `password` akan memicu pada `Log.d("Auth", "password field validated")` — yang **tidak** membocorkan apa pun. Sebaliknya, `Log.d("X", "u=$a p=$b")` tampak tidak berbahaya padahal membocorkan kredensial. Selalu tinjau nilai sebenarnya, dan gunakan backtrace untuk memahami konteks kode.

7. **Bedakan asal-usul log.** Gunakan backtrace untuk menentukan apakah pemanggil adalah kode aplikasi sendiri, custom logger wrapper, atau **SDK pihak ketiga**. Temuan pada SDK tetap tanggung jawab developer aplikasi, tetapi remediasinya berbeda (konfigurasi/update/ganti SDK, atau matikan debug flag SDK-nya).

8. **Severity dimodulasi oleh beberapa faktor:**

   | Faktor | Efek pada severity |
   |---|---|
   | Password / token / private key tercatat di release build | **Tertinggi** |
   | Log dikirim ke server pihak ketiga (crash reporter) | Naik — data keluar dari device |
   | Log ditulis ke file di external storage | Naik — bertaut dengan MASWE-0002, terbaca app lain |
   | PII tercatat (email, NIK, lokasi, IMEI) | Naik pada dimensi **privasi/regulasi**, meski bukan kredensial |
   | Hanya terjadi di debug build, release sudah di-strip | Turun signifikan — catat sebagai informational/hygiene |
   | Hanya detail internal non-sensitif (nama kelas, timing) | Rendah — information disclosure ringan |
   | Target device lama (< API 16) dalam `minSdkVersion` | Naik — aplikasi biasa pun bisa membaca log |

9. **Dokumentasikan bukti lengkap per temuan:** API yang dipanggil beserta level, tag, isi pesan (redaksi sebagian bila perlu tapi cukup untuk membuktikan), backtrace/lokasi kode, **jenis build yang diuji (debug/release)**, kutipan logcat yang bersesuaian, langkah reproduksi termasuk canary value yang dipakai, serta status konfigurasi ProGuard/R8. Cantumkan juga batasan (mis. logging native belum dianalisis).

---

## 4. Rekomendasi Perbaikan

### 4.1 Prinsip Utama (urutan prioritas)

**Prioritas 1 — Jangan catat data sensitif sejak awal.** Ini satu-satunya remediasi yang menghilangkan akar masalah. Semua teknik lain (stripping, redaksi) adalah lapisan pertahanan tambahan.

Berdasarkan panduan Android dan MASTG-BEST-0022, **hindari mencatat**:
- Header dan body request/response secara penuh
- Token autentikasi, cookie, session identifier, API key
- Username, alamat email, atau data pribadi lain kecuali benar-benar perlu dan terlindungi
- Objek error penuh, konteks diagnostik, metadata, nested cause, dan stack trace
- Hostname backend, endpoint staging, feature flag, nama modul/kelas internal
- Perilaku validasi sertifikat, status SSL pinning, logika retry, atau detail keamanan jaringan lainnya

```kotlin
// ❌ SALAH
Log.d(TAG, "login: user=$username pass=$password")
Log.i(TAG, "token=$accessToken")
Log.e(TAG, "API error: $response")            // response bisa memuat PII
e.printStackTrace()                            // message bisa memuat URL+token

// ✅ BENAR — hanya event operasional, tanpa nilai sensitif
Log.e(TAG, "Authentication failed")            // generik, tanpa detail
Log.w(TAG, "Network timeout on endpoint #3")
```

**Prioritas 2 — Hapus kode logging dari release build (MASTG-BEST-0002).**

MASTG-BEST-0002 menyatakan: *"Ideally, a release build shouldn't use any logging functions, making it easier to assess sensitive data exposure."*

Konfigurasi ProGuard/R8 (`proguard-rules.pro`) untuk menghapus **semua** pemanggilan `Log`:

```proguard
-assumenosideeffects class android.util.Log
{
  public static boolean isLoggable(java.lang.String, int);
  public static int v(...);
  public static int i(...);
  public static int w(...);
  public static int d(...);
  public static int e(...);
  public static int wtf(...);
}
```

Atau varian yang **mempertahankan warning & error** saja (sesuai rekomendasi Android *"Keep only Warning and Error logs in production"*) — cukup hapus baris `w(...)` dan `e(...)` dari blok di atas.

Pastikan juga shrinking benar-benar aktif:

```gradle
android {
    buildTypes {
        release {
            minifyEnabled true
            proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'),
                          'proguard-rules.pro'
        }
    }
}
```

> ⚠️ **PERINGATAN PENTING — jangan berhenti di sini.** MASTG-BEST-0002 memberi catatan kritis: konfigurasi di atas hanya menjamin *pemanggilan metode* kelas `Log` dihapus. **Jika string yang dicatat dibangun secara dinamis, kode pembangun string bisa tetap ada di bytecode.**
>
> Contoh:
> ```kotlin
> Log.v("Private key tag", "Private key [byte format]: $key")
> ```
> Bytecode hasil kompilasinya setara dengan:
> ```kotlin
> Log.v("Private key tag", StringBuilder("Private key [byte format]: ").append(key).toString())
> ```
> ProGuard menjamin pemanggilan `Log.v` dihapus. Apakah sisanya (`StringBuilder ...`) juga terhapus **bergantung pada kompleksitas kode dan versi ProGuard**.
>
> **Ini risiko keamanan nyata:** string yang (tidak terpakai itu) membocorkan data plaintext **ke dalam memori**, yang dapat diakses lewat debugger atau memory dump.
>
> MASTG menyatakan tidak ada *silver bullet* untuk masalah ini, tetapi solusi yang disarankan adalah **membuat facility logging kustom yang menerima argumen sederhana dan membangun string di dalamnya**:
> ```java
> SecureLog.v("Private key [byte format]: ", key);
> ```
> lalu konfigurasikan ProGuard untuk strip pemanggilan `SecureLog`.

**Prioritas 3 — Gate logging dengan build flag / custom logging facility.**

```kotlin
// Custom logger yang mati total di release
object AppLog {
    private const val ENABLED = BuildConfig.DEBUG

    // Argumen sederhana; string dibangun DI DALAM — mencegah StringBuilder tertinggal
    fun d(tag: String, prefix: String, value: Any?) {
        if (ENABLED) Log.d(tag, prefix + value)
    }

    fun e(tag: String, msg: String) {
        if (ENABLED) Log.e(tag, msg)
    }
}
```

Lalu strip juga kelas ini di release:

```proguard
-assumenosideeffects class com.example.AppLog { *; }
```

Untuk Timber, gunakan pola resmi: pasang `DebugTree` **hanya** di debug build.

```kotlin
// Application.onCreate()
if (BuildConfig.DEBUG) {
    Timber.plant(Timber.DebugTree())
}
// Di release: tidak ada Tree yang dipasang → Timber.d() tidak menghasilkan output
```

**Prioritas 4 — Redaksi / masking data sensitif bila logging tetap diperlukan.**

Teknik yang direkomendasikan Android:

| Teknik | Cara kerja | Catatan |
|---|---|---|
| **Tokenization** | Simpan data sensitif di vault; catat token-nya saja | Paling kuat bila korelasi tetap dibutuhkan |
| **Data masking** | Proses satu arah, sebagian data disisakan: `1234-5678-9012-3456` → `XXXX-XXXX-XXXX-1313` | ⚠️ **Jangan dipakai untuk password atau data sangat kritis** |
| **Redaction** | Sembunyikan seluruh isi field: `1234-5678-9012-3456` → `XXXX-XXXX-XXXX-XXXX` | Paling aman |
| **Filtering** | Terapkan format string di logging library; modifikasi nilai non-konstan sebelum dicatat | Dapat ditegakkan secara sistematis |

Implementasi dengan **override `toString()`** agar data sensitif tidak pernah bocor walaupun objeknya tercatat secara tidak sengaja:

```kotlin
data class Credential<T>(val data: String) {
    /** Returns a redacted value to avoid accidental inclusion in logs. */
    override fun toString() = "Credential XX"
}
```

Atau komponen sanitizer yang lebih umum:

```kotlin
data class ToMask<T>(private val data: T) {
    // Mencegah logging tak sengaja saat terjadi error
    override fun toString() = "XX"

    // Membuat akses ke data sensitif jadi eksplisit & sulit dilakukan tanpa sengaja
    fun getDataToMask(): T = data
}

data class Person(
    val email: ToMask<String>,
    val username: String
)

fun main() {
    val person = Person(ToMask("name@gmail.com"), "myname")
    println(person)                         // Person(email=XX, username=myname)
    println(person.email.getDataToMask())   // "name@gmail.com"
}
```

Pola ini efektif karena melindungi dari jalur kebocoran paling umum: seseorang mencatat **seluruh objek** (`Log.d(TAG, "$user")`) tanpa menyadari isinya.

**Prioritas 5 — Tegakkan secara struktural, jangan bergantung pada disiplin manual.**

- Gunakan **ErrorProne** dengan anotasi `@CompileTimeConstant` agar hanya konstanta waktu-kompilasi yang boleh masuk ke parameter log — ini mencegah variabel runtime tercatat, ditegakkan oleh compiler.
- Hindari isi log yang tidak dapat diprediksi.
- Konfigurasikan backend `logcat` **hanya untuk developer build**.
- Terapkan *principle of least privilege* pada data yang masuk ke log.
- Gunakan **stripping otomatis dengan R8** alih-alih penghapusan manual.

**Prioritas 6 — Tutup jalur kebocoran sekunder.**

```kotlin
// ❌ OkHttp: jangan pernah Level.BODY / Level.HEADERS di release
val logging = HttpLoggingInterceptor().apply {
    level = if (BuildConfig.DEBUG) HttpLoggingInterceptor.Level.BASIC
            else HttpLoggingInterceptor.Level.NONE
}
```

- **Jangan gunakan `printStackTrace()`.** Ganti dengan logging terkontrol yang hanya mencatat tipe exception, tanpa message maupun stack trace: `Log.e(TAG, "Op failed: ${e.javaClass.simpleName}")`.
- **Jangan tulis log ke external storage.** Bila log lokal memang diperlukan (mis. untuk dikirim ke endpoint saat online, sebagaimana skenario sah di MASTG-KNOW-0049), simpan di **internal storage** dan **enkripsi** — lihat MASTG-TEST-0200 dan MASWE-0002.
- **Audit crash reporter.** Pastikan `Crashlytics.log()` / Sentry breadcrumbs tidak memuat PII atau kredensial, karena data itu dikirim ke server pihak ketiga.
- **WebView:** jangan teruskan `ConsoleMessage` ke `Log` di release build.
- **Kode native:** hapus `__android_log_print` dari build release (mis. dengan makro `#ifndef NDEBUG`).

**Prioritas 7 — Siapkan mekanisme respons insiden.** Bila log produksi memang harus dipertahankan, siapkan **conditional flag untuk mematikan logging saat insiden**. Prioritaskan: keamanan deployment, kecepatan & kemudahan deployment, ketuntasan redaksi log, penggunaan memori, lalu biaya performa pemindaian pesan log.

### 4.2 Checklist Remediasi

- [ ] Setiap instance logging dari output trace sudah ditinjau dan diklasifikasikan (sensitif / tidak)
- [ ] Tidak ada password, PIN, token, API key, session ID, atau JWT yang dicatat
- [ ] Tidak ada material kriptografi (kunci, IV, salt, seed phrase) yang dicatat
- [ ] Tidak ada PII (nama, email, NIK, telepon, alamat, lokasi, IMEI, MAC) yang dicatat
- [ ] Tidak ada data finansial/kesehatan yang dicatat
- [ ] Tidak ada full request/response HTTP yang dicatat; `HttpLoggingInterceptor` = `Level.NONE` di release
- [ ] `printStackTrace()` sudah dihapus/diganti dengan logging terkontrol
- [ ] Tidak ada detail internal sensitif (endpoint staging, feature flag, status SSL pinning) di log
- [ ] `proguard-rules.pro` memuat `-assumenosideeffects class android.util.Log` dan `minifyEnabled true` aktif di release
- [ ] **Diverifikasi bahwa string dinamis tidak tertinggal di bytecode** setelah stripping (risiko kebocoran ke memori)
- [ ] Custom logging facility dipakai dengan argumen sederhana (string dibangun internal), dan pemanggilannya di-strip di release
- [ ] Timber `DebugTree` dipasang hanya bila `BuildConfig.DEBUG`
- [ ] Logging sensitif yang tak terhindarkan sudah di-redaksi/masking; `toString()` di-override untuk objek sensitif
- [ ] `@CompileTimeConstant` (ErrorProne) diterapkan pada parameter logging, bila memungkinkan
- [ ] Level log di produksi dibatasi hanya `w`/`e` dengan isi generik
- [ ] Log tidak ditulis ke external storage; bila log lokal perlu, ditulis ke internal storage dan ter-enkripsi
- [ ] Crash reporter (Crashlytics/Sentry) diaudit — tidak mengirim PII/kredensial ke pihak ketiga
- [ ] Logging dari kode native (`__android_log_print`) dihapus di build release
- [ ] WebView `onConsoleMessage` tidak meneruskan ke `Log` di release
- [ ] Conditional flag tersedia untuk mematikan logging saat insiden
- [ ] **Verifikasi ulang pada APK RELEASE:** jalankan kembali MASTG-TEST-0203 → output trace kosong atau bersih dari data sensitif
- [ ] **Verifikasi silang:** jalankan MASTG-TEST-0231 (statis) untuk menemukan pemanggilan logging di jalur kode yang belum di-*exercise*
- [ ] **Verifikasi logcat:** `adb logcat` + grep canary value → tidak ada hasil

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0203: Runtime Use of Logging APIs](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0203/)
- [MASTG-TEST-0231: References to Logging APIs](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0231/)
- [MASTG-TEST-0003: Testing Logs for Sensitive Data](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0003/) *(deprecated — digantikan MASTG-TEST-0203 & 0231)*
- [MASWE-0005: Insertion of Sensitive Data into Logs](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0005/)
- [MASTG-DEMO-0006: Tracing Common Logging APIs Looking for Secrets](https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0006/MASTG-DEMO-0006/)
- [MASTG-KNOW-0049: Logs](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0049/)
- [MASTG-BEST-0002: Remove Logging Code](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0002/)
- [MASTG-BEST-0022: Disable Verbose and Debug Logging in Production Builds](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0022/) *(platform iOS — prinsipnya berlaku umum)*
- [MASTG-TECH-0043: Method Hooking](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/)
- [MASTG-TECH-0005: Installing Apps](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0005/)
- [MASTG-TECH-0013: Reverse Engineering Android Apps](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/)
- [MASTG-TECH-0014: Static Analysis on Android](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/)
- [MASTG-TOOL-0001: Frida](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0001/)
- [MASTG-TOOL-0022: ProGuard](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0022/)
- [MASVS-STORAGE: Storage](https://mas.owasp.org/MASVS/05-MASVS-STORAGE/)
- [OWASP MASTG Repository (GitHub)](https://github.com/OWASP/mastg)
- [OWASP Mobile Top 10 2024 — M9: Insecure Data Storage](https://owasp.org/www-project-mobile-top-10/2023-risks/m9-insecure-data-storage)
- [OWASP Mobile Top 10 2024 — M1: Improper Credential Usage](https://owasp.org/www-project-mobile-top-10/2023-risks/m1-improper-credential-usage.html)

### 5.2 Dokumentasi Resmi Android / Google

- [Log Info Disclosure — Android Security Risks](https://developer.android.com/privacy-and-security/risks/log-info-disclosure)
- [`android.util.Log` — API reference](https://developer.android.com/reference/kotlin/android/util/Log)
- [`java.util.logging.Logger` — API reference](https://developer.android.com/reference/java/util/logging/Logger)
- [`READ_LOGS` permission — API reference](https://developer.android.com/reference/android/Manifest.permission#READ_LOGS)
- [Logcat command-line tool](https://developer.android.com/tools/logcat)
- [View logs with Logcat (Android Studio)](https://developer.android.com/studio/debug/logcat)
- [Shrink, obfuscate, and optimize your app (R8/ProGuard)](https://developer.android.com/build/shrink-code)
- [Enable shrinking, obfuscation, and optimization](https://developer.android.com/studio/build/shrink-code#enable)
- [Capture and read bug reports](https://developer.android.com/studio/debug/bug-report)
- [App security best practices](https://developer.android.com/privacy-and-security/security-best-practices)
- [Android Keystore system](https://developer.android.com/privacy-and-security/keystore)
- [ProGuard manual — example of removing logging code (Guardsquare)](https://www.guardsquare.com/en/products/proguard/manual/examples#logging)
- [ErrorProne — `@CompileTimeConstant` bug pattern](https://errorprone.info/bugpattern/CompileTimeConstant)
- [Timber — logging library (JakeWharton)](https://github.com/JakeWharton/timber)
- [OkHttp `HttpLoggingInterceptor`](https://square.github.io/okhttp/features/interceptors/)

### 5.3 Standar, Taksonomi, dan Guideline Lain

- [CWE-532: Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
- [CWE-359: Exposure of Private Personal Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/359.html)
- [CWE-117: Improper Output Neutralization for Logs](https://cwe.mitre.org/data/definitions/117.html)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [OWASP ASVS V7 — Error Handling and Logging](https://owasp.org/www-project-application-security-verification-standard/)
- [NVD — CVE-2023-21387 (Android User Backup Manager log info disclosure)](https://nvd.nist.gov/vuln/detail/CVE-2023-21387)
- [NVD — CVE-2018-6599](https://nvd.nist.gov/vuln/detail/CVE-2018-6599)
- [NIST SP 800-163 Rev.1 — Vetting the Security of Mobile Applications](https://csrc.nist.gov/publications/detail/sp/800-163/rev-1/final)
- [CISA — Principle of Least Privilege](https://www.cisa.gov/uscert/bsi/articles/knowledge/principles/least-privilege)
- [MITRE ATT&CK Mobile — T1409: Stored Application Data](https://attack.mitre.org/techniques/T1409/)
- [MITRE ATT&CK Mobile — T1636: Protected User Data](https://attack.mitre.org/techniques/T1636/)

### 5.4 Riset Keamanan & Artikel Teknis

- [USENIX Security 2023 — *Log: It's Big, It's Heavy, It's Filled with Personal Data!*](https://www.usenix.org/system/files/sec23fall-prepub-89-lyons.pdf)
- [Thore Göbel — *Please Don't Write Passwords to Android Logs*](https://thore.io/posts/2023/05/please-dont-write-passwords-to-android-logs/)
- [TechRadar — Android devices are leaking contact tracing data all over the place](https://www.techradar.com/news/android-devices-are-leaking-contact-tracing-data-all-over-the-place)
- [arXiv — Dissecting contact tracing apps in the Android platform](https://arxiv.org/pdf/2008.00214)
- [Valency Networks — Sensitive Information Exposure via System Logs (Logcat Leakage)](https://www.valencynetworks.com/kb/sensitive-information-exposure-via-system-logs.html)
- [Medium — Android Logcat: The Hidden Goldmine of Sensitive Data for Pentesters](https://medium.com/@gowthami09027/android-logcat-the-hidden-goldmine-of-sensitive-data-for-pentesters-66a11109781a)
- [PTKD Journal — Insecure logging: sensitive data in your app's logs](https://ptkd.com/journal/insecure-logging-sensitive-data-app-logs)
- [Haxoris Wiki — Tokens Leaked In Logs](https://haxoris.com/haxoris-wiki/mobile-owasp-top-10/m1-improper-credential-usage/tokens-in-logs)
- [Securium Solutions — Sensitive information using logs cause leak of user details, password, token](https://securiumsolutions.com/sensitive-information-using-logs-cause-leak-of-users-personal-details-password-token/)
- [HackTricks — Android Applications Pentesting](https://book.hacktricks.wiki/en/mobile-pentesting/android-app-pentesting/index.html)

### 5.5 Dokumentasi Tools

- [Frida — Documentation Home](https://frida.re/docs/home/)
- [Frida — `frida-trace` CLI reference](https://frida.re/docs/frida-trace/)
- [Frida — JavaScript API: `Java`](https://frida.re/docs/javascript-api/#java)
- [Frida — Android instrumentation guide](https://frida.re/docs/android/)
- [Objection — runtime mobile exploration](https://github.com/sensepost/objection)
- [pidcat — colored logcat per package](https://github.com/JakeWharton/pidcat)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [mobsfscan — static analysis untuk Android/iOS](https://github.com/MobSF/mobsfscan)
- [TruffleHog — secret scanning](https://github.com/trufflesecurity/trufflehog)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026), dokumentasi resmi Frida dan Android Developers, standar CWE/NIST/OWASP, serta riset keamanan pihak ketiga.*
