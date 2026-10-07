# MASTG-TEST-0227 Debugging Enabled for WebViews

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0227 |
| **Platform** | Android |
| **Kategori MASVS** | **MASVS-RESILIENCE** (Resilience Against Reverse Engineering and Tampering) |
| **Weakness** | **MASWE-0063** — *Debug Mechanisms Not Disabled* (weakness yang sama dengan MASTG-TEST-0226) |
| **Tipe Pengujian** | **Static**, Code |
| **Profile** | **R** (Resilience) |
| **Knowledge** | MASTG-KNOW-0028 (Anti-Debugging) |
| **Best Practice** | MASTG-BEST-0008 (Debugging Disabled for WebViews) |
| **Teknik terkait** | MASTG-TECH-0013 (Reverse Engineering Android Apps), MASTG-TECH-0014 (Static Analysis on Android) |
| **Demo terkait** | — (MASTG belum menyediakan demo untuk test ini) |
| **Test bersaudara** | **MASTG-TEST-0226** (Debuggable Flag Enabled) — weakness sama, objek berbeda: manifest vs API runtime WebView |
| **API utama** | `android.webkit.WebView.setWebContentsDebuggingEnabled(boolean)`, `android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE` |
| **CWE terkait** | CWE-489 (Active Debug Code), CWE-215 (Insertion of Sensitive Information Into Debugging Code), CWE-1244 (Internal Asset Exposed to Unsafe Debug Access) |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Kutipan langsung dari overview MASTG:

> *"The `WebView.setWebContentsDebuggingEnabled(true)` API enables debugging for **all** WebViews in the application. This feature can be useful during development, but introduces significant security risks if left enabled in production. When enabled, a connected PC can **debug, eavesdrop, or modify communication** within any WebView in the application."*
>
> *"Note that this flag works **independently** of the `debuggable` attribute (`ApplicationInfo.FLAG_DEBUGGABLE`) in the `AndroidManifest.xml` (see MASTG-TEST-0226). **Even if the app is not marked as debuggable, the WebViews can still be debugged** by calling this API."*

Poin kedua adalah **yang paling penting untuk dipahami** sebelum melanjutkan — ini bukan sekadar variasi dari MASTG-TEST-0226, melainkan **jalur risiko yang sepenuhnya independen**. Aplikasi dapat lolos MASTG-TEST-0226 dengan sempurna (`android:debuggable="false"` di manifest) dan **tetap FAIL** di test ini, karena `setWebContentsDebuggingEnabled(true)` adalah API runtime terpisah yang tidak bergantung sama sekali pada flag manifest tersebut.

### 1.2 Apa yang Sebenarnya Bisa Dilakukan Penyerang

`setWebContentsDebuggingEnabled(true)` mengaktifkan **Chrome DevTools remote debugging** untuk seluruh instance WebView dalam aplikasi (tersedia sejak Android 4.4 KitKat). Begitu aktif, WebView yang dapat di-debug akan muncul di halaman `chrome://inspect` pada komputer yang terhubung ke perangkat (via USB dengan ADB debugging aktif) — dan dari sana, siapa pun yang membuka DevTools mendapatkan **akses selevel browser penuh** terhadap konten WebView tersebut:

| Kapabilitas DevTools Protocol | Dampak keamanan |
|---|---|
| **Inspeksi & modifikasi DOM** | Melihat/mengubah struktur halaman yang dirender WebView secara real-time |
| **Eksekusi JavaScript arbitrer** dalam konteks WebView | Memanggil fungsi internal, memanipulasi state aplikasi web yang berjalan di WebView, memicu JavaScript bridge (`addJavascriptInterface`) yang mungkin terpapar ke native |
| **Monitoring lalu lintas jaringan** WebView | Melihat request/response yang dikirim WebView, termasuk header dan body — berpotensi termasuk token otentikasi bila WebView dipakai untuk alur login/OAuth |
| **Akses penyimpanan sisi klien** | Cookie, `localStorage`, `sessionStorage`, IndexedDB yang dipakai WebView — sering berisi token sesi |
| **Breakpoint pada JavaScript** | Menghentikan eksekusi untuk menganalisis alur logika bisnis yang diimplementasikan di sisi web (relevan untuk WebView yang menjalankan modul pembayaran/verifikasi) |

Ini persis kapabilitas yang tersedia bagi developer yang sah men-debug WebView-nya sendiri saat pengembangan — dan **tidak ada perbedaan** kapabilitas antara developer yang sah dengan penyerang yang berhasil terhubung ke perangkat target, selama flag ini aktif.

### 1.3 Skenario Serangan yang Realistis

MASTG-BEST-0008 secara jujur menjelaskan prasyarat yang dibutuhkan penyerang, sehingga penilaian risiko tetap proporsional:

> *"For an attacker to exploit WebView debugging, they must have **physical access** to the device (e.g., a stolen or test device) or **remote access through malware** or other malicious means. Additionally, the device must typically be **unlocked**, and the attacker would need to know the device PIN, password, or biometric authentication to gain full control and connect debugging tools like `adb` or Chrome DevTools."*

Ini konteks penting: eksploitasi test ini **bukan** serangan jarak jauh murni tanpa prasyarat — dibutuhkan salah satu dari:
- **Akses fisik ke perangkat yang unlocked** dengan USB debugging aktif (perangkat curian, perangkat pengujian yang tertinggal, perangkat kios/POS yang diakses tanpa pengawasan), **atau**
- **Malware/akses remote lain** yang sudah berhasil masuk ke perangkat dan dapat mem-forward port debugging.

Namun demikian, skenario ini **sangat relevan** untuk kategori aplikasi tertentu:
- Aplikasi **perbankan/pembayaran** yang memakai WebView untuk halaman checkout pihak ketiga (3D Secure, payment gateway) — di sinilah token pembayaran dan data kartu berlalu-lalang.
- Aplikasi dengan **login SSO/OAuth berbasis WebView** — token akses dapat dicuri langsung dari `localStorage`/cookie yang terlihat di DevTools.
- Aplikasi **enterprise/BYOD** di mana perangkat bisa hilang/dicuri dan berisi WebView yang me-render dokumen internal sensitif.
- Skenario **"evil maid"** — penyerang dengan akses fisik singkat ke perangkat unlocked (mis. saat pemiliknya lengah) dapat mengaktifkan USB debugging bila belum aktif, lalu langsung meng-inspect WebView tanpa perlu root maupun exploit apa pun.

### 1.4 Mengapa Ini Terpisah dari MASTG-TEST-0226

Tabel perbandingan untuk memperjelas relasi kedua test bersaudara ini:

| | MASTG-TEST-0226 | MASTG-TEST-0227 *(dokumen ini)* |
|---|---|---|
| **Objek yang diperiksa** | Atribut statis `android:debuggable` di `AndroidManifest.xml` | Pemanggilan API runtime `WebView.setWebContentsDebuggingEnabled()` di dalam kode |
| **Cakupan dampak** | **Seluruh proses aplikasi** dapat di-attach debugger Java (JDWP) | **Hanya WebView** yang dapat diinspeksi lewat Chrome DevTools Protocol — permukaan lebih sempit, tetapi tetap signifikan bila WebView menangani data sensitif |
| **Ketergantungan** | Berdiri sendiri — nilai atribut manifest | **Independen dari MASTG-TEST-0226** — API ini bekerja terlepas dari status `debuggable` |
| **Metode deteksi** | Baca satu atribut di manifest | Analisis kode untuk menemukan **konteks pemanggilan** API (unconditional vs bersyarat) |
| **Kompleksitas evaluasi** | Biner sederhana (`true`/`false`) | **Butuh analisis konteks** — nilai `true` saja tidak cukup untuk vonis, harus diperiksa apakah dibungkus pengecekan `FLAG_DEBUGGABLE` |

Poin terakhir adalah perbedaan metodologis paling signifikan: MASTG-TEST-0226 murni membaca nilai atribut, sementara test ini menuntut **pemahaman alur kode di sekitar pemanggilan API** — mendekati gaya pengujian pada test-test kripto sebelumnya (MASTG-TEST-0204/0205) yang juga membutuhkan verifikasi konteks, bukan sekadar pattern matching sederhana.

### 1.5 Pola Kode yang Benar (Baseline untuk Menilai Konteks)

MASTG-BEST-0008 memberi contoh kode eksplisit tentang pola yang dianggap benar:

```kotlin
if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
    if (0 != (getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE))
    { WebView.setWebContentsDebuggingEnabled(true); }
}
```

Pola ini **membungkus** pemanggilan `setWebContentsDebuggingEnabled(true)` dengan pengecekan `ApplicationInfo.FLAG_DEBUGGABLE` — sehingga WebView debugging hanya aktif **ketika aplikasi itu sendiri juga debuggable** (yakni pada build development, bukan build release). Pada build release standar (`debuggable=false`), kondisi ini tidak pernah terpenuhi, sehingga baris `setWebContentsDebuggingEnabled(true)` tidak pernah tereksekusi.

Inilah mengapa **overview MASTG secara eksplisit menyebutkan `ApplicationInfo.FLAG_DEBUGGABLE`** sebagai bagian dari langkah Observation — kehadiran pengecekan ini di sekitar pemanggilan API adalah pembeda antara kode yang aman dan yang tidak.

### 1.6 Keterbatasan Mitigasi — Diakui Eksplisit oleh MASTG

Sama seperti pola pada MASTG-TEST-0226, MASTG-BEST-0008 menegaskan bahwa menonaktifkan WebView debugging **bukan proteksi absolut**:

> *"However, disabling WebView debugging **does not eliminate all attack vectors**. An attacker could:*
> 1. *Patch the app to add calls to these APIs, then repackage and re-sign it.*
> 2. *Use runtime method hooking (Frida) to enable WebView debugging dynamically at runtime.*
>
> *Disabling WebView debugging serves as **one layer of defense** to reduce risks but should be combined with other security measures."*

Penyerang yang cukup canggih dapat:
- **Melakukan binary patching** pada APK untuk menyisipkan pemanggilan `setWebContentsDebuggingEnabled(true)` sendiri, lalu repackaging dan re-signing dengan kunci sendiri (bertaut dengan MASTG-TEST-0224/0225 — signature scheme yang kuat tidak mencegah repackaging, hanya mendeteksi bahwa hasilnya bukan APK asli).
- **Menggunakan Frida** untuk memanggil API ini secara langsung saat runtime, melewati kode aplikasi sepenuhnya — tidak peduli seberapa ketat pengecekan `FLAG_DEBUGGABLE` di kode asli, karena Frida beroperasi di luar alur kode yang diperiksa.

Ini kembali menegaskan tema yang sama dengan MASTG-TEST-0226: kontrol berbasis flag adalah **lapisan pertama**, bukan solusi tunggal, terutama untuk aplikasi berprofil R yang memerlukan resiliensi lebih tinggi.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | MASTG ID | Fungsi |
|---|---|---|
| **jadx** | MASTG-TOOL-0018 | **Dekompilasi DEX → Java** (MASTG-TECH-0013). Wajib untuk membaca **konteks** pemanggilan API — bukan hanya keberadaannya |
| **grep / ripgrep** | — | Pencarian pola pada kode hasil dekompilasi. **Metode utama** karena MASTG tidak menyediakan rule semgrep resmi untuk test ini |
| **apktool** | MASTG-TOOL-0011 | Alternatif dekompilasi; analisis smali bila diperlukan |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **semgrep** | Tidak ada rule resmi MASTG — perlu rule kustom (§3.3) untuk mendeteksi pemanggilan **tanpa** pengecekan `FLAG_DEBUGGABLE` di sekitarnya |
| **CodeQL** | Taint/control-flow analysis — dapat memverifikasi secara terprogram apakah pemanggilan API berada di dalam cabang kondisional yang memeriksa `FLAG_DEBUGGABLE` |
| **MobSF** | Analisis otomatis, dapat menandai pemanggilan `setWebContentsDebuggingEnabled(true)` sebagai temuan dalam laporan APK |
| **adb + Chrome DevTools (`chrome://inspect`)** | **Konfirmasi dinamis paling meyakinkan** — membuktikan WebView benar-benar dapat diinspeksi dari luar pada aplikasi yang berjalan (§3.5) |
| **Frida** | Untuk menguji ketahanan mitigasi (§1.6) — mencoba mengaktifkan flag ini secara paksa via hooking meski kode sumber sudah membungkusnya dengan pengecekan yang benar |

### 2.3 Prasyarat Lingkungan

- **Tidak butuh device dan tidak butuh root** untuk pemeriksaan statis dasar — cukup file APK.
- **Untuk konfirmasi dinamis** (§3.5), butuh device/emulator dengan USB debugging aktif — tidak perlu root.
- **Perhatikan bahwa API ini tersedia sejak Android 4.4 (API 19/KitKat)** — kode yang memeriksa `Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT` sebelum memanggil API ini adalah pola normal untuk kompatibilitas versi lama, **bukan** indikasi kerentanan tersendiri.
- **Uji APK final yang didistribusikan**, konsisten dengan pendekatan pada test-test bersaudara lainnya di MASVS-RESILIENCE.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0013** (*Reverse Engineering Android Apps*) untuk me-reverse engineer aplikasi.
2. Gunakan **MASTG-TECH-0014** (*Static Analysis on Android*) untuk mencari API yang relevan.

### 3.2 Metode A — grep/ripgrep pada kode dekompilasi *(metode utama, tanpa rule resmi)*

```bash
jadx -d ./decompiled ./target-app.apk
D=./decompiled/sources

# --- 1. Cari SEMUA pemanggilan setWebContentsDebuggingEnabled ---
rg -n --no-heading "setWebContentsDebuggingEnabled" $D

# --- 2. Untuk setiap hasil, tampilkan KONTEKS di sekitarnya (10 baris sebelum) ---
#     Inilah langkah krusial: nilai true SAJA tidak cukup untuk vonis
rg -n -B10 "setWebContentsDebuggingEnabled\s*\(\s*true\s*\)" $D

# --- 3. Cari referensi ke FLAG_DEBUGGABLE sebagai pembanding ---
#     (disebutkan eksplisit sebagai bagian Observation di overview MASTG)
rg -n --no-heading "FLAG_DEBUGGABLE" $D
```

**Cara membaca hasil Langkah 2** — ini inti penilaian manual test ini:

```java
// ✅ POLA AMAN — ditemukan pengecekan FLAG_DEBUGGABLE membungkus pemanggilan
if ((getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
    WebView.setWebContentsDebuggingEnabled(true);   // <-- hanya jalan bila app debuggable
}

// ❌ POLA TIDAK AMAN — dipanggil UNCONDITIONAL, tanpa pengecekan apa pun
WebView.setWebContentsDebuggingEnabled(true);        // <-- selalu aktif, termasuk di release

// ❌ POLA TIDAK AMAN — dibungkus kondisi yang TIDAK RELEVAN dengan debuggability
if (BuildConfig.ENABLE_LOGGING) {                    // <-- ini flag logging, BUKAN FLAG_DEBUGGABLE!
    WebView.setWebContentsDebuggingEnabled(true);
}
```

> Perhatikan pola ketiga — ini kesalahan yang sering terlewat: developer membungkus pemanggilan dengan kondisi **yang terlihat aman** (mis. `BuildConfig.DEBUG`, flag custom internal) tetapi **bukan** `ApplicationInfo.FLAG_DEBUGGABLE` yang sebenarnya disyaratkan MASTG. Perlu diperiksa lebih lanjut apakah `BuildConfig.DEBUG` benar-benar selalu selaras dengan status debuggable pada build release final — dalam praktiknya ini **umumnya aman** karena Android Gradle Plugin menyinkronkan `BuildConfig.DEBUG` dengan build type, tetapi ini asumsi yang perlu diverifikasi, bukan diterima begitu saja (lihat catatan penilaian §3.7).

### 3.3 Metode B — semgrep dengan rule kustom *(gate CI/CD, kontrol konteks otomatis)*

```yaml
rules:
  - id: custom-webview-debugging-unconditional
    severity: ERROR
    languages: [java, kotlin]
    message: "[MASVS-RESILIENCE] setWebContentsDebuggingEnabled(true) dipanggil tanpa terdeteksi pengecekan FLAG_DEBUGGABLE dalam pattern sederhana ini — verifikasi manual tetap diperlukan"
    patterns:
      - pattern: android.webkit.WebView.setWebContentsDebuggingEnabled(true)
      - pattern-not-inside: |
          if (...) {
            ...
            android.webkit.WebView.setWebContentsDebuggingEnabled(true);
            ...
          }

  - id: custom-webview-debugging-any-call
    severity: INFO
    languages: [java, kotlin]
    message: "[MASVS-RESILIENCE] Pemanggilan setWebContentsDebuggingEnabled ditemukan — verifikasi konteks pengecekan FLAG_DEBUGGABLE secara manual"
    pattern: android.webkit.WebView.setWebContentsDebuggingEnabled(...)
```

```bash
semgrep -c ./webview-debug-rules.yml ./decompiled/sources/
```

> **Keterbatasan pattern semgrep di atas:** rule `custom-webview-debugging-unconditional` hanya mendeteksi **ketiadaan blok `if` di sekitarnya secara struktural** — ia tidak dapat memverifikasi **isi kondisi** tersebut benar-benar memeriksa `FLAG_DEBUGGABLE` dan bukan kondisi lain yang tidak relevan (pola ketiga di §3.2). Gunakan rule `custom-webview-debugging-any-call` (severity INFO) untuk menangkap semua kandidat, lalu **selalu lakukan verifikasi manual** pada setiap hasil sebelum menandainya FAIL/PASS — ini adalah salah satu test di mana automasi murni tidak cukup dan review manual (MASTG-TECH-0023-style) benar-benar wajib.

### 3.4 Metode C — CodeQL *(memverifikasi kondisi secara terprogram)*

Ini metode yang paling mendekati verifikasi otomatis yang benar-benar dapat diandalkan untuk konteks kondisional, karena CodeQL memahami *control flow graph*, bukan sekadar pola tekstual.

```ql
/**
 * @name WebView debugging enabled without FLAG_DEBUGGABLE guard
 * @kind problem
 * @problem.severity warning
 */
import java

from MethodAccess ma, IfStmt ifStmt
where
  ma.getMethod().hasName("setWebContentsDebuggingEnabled") and
  ma.getAnArgument().(BooleanLiteral).getBooleanValue() = true and
  (
    // Tidak berada di dalam blok if apa pun
    not exists(IfStmt enclosing | ma.getEnclosingStmt().getEnclosingStmt*() = enclosing)
    or
    // Berada di dalam if, tetapi kondisinya tidak mereferensikan FLAG_DEBUGGABLE
    (
      ma.getEnclosingStmt().getEnclosingStmt*() = ifStmt and
      not ifStmt.getCondition().toString().matches("%FLAG_DEBUGGABLE%")
    )
  )
select ma, "setWebContentsDebuggingEnabled(true) dipanggil tanpa guard FLAG_DEBUGGABLE yang jelas"
```

```bash
codeql database create ./cqldb --language=java --command="./gradlew assembleDebug"
codeql database analyze ./cqldb ./webview-debug-query.ql --format=sarif-latest --output=result.sarif
```

### 3.5 Metode D — Konfirmasi dinamis dengan Chrome DevTools *(bukti eksploitabilitas paling meyakinkan)*

Ini metode yang mengangkat temuan statis menjadi **bukti dampak nyata** — sangat direkomendasikan untuk pelaporan pentest.

```bash
# 1. Install dan jalankan aplikasi target
adb install -r YourApp.apk
adb shell am start -n com.example.target/.MainActivity

# 2. Buka Chrome di komputer yang terhubung via USB dengan device
#    Navigasi ke: chrome://inspect/#devices

# 3. Bila WebView aplikasi debuggable, akan muncul dalam daftar
#    dengan opsi "inspect" -> membuka DevTools penuh terhubung ke WebView tersebut
```

**Verifikasi dari sisi command-line** (tanpa membuka Chrome secara manual), dengan memeriksa socket debug yang terbuka:

```bash
# Socket abstrak webview_devtools_remote_<pid> menandakan WebView debugging aktif
adb shell cat /proc/net/unix | grep webview_devtools_remote

# Atau via forward port dan curl endpoint JSON DevTools Protocol
adb forward tcp:9222 localabstract:webview_devtools_remote_<pid>
curl http://localhost:9222/json
# Bila WebView debugging aktif, akan mengembalikan daftar target yang dapat di-debug
```

> Bila perintah di atas mengembalikan daftar JSON berisi target WebView (bukan connection refused/kosong), ini **bukti definitif** bahwa `setWebContentsDebuggingEnabled(true)` aktif pada instance aplikasi yang sedang berjalan — melengkapi temuan statis dengan konfirmasi runtime.

### 3.6 Metode E — MobSF

```bash
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
```

Upload APK → bagian **Code Analysis** mencari pola *"WebView debugging is enabled"* atau sejenisnya bila MobSF mendeteksi pemanggilan API ini dalam kode. Catat bahwa MobSF, seperti kebanyakan scanner otomatis, **kemungkinan tidak dapat memverifikasi konteks kondisional secara andal** — hasilnya tetap perlu diverifikasi manual sesuai §3.2.

### 3.7 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Memverifikasi konteks kondisional? | Butuh device? | Membuktikan eksploitabilitas nyata? | Kapan dipakai |
|---|---|---|---|---|---|
| **A** | grep/ripgrep + review manual | Manual (wajib) | Tidak | ❌ | **Baseline utama** — tidak ada rule resmi, review manual tak terhindarkan |
| **B** | semgrep kustom | Sebagian (struktural, bukan semantik) | Tidak | ❌ | Gate CI/CD sebagai penyaring awal, bukan vonis final |
| **C** | CodeQL | ✅ **(paling andal secara otomatis)** | Tidak | ❌ | Verifikasi terprogram atas konteks kondisi |
| **D** | Chrome DevTools / socket check | — | **Ya** | ✅ **(kunci)** | **Bukti pentest paling meyakinkan** |
| **E** | MobSF | ❌ | Tidak | ❌ | Triase awal cepat |

**Kombinasi minimum yang aku rekomendasikan:** **A (grep + review manual) selalu**, karena tidak ada jalan pintas yang sepenuhnya andal untuk memverifikasi konteks kondisional secara otomatis dengan sempurna. Gunakan **C (CodeQL)** bila tersedia source code untuk mengurangi beban review manual pada aplikasi besar. Tambahkan **D (DevTools/socket)** setiap kali ditemukan FAIL, untuk mengonfirmasi dampak dan memperkuat laporan pentest dengan bukti konkret, bukan sekadar kutipan kode.

---

### 3.8 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Observation:** *"The output should list: All locations where `WebView.setWebContentsDebuggingEnabled` is called with `true` at runtime. Any references to `ApplicationInfo.FLAG_DEBUGGABLE`."*
>
> **Evaluation:** *"The test case **fails** if `WebView.setWebContentsDebuggingEnabled(true)` is called **unconditionally** or in contexts where the `ApplicationInfo.FLAG_DEBUGGABLE` flag **is not checked**."*

Perhatikan bahwa kriteria FAIL memiliki **dua kondisi yang masing-masing cukup untuk membuat FAIL** (bukan harus keduanya sekaligus):
1. Dipanggil **tanpa syarat** (unconditional), **ATAU**
2. Dipanggil di dalam konteks bersyarat, tetapi kondisinya **tidak memeriksa** `FLAG_DEBUGGABLE`.

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi | Contoh bukti |
|---|---|---|
| F1 | `setWebContentsDebuggingEnabled(true)` dipanggil **tanpa** pembungkus kondisi apa pun | `WebView.setWebContentsDebuggingEnabled(true);` berdiri sendiri, mis. langsung di `onCreate()` |
| F2 | Dipanggil di dalam `if` yang mereferensikan flag/kondisi **selain** `FLAG_DEBUGGABLE` | Dibungkus `BuildConfig.ENABLE_WEBVIEW_DEBUG` (flag custom) yang **tidak** disinkronkan dengan status debuggable aplikasi |
| F3 | Dipanggil di dalam `if` yang memeriksa `FLAG_DEBUGGABLE`, tetapi dengan **logika terbalik** (mengaktifkan debugging justru saat `FLAG_DEBUGGABLE` bernilai `false`) | Kesalahan logika negasi — jarang, tetapi harus diperiksa secara aktual, bukan diasumsikan benar hanya karena nama variabel terlihat tepat |
| F4 | Chrome DevTools / pemeriksaan socket (§3.5) mengonfirmasi WebView debugging aktif pada **APK release final** yang diinstal | `curl http://localhost:9222/json` mengembalikan daftar target WebView pada APK produksi |
| F5 | Kondisi pembungkus ada, tetapi dapat dilewati/selalu bernilai `true` karena kesalahan konfigurasi build (mis. `BuildConfig.DEBUG` yang keliru tetap `true` pada build release akibat kesalahan pipeline) | Ditemukan lewat verifikasi APK final — bertaut dengan catatan pada MASTG-TEST-0226 tentang pentingnya menguji artefak akhir |

**Contoh bukti (ilustratif — MASTG belum menyediakan demo resmi untuk test ini):**

```java
// Ditemukan di com/example/target/MainActivity.java, baris 42 (hasil dekompilasi jadx)
public class MainActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        WebView.setWebContentsDebuggingEnabled(true);   // <-- UNCONDITIONAL, tidak ada pengecekan apa pun
        WebView webView = findViewById(R.id.webview);
        webView.loadUrl("https://payment.example.com/checkout");
    }
}
```

```bash
$ rg -n -B10 "setWebContentsDebuggingEnabled\s*\(\s*true\s*\)" ./decompiled/sources/
com/example/target/MainActivity.java-40-    protected void onCreate(Bundle savedInstanceState) {
com/example/target/MainActivity.java-41-        super.onCreate(savedInstanceState);
com/example/target/MainActivity.java:42:        WebView.setWebContentsDebuggingEnabled(true);
```

Interpretasi: pemanggilan berada **langsung** di `onCreate()` tanpa pembungkus kondisi apa pun, dan WebView yang di-debug ini memuat halaman **checkout pembayaran** → **FAIL** dengan severity tinggi, karena token pembayaran dan data sensitif transaksi berpotensi terekspos lewat DevTools pada perangkat yang unlocked dengan ADB aktif.

Verifikasi dampak nyata:

```bash
$ adb install -r TargetApp-release.apk
$ adb shell am start -n com.example.target/.MainActivity
$ adb forward tcp:9222 localabstract:webview_devtools_remote_12345
$ curl http://localhost:9222/json
[
  {
    "description": "",
    "devtoolsFrontendUrl": "...",
    "title": "Checkout - Example Payment",
    "type": "page",
    "url": "https://payment.example.com/checkout",
    "webSocketDebuggerUrl": "ws://localhost:9222/devtools/page/..."
  }
]
```

Interpretasi: WebView berisi halaman checkout **benar-benar dapat di-debug** pada APK release yang sudah diinstal — bukti konkret bahwa temuan statis memiliki dampak nyata yang dapat dieksploitasi.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi | Contoh bukti |
|---|---|---|
| P1 | `setWebContentsDebuggingEnabled` **tidak pernah dipanggil** di seluruh kode aplikasi (tidak ada WebView debugging yang diaktifkan sama sekali) | `rg "setWebContentsDebuggingEnabled"` → tidak ada hasil |
| P2 | Dipanggil dengan `true`, tetapi **dibungkus** pengecekan `ApplicationInfo.FLAG_DEBUGGABLE` yang benar dan terverifikasi logikanya | Sesuai pola resmi MASTG-BEST-0008 |
| P3 | Dipanggil dengan argumen `false` secara eksplisit (menonaktifkan secara eksplisit, meski default sudah `false`) | `WebView.setWebContentsDebuggingEnabled(false);` |
| P4 | Chrome DevTools / pemeriksaan socket (§3.5) **mengonfirmasi** WebView tidak dapat diinspeksi pada APK release final | `curl http://localhost:9222/json` → connection refused / tidak ada target |

**Contoh output yang menandakan PASS:**

```bash
$ rg -n "setWebContentsDebuggingEnabled" ./decompiled/sources/
# (tidak ada hasil sama sekali)
```

Atau — dipanggil dengan pengecekan yang benar:

```java
// com/example/target/MainActivity.java
if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
    if (0 != (getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE)) {
        WebView.setWebContentsDebuggingEnabled(true);
    }
}
```

Verifikasi dinamis pada APK release final:

```bash
$ adb forward tcp:9222 localabstract:webview_devtools_remote_12345
$ curl http://localhost:9222/json
curl: (7) Failed to connect to localhost port 9222: Connection refused
```

Interpretasi: kondisi `FLAG_DEBUGGABLE` terverifikasi ada di kode, **dan** dikonfirmasi secara dinamis tidak ada socket debug yang terbuka pada APK release → **PASS**, dengan bukti ganda (statis + dinamis).

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Ini test yang menuntut verifikasi konteks manual — bukan sekadar pattern matching biner.** Berbeda dari MASTG-TEST-0226 yang murni membaca satu nilai atribut, di sini **keberadaan** pemanggilan API dengan `true` **belum cukup** untuk vonis FAIL. Wajib membaca kondisi pembungkus (bila ada) dan memverifikasi bahwa kondisi tersebut benar-benar merujuk `ApplicationInfo.FLAG_DEBUGGABLE`, bukan flag lain yang terlihat mirip secara nama tetapi berbeda secara fungsi.

2. **Jangan asumsikan `BuildConfig.DEBUG` selalu ekuivalen dengan `FLAG_DEBUGGABLE`.** Meski dalam praktik Android Gradle Plugin standar menyinkronkan keduanya, kriteria evaluasi MASTG secara spesifik menyebut `ApplicationInfo.FLAG_DEBUGGABLE` — bila aplikasi memakai `BuildConfig.DEBUG` atau flag custom lain sebagai gantinya, catat ini sebagai **temuan yang perlu verifikasi tambahan** terhadap konsistensi build pipeline, bukan otomatis diterima sebagai pola yang setara.

3. **Independensi dari MASTG-TEST-0226 berarti kedua test HARUS dijalankan terpisah, bukan diasumsikan berkorelasi.** Jangan pernah menyimpulkan "MASTG-TEST-0226 sudah PASS jadi test ini pasti juga PASS" — keduanya menguji jalur kode yang sama sekali berbeda dan tidak saling bergantung.

4. **Semgrep/tool statis lain hanya dapat menangkap pola struktural, tidak semantik.** Rule kustom di §3.3 dapat mendeteksi "ada `if` di sekitarnya atau tidak", tetapi **tidak dapat membaca makna** dari kondisi tersebut. CodeQL (Metode C) sedikit lebih baik karena memahami *control flow*, tetapi verifikasi manual akhir tetap direkomendasikan untuk kepastian penuh.

5. **Buktikan dampak dengan Chrome DevTools/socket check bila memungkinkan (dalam lingkup yang diizinkan).** Ini test lain di mana MASTG mengakui langsung bahwa temuan statis "bukan kerentanan langsung" tanpa prasyarat tambahan (akses fisik + perangkat unlocked, sesuai MASTG-BEST-0008) — sehingga bukti dampak nyata memperkuat kredibilitas laporan secara signifikan, terutama untuk WebView yang menangani data sensitif (payment, SSO).

6. **Prioritaskan review pada WebView yang menangani data sensitif.** Bila aplikasi memiliki banyak WebView untuk keperluan berbeda (bantuan/FAQ non-sensitif vs checkout pembayaran), severity temuan harus dibedakan berdasarkan **konten dan fungsi** WebView yang terpapar — bukan diperlakukan seragam hanya karena API yang dipanggil sama.

7. **Severity dimodulasi oleh konteks aplikasi dan fungsi WebView:**

   | Faktor | Severity |
   |---|---|
   | WebView yang menangani pembayaran/checkout/SSO dengan debugging aktif tanpa syarat | **Tinggi** |
   | WebView non-sensitif (mis. halaman bantuan statis) dengan debugging aktif tanpa syarat | **Menengah** |
   | Dikonfirmasi dinamis (DevTools/socket) benar-benar dapat diinspeksi pada APK produksi | **Naikkan severity** — dampak terbukti, bukan sekadar potensi |
   | Dibungkus kondisi yang salah/tidak relevan (F2) | **Tinggi** — false sense of security bagi developer |
   | Dibungkus `FLAG_DEBUGGABLE` dengan benar, atau tidak dipanggil sama sekali | **Bukan temuan** |

8. **Dokumentasikan:** lokasi kode (file + baris) hasil dekompilasi, **kutipan konteks kondisional lengkap** (bukan hanya baris pemanggilan API itu sendiri), fungsi/tujuan WebView yang terdampak (payment/SSO/general content), hasil verifikasi dinamis (DevTools/socket) bila dilakukan, serta apakah APK yang diuji adalah build final atau internal.

---

## 4. Rekomendasi Perbaikan

### 4.1 Prinsip Utama (MASTG-BEST-0008)

**Prioritas 1 — Hapus pemanggilan API ini sepenuhnya bila tidak dibutuhkan di production.** Solusi paling sederhana dan paling tahan kesalahan:

```kotlin
// ✅ PALING AMAN — tidak ada pemanggilan sama sekali di kode yang di-ship
// (hapus baris ini seluruhnya dari kode produksi bila hanya dipakai untuk debugging development)
```

**Prioritas 2 — Bila WebView debugging tetap dibutuhkan untuk keperluan development, bungkus dengan pengecekan `FLAG_DEBUGGABLE` sesuai pola resmi MASTG-BEST-0008:**

```kotlin
if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
    if (0 != (applicationContext.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE)) {
        WebView.setWebContentsDebuggingEnabled(true)
    }
}
```

**Prioritas 3 — Verifikasi bahwa mekanisme flag yang dipakai benar-benar disinkronkan dengan build type produksi**, bukan flag custom yang berisiko lolos ke build release:

```kotlin
// ✅ LEBIH BAIK — gunakan BuildConfig.DEBUG yang otomatis disinkronkan AGP,
//    DIKOMBINASIKAN dengan pengecekan FLAG_DEBUGGABLE untuk lapisan ganda
if (BuildConfig.DEBUG &&
    (0 != (applicationContext.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE))) {
    WebView.setWebContentsDebuggingEnabled(true)
}
```

**Prioritas 4 — Terapkan pertahanan berlapis untuk WebView yang menangani data sangat sensitif** (pembayaran, SSO), mengingat keterbatasan mitigasi ini terhadap penyerang canggih (§1.6):

- Terapkan **deteksi debugger aktif** (MASTG-TEST-0352/0353, MASWE-0064) sebagai lapisan tambahan yang dapat mendeteksi upaya mengaktifkan debugging secara paksa lewat hooking/patching.
- Untuk fungsi paling kritis (mis. modul pembayaran), pertimbangkan **memindahkan logika sensitif keluar dari WebView** sepenuhnya ke kode native yang lebih sulit diinspeksi lewat DevTools Protocol.
- Terapkan **certificate pinning dan validasi integritas** pada konten yang dimuat WebView, sehingga meski DevTools terbuka, modifikasi konten/trafik tetap sulit dieksploitasi tanpa terdeteksi.

**Prioritas 5 — Integrasikan pemeriksaan ini ke pipeline rilis** sebagai gate otomatis:

```bash
#!/bin/bash
# ci-verify-webview-debug.sh
APK_SOURCES_DIR=$1
if grep -rq "setWebContentsDebuggingEnabled(true)" "$APK_SOURCES_DIR" 2>/dev/null; then
    echo "[PERINGATAN] Ditemukan pemanggilan setWebContentsDebuggingEnabled(true) — verifikasi manual konteks pengecekan FLAG_DEBUGGABLE diperlukan sebelum rilis"
    exit 1
fi
echo "[OK] Tidak ditemukan pemanggilan WebView debugging"
```

> Catat bahwa gate otomatis ini bersifat **penyaring awal** (menangkap kandidat), bukan keputusan final — sesuai keterbatasan otomasi yang dijelaskan di §3.7, hasil positif dari gate ini tetap perlu direview manual untuk memastikan bukan false positive dari pola yang sudah benar.

**Prioritas 6 — Verifikasi pada APK final terdistribusi**, konsisten dengan pendekatan pada test-test bersaudara di MASVS-RESILIENCE (MASTG-TEST-0224/0225/0226) — konfigurasi build yang benar di source code tidak menjamin artefak akhir bebas dari kesalahan pipeline.

### 4.2 Checklist Remediasi

- [ ] Seluruh pemanggilan `WebView.setWebContentsDebuggingEnabled` di kode sudah diidentifikasi dan ditinjau konteksnya
- [ ] Pemanggilan yang tidak dibutuhkan di production telah dihapus sepenuhnya
- [ ] Pemanggilan yang tersisa (untuk keperluan development) dibungkus pengecekan `ApplicationInfo.FLAG_DEBUGGABLE` yang benar
- [ ] Logika kondisi pembungkus diverifikasi tidak terbalik dan benar-benar merujuk `FLAG_DEBUGGABLE` (bukan flag custom yang tidak tersinkronisasi)
- [ ] Verifikasi dinamis (Chrome DevTools / socket `webview_devtools_remote_*`) mengonfirmasi tidak ada WebView yang dapat di-debug pada APK release final
- [ ] WebView yang menangani data sensitif (pembayaran, SSO) diberi prioritas review dan pertahanan berlapis tambahan
- [ ] Untuk aplikasi profil R: deteksi debugger aktif (MASWE-0064) diimplementasikan sebagai lapisan tambahan terhadap bypass via hooking/patching
- [ ] Pemeriksaan statis diintegrasikan sebagai gate CI/CD, dengan pemahaman bahwa hasil tetap perlu verifikasi manual
- [ ] APK final terdistribusi (bukan hanya build lokal) diverifikasi terpisah
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0227 setelah setiap perubahan kode yang menyentuh konfigurasi WebView

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0227: Debugging Enabled for WebViews](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0227/)
- [MASTG-TEST-0226: Debuggable Flag Enabled in the AndroidManifest](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0226/)
- [MASTG-TEST-0352: References to Debugging Detection APIs](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0352/)
- [MASTG-TEST-0353: Runtime Use of Debugging Detection APIs](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0353/)
- [MASWE-0063: Debug Mechanisms Not Disabled](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0063/)
- [MASWE-0064: Debugger Detection Not Implemented](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0064/)
- [MASTG-KNOW-0028: Anti-Debugging](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0028/)
- [MASTG-BEST-0008: Debugging Disabled for WebViews](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0008/)
- [MASTG-TECH-0013: Reverse Engineering Android Apps](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/)
- [MASTG-TECH-0014: Static Analysis on Android](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/)
- [MASTG-TECH-0023: Reviewing Decompiled Java Code](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/)
- [MASTG-TECH-0038: Bypassing Debugger Detection (binary patching)](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0038/)
- [MASTG-TECH-0039: Repackaging (Reverse Engineering and Tampering)](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0039/)
- [MASTG-TECH-0043: Method Hooking](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/)
- [MASVS-RESILIENCE: Resilience Against Reverse Engineering and Tampering](https://mas.owasp.org/MASVS/11-MASVS-RESILIENCE/)
- [OWASP Mobile Top 10 2024 — M7: Insufficient Binary Protections](https://owasp.org/www-project-mobile-top-10/2023-risks/m7-insufficient-binary-protections.html)

### 5.2 Dokumentasi Resmi Android / Chrome DevTools

- [Chrome DevTools — Remote debugging WebViews](https://developer.chrome.com/docs/devtools/remote-debugging/webviews/)
- [Chrome DevTools — Configure WebViews for debugging](https://developer.chrome.com/docs/devtools/remote-debugging/webviews/#configure_webviews_for_debugging)
- [Android — `WebView.setWebContentsDebuggingEnabled` API reference](https://developer.android.com/reference/android/webkit/WebView#setWebContentsDebuggingEnabled(boolean))
- [Android — `ApplicationInfo.FLAG_DEBUGGABLE` API reference](https://developer.android.com/reference/android/content/pm/ApplicationInfo#FLAG_DEBUGGABLE)
- [Chrome DevTools Protocol — official documentation](https://chromedevtools.github.io/devtools-protocol/)
- [Android — WebView overview](https://developer.android.com/reference/android/webkit/WebView)
- [Android — `addJavascriptInterface` security considerations](https://developer.android.com/reference/android/webkit/WebView#addJavascriptInterface(java.lang.Object,%20java.lang.String))

### 5.3 Standar & Taksonomi

- [CWE-489: Active Debug Code](https://cwe.mitre.org/data/definitions/489.html)
- [CWE-215: Insertion of Sensitive Information Into Debugging Code](https://cwe.mitre.org/data/definitions/215.html)
- [CWE-1244: Internal Asset Exposed to Unsafe Debug Access](https://cwe.mitre.org/data/definitions/1244.html)
- [NIST SP 800-163 Rev.1 — Vetting the Security of Mobile Applications](https://csrc.nist.gov/publications/detail/sp/800-163/rev-1/final)

### 5.4 Riset & Artikel Teknis

- [HackTricks — Android WebView Attacks](https://book.hacktricks.wiki/en/mobile-pentesting/android-app-pentesting/webview-attacks.html)
- [PortSwigger — DOM-based vulnerabilities via WebView debugging (conceptual background)](https://portswigger.net/web-security/dom-based)
- [OWASP MASTG — Testing WebViews (chapter overview)](https://mas.owasp.org/MASTG/0x05h-Testing-Platform-Interaction/)

### 5.5 Dokumentasi Tools

- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [apktool — Reverse engineering Android APK files](https://apktool.org/)
- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
- [Frida — Documentation Home](https://frida.re/docs/home/)
- [adb — Android Debug Bridge](https://developer.android.com/tools/adb)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026), dokumentasi resmi Android Developers dan Chrome DevTools mengenai remote debugging WebView. Test ini belum memiliki demo (MASTG-DEMO) resmi dari MASTG, dan merupakan pasangan konseptual MASTG-TEST-0226 yang menguji jalur debugging independen (WebView, bukan proses aplikasi secara keseluruhan).*
