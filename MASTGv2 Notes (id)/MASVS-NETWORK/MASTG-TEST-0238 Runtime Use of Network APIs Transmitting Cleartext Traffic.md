# MASTG-TEST-0238 Runtime Use of Network APIs Transmitting Cleartext Traffic

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0238 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-NETWORK (MASVS-NETWORK-1: Seluruh lalu lintas jaringan dienkripsi memakai TLS) |
| **Weakness** | MASWE-0026 — *Network Traffic Not Encrypted* |
| **Tipe Pengujian** | **Dynamic, Hooks** |
| **Profile** | L1, L2 |
| **Status resmi MASTG** | **`placeholder`** — belum ada Overview/Steps/Observation/Evaluation lengkap dari MASTG |
| **Catatan resmi (satu-satunya konten yang tersedia)** | *"Using Frida, you can trace all traffic of the app, mitigating the limitation of the dynamic analysis that you do not know which app, or which location is responsible for the traffic. Using Frida (and `.backtrace()`), you can be sure this is from the analyzed app, and know the exact location. A new limitation is then that all relevant networking APIs need to be instrumented."* |
| **Test terkait** | **MASTG-TEST-0233** (lokasi statis URL HTTP), **MASTG-TEST-0235** (konfigurasi cleartext native), **MASTG-TEST-0236** (capture jaringan level-paket — punya keterbatasan atribusi yang test ini pecahkan), **MASTG-TEST-0237** (konfigurasi cross-platform framework) |
| **Demo terkait** | — (tidak ada) |
| **Rule resmi** | — (tidak relevan; ini test dinamis berbasis hooking, bukan analisis kode statis) |
| **CWE terkait** | CWE-319 (Cleartext Transmission of Sensitive Information) |

---

## 1. Penjelasan

### 1.1 Status Test Ini: Placeholder Resmi

Sama seperti MASTG-TEST-0237, test ini berstatus **`status: placeholder`** — belum ada Overview/Steps/Observation/Evaluation formal dari MASTG. Namun berbeda dari 0237, di sini MASTG menyertakan **satu paragraf `note` yang cukup substantif** yang menjelaskan *rationale* di balik pendekatan test ini secara jelas, sehingga dokumen ini dapat dibangun dengan fondasi resmi yang lebih kuat, dilengkapi riset independen untuk detail implementasi.

### 1.2 Masalah yang Dipecahkan Test Ini: Kelemahan Atribusi pada MASTG-TEST-0236

Untuk memahami mengapa test ini ada, penting membaca dulu **keterbatasan yang secara eksplisit diakui MASTG sendiri** pada MASTG-TEST-0236 (Cleartext Traffic Observed on the Network):

> *"Intercepting traffic on a network level will show all traffic the device performs, not only the single app. Linking the traffic back to a specific app can be difficult, especially when more apps are installed on the device."*
>
> *"Linking the intercepted traffic back to specific locations in the app can be difficult and requires manual analysis of the code."*

Inilah **dua celah presisi** dari pendekatan capture jaringan level-paket (proxy MITM, tcpdump, Wireshark):

1. **Masalah atribusi aplikasi**: pada perangkat uji dengan banyak aplikasi terpasang (termasuk aplikasi sistem yang aktif melakukan telemetri di latar belakang), traffic HTTP cleartext yang tertangkap proxy **belum tentu berasal dari aplikasi target** yang sedang diuji.
2. **Masalah atribusi lokasi kode**: bahkan setelah dipastikan traffic berasal dari aplikasi target, proxy/capture tool **tidak memberi tahu baris kode mana** yang bertanggung jawab membuat request tersebut — penguji harus menebak dan menelusuri manual berdasarkan konteks URL/payload.

Catatan resmi MASTG-TEST-0238 secara eksplisit menyatakan **solusi** untuk kedua masalah ini:

> *"Using Frida, you can trace all traffic of the app, mitigating the limitation of the dynamic analysis that you do not know which app, or which location is responsible for the traffic. Using Frida (and `.backtrace()`), you can be sure this is from the analyzed app, and know the exact location."*

Karena Frida melakukan **instrumentasi langsung pada proses aplikasi target** (bukan mengintersepsi paket di level jaringan), setiap pemanggilan API networking yang ter-hook **pasti berasal dari proses aplikasi yang sedang diinstrumentasi** — masalah atribusi aplikasi (#1) terpecahkan secara struktural. Dan dengan memanggil `Java.use("java.lang.Throwable").$new().getStackTrace()` atau `Thread.currentThread().getStackTrace()` pada titik hook, penguji mendapatkan **stack trace lengkap** yang menunjukkan persis fungsi/kelas mana dalam kode aplikasi yang memicu pemanggilan tersebut — masalah atribusi lokasi kode (#2) juga terpecahkan.

### 1.3 Keterbatasan Baru yang Muncul: Cakupan Instrumentasi

MASTG secara jujur mengakui trade-off dari pendekatan ini di kalimat penutup `note`:

> *"A new limitation is then that all relevant networking APIs need to be instrumented."*

Berbeda dari MASTG-TEST-0236 yang menangkap **semua** traffic tanpa peduli API apa yang dipakai (karena ia bekerja di level paket jaringan, bukan level API), pendekatan hooking Frida **hanya efektif untuk API yang benar-benar di-hook**. Bila skrip Frida hanya meng-hook `HttpURLConnection` tapi aplikasi diam-diam memakai `OkHttp` versi tertentu atau bahkan `SSLSocket`/socket mentah untuk sebagian traffic-nya, request lewat jalur yang tidak di-hook tersebut **akan lolos tanpa terdeteksi** — bukan karena tidak cleartext, tapi karena instrumentasinya tidak lengkap.

Ini mengapa **daftar API yang perlu di-hook** (§2, §3.2) menjadi bagian paling krusial dari implementasi test ini — semakin lengkap cakupan API yang diinstrumentasi, semakin dapat diandalkan hasil negatifnya (tidak ada temuan ≠ pasti aman, kecuali cakupan hooking benar-benar menyeluruh).

### 1.4 Posisi Test Ini dalam Rangkaian Lengkap MASVS-NETWORK Cleartext

Melengkapi diagram yang sudah dibangun di dokumen MASTG-TEST-0233/0235/0237, berikut posisi lengkap MASTG-TEST-0238:

```
TEST-0233 (statis)     ──► Temukan lokasi kode string http://
TEST-0235 (statis)     ──► Periksa apakah konfigurasi native mengizinkan cleartext
TEST-0237 (statis+dinamis) ──► Periksa konfigurasi framework cross-platform (Flutter/RN/Cordova)
        │
        ▼
TEST-0238 (dinamis, hooks)  ──► Hook SEMUA API networking yang relevan, tangkap
        │                        pemanggilan cleartext BESERTA lokasi kode pemicunya
        ▼
TEST-0236 (dinamis, network) ──► Capture paket mentah di jaringan — bukti definitif
                                  bahwa data BENAR-BENAR terkirim di kabel
```

TEST-0238 menempati posisi unik: ia **satu-satunya** test dalam rangkaian ini yang secara bersamaan memberi (a) bukti dinamis nyata bahwa API tersebut **benar-benar dipanggil**, dan (b) atribusi presisi ke **lokasi kode** pemicunya — kombinasi yang tidak dimiliki baik oleh analisis statis murni (yang tidak tahu apa yang benar-benar tereksekusi) maupun capture jaringan murni (yang tidak tahu lokasi kode/app mana yang bertanggung jawab).

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **Frida** | Instrumentasi dinamis inti — hooking API networking dan pengambilan stack trace |
| **frida-tools** (`frida`, `frida-trace`) | CLI untuk menjalankan skrip hook dan melakukan tracing cepat tanpa menulis skrip kustom |
| **objection** | Wrapper Frida siap pakai — memiliki modul `android sslpinning disable` dan kemampuan tracing kelas/method tanpa perlu menulis JavaScript dari nol |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **r0capture** | Skrip Python berbasis Frida yang dirancang khusus untuk *"packet capture universal"* di level aplikasi — meng-hook `HttpURLConnection`, `OkHttp` versi 1/3/4, `Retrofit`/`Volley`, serta mendukung protokol non-HTTP (WebSocket, FTP, XMPP, IMAP, SMTP, Protobuf) sekaligus versi TLS-nya. Cocok sebagai **jalan pintas** bila tidak ingin menulis skrip hook API satu per satu — sudah menangani sebagian besar framework HTTP populer sekaligus |
| **frida_ssl_logger** | Basis dari r0capture, fokus pada logging data yang lewat lapisan SSL/TLS sebelum dienkripsi — berguna untuk melihat payload plaintext yang **akan** dienkripsi (relevan untuk memverifikasi PASS: pastikan data sensitif memang lewat jalur TLS) |
| **Inspeckage** | Tool analisis dinamis Android berbasis Xposed/Frida yang menyediakan dashboard web untuk memonitor pemanggilan API (termasuk networking) secara visual, tanpa perlu menulis skrip |
| **HTTP Toolkit** | Proxy MITM dengan auto-setup sertifikat + interceptor — melengkapi hasil hooking dengan tampilan traffic HTTP yang lebih ramah baca |
| **PCAPdroid** | Untuk korelasi hasil hooking dengan capture jaringan mentah (MASTG-TEST-0236) tanpa memerlukan root |

### 2.3 Prasyarat Lingkungan

- **Butuh device/emulator dengan Frida server terpasang** — tidak seperti test statis lain di seri ini, test ini murni dinamis dan tidak dapat dilakukan hanya dengan file APK.
- **Root atau `frida-gadget` yang di-inject** untuk aplikasi non-debuggable pada perangkat non-root.
- **Interaksi menyeluruh dengan aplikasi** sangat penting — sesuai sifat pengujian dinamis, jalur kode yang tidak dieksekusi selama sesi pengujian tidak akan pernah terdeteksi (lihat juga catatan MASTG-TEST-0236 tentang hasil yang "likely not exhaustive").
- **Inventarisasi API yang akan di-hook harus dilakukan di awal** (idealnya dipandu oleh hasil MASTG-TEST-0233 statis — API apa saja yang benar-benar dipakai aplikasi target) agar cakupan instrumentasi (§1.3) semaksimal mungkin.

---

## 3. Cara Pengujian

Karena tidak ada langkah resmi rinci (status placeholder), bagian ini disusun dari elaborasi `note` resmi MASTG ditambah riset independen tentang praktik hooking networking API Android yang komprehensif.

### 3.1 Langkah Umum (Elaborasi dari `Note` Resmi)

1. Identifikasi seluruh API networking yang berpotensi dipakai aplikasi (idealnya berdasarkan temuan MASTG-TEST-0233).
2. Tulis/pakai skrip Frida yang meng-hook **setiap** API tersebut.
3. Pada setiap hook, tangkap: (a) URL/host tujuan, (b) skema (`http`/`https`), (c) **stack trace** pemanggil.
4. Interaksi menyeluruh dengan aplikasi untuk memicu sebanyak mungkin jalur kode.
5. Filter hasil untuk skema `http://` dan analisis stack trace untuk menentukan lokasi kode sumbernya.

### 3.2 Metode A — Skrip Frida Kustom Meng-hook Seluruh Lapisan Networking Android *(metode utama, langsung mengimplementasikan `note` resmi)*

Daftar API yang perlu di-hook untuk cakupan menyeluruh (menjawab keterbatasan §1.3):

```javascript
// hook-all-networking-cleartext.js
Java.perform(function () {
    function getBacktrace() {
        return Java.use("android.util.Log").getStackTraceString(
            Java.use("java.lang.Exception").$new()
        );
    }

    function reportIfCleartext(apiName, urlString) {
        if (urlString && urlString.toLowerCase().indexOf("http://") === 0) {
            console.log("\n[!] CLEARTEXT terdeteksi via " + apiName);
            console.log("    URL: " + urlString);
            console.log("    Stack trace:\n" + getBacktrace());
        }
    }

    // 1. java.net.URL — dasar dari HttpURLConnection
    try {
        var URL = Java.use("java.net.URL");
        URL.$init.overload("java.lang.String").implementation = function (spec) {
            reportIfCleartext("java.net.URL", spec);
            return this.$init(spec);
        };
    } catch (e) { console.log("[x] java.net.URL hook gagal: " + e); }

    // 2. OkHttp3 — Request.Builder().url()
    try {
        var RequestBuilder = Java.use("okhttp3.Request$Builder");
        RequestBuilder.url.overload("java.lang.String").implementation = function (url) {
            reportIfCleartext("OkHttp3 Request.Builder", url);
            return this.url(url);
        };
    } catch (e) { console.log("[x] OkHttp3 hook gagal (mungkin tidak dipakai/di-obfuscate): " + e); }

    // 3. OkHttp3 — HttpUrl.parse() (kadang dipakai langsung tanpa Request.Builder)
    try {
        var HttpUrl = Java.use("okhttp3.HttpUrl");
        HttpUrl.parse.overload("java.lang.String").implementation = function (url) {
            reportIfCleartext("OkHttp3 HttpUrl.parse", url);
            return this.parse(url);
        };
    } catch (e) { console.log("[x] OkHttp3 HttpUrl hook gagal: " + e); }

    // 4. Apache HttpClient (legacy — masih ditemukan di aplikasi lawas/library lama)
    try {
        var HttpGet = Java.use("org.apache.http.client.methods.HttpGet");
        HttpGet.$init.overload("java.lang.String").implementation = function (uri) {
            reportIfCleartext("Apache HttpClient (HttpGet)", uri);
            return this.$init(uri);
        };
    } catch (e) { console.log("[x] Apache HttpClient tidak ditemukan (umum untuk app modern): " + e); }

    // 5. Volley (RequestQueue biasanya dibangun di atas HttpURLConnection/OkHttp,
    //    tapi StringRequest/JsonObjectRequest menerima URL langsung sebagai konstruktor)
    try {
        var StringRequest = Java.use("com.android.volley.toolbox.StringRequest");
        StringRequest.$init.overload("int", "java.lang.String", "com.android.volley.Response$Listener", "com.android.volley.Response$ErrorListener")
            .implementation = function (method, url, listener, errorListener) {
                reportIfCleartext("Volley StringRequest", url);
                return this.$init(method, url, listener, errorListener);
            };
    } catch (e) { console.log("[x] Volley tidak ditemukan: " + e); }

    // 6. WebView.loadUrl — traffic yang dimuat browser tertanam
    try {
        var WebView = Java.use("android.webkit.WebView");
        WebView.loadUrl.overload("java.lang.String").implementation = function (url) {
            reportIfCleartext("WebView.loadUrl", url);
            return this.loadUrl(url);
        };
    } catch (e) { console.log("[x] WebView hook gagal: " + e); }

    // 7. SSLSocketFactory.createSocket — lapisan socket mentah (lihat MASTG-TEST-0234)
    //    Catatan: SSLSocket secara definisi selalu TLS, tapi cek plain Socket berikut ini
    //    penting untuk menangkap koneksi non-TLS yang dibangun manual
    try {
        var Socket = Java.use("java.net.Socket");
        Socket.$init.overload("java.lang.String", "int").implementation = function (host, port) {
            console.log("\n[?] Plain java.net.Socket dibuat ke " + host + ":" + port
                + " (periksa manual apakah ini dibungkus TLS setelahnya)");
            console.log("    Stack trace:\n" + getBacktrace());
            return this.$init(host, port);
        };
    } catch (e) { console.log("[x] Socket hook gagal: " + e); }
});
```

```bash
frida -U -f com.target.app -l hook-all-networking-cleartext.js --no-pause
# Berinteraksi menyeluruh dengan aplikasi di sini
```

### 3.3 Metode B — r0capture (cakupan API siap pakai, mengurangi risiko celah instrumentasi)

Karena keterbatasan inti test ini adalah **kelengkapan cakupan API** (§1.3), memakai tool yang sudah mendukung banyak framework sekaligus mengurangi risiko API yang lolos dari instrumentasi kustom:

```bash
git clone https://github.com/r0ysue/r0capture
cd r0capture
frida-server &  # di device/emulator, sesuai arsitektur
python3 r0capture.py -U -f com.target.app -v -p output.pcap
```

Hasil `output.pcap` dapat dibuka di Wireshark, dan karena r0capture bekerja dengan mem-bypass pinning sekaligus menangkap plaintext sebelum/sesudah enkripsi TLS, hasil capture-nya **secara efektif menyatukan** kemampuan MASTG-TEST-0238 (atribusi lokasi via hook API) dengan kemudahan analisis format pcap standar MASTG-TEST-0236.

### 3.4 Metode C — objection (tanpa menulis skrip Frida kustom)

```bash
objection -g com.target.app explore
# Di dalam console objection:
android hooking watch class_method okhttp3.Request$Builder.url --dump-args
android hooking watch class_method java.net.URL.<init> --dump-args --dump-backtrace
```

Perintah `--dump-backtrace` di objection secara langsung mengimplementasikan persis apa yang diminta `note` resmi MASTG — memanggil `.backtrace()` untuk memastikan lokasi kode pemicu tanpa perlu menulis JavaScript sendiri.

### 3.5 Metode D — Inspeckage (dashboard visual, cocok untuk eksplorasi cepat non-scripted)

```bash
# Setelah Inspeckage terpasang di device dan dikonfigurasi menargetkan aplikasi
adb forward tcp:8008 tcp:8008
# Buka http://localhost:8008 di browser, pilih tab "Network" untuk melihat
# seluruh pemanggilan API HTTP secara real-time saat aplikasi dipakai
```

### 3.6 Metode E — Verifikasi Cakupan Instrumentasi (menjawab keterbatasan §1.3 secara langsung)

Untuk memvalidasi bahwa hook Metode A benar-benar menangkap semua traffic (bukan karena API yang dipakai aplikasi berbeda dari yang di-hook), jalankan **bersamaan** dengan capture jaringan independen (MASTG-TEST-0236):

```bash
# Terminal 1: hook Frida (Metode A/B)
frida -U -f com.target.app -l hook-all-networking-cleartext.js --no-pause

# Terminal 2: capture jaringan independen secara paralel
adb shell am start ... # setelah aplikasi berjalan
mitmdump -w capture.mitm
```

Bandingkan jumlah dan detail request yang tertangkap Frida vs jumlah koneksi yang tertangkap capture jaringan. **Bila capture jaringan menunjukkan lebih banyak koneksi HTTP dibanding yang berhasil di-hook Frida**, ini bukti langsung adanya API yang belum ter-instrumentasi (celah §1.3) — periksa koneksi yang "hilang" tersebut untuk mengidentifikasi API/library apa yang belum ter-cover skrip hook.

### 3.7 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Kelebihan | Kapan dipakai |
|---|---|---|---|
| **A** | Skrip Frida kustom | Kontrol penuh atas API mana yang di-hook + stack trace detail | Baseline utama, disesuaikan API spesifik aplikasi target |
| **B** | r0capture | Cakupan API siap pakai (OkHttp 1/3/4, Volley, dll.), output pcap standar | Mengurangi risiko celah instrumentasi tanpa menulis skrip dari nol |
| **C** | objection | Cepat, tanpa scripting, `--dump-backtrace` built-in | Eksplorasi awal cepat, verifikasi ad-hoc |
| **D** | Inspeckage | Dashboard visual, ramah untuk penguji non-teknis-scripting | Demo/presentasi temuan, eksplorasi cepat |
| **E** | Frida + capture jaringan paralel | Memvalidasi kelengkapan cakupan hook | **Wajib** sebelum menyimpulkan hasil negatif (tidak ada temuan) sebagai PASS |

**Kombinasi minimum yang aku rekomendasikan:** **A atau B (hooking komprehensif) → E (validasi cakupan lewat capture paralel) → korelasi dengan MASTG-TEST-0236** untuk konfirmasi akhir bahwa temuan hook benar-benar termanifestasi sebagai paket nyata di jaringan.

---

### 3.8 Kriteria Evaluasi: Positive Case & Negative Case

Karena tidak ada klausul Evaluation resmi (status placeholder), kriteria berikut diturunkan dari prinsip MASWE-0026 dan `note` resmi test ini.

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Hook API networking manapun (Metode A/B/C/D) menangkap pemanggilan dengan skema `http://` **selama interaksi normal aplikasi** (bukan hanya saat dipaksa lewat input abnormal) |
| F2 | Stack trace hasil hook menunjukkan pemanggilan tersebut berasal dari **kode aplikasi sendiri** (bukan dari SDK sistem/OS yang independen dari kendali developer) |
| F3 | Payload/data yang menyertai request cleartext tersebut (dilihat lewat r0capture/frida_ssl_logger) mengandung data sensitif (kredensial, token, PII) |
| F4 | Validasi cakupan (Metode E) mengonfirmasi bahwa traffic cleartext yang terlihat di capture jaringan **memang berasal** dari pemanggilan API yang berhasil di-hook (bukan false alarm dari aplikasi lain di perangkat) |

**Contoh bukti (ilustratif — MASTG belum menyediakan demo resmi untuk test ini):**

```
[!] CLEARTEXT terdeteksi via OkHttp3 Request.Builder
    URL: http://analytics-legacy.example.com/track?event=app_open&user_id=8827
    Stack trace:
        at com.example.target.analytics.LegacyTracker.trackEvent(LegacyTracker.java:47)
        at com.example.target.MainActivity.onCreate(MainActivity.java:32)
        at android.app.Activity.performCreate(Activity.java:8000)
```

Interpretasi: stack trace menunjukkan dengan tepat `LegacyTracker.trackEvent()` di baris 47 sebagai sumber pemanggilan, dipicu dari `MainActivity.onCreate()` — memberi lokasi kode presisi untuk remediasi, sesuatu yang tidak mungkin diperoleh hanya dari capture jaringan MASTG-TEST-0236 semata.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Seluruh hook API (dengan cakupan tervalidasi via Metode E) **tidak pernah** menangkap skema `http://` selama sesi pengujian menyeluruh |
| P2 | Ditemukan pemanggilan `http://`, tetapi stack trace mengonfirmasi itu berasal dari **SDK pihak ketiga** yang terbukti melakukan **redirect otomatis ke HTTPS** di level library sebelum data benar-benar dikirim (dikonfirmasi lewat korelasi MASTG-TEST-0236 yang tidak menunjukkan paket cleartext nyata) |
| P3 | Validasi cakupan (Metode E) menunjukkan jumlah koneksi yang tertangkap Frida **konsisten** dengan capture jaringan independen, dan keduanya sepakat tidak ada cleartext |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Hasil "tidak ditemukan apa-apa" TIDAK OTOMATIS berarti PASS** — ini catatan terpenting dari seluruh dokumen ini, langsung dari keterbatasan yang diakui resmi di §1.3. Selalu validasi cakupan instrumentasi dengan Metode E sebelum menyimpulkan PASS.

2. **Stack trace adalah nilai tambah unik test ini — manfaatkan sepenuhnya untuk laporan.** Jangan hanya melaporkan "ditemukan cleartext di URL X" seperti pada test capture jaringan biasa — sertakan **lokasi kode presisi** (kelas, method, baris) yang menjadi keunggulan khas metodologi test ini dibanding MASTG-TEST-0236.

3. **Perluas cakupan hook secara iteratif berdasarkan temuan MASTG-TEST-0233.** Bila analisis statis (MASTG-TEST-0233) menemukan referensi ke library HTTP yang tidak tercakup skrip hook baku (§3.2), tambahkan hook khusus untuk library tersebut sebelum menyimpulkan hasil pengujian dinamis final.

4. **Interaksi aplikasi yang tidak menyeluruh adalah sumber false negative terbesar** — sifat dinamis dari test ini mewarisi keterbatasan yang sama seperti diakui MASTG-TEST-0236 ("results ... are likely not exhaustive"). Jalur kode yang jarang tereksekusi (fitur premium, alur error tertentu) tetap berisiko luput meski instrumentasi API sudah lengkap.

5. **Severity dimodulasi oleh jenis data dalam payload dan kemudahan reproduksi:**

   | Faktor | Severity |
   |---|---|
   | Data sensitif terkirim cleartext, mudah direproduksi di alur utama aplikasi | **Kritis** |
   | Data non-sensitif (telemetri) terkirim cleartext | **Menengah** |
   | Cleartext hanya terjadi pada kondisi tepi (edge case) yang jarang terjadi | **Rendah/Menengah** tergantung sensitivitas data |

6. **Dokumentasikan:** daftar API yang di-hook (untuk transparansi cakupan instrumentasi), hasil validasi cakupan (Metode E), setiap temuan lengkap dengan URL, payload, dan stack trace, serta korelasi dengan hasil MASTG-TEST-0236 bila tersedia.

---

## 4. Rekomendasi Perbaikan

### 4.1 Perbaikan di Level Kode (Lokasi Presisi dari Stack Trace)

Manfaatkan lokasi kode presisi yang diberikan test ini untuk remediasi langsung tanpa perlu menebak:

```java
// SEBELUM (ditemukan via stack trace: LegacyTracker.java:47)
String endpoint = "http://analytics-legacy.example.com/track";

// SESUDAH
String endpoint = "https://analytics-legacy.example.com/track";
```

### 4.2 Integrasikan Pengujian Ini ke Pipeline QA Otomatis

```bash
#!/bin/bash
# ci-dynamic-cleartext-check.sh — jalankan di emulator sebagai bagian dari smoke test
frida -U -f com.target.app -l hook-all-networking-cleartext.js --no-pause &
FRIDA_PID=$!
sleep 5
# Jalankan skenario UI test otomatis (Espresso/UIAutomator) untuk memicu jalur kode
./run-ui-test-suite.sh
kill $FRIDA_PID
```

### 4.3 Perluas Cakupan Instrumentasi Sesuai Dependency Aplikasi

Selalu sesuaikan daftar hook (§3.2) dengan hasil audit dependency proyek (`build.gradle`) — bila aplikasi memakai library HTTP yang tidak tercakup skrip baku (mis. Ktor, Retrofit dengan custom `CallAdapter`, atau SDK vendor proprietary), tambahkan hook khusus untuk API tersebut.

### 4.4 Checklist Remediasi

- [ ] Skrip hook mencakup seluruh library networking yang teridentifikasi lewat audit dependency proyek
- [ ] Validasi cakupan instrumentasi (Metode E) sudah dilakukan dan dikonfirmasi konsisten dengan capture jaringan independen
- [ ] Setiap temuan cleartext sudah diperbaiki di lokasi kode presisi yang ditunjukkan stack trace
- [ ] Pengujian sudah mencakup interaksi menyeluruh dengan seluruh fitur aplikasi, termasuk alur error dan fitur yang jarang dipakai
- [ ] Hasil dikorelasikan dengan MASTG-TEST-0233 (statis), MASTG-TEST-0235/0237 (konfigurasi), dan MASTG-TEST-0236 (capture jaringan) untuk gambaran lengkap
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0238 pada build final setelah remediasi

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0238: Runtime Use of Network APIs Transmitting Cleartext Traffic](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0238/)
- [MASTG-TEST-0236: Cleartext Traffic Observed on the Network](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0236/)
- [MASTG-TEST-0233: Hardcoded HTTP URLs](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0233/)
- [MASTG-TEST-0235: Android App Configurations Allowing Cleartext Traffic](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0235/)
- [MASWE-0026: Network Traffic Not Encrypted](https://mas.owasp.org/MASWE/MASVS-NETWORK/MASWE-0026/)
- [OWASP Mobile Top 10 2024 — M5: Insecure Communication](https://owasp.org/www-project-mobile-top-10/2023-risks/m5-insecure-communication)

### 5.2 Riset dan Tools Pihak Ketiga

- [r0ysue/r0capture — Universal Android application layer packet capture script (GitHub)](https://github.com/r0ysue/r0capture)
- [frida_ssl_logger — basis teknis r0capture](https://github.com/google/frida_ssl_logger)
- [Pentest-Tools.com — How to extract TLS secrets from Android apps using Frida and Wireshark](https://pentest-tools.com/blog/extract-tls-secrets)
- [Inspeckage — Android Package Inspector (dashboard dinamis berbasis Xposed/Frida)](https://github.com/ac-pm/Inspeckage)
- [Objection — Runtime Mobile Exploration toolkit](https://github.com/sensepost/objection)
- [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)

### 5.3 Dokumentasi Tools

- [Frida — Dynamic instrumentation toolkit](https://frida.re/docs/javascript-api/)
- [Frida — Java API reference (Java.perform, Java.use)](https://frida.re/docs/javascript-api/#java)
- [OkHttp — Documentation](https://square.github.io/okhttp/)
- [HTTP Toolkit](https://httptoolkit.com/)
- [PCAPdroid](https://github.com/emanuele-f/PCAPdroid)
- [mitmproxy](https://mitmproxy.org/)

---

*Dokumen ini disusun terutama dari elaborasi catatan resmi (`note`) MASTG-TEST-0238 yang berstatus **placeholder**, dilengkapi riset independen tentang praktik hooking Frida komprehensif untuk API networking Android dan tool pihak ketiga (r0capture, Inspeckage, objection). Nilai unik test ini — dibanding MASTG-TEST-0236 — adalah kemampuannya memberi **atribusi presisi** (aplikasi mana, lokasi kode mana) yang secara eksplisit diakui MASTG sebagai keterbatasan capture jaringan level-paket biasa; namun keandalannya bergantung penuh pada kelengkapan cakupan API yang diinstrumentasi, sehingga validasi cakupan (§3.6) menjadi langkah yang tidak boleh dilewatkan.*
