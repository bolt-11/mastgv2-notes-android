# MASTG-TEST-0217 Insecure TLS Protocols Explicitly Allowed in Code

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0217 |
| **Platform** | Android |
| **Kategori MASVS** | **MASVS-NETWORK** (MASVS-NETWORK-1: Aplikasi mengamankan seluruh lalu lintas jaringan sesuai praktik terkini) |
| **Weakness** | **MASWE-0026** — *Network Traffic Not Encrypted* |
| **Tipe Pengujian** | **Static**, Code |
| **Profile** | L1, L2 |
| **Teknik terkait** | MASTG-TECH-0013 (Reverse Engineering Android Apps), MASTG-TECH-0014 (Static Analysis on Android), MASTG-TECH-0023 (Reviewing Decompiled Java Code) |
| **Demo terkait** | — (MASTG belum menyediakan demo untuk test ini) |
| **APIs utama** | `javax.net.ssl.SSLContext.getInstance(String)`, `javax.net.ssl.SSLSocket.setEnabledProtocols(String[])`, `okhttp3.ConnectionSpec` (`COMPATIBLE_TLS`, `tlsVersions(...)`, `connectionSpecs(...)`) |
| **CWE terkait** | CWE-326 (Inadequate Encryption Strength), CWE-327 (Use of a Broken or Risky Cryptographic Algorithm), CWE-757 (Selection of Less-Secure Algorithm During Negotiation / 'Algorithm Downgrade'), CWE-319 (Cleartext Transmission of Sensitive Information) |
| **Standar acuan** | RFC 8996 (deprecating TLS 1.0/1.1), RFC 8446 (TLS 1.3), NIST SP 800-52 Rev. 2, PCI DSS 4.0 |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Test ini mencari, melalui analisis statis, **penggunaan versi TLS yang tidak aman yang secara eksplisit diaktifkan di dalam kode** aplikasi Android.

Kutipan langsung dari overview MASTG:

> *"The Android Network Security Configuration does not provide direct control over specific TLS versions (unlike iOS), and starting with Android 10, TLS v1.3 is enabled by default for all TLS connections."*
>
> *"There are still several ways to enable insecure versions of TLS..."*

Poin pertama sangat penting untuk memahami mengapa test ini bersifat **statis dan berbasis kode** — bukan berbasis konfigurasi seperti kebanyakan test MASVS-NETWORK lainnya:

- Di **iOS**, versi TLS minimum diatur secara deklaratif lewat `NSExceptionMinimumTLSVersion` di `Info.plist`.
- Di **Android, tidak ada mekanisme deklaratif setara**. Android Network Security Configuration (`network_security_config.xml`) mengontrol trust anchor, cleartext, dan pinning — **tetapi tidak versi TLS**.

Konsekuensinya: satu-satunya cara aplikasi Android menurunkan versi TLS adalah **melalui kode**, lewat API JCA atau library pihak ketiga. Karena itu, satu-satunya cara mendeteksinya adalah dengan **membaca kode**.

### 1.2 Kabar Baik: Default Android Sudah Aman

Sebelum masuk ke deteksi, penting memahami baseline-nya agar penilaian proporsional:

- **Sejak Android 10 (API 29), TLS 1.3 aktif secara default** untuk semua koneksi TLS.
- Android modern **sudah menonaktifkan** SSLv3, dan TLS 1.0/1.1 secara bertahap dihapus dari platform.
- Aplikasi yang **tidak menyentuh konfigurasi TLS sama sekali** umumnya sudah aman — sistem memilih versi terbaik yang didukung kedua pihak.

Artinya: **test ini mencari penyimpangan dari default yang sudah aman.** Kelemahan muncul ketika developer secara **sengaja** memaksa versi lama — biasanya karena alasan kompatibilitas dengan server lama, warisan kode, atau salin-tempel dari StackOverflow. Ini berbeda dari test kripto lain di mana masalahnya adalah "lupa mengonfigurasi"; di sini masalahnya adalah "mengonfigurasi secara salah".

### 1.3 Mengapa TLS 1.0/1.1 Berbahaya

TLS 1.0 dan 1.1 secara resmi **di-deprecate oleh IETF pada Maret 2021 lewat RFC 8996** dan dipindahkan ke status *Historic*. Alasannya:

| Kerentanan | Menyerang | Dampak |
|---|---|---|
| **BEAST** (CVE-2011-3389) | TLS 1.0 — IV CBC yang dapat diprediksi | Pemulihan plaintext seperti session cookie |
| **POODLE** | SSL 3.0, juga TLS 1.0/1.1 (padding) | Dekripsi data via padding oracle |
| **Lucky 13, Sweet32** | Cipher CBC & block 64-bit yang umum di TLS lama | Pemulihan plaintext |
| **Downgrade attack** (CWE-757) | Negosiasi versi | Penyerang MitM memaksa turun ke versi paling lemah yang diizinkan |

RFC 8996 menekankan bahwa masalahnya bukan hanya kerentanan yang sudah diketahui: TLS 1.0/1.1 **tidak mendukung algoritma kriptografi terkini**, dan bug masa depan pada versi lama mungkin tidak akan di-patch. Menghapus dukungan versi lama **mengurangi attack surface** dan menutup peluang misconfiguration.

Berbagai profil industri juga mewajibkan penghapusannya: **PCI DSS** (sejak 30 Juni 2018 untuk TLS 1.0), **NIST SP 800-52 Rev. 2** (mewajibkan TLS 1.2 minimum, TLS 1.3 direkomendasikan), dan semua browser utama menghentikan dukungan TLS 1.0/1.1 pada 2020.

**Klasifikasi versi TLS** (acuan penilaian):

| Versi | RFC | Status | Verdict |
|---|---|---|---|
| SSLv1 / SSLv2 / SSLv3 | RFC 6176 / 6101 | Broken | ❌ Tidak boleh |
| **TLS 1.0** | RFC 2246 | **Deprecated (RFC 8996)** | ❌ Insecure |
| **TLS 1.1** | RFC 4346 | **Deprecated (RFC 8996)** | ❌ Insecure |
| **TLS 1.2** | RFC 5246 | Aktif | ✅ Praktik terbaik |
| **TLS 1.3** | RFC 8446 | Aktif | ✅ Praktik terbaik (default Android 10+) |

### 1.4 Kenapa Dipetakan ke MASWE-0026 ("Network Traffic Not Encrypted")

Ini nuansa yang perlu dipahami agar tidak bingung. Judul weakness-nya adalah *"Network Traffic Not Encrypted"* — terkesan tentang cleartext (HTTP), bukan TLS lemah. Pemetaannya masuk akal bila dibaca dari perspektif keamanan efektif: **TLS 1.0/1.1 yang dapat dipecahkan (BEAST/POODLE) atau diturunkan oleh MitM secara efektif setara dengan tidak terenkripsi** — data dapat dibaca penyerang. Jadi "traffic not encrypted" mencakup baik cleartext maupun enkripsi yang tidak lagi memberikan jaminan kerahasiaan.

Untuk pelaporan, tetap deskripsikan temuan sebagai **"versi TLS tidak aman diaktifkan secara eksplisit"** dan rujuk MASWE-0026 sebagai weakness-nya.

### 1.5 Peta API yang Perlu Diperiksa

Overview MASTG menyebut tiga jalur. Berikut peta lengkapnya:

**Jalur A — Java Sockets / JCA (langsung):**

| API | Pola berbahaya | Catatan |
|---|---|---|
| `SSLContext.getInstance(String)` | `getInstance("TLSv1")`, `getInstance("TLSv1.1")`, `getInstance("SSL")`, `getInstance("SSLv3")` | Membuat context dengan protokol lama. `getInstance("TLS")` sendiri **netral** (memakai default platform) |
| `SSLSocket.setEnabledProtocols(String[])` | `setEnabledProtocols(new String[]{"TLSv1", "TLSv1.1"})` atau yang menyertakan versi lama | **API paling eksplisit** — developer secara sengaja mendaftar versi |
| `SSLEngine.setEnabledProtocols(String[])` | Sama | Untuk koneksi non-blocking |
| `SSLParameters.setProtocols(String[])` | Sama | Dipakai bersama `SSLSocket.setSSLParameters()` |

**Jalur B — OkHttp / Retrofit (paling umum di aplikasi modern):**

| API | Pola berbahaya | Catatan |
|---|---|---|
| `ConnectionSpec.COMPATIBLE_TLS` | `connectionSpecs(Arrays.asList(ConnectionSpec.COMPATIBLE_TLS))` | **Disebut eksplisit di kriteria evaluasi MASTG sebagai FAIL.** Fallback yang memuat versi lama pada beberapa versi OkHttp |
| `ConnectionSpec.Builder.tlsVersions(...)` | `.tlsVersions(TlsVersion.TLS_1_0, TlsVersion.TLS_1_1)` | Set eksplisit versi lama |
| `ConnectionSpec.Builder.connectionSpecs(...)` | Menyertakan spec yang memuat versi lama | — |
| Retrofit memakai OkHttp di baliknya | Sama seperti OkHttp | Retrofit mewarisi konfigurasi `OkHttpClient` |

> **Konteks OkHttp yang penting:** default OkHttp adalah **`MODERN_TLS`** (aman). `RESTRICTED_TLS` bahkan lebih ketat. `COMPATIBLE_TLS` adalah fallback yang secara historis memuat TLS 1.0/1.1. Konfigurasi tiap spec **berubah antar versi OkHttp** — versi lama `COMPATIBLE_TLS` lebih permisif. Karena itu MASTG merujuk *"OkHttp configuration history"*.

**Jalur C — Apache HttpClient & library lain:**

| Library | Pola berbahaya |
|---|---|
| Apache HttpClient (`SSLConnectionSocketFactory`) | Konstruktor dengan array protokol yang memuat versi lama |
| Volley (`HurlStack` dengan `SSLSocketFactory` kustom) | `SSLContext` lama diteruskan |
| Conscrypt / provider kustom | `SSLContext.getInstance("TLSv1.1", provider)` |
| gRPC / Netty (`SslContextBuilder.protocols(...)`) | Versi lama didaftarkan |

**Jalur D — Konsekuensi tak langsung dari `TrustManager`/`SSLSocketFactory` kustom:**
Aplikasi yang mengganti `SSLSocketFactory` sering **lupa membatasi versi**, sehingga socket memakai seluruh protokol yang didukung platform. Ini bertaut dengan MASTG-TEST-0282 (TrustManager tidak validasi) — periksa keduanya bersamaan.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | MASTG ID | Fungsi |
|---|---|---|
| **jadx** | MASTG-TOOL-0018 | **Dekompilasi DEX → Java** (MASTG-TECH-0013). Wajib juga untuk MASTG-TECH-0023 — meninjau konteks pemanggilan |
| **grep / ripgrep** | — | Pencarian pola API TLS. **Metode utama** karena MASTG tidak menyediakan rule semgrep resmi untuk test ini |
| **apktool** | MASTG-TOOL-0011 | Alternatif dekompilasi; analisis smali |

### 2.2 Tools Pendukung

| Tool | Fungsi |
|---|---|
| **semgrep** (MASTG-TOOL-0110) | **Tidak ada rule MASTG resmi**, tetapi registry Semgrep punya rule TLS lemah (`java.lang.security.audit.crypto.ssl.*`). Perlu rule kustom (§3.3) |
| **CodeQL** | Query bawaan `java/insecure-tls` / `java/android/insecure-tls-version` — melacak konfigurasi protokol lintas fungsi |
| **MobSF / mobsfscan** | Menandai `SSLContext.getInstance` dengan versi lama dan konfigurasi TLS berisiko |
| **SonarQube** | Rule `java:S4423` — *Weak SSL/TLS protocols should not be used* |
| **QARK** | Scanner Android lama yang punya check versi TLS |
| **jadx-gui** | "Find Usage" untuk melacak variabel array protokol dan konstanta |
| **Ghidra / `strings`** | Konfigurasi TLS di kode native (`SSL_CTX_set_min_proto_version`, string `TLSv1`) |
| **testssl.sh / sslscan / nmap `ssl-enum-ciphers`** | **Verifikasi sisi server** — melengkapi analisis klien (lihat §3.6) |
| **Frida** (MASTG-TOOL-0001) | **Konfirmasi dinamis** versi TLS yang benar-benar dinegosiasikan saat runtime (§3.5) |
| **mitmproxy / Wireshark** | Mengamati versi TLS aktual di handshake (§3.6) |

### 2.3 Prasyarat Lingkungan

- **Tidak butuh device** untuk bagian statis — cukup APK. Mudah diotomatisasi di CI/CD.
- **APK lengkap**, termasuk semua split APK / dynamic feature module.
- **Ketahui versi OkHttp yang di-bundle.** Perilaku `COMPATIBLE_TLS` bergantung versi — periksa `META-INF/` atau `okhttp3/internal/Version` di APK. Ini menentukan apakah `COMPATIBLE_TLS` benar-benar memuat TLS 1.0/1.1.
- **Ketahui `minSdkVersion`.** Aplikasi yang menargetkan API lama mungkin sengaja mengaktifkan TLS lama karena TLS 1.2 baru default sejak API 20/21 dan TLS 1.3 sejak API 29. Ini menjelaskan *mengapa* (tapi tidak membenarkan) temuan.
- **Waspadai obfuscation.** Nama API JCA (`SSLContext`, `setEnabledProtocols`) tidak di-obfuscate karena API sistem, sehingga deteksi tetap efektif. String versi TLS (`"TLSv1.1"`) juga literal dan mudah dicari — kecuali dienkripsi string.
- **Analisis statis saja tidak konklusif untuk versi final.** Versi TLS yang **benar-benar dipakai** hasil negosiasi klien-server; konfirmasi dengan §3.5/§3.6 bila memungkinkan.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0013** (*Reverse Engineering Android Apps*) untuk me-reverse engineer aplikasi.
2. Gunakan **MASTG-TECH-0014** (*Static Analysis on Android*) untuk mencari API yang relevan.

Untuk evaluasi: gunakan **MASTG-TECH-0023** untuk meninjau setiap lokasi temuan.

### 3.2 Metode A — grep/ripgrep terstruktur *(metode utama)*

Karena MASTG tidak menyediakan rule semgrep resmi untuk test ini, pencarian pola adalah baseline-nya.

```bash
jadx -d ./decompiled ./target-app.apk
D=./decompiled/sources

# --- Jalur A: JCA / Java Sockets ---
# SSLContext dengan protokol lama (getInstance("TLS") netral, tidak dihitung)
rg -n --no-heading 'SSLContext\.getInstance\(\s*"(SSL|SSLv3|TLSv1|TLSv1\.1)"' $D

# setEnabledProtocols — periksa isinya (INI API PALING EKSPLISIT)
rg -n --no-heading 'setEnabledProtocols' $D -A2

# SSLParameters.setProtocols
rg -n --no-heading 'setProtocols\(' $D -A2

# Versi lama sebagai string literal di mana pun
rg -n --no-heading '"(SSLv3|TLSv1|TLSv1\.1)"' $D

# --- Jalur B: OkHttp / Retrofit ---
# COMPATIBLE_TLS — FAIL menurut kriteria evaluasi MASTG
rg -n --no-heading 'ConnectionSpec\.COMPATIBLE_TLS|COMPATIBLE_TLS' $D
# tlsVersions dengan versi lama
rg -n --no-heading 'tlsVersions\(' $D -A2
rg -n --no-heading 'TlsVersion\.(TLS_1_0|TLS_1_1|SSL_3_0)' $D
# connectionSpecs
rg -n --no-heading 'connectionSpecs\(' $D -A2

# --- Jalur C: Apache HttpClient / Volley / gRPC ---
rg -n --no-heading 'SSLConnectionSocketFactory|SSLSocketFactory' $D -A2
rg -n --no-heading 'SslContextBuilder|\.protocols\(' $D -A2

# --- Cek versi OkHttp yang di-bundle (menentukan perilaku COMPATIBLE_TLS) ---
unzip -o ./target-app.apk -d ./apk_x >/dev/null
rg -n --no-heading 'okhttp' ./apk_x/META-INF/*.version 2>/dev/null
strings ./apk_x/**/*.dex 2>/dev/null | grep -oE "okhttp/[0-9.]+" | sort -u

# --- Indikator BAIK (untuk menilai PASS) ---
rg -n --no-heading 'TlsVersion\.(TLS_1_2|TLS_1_3)|RESTRICTED_TLS|"TLSv1\.2"|"TLSv1\.3"' $D
```

### 3.3 Metode B — semgrep dengan rule kustom *(gate CI/CD)*

MASTG tidak punya rule resmi, jadi ini rule buatan yang menutup ketiga jalur:

```yaml
rules:
  - id: android-insecure-tls-sslcontext
    severity: ERROR
    languages: [java, kotlin]
    message: "[MASVS-NETWORK-1] SSLContext dibuat dengan versi TLS/SSL tidak aman"
    pattern-either:
      - pattern: javax.net.ssl.SSLContext.getInstance("SSL")
      - pattern: javax.net.ssl.SSLContext.getInstance("SSLv3")
      - pattern: javax.net.ssl.SSLContext.getInstance("TLSv1")
      - pattern: javax.net.ssl.SSLContext.getInstance("TLSv1.1")
      - pattern: javax.net.ssl.SSLContext.getInstance("SSL", ...)
      - pattern: javax.net.ssl.SSLContext.getInstance("TLSv1", ...)

  - id: android-insecure-tls-setenabledprotocols
    severity: ERROR
    languages: [java, kotlin]
    message: "[MASVS-NETWORK-1] setEnabledProtocols/setProtocols menyertakan versi lama — periksa array"
    pattern-either:
      - pattern-regex: 'setEnabledProtocols\s*\([^)]*"(SSLv3|TLSv1|TLSv1\.1)"'
      - pattern-regex: 'setProtocols\s*\([^)]*"(SSLv3|TLSv1|TLSv1\.1)"'

  - id: android-insecure-tls-okhttp
    severity: WARNING
    languages: [java, kotlin]
    message: "[MASVS-NETWORK-1] OkHttp COMPATIBLE_TLS atau tlsVersions dengan versi lama"
    pattern-either:
      - pattern: okhttp3.ConnectionSpec.COMPATIBLE_TLS
      - pattern: $B.tlsVersions(..., okhttp3.TlsVersion.TLS_1_0, ...)
      - pattern: $B.tlsVersions(..., okhttp3.TlsVersion.TLS_1_1, ...)
      - pattern: $B.tlsVersions(..., okhttp3.TlsVersion.SSL_3_0, ...)
```

```bash
semgrep -c ./tls-rules.yml ./decompiled/sources/
# Plus rule registry
semgrep --config "r/java.lang.security.audit.crypto.ssl.no-null-cipher" ./decompiled/sources/
```

> **Catatan penting tentang `getInstance("TLS")`:** Semgrep registry menandai `SSLContext.getInstance("TLS")` sebagai *medium severity*, tetapi ini **kontroversial dan sering false positive** — `"TLS"` memakai default platform yang pada Android modern **sudah TLS 1.3**. Jangan otomatis melaporkan `getInstance("TLS")` sebagai FAIL; ia hanya masalah bila **dikombinasikan** dengan `setEnabledProtocols` yang memaksa versi lama. (Isu ini didokumentasikan di semgrep issue #10452.)

### 3.4 Metode C — MobSF, mobsfscan, SonarQube, CodeQL

**MobSF** — cari di Code Analysis: *"The App uses an insecure/weak SSL/TLS version"*.

```bash
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
```

**mobsfscan** (CI/CD):

```bash
mobsfscan --json -o out.json ./decompiled/sources/
jq '.results | to_entries[] | select(.key | test("tls|ssl"))' out.json
```

**SonarQube** — rule `java:S4423` (*Weak SSL/TLS protocols should not be used*) memahami konteks `SSLContext`, `setEnabledProtocols`, dan OkHttp. Muncul di IDE via SonarLint.

```bash
sonar-scanner -Dsonar.projectKey=android-app -Dsonar.sources=./app/src
```

**CodeQL** — untuk menyelesaikan array protokol yang berasal dari variabel:

```bash
codeql database create ./cqldb --language=java --command="./gradlew assembleDebug"
codeql database analyze ./cqldb \
  codeql/java-queries:Security/CWE/CWE-327/InsecureTrustManager.ql \
  codeql/java-queries:Security/CWE/CWE-757/InsecureTLSVersion.ql \
  --format=sarif-latest --output=tls.sarif
```

### 3.5 Metode D — Konfirmasi dinamis dengan Frida *(versi yang benar-benar dinegosiasikan)*

Analisis statis menunjukkan versi yang **diaktifkan**; hooking menunjukkan versi yang **benar-benar dipakai** — termasuk ketika array protokol berasal dari variabel atau konfigurasi remote.

```javascript
// tls_version_trace.js
function bt() {
    const E = Java.use("java.lang.Exception");
    return E.$new().getStackTrace().slice(0, 10).map(f => "    " + f).join("\n");
}

Java.perform(() => {
    // --- SSLContext.getInstance ---
    const Ctx = Java.use("javax.net.ssl.SSLContext");
    Ctx.getInstance.overload('java.lang.String').implementation = function (p) {
        console.log(`\n[SSLContext] getInstance("${p}")` +
            (/^(SSL|SSLv3|TLSv1|TLSv1\.1)$/.test(p) ? "  [!! INSECURE !!]" : ""));
        console.log(bt());
        return this.getInstance(p);
    };

    // --- setEnabledProtocols: array yang BENAR-BENAR di-set ---
    const Sock = Java.use("javax.net.ssl.SSLSocket");
    Sock.setEnabledProtocols.implementation = function (arr) {
        const list = arr ? Java.array('java.lang.String', arr).join(", ") : "null";
        const bad = /SSLv3|TLSv1(?!\.[23])|TLSv1\.1/.test(list);
        console.log(`\n[SSLSocket] setEnabledProtocols([${list}])` + (bad ? "  [!! INSECURE !!]" : ""));
        console.log(bt());
        return this.setEnabledProtocols(arr);
    };

    // --- Versi yang DINEGOSIASIKAN (kebenaran akhir) ---
    const Session = Java.use("com.android.org.conscrypt.ActiveSession");
    try {
        Session.getProtocol.implementation = function () {
            const v = this.getProtocol();
            console.log(`\n[Negotiated] TLS version = ${v}`);
            return v;
        };
    } catch (e) { /* nama kelas berbeda antar versi Android */ }
});
```

```bash
frida -U -f com.example.target -l tls_version_trace.js -o tls.log
# Exercise fitur yang memicu koneksi jaringan
```

### 3.6 Metode E — Verifikasi dari jaringan *(handshake aktual + sisi server)*

Analisis klien tidak lengkap tanpa mengetahui apa yang diterima server. Dua sisi:

**E1 — Amati versi handshake aktual (klien):**

```bash
# Wireshark/tshark — versi TLS di ClientHello & ServerHello
tcpdump -i any -w tls.pcap    # di device (root) atau via emulator
tshark -r tls.pcap -Y "tls.handshake.type==1" -T fields \
  -e tls.handshake.version -e tls.handshake.extensions.supported_version

# mitmproxy menampilkan versi TLS tiap flow
mitmdump --set flow_detail=3 | grep -i "tls"
```

**E2 — Audit versi TLS yang diterima SERVER** (melengkapi: server yang hanya menerima TLS 1.2/1.3 memaksa klien turun ke default aman):

```bash
# testssl.sh — audit menyeluruh protokol & cipher
testssl.sh --protocols api.example.com:443

# sslscan
sslscan api.example.com

# nmap
nmap --script ssl-enum-ciphers -p 443 api.example.com
```

> Bila **server** hanya menerima TLS 1.2/1.3, meski aplikasi mengaktifkan TLS 1.0 di kode, koneksi nyata tetap aman (server menolak versi lama). Ini menurunkan **eksploitabilitas** temuan — tetapi kode yang mengaktifkan versi lama **tetap FAIL** menurut kriteria MASTG, karena rentan terhadap server MitM yang jahat. Dokumentasikan keduanya.

### 3.7 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Butuh device? | Menyelesaikan array dari variabel? | Menunjukkan versi aktual? | Kapan dipakai |
|---|---|---|---|---|---|
| **A** | ripgrep terstruktur | Tidak | Manual | ❌ | **Baseline** (tidak ada rule MASTG resmi) |
| **B** | semgrep rule kustom | Tidak | ❌ | ❌ | Gate CI/CD |
| **C1** | MobSF / mobsfscan | Tidak | ❌ | ❌ | Laporan siap kutip + CI |
| **C2** | SonarQube `java:S4423` | Tidak | ✅ | ❌ | Shift-left di IDE |
| **C3** | CodeQL | Tidak | ✅ **otomatis** | ❌ | Array protokol dari variabel |
| **D** | Frida | **Ya** | ✅ (nilai runtime) | ✅ (negosiasi) | Konfigurasi dari variabel/remote, ter-obfuscate |
| **E1** | Wireshark / mitmproxy | **Ya** | — | ✅ **(handshake)** | Versi TLS yang benar-benar dipakai |
| **E2** | testssl.sh / sslscan / nmap | Tidak¹ | — | ✅ **(sisi server)** | Kalibrasi eksploitabilitas |
| **F** | `strings` / Ghidra | Tidak | Manual | ❌ | Konfigurasi TLS di kode native |

¹ E2 butuh akses jaringan ke server, bukan device.

**Kombinasi minimum yang aku rekomendasikan:** **A (ripgrep) → C2 atau C3 (Sonar/CodeQL) → D (Frida)**.
A memberi cakupan awal cepat, Sonar/CodeQL menyelesaikan array yang berasal dari variabel (celah grep), dan Frida membuktikan versi yang benar-benar dinegosiasikan. Tambahkan **E2 (testssl.sh)** untuk mengkalibrasi seberapa nyata risikonya, dan **F** bila APK memuat `.so` dengan stack TLS sendiri (mis. aplikasi yang mem-bundle BoringSSL/OpenSSL).

### 3.8 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Observation:** *"The output should contain a list of all enabled TLS versions in the above mentioned API calls."*
>
> **Evaluation:** *"The test case **fails** if any insecure TLS version is directly enabled, or if the app enabled any settings allowing the use of outdated TLS versions, such as `okhttp3.ConnectionSpec.COMPATIBLE_TLS`."*

Kriterianya lugas: **versi TLS tidak aman diaktifkan secara eksplisit → FAIL.** Termasuk pengaktifan **tidak langsung** lewat `COMPATIBLE_TLS`.

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi | Contoh bukti |
|---|---|---|
| F1 | `SSLContext.getInstance()` dengan protokol lama | `SSLContext.getInstance("TLSv1.1")`, `getInstance("SSL")`, `getInstance("SSLv3")` |
| F2 | `setEnabledProtocols` / `setProtocols` menyertakan versi lama | `socket.setEnabledProtocols(new String[]{"TLSv1", "TLSv1.1"})` |
| F3 | OkHttp `ConnectionSpec.COMPATIBLE_TLS` dipakai | `connectionSpecs(Arrays.asList(ConnectionSpec.COMPATIBLE_TLS))` — **disebut eksplisit MASTG sebagai FAIL** |
| F4 | OkHttp `tlsVersions(...)` menyertakan versi lama | `.tlsVersions(TlsVersion.TLS_1_0, TlsVersion.TLS_1_2)` |
| F5 | Apache HttpClient / Volley / gRPC dikonfigurasi dengan versi lama | `new SSLConnectionSocketFactory(ctx, new String[]{"TLSv1"}, ...)` |
| F6 | `SSLSocketFactory` kustom yang meng-enable versi lama | Socket yang di-return memuat TLSv1/1.1 di enabled protocols |
| F7 | Versi lama diaktifkan di **kode native** | `strings lib.so` → `TLSv1`, atau `SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION)` |
| F8 | Frida mengonfirmasi versi lama benar-benar dinegosiasikan | `[Negotiated] TLS version = TLSv1.1` |

**Contoh kode yang FAIL:**

```java
// F1 — SSLContext dengan protokol lama
SSLContext ctx = SSLContext.getInstance("TLSv1.1");

// F2 — setEnabledProtocols menyertakan versi lama
SSLSocket socket = (SSLSocket) factory.createSocket(host, 443);
socket.setEnabledProtocols(new String[]{"TLSv1", "TLSv1.1", "TLSv1.2"});

// F3 — OkHttp COMPATIBLE_TLS
OkHttpClient client = new OkHttpClient.Builder()
    .connectionSpecs(Arrays.asList(ConnectionSpec.COMPATIBLE_TLS))
    .build();

// F4 — OkHttp tlsVersions dengan versi lama
ConnectionSpec spec = new ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
    .tlsVersions(TlsVersion.TLS_1_0, TlsVersion.TLS_1_1, TlsVersion.TLS_1_2)
    .build();
```

> **Catatan:** MASTG belum menyediakan demo (MASTG-DEMO) untuk test ini, sehingga tidak ada output tool resmi untuk dikutip. Contoh di atas disusun dari deskripsi API pada overview MASTG dan dokumentasi OkHttp.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi | Contoh bukti |
|---|---|---|
| P1 | Aplikasi **tidak menyentuh konfigurasi TLS** sama sekali | Tidak ada `SSLContext.getInstance` dengan versi, tidak ada `setEnabledProtocols`, tidak ada `ConnectionSpec` kustom → memakai default platform (TLS 1.3 pada Android 10+) |
| P2 | `SSLContext.getInstance("TLS")` / `getInstance("TLSv1.2")` / `getInstance("TLSv1.3")` | Memakai default aman atau versi modern eksplisit |
| P3 | `setEnabledProtocols` **hanya** versi modern | `setEnabledProtocols(new String[]{"TLSv1.2", "TLSv1.3"})` |
| P4 | OkHttp memakai `MODERN_TLS` (default) atau `RESTRICTED_TLS` | Tidak ada `connectionSpecs` kustom, atau eksplisit `MODERN_TLS`/`RESTRICTED_TLS` |
| P5 | OkHttp `tlsVersions(...)` **hanya** versi modern | `.tlsVersions(TlsVersion.TLS_1_3, TlsVersion.TLS_1_2)` |
| P6 | Frida mengonfirmasi negosiasi TLS 1.2/1.3 | `[Negotiated] TLS version = TLSv1.3` |

**Contoh output yang menandakan PASS:**

```bash
$ rg -n 'SSLContext\.getInstance\("(SSL|SSLv3|TLSv1|TLSv1\.1)"|setEnabledProtocols|COMPATIBLE_TLS|TlsVersion\.(TLS_1_0|TLS_1_1|SSL_3_0)' ./decompiled/sources/
# (tidak ada hasil)
```

Kode yang benar:

```kotlin
// ✅ Paling sederhana & aman: JANGAN sentuh konfigurasi TLS — biarkan default platform
val client = OkHttpClient()      // MODERN_TLS default

// ✅ Bila perlu eksplisit ketat:
val spec = ConnectionSpec.Builder(ConnectionSpec.RESTRICTED_TLS)
    .tlsVersions(TlsVersion.TLS_1_3, TlsVersion.TLS_1_2)
    .build()
val client2 = OkHttpClient.Builder()
    .connectionSpecs(listOf(spec))
    .build()

// ✅ JCA eksplisit modern
val ctx = SSLContext.getInstance("TLSv1.3")
```

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Tidak ada rule MASTG resmi dan tidak ada demo.** Test ini sepenuhnya bertumpu pada grep + review manual. Jangan berharap ada output tool "resmi" untuk dikutip; bangun bukti dari potongan kode dekompilasi dan (idealnya) konfirmasi Frida.

2. **`SSLContext.getInstance("TLS")` bukan otomatis FAIL.** `"TLS"` = default platform, yang pada Android modern sudah TLS 1.3. Ia hanya menjadi masalah bila digabung dengan `setEnabledProtocols` yang menurunkan versi. Semgrep registry sering false-positive di sini (issue #10452) — verifikasi manual.

3. **`COMPATIBLE_TLS` adalah FAIL menurut MASTG, terlepas versi OkHttp.** Meski versi OkHttp terbaru mungkin sudah tidak memasukkan TLS 1.0/1.1 ke `COMPATIBLE_TLS`, kriteria evaluasi MASTG menyebutnya eksplisit. Laporkan sebagai FAIL, tetapi sertakan versi OkHttp dan perilaku `COMPATIBLE_TLS` pada versi itu untuk mengkalibrasi severity.

4. **Periksa array yang berasal dari variabel.** `setEnabledProtocols(protocolArray)` di mana `protocolArray` didefinisikan di tempat lain tidak tertangkap grep sederhana. Gunakan CodeQL (§3.4) atau Frida (§3.5).

5. **Analisis statis menunjukkan yang DIAKTIFKAN, bukan yang DIPAKAI.** Versi final hasil negosiasi. Untuk severity yang akurat, konfirmasi dengan Frida (versi negosiasi) dan testssl.sh (apa yang server terima). Kode yang mengaktifkan TLS 1.0 tetap FAIL meski server menolaknya — karena server MitM jahat bisa menerimanya (downgrade).

6. **Titik buta kode native.** Aplikasi yang mem-bundle stack TLS sendiri (BoringSSL/OpenSSL via NDK, Flutter, React Native, Xamarin) mengonfigurasi TLS di luar JCA. Periksa `.so` dengan `strings`/Ghidra (`SSL_CTX_set_min_proto_version`, `TLS1_VERSION`).

7. **Framework cross-platform.** Flutter (`dart:io SecurityContext`), React Native (jaringan via OkHttp — tercakup Jalur B), Xamarin/.NET (`ServicePointManager.SecurityProtocol`) punya API TLS sendiri. Periksa sesuai stack.

8. **Konteks `minSdkVersion` menjelaskan tapi tidak membenarkan.** Aplikasi dengan `minSdk` sangat rendah mungkin mengaktifkan TLS lama demi kompatibilitas perangkat lama. Tetap FAIL, tetapi solusinya bisa dikombinasikan dengan menaikkan `minSdk` atau memakai Conscrypt provider (§4).

9. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | SSLv3 / TLS 1.0 diaktifkan pada koneksi yang membawa data sensitif | **Tinggi** |
   | `COMPATIBLE_TLS` pada versi OkHttp lama yang benar-benar memuat TLS 1.0/1.1 | **Tinggi** |
   | TLS 1.1 diaktifkan | **Menengah–Tinggi** |
   | Versi lama diaktifkan di kode tetapi server terbukti hanya menerima TLS 1.2/1.3 | **Menengah** — eksploitabilitas turun, tetapi rentan downgrade via MitM |
   | `getInstance("TLS")` tanpa penurunan versi | **Bukan temuan** (default aman) |
   | Hanya TLS 1.2/1.3 diaktifkan | **Bukan temuan** |

10. **Dokumentasikan:** lokasi kode + potongan dekompilasi, versi TLS yang diaktifkan, jalur (JCA/OkHttp/native), versi OkHttp bila relevan, hasil konfirmasi Frida (versi negosiasi), hasil testssl.sh (versi yang server terima), `minSdkVersion`, dan severity beserta justifikasinya.

---

## 4. Rekomendasi Perbaikan

### 4.1 Prinsip Utama (urutan prioritas)

**Prioritas 1 — Jangan sentuh konfigurasi TLS; biarkan default platform.** Ini remediasi paling sederhana dan paling aman. Sejak Android 10, default sudah TLS 1.3. Hapus setiap `SSLContext.getInstance("TLSv1...")`, `setEnabledProtocols`, dan `ConnectionSpec` kustom yang menurunkan versi.

```kotlin
// ✅ Cukup ini — sistem memilih versi terbaik
val client = OkHttpClient()
```

**Prioritas 2 — Bila harus eksplisit, pakai hanya TLS 1.2 + 1.3.**

```kotlin
// OkHttp
val spec = ConnectionSpec.Builder(ConnectionSpec.RESTRICTED_TLS)
    .tlsVersions(TlsVersion.TLS_1_3, TlsVersion.TLS_1_2)
    .build()
val client = OkHttpClient.Builder().connectionSpecs(listOf(spec)).build()

// JCA
val ctx = SSLContext.getInstance("TLSv1.2")   // atau "TLSv1.3"
socket.enabledProtocols = arrayOf("TLSv1.3", "TLSv1.2")
```

- Ganti `COMPATIBLE_TLS` → `MODERN_TLS` (default) atau `RESTRICTED_TLS` (paling ketat).
- Hapus semua `TlsVersion.TLS_1_0` / `TLS_1_1` / `SSL_3_0` dari `tlsVersions(...)`.

**Prioritas 3 — Update library jaringan.** Perilaku `COMPATIBLE_TLS` dan cipher default membaik antar versi OkHttp. Pakai versi terbaru dan pantau [OkHttp TLS configuration history](https://square.github.io/okhttp/security/tls_configuration_history/).

**Prioritas 4 — Untuk kompatibilitas perangkat lama, pakai Conscrypt — bukan menurunkan versi.** Aplikasi dengan `minSdk` rendah sering menurunkan TLS agar berjalan di Android lama. Solusi yang benar: sematkan **Conscrypt** sebagai security provider, yang membawa TLS 1.3 ke Android 5.0+.

```kotlin
// build.gradle: implementation("org.conscrypt:conscrypt-android:2.5.2")
Security.insertProviderAt(Conscrypt.newProvider(), 1)
// Kini TLS 1.3 tersedia bahkan di Android lama, tanpa perlu mengaktifkan versi usang
```

**Prioritas 5 — Perkuat sisi server.** Konfigurasikan server agar **hanya** menerima TLS 1.2/1.3 (audit dengan testssl.sh). Ini menutup celah downgrade dari sisi yang kamu kendalikan — tetapi bukan pengganti perbaikan klien.

**Prioritas 6 — Periksa stack native & cross-platform.** Untuk `.so` dengan OpenSSL/BoringSSL, set `SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)`. Untuk Flutter/RN/Xamarin, konfigurasikan minimum TLS lewat API framework masing-masing.

**Prioritas 7 — Tegakkan di CI/CD.** Tambahkan rule semgrep (§3.3) / SonarQube `java:S4423` sebagai gate; gagalkan build bila muncul versi TLS lama. Pantau juga versi library jaringan lewat dependency scanning.

### 4.2 Checklist Remediasi

- [ ] Tidak ada `SSLContext.getInstance()` dengan `"SSL"`, `"SSLv3"`, `"TLSv1"`, atau `"TLSv1.1"`
- [ ] Tidak ada `setEnabledProtocols` / `setProtocols` yang menyertakan versi lama
- [ ] Tidak ada OkHttp `ConnectionSpec.COMPATIBLE_TLS`
- [ ] Tidak ada `tlsVersions(...)` dengan `TLS_1_0` / `TLS_1_1` / `SSL_3_0`
- [ ] `SSLSocketFactory` / `SSLConnectionSocketFactory` kustom tidak meng-enable versi lama
- [ ] Idealnya: konfigurasi TLS tidak disentuh sama sekali (default platform)
- [ ] Bila eksplisit: hanya TLS 1.2 + 1.3
- [ ] OkHttp memakai `MODERN_TLS` atau `RESTRICTED_TLS`
- [ ] Library jaringan (OkHttp/Retrofit) diperbarui ke versi terbaru
- [ ] Kompatibilitas perangkat lama ditangani dengan **Conscrypt**, bukan menurunkan versi
- [ ] Stack TLS native (`.so`) memakai `TLS1_2_VERSION` sebagai minimum
- [ ] Framework cross-platform dikonfigurasi minimum TLS 1.2
- [ ] Server hanya menerima TLS 1.2/1.3 (diaudit dengan testssl.sh)
- [ ] Frida mengonfirmasi negosiasi TLS 1.2/1.3 pada koneksi nyata
- [ ] Rule SAST TLS terintegrasi di CI/CD sebagai gate
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0217 → tidak ada versi lama diaktifkan
- [ ] **Verifikasi silang:** MASTG-TEST-0282 (TrustManager), MASTG-TEST-0283 (HostnameVerifier), MASTG-TEST-0286 (Network Security Config) — kelemahan TLS sering berpasangan

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0217: Insecure TLS Protocols Explicitly Allowed in Code](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0217/)
- [MASWE-0026: Network Traffic Not Encrypted](https://mas.owasp.org/MASWE/MASVS-NETWORK/MASWE-0026/)
- [MASTG — Testing Network Communication (Recommended TLS Settings)](https://mas.owasp.org/MASTG/0x04f-Testing-Network-Communication/)
- [MASTG-TEST-0282: Use of a TrustManager that Does Not Validate Certificate Chains](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0282/)
- [MASTG-TEST-0283: Use of the HostnameVerifier that Allows Any Hostname](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0283/)
- [MASTG-TEST-0284: WebView Ignoring TLS Errors in onReceivedSslError](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0284/)
- [MASTG-TEST-0286: Network Security Configuration Allows User-Added Certificates](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0286/)
- [MASTG-TECH-0013: Reverse Engineering Android Apps](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/)
- [MASTG-TECH-0014: Static Analysis on Android](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/)
- [MASTG-TECH-0023: Reviewing Decompiled Java Code](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/)
- [MASVS-NETWORK: Network Communication](https://mas.owasp.org/MASVS/06-MASVS-NETWORK/)
- [OWASP Mobile Top 10 2024 — M5: Insecure Communication](https://owasp.org/www-project-mobile-top-10/2023-risks/m5-insecure-communication.html)
- [OWASP Transport Layer Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)

### 5.2 Dokumentasi Resmi Android / Google / Java

- [Android — SSL/Security (Updates to SSL, TLS 1.3 default)](https://developer.android.com/privacy-and-security/security-ssl)
- [Android 10 behavior changes — TLS 1.3 enabled by default](https://developer.android.com/about/versions/10/behavior-changes-all#tls-1.3)
- [`javax.net.ssl.SSLContext` — API reference](https://developer.android.com/reference/javax/net/ssl/SSLContext)
- [`javax.net.ssl.SSLSocket.setEnabledProtocols` — API reference](https://developer.android.com/reference/javax/net/ssl/SSLSocket#setEnabledProtocols(java.lang.String[]))
- [`SSLParameters.setProtocols` — API reference](https://developer.android.com/reference/javax/net/ssl/SSLParameters)
- [Android — Network Security Configuration](https://developer.android.com/privacy-and-security/security-config)
- [Conscrypt — modern TLS provider (TLS 1.3 di Android lama)](https://github.com/google/conscrypt)
- [Android GMS ProviderInstaller — update security provider](https://developer.android.com/privacy-and-security/security-gms-provider)

### 5.3 Dokumentasi OkHttp / Library

- [OkHttp — HTTPS & ConnectionSpec](https://square.github.io/okhttp/features/https/)
- [OkHttp — TLS Configuration History](https://square.github.io/okhttp/security/tls_configuration_history/)
- [OkHttp `ConnectionSpec` — API reference](https://square.github.io/okhttp/3.x/okhttp/okhttp3/ConnectionSpec.html)
- [OkHttp `TlsVersion` — API reference](https://square.github.io/okhttp/4.x/okhttp/okhttp3/-tls-version/)
- [Retrofit — dokumentasi (memakai OkHttp)](https://square.github.io/retrofit/)
- [Apache HttpClient — SSL/TLS customization](https://hc.apache.org/httpcomponents-client-5.2.x/current/httpclient5/apidocs/org/apache/hc/client5/http/ssl/SSLConnectionSocketFactory.html)

### 5.4 Standar Kriptografi & Taksonomi

- [RFC 8996 — Deprecating TLS 1.0 and TLS 1.1](https://www.rfc-editor.org/rfc/rfc8996.html)
- [RFC 8446 — TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446)
- [RFC 5246 — TLS 1.2](https://tools.ietf.org/html/rfc5246)
- [RFC 7525 / BCP 195 — Recommendations for Secure Use of TLS and DTLS](https://datatracker.ietf.org/doc/bcp195/)
- [NIST SP 800-52 Rev. 2 — Guidelines for TLS Implementations](https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final)
- [CWE-326: Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)
- [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
- [CWE-757: Selection of Less-Secure Algorithm During Negotiation ('Algorithm Downgrade')](https://cwe.mitre.org/data/definitions/757.html)
- [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
- [SonarQube Rule java:S4423 — Weak SSL/TLS protocols should not be used](https://rules.sonarsource.com/java/RSPEC-4423/)
- [PCI DSS — Migrating from SSL and early TLS](https://www.pcisecuritystandards.org/documents/Migrating-from-SSL-Early-TLS-Info-Supp-v1_1.pdf)

### 5.5 Riset Keamanan & Artikel Teknis

- [RFC Editor — RFC 8996 (PDF)](https://www.rfc-editor.org/rfc/rfc8996.pdf)
- [Feisty Duck — IETF Formally Deprecates TLS 1.0 and 1.1](https://www.feistyduck.com/newsletter/issue_75_ietf_formally_deprecates_tls_1_0_and_1_1)
- [KeyCDN — Deprecating TLS 1.0 and 1.1](https://www.keycdn.com/blog/deprecating-tls-1-0-and-1-1)
- [Invicti/Acunetix — Examples of TLS/SSL Vulnerabilities (BEAST, POODLE, Lucky 13)](https://www.acunetix.com/blog/articles/tls-vulnerabilities-attacks-final-part/)
- [PortSwigger Daily Swig — Browser-makers ditch support for TLS 1.0/1.1](https://portswigger.net/daily-swig/the-end-is-nigh-browser-makers-ditch-support-for-aging-tls-1-0-1-1-protocols)
- [PacketMania — Please Stop Using TLS 1.0 and TLS 1.1 Now!](https://www.packetmania.net/en/2022/11/10/Stop-TLS1-0-TLS1-1/)
- [Semgrep issue #10452 — SAST advice for minimum TLS versions in Java](https://github.com/semgrep/semgrep/issues/10452)
- [GitHub Gist — TLS 1.3 with OkHttp and Conscrypt on all Android versions](https://gist.github.com/Karewan/4b0270755e7053b471fdca4419467216)
- [Qualys SSL Labs — SSL and TLS Deployment Best Practices](https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices)
- [HackTricks — Android Applications Pentesting](https://book.hacktricks.wiki/en/mobile-pentesting/android-app-pentesting/index.html)

### 5.6 Dokumentasi Tools

- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [apktool — Reverse engineering Android APK files](https://apktool.org/)
- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
- [mobsfscan](https://github.com/MobSF/mobsfscan)
- [Frida — Documentation Home](https://frida.re/docs/home/)
- [testssl.sh — Testing TLS/SSL encryption](https://testssl.sh/)
- [sslscan](https://github.com/rbsec/sslscan)
- [nmap — ssl-enum-ciphers script](https://nmap.org/nsedoc/scripts/ssl-enum-ciphers.html)
- [Wireshark — User's Guide](https://www.wireshark.org/docs/wsug_html_chunked/)
- [mitmproxy — Documentation](https://docs.mitmproxy.org/stable/)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026), dokumentasi resmi Android Developers dan OkHttp, standar RFC/NIST/PCI DSS, serta riset keamanan pihak ketiga. Test ini belum memiliki demo (MASTG-DEMO) resmi, sehingga contoh kode FAIL/PASS disusun dari deskripsi API pada overview MASTG dan dokumentasi vendor.*
