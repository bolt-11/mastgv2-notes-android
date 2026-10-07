# MASTG-TEST-0239 Using Low-Level APIs (e.g. Socket) to Set Up a Custom HTTP Connection

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0239 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-NETWORK (MASVS-NETWORK-1: Seluruh lalu lintas jaringan dienkripsi memakai TLS) |
| **Weakness** | MASWE-0026 — *Network Traffic Not Encrypted* (dengan catatan resmi bahwa **MASWE-0047** — *Using Non-Standard APIs for Security-Critical Functionality* — juga relevan, lihat §1.2) |
| **Tipe Pengujian** | Static, Code |
| **Profile** | L1, L2 |
| **Status resmi MASTG** | **`placeholder`** — belum ada Overview/Steps/Observation/Evaluation lengkap dari MASTG |
| **Catatan resmi (satu-satunya konten yang tersedia)** | *"This test could also be for MASWE-0047 but we'd need to support multiple weaknesses."* |
| **Test terkait** | **MASTG-TEST-0234** (Missing Hostname Verification with SSLSockets — kasus spesifik dari masalah yang lebih umum diuji di sini), **MASTG-TEST-0233/0235/0238** (rangkaian pengujian cleartext lain) |
| **Demo terkait** | — (tidak ada) |
| **Rule resmi** | — (tidak ada) |
| **CWE terkait** | CWE-319 (Cleartext Transmission of Sensitive Information), CWE-296 (Improper Following of a Certificate's Chain of Trust) |

---

## 1. Penjelasan

### 1.1 Status Test Ini dan Cakupannya

Sama seperti MASTG-TEST-0237 dan MASTG-TEST-0238, test ini berstatus **`status: placeholder`**. Judul resminya, *"Using low-level APIs (e.g. Socket) to set up a custom HTTP connection"*, menunjukkan fokus test ini: mendeteksi ketika developer **mengabaikan** API HTTP client standar Android (`HttpURLConnection`, `OkHttp`, `Volley`) dan sebagai gantinya **membangun ulang protokol HTTP secara manual** di atas `java.net.Socket` atau `SSLSocket` mentah — menulis baris request HTTP (`GET / HTTP/1.1\r\nHost: ...`) dan mem-parsing response secara langsung lewat stream socket.

### 1.2 Insight Kunci dari Catatan Resmi: Dua Weakness Sekaligus

Catatan resmi MASTG untuk test ini sangat singkat namun mengandung insight arsitektural yang penting:

> *"This test could also be for MASWE-0047 but we'd need to support multiple weaknesses."*

**MASWE-0047 (Using Non-Standard APIs for Security-Critical Functionality)** adalah weakness di bawah kategori **MASVS-CODE**, berbeda dari MASWE-0026 (MASVS-NETWORK) yang jadi weakness resmi test ini saat ini. Catatan ini secara eksplisit mengakui bahwa masalah "memakai `Socket` mentah untuk HTTP" sebenarnya adalah **dua masalah independen yang bertumpuk**:

1. **Dari sudut pandang MASVS-NETWORK (MASWE-0026)**: risikonya adalah **traffic mungkin berakhir cleartext** — karena reimplementasi manual protokol HTTP di atas `Socket` polos (bukan `SSLSocket`) tidak akan pernah memiliki enkripsi TLS sama sekali, kecuali developer secara eksplisit membungkusnya sendiri.
2. **Dari sudut pandang MASVS-CODE (MASWE-0047)**: risikonya adalah **penggunaan API non-standar untuk fungsi keamanan-kritis** itu sendiri — **terlepas dari apakah hasil akhirnya cleartext atau berhasil dienkripsi**, keputusan untuk mereimplementasi ulang stack HTTP/TLS secara manual alih-alih memakai API standar yang sudah diuji dan di-maintain (yang secara otomatis menangani validasi sertifikat, hostname verification, penerapan Network Security Configuration, dan penanganan cipher suite yang aman) adalah **anti-pattern arsitektural** yang meningkatkan permukaan risiko secara keseluruhan.

Ini artinya **bahkan implementasi Socket kustom yang "berhasil" menambahkan TLS secara manual (`SSLSocket`) pun tetap berisiko** dari sudut pandang MASWE-0047 — karena setiap detail keamanan yang biasanya ditangani otomatis oleh `HttpsURLConnection`/OkHttp (hostname verification — lihat MASTG-TEST-0234, penerapan NSC, validasi rantai sertifikat, dukungan cipher suite modern) sekarang menjadi **tanggung jawab manual developer** yang rawan kesalahan implementasi.

### 1.3 Mengapa Ini Bermasalah: NSC dan Perlindungan Platform Tidak Berlaku

Poin teknis paling penting, konsisten dengan tema yang sudah dibahas di MASTG-TEST-0234 (§1.3 dokumen tersebut) — **Network Security Configuration hanya berlaku pada lapisan networking framework Android** (`HttpsURLConnection`, `OkHttp`, `WebView`, dan library yang dibangun di atasnya). Riset independen menegaskan hal ini secara eksplisit:

> *"NSC operates at the Android framework level during standard network connections. When developers circumvent recommended libraries (HttpsURLConnection, OkHttp) and implement custom socket handling, they escape NSC's protective mechanisms entirely."*

Konsekuensinya, aplikasi bisa memiliki `network_security_config.xml` yang **sempurna** — `cleartextTrafficPermitted="false"` di seluruh domain, pinning yang benar, trust anchor yang ketat — dan tetap sepenuhnya rentan bila ada satu jalur kode yang membangun koneksinya sendiri lewat `Socket` mentah. **MASTG-TEST-0235 (yang memeriksa NSC) tidak akan pernah mendeteksi celah ini**, karena celah tersebut terjadi persis di titik yang berada di luar jangkauan NSC.

### 1.4 Skala Masalah di Dunia Nyata: Riset Akademik USENIX

Riset akademik *"Revisiting TLS (In)Security in Android Applications"* (USENIX Security, dirujuk dalam riset untuk dokumen ini) memberikan data skala nyata tentang seberapa umum developer menyimpang dari implementasi TLS standar Android:

> Dari lebih dari 1,3 juta aplikasi Android gratis yang dianalisis di Google Play, **99.212 aplikasi** menyertakan pengaturan NSC kustom — dan dari jumlah tersebut, **lebih dari 88,87%** justru **melemahkan keamanan** dengan menurunkan (*downgrade*) pengaturan default yang aman.

Meski riset ini secara spesifik membahas kustomisasi NSC (bukan hanya Socket mentah), ia menggambarkan pola perilaku yang sama: developer sering menganggap "menyesuaikan sendiri" lapisan jaringan sebagai solusi praktis untuk masalah kompatibilitas/kemudahan integrasi, tanpa menyadari bahwa penyesuaian tersebut hampir selalu **menurunkan**, bukan meningkatkan, postur keamanan dibanding memakai default platform.

### 1.5 Alasan Umum Developer Memakai Socket Mentah (Konteks untuk Triase)

Memahami motivasi di balik pola ini membantu penguji menilai risiko secara proporsional:

- **Protokol non-HTTP** yang butuh kontrol byte-level penuh (protokol biner kustom, game networking, IoT pairing) — kasus legitimate di mana `Socket`/`SSLSocket` memang API yang tepat, tapi tetap harus diimplementasikan dengan verifikasi keamanan lengkap (lihat MASTG-TEST-0234).
- **Optimasi performa** yang diklaim (menghindari overhead parsing HTTP penuh) — seringkali prematur dan tidak sepadan dengan risiko keamanan yang ditimbulkan.
- **Migrasi kode dari platform lain** (Java desktop/server, atau porting dari iOS/kode native cross-platform) yang membawa pola Socket API yang sama tanpa penyesuaian untuk konteks keamanan mobile.
- **Menghindari pembatasan NSC yang dianggap menyulitkan** — pola paling berbahaya, di mana developer secara **sadar** memilih Socket mentah justru untuk **melewati** pembatasan cleartext yang diberlakukan NSC pada lapisan networking standar.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **jadx** | Dekompilasi DEX → Java untuk pencarian pola `Socket`/`SSLSocket` dan konstruksi manual protokol HTTP |
| **grep / ripgrep** | Pencarian pola API level-rendah dan string literal HTTP request manual (`"GET "`, `"HTTP/1.1"`, `"Host: "`) |
| **semgrep** | Rule kustom untuk pola pembangunan request HTTP manual di atas stream socket |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **CodeQL** | Menelusuri apakah `OutputStream`/`InputStream` dari objek `Socket` diikuti pola penulisan string yang menyerupai HTTP request line — mendeteksi reimplementasi protokol tanpa bergantung pada string literal eksplisit |
| **MobSF** | Kadang menandai penggunaan `Socket`/`ServerSocket` di laporan Code Analysis, meski umumnya kurang presisi untuk kasus spesifik ini |
| **Frida** | Hooking `Socket.getOutputStream().write()` dan `Socket.getInputStream().read()` untuk mengonfirmasi runtime apakah data yang ditulis/dibaca benar-benar menyerupai payload HTTP mentah, sekaligus mengonfirmasi cleartext vs terenkripsi |
| **Wireshark / PCAPdroid** | Konfirmasi definitif — bila koneksi ini benar-benar cleartext, capture jaringan akan menampilkan payload HTTP mentah yang dapat dibaca langsung |

### 2.3 Prasyarat Lingkungan

- **Tidak butuh device/root** untuk analisis statis inti.
- **Fokuskan pencarian pada kode yang secara eksplisit mengimpor `java.net.Socket`, `java.net.ServerSocket`, atau `javax.net.ssl.SSLSocket`** — ini penanda paling langsung dari pola yang diuji test ini.
- **Bedakan dari pola legitimate**: tidak semua penggunaan `Socket` adalah masalah — protokol non-HTTP yang memang membutuhkan kontrol level-rendah bukanlah pelanggaran MASWE-0026/0047 secara otomatis. Fokus triase pada kasus di mana `Socket` dipakai **untuk mereimplementasi HTTP** (yang seharusnya memakai `HttpURLConnection`/OkHttp) atau di mana penggunaannya **menghasilkan cleartext untuk data sensitif**.

---

## 3. Cara Pengujian

Karena tidak ada langkah resmi (status placeholder), bagian ini disusun dari riset independen dan pola-pola yang relevan dengan definisi test dari judulnya.

### 3.1 Langkah Umum

1. Identifikasi seluruh penggunaan `java.net.Socket`/`SSLSocket` di codebase (Metode A).
2. Untuk setiap lokasi, tentukan apakah socket dipakai untuk **mereimplementasi protokol HTTP** (bukan protokol biner/kustom yang legitimate).
3. Bila ya, tentukan apakah **TLS diterapkan** (`SSLSocket` dengan verifikasi lengkap sesuai MASTG-TEST-0234) atau **tidak** (plain `Socket` — otomatis cleartext).
4. Konfirmasi lewat capture jaringan (§3.4) untuk bukti definitif.

### 3.2 Metode A — grep/ripgrep untuk Pola Reimplementasi HTTP Manual *(metode utama)*

```bash
jadx -d ./decompiled ./target-app.apk
D=./decompiled/sources

# 1. Temukan seluruh instansiasi Socket/SSLSocket
rg -n 'new Socket\(|new SSLSocket\(|\(SSLSocket\)|SocketFactory.*createSocket' $D

# 2. Cari pola penulisan request HTTP manual — indikator kuat reimplementasi protokol
rg -n '"GET \+|"POST \+|"HTTP/1\.[01]"|"Host: "|write.*"GET\|POST' $D
rg -n 'getOutputStream\(\).*write' $D -A3 | grep -i "http\|get \|post "

# 3. Cari parsing response manual (indikator tambahan)
rg -n 'BufferedReader.*getInputStream\(\)|readLine\(\).*[Hh][Tt][Tt][Pp]' $D
```

### 3.3 Metode B — Semgrep Kustom

```yaml
rules:
  - id: custom-raw-socket-http-reimplementation
    languages: [java, kotlin]
    severity: WARNING
    message: "[MASVS-NETWORK-1 / MASWE-0047] Kemungkinan reimplementasi manual protokol HTTP di atas Socket — pertimbangkan memakai HttpURLConnection/OkHttp"
    patterns:
      - pattern-either:
          - pattern: |
              $SOCKET = new Socket($HOST, $PORT);
              ...
              $SOCKET.getOutputStream().write(...)
          - pattern: |
              $SOCKET = $FACTORY.createSocket($HOST, $PORT);
              ...
              $SOCKET.getOutputStream().write(...)

  - id: custom-plain-socket-no-tls
    languages: [java, kotlin]
    severity: ERROR
    message: "[MASVS-NETWORK-1] Socket polos (BUKAN SSLSocket) dipakai untuk komunikasi jaringan — traffic ini otomatis CLEARTEXT"
    pattern: new Socket($HOST, $PORT)
```

```bash
semgrep -c ./raw-socket-http-rules.yml ./decompiled/sources/
```

Rule kedua (`custom-plain-socket-no-tls`) memberi sinyal prioritas tertinggi — berbeda dari `SSLSocket` yang setidaknya **berupaya** menerapkan TLS (meski implementasinya bisa saja salah, lihat MASTG-TEST-0234), penggunaan `Socket` polos untuk komunikasi jaringan **secara definisi selalu cleartext**, tanpa perlu analisis lebih lanjut untuk memastikan kondisi FAIL dari sudut pandang MASWE-0026.

### 3.4 Metode C — CodeQL (deteksi berbasis pola struktural, bukan string literal)

```ql
import java

class SocketOutputWrite extends MethodAccess {
  SocketOutputWrite() {
    exists(MethodAccess getOutputCall |
      getOutputCall.getMethod().hasName("getOutputStream") and
      getOutputCall.getQualifier().getType().(RefType).hasQualifiedName("java.net", "Socket") |
      this.getQualifier() = getOutputCall
    ) and
    this.getMethod().hasName(["write", "print", "println"])
  }
}

from SocketOutputWrite write
select write, "Penulisan data langsung ke OutputStream Socket — periksa apakah ini reimplementasi manual protokol HTTP"
```

### 3.5 Metode D — Frida (Konfirmasi Runtime)

```javascript
// hook-socket-write.js
Java.perform(function () {
    var SocketOutputStream = Java.use("java.net.SocketOutputStream");
    SocketOutputStream.write.overload("[B", "int", "int").implementation = function (buf, offset, len) {
        var bytes = Java.array('byte', buf);
        var str = "";
        for (var i = offset; i < offset + Math.min(len, 200); i++) {
            str += String.fromCharCode(bytes[i] & 0xff);
        }
        if (str.indexOf("HTTP/") !== -1 || str.match(/^(GET|POST|PUT|DELETE) /)) {
            console.log("[!] Reimplementasi HTTP manual terdeteksi via raw Socket:");
            console.log(str);
            console.log("Stack:\n" + Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        }
        return this.write(buf, offset, len);
    };
});
```

```bash
frida -U -f com.target.app -l hook-socket-write.js --no-pause
```

### 3.6 Metode E — Capture Jaringan (Bukti Definitif Cleartext)

```bash
# PCAPdroid atau Wireshark pada jaringan yang sama
# Filter untuk paket yang mengandung string "HTTP/1." pada port non-standar (bukan 80/443)
# yang mengindikasikan reimplementasi protokol HTTP manual di atas socket kustom
```

Bila payload mentah dapat dibaca langsung sebagai teks HTTP (`GET /api/data HTTP/1.1`) tanpa proses dekripsi apa pun, ini bukti definitif bahwa komunikasi tersebut cleartext.

### 3.7 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Menemukan reimplementasi HTTP? | Menemukan cleartext (khusus)? | Kapan dipakai |
|---|---|---|---|---|
| **A** | grep/ripgrep | ✅ | Sebagian (via Socket vs SSLSocket) | Baseline utama |
| **B** | semgrep kustom | ✅ | ✅ (rule `plain-socket-no-tls`) | Gate CI/CD |
| **C** | CodeQL | ✅ (struktural, robust terhadap obfuscation string) | ❌ | Codebase besar/kompleks |
| **D** | Frida | ✅ (konfirmasi eksekusi nyata) | ✅ (payload terlihat langsung) | Konfirmasi runtime |
| **E** | Capture jaringan | N/A | ✅ (bukti definitif) | Konfirmasi akhir |

**Kombinasi minimum yang aku rekomendasikan:** **A/B (baseline statis) → D (Frida untuk konfirmasi runtime) → E (capture jaringan)**. Untuk setiap temuan `Socket` (bukan `SSLSocket`) yang dipakai membangun request HTTP, korelasikan juga dengan MASTG-TEST-0234 bila ternyata dipakai `SSLSocket` (untuk menilai apakah TLS-nya diimplementasikan dengan benar).

---

### 3.8 Kriteria Evaluasi: Positive Case & Negative Case

Karena tidak ada klausul Evaluation resmi (status placeholder), kriteria berikut diturunkan dari MASWE-0026 dan MASWE-0047.

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi | Weakness terkait |
|---|---|---|
| F1 | `java.net.Socket` polos (bukan `SSLSocket`) dipakai untuk membangun request HTTP manual ke server eksternal | MASWE-0026 (otomatis cleartext) |
| F2 | Konfirmasi runtime/capture jaringan (Metode D/E) menunjukkan payload HTTP mentah yang dapat dibaca langsung | MASWE-0026 |
| F3 | `SSLSocket` dipakai untuk mereimplementasi HTTP manual, **tanpa** hostname verification yang benar (kondisi FAIL MASTG-TEST-0234) | MASWE-0026 + MASWE-0047 |
| F4 | Reimplementasi HTTP manual ditemukan **terlepas dari status enkripsinya** — API standar (`HttpURLConnection`/OkHttp) tersedia dan seharusnya dipakai, tapi developer memilih membangun ulang stack protokol secara manual untuk fungsi yang keamanan-kritis (mis. autentikasi, transmisi kredensial) | MASWE-0047 (murni, independen dari hasil MASWE-0026) |

**Contoh bukti (ilustratif — MASTG belum menyediakan demo resmi untuk test ini):**

```java
// Ditemukan di com/example/target/net/LegacyHttpClient.java (hasil dekompilasi jadx)
public class LegacyHttpClient {
    public String sendRequest(String host, int port, String path, String authToken) throws IOException {
        Socket socket = new Socket(host, port);   // baris 15 — Socket POLOS, bukan SSLSocket
        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
        out.println("GET " + path + " HTTP/1.1");
        out.println("Host: " + host);
        out.println("Authorization: Bearer " + authToken);   // baris 19 — token dikirim CLEARTEXT
        out.println();
        // ... baca response
    }
}
```

```bash
$ rg -n 'new Socket\(' ./decompiled/sources/com/example/target/net/LegacyHttpClient.java
15:        Socket socket = new Socket(host, port);
$ semgrep -c ./raw-socket-http-rules.yml ./decompiled/sources/com/example/target/net/LegacyHttpClient.java
custom-plain-socket-no-tls: baris 15
```

Interpretasi: `Socket` polos dipakai untuk membangun request HTTP manual yang membawa `Authorization: Bearer` token di baris 19 — **FAIL kritis**, ganda: MASWE-0026 (cleartext pasti) dan MASWE-0047 (reimplementasi HTTP manual untuk fungsi keamanan-kritis).

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | **Tidak ditemukan** penggunaan `Socket`/`SSLSocket` untuk mereimplementasi HTTP di codebase — seluruh komunikasi memakai `HttpURLConnection`/OkHttp/library standar |
| P2 | `Socket`/`SSLSocket` ditemukan, tetapi dipakai untuk **protokol non-HTTP legitimate** (mis. protokol biner kustom yang memang membutuhkan kontrol byte-level), bukan reimplementasi HTTP |
| P3 | `SSLSocket` dipakai untuk HTTP manual, **dan** hostname verification diimplementasikan dengan benar sesuai MASTG-TEST-0234 (mengurangi risiko MASWE-0026, meski MASWE-0047 tetap relevan sebagai catatan code quality) |
| P4 | Capture jaringan (Metode E) mengonfirmasi tidak ada payload HTTP mentah yang terdeteksi pada koneksi socket kustom manapun |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Ini test dengan dua weakness yang perlu dipertimbangkan secara terpisah** (§1.2) — sebuah temuan bisa PASS untuk MASWE-0026 (karena TLS diterapkan dengan benar via `SSLSocket`) namun tetap layak dicatat sebagai code quality concern di bawah MASWE-0047 (karena tetap merupakan reimplementasi manual dari fungsi yang seharusnya diserahkan ke API standar teruji).

2. **Jangan menandai setiap penggunaan `Socket` sebagai temuan otomatis.** Protokol non-HTTP legitimate (chat proprietary, game networking) adalah penggunaan yang sah — fokus triase pada bukti bahwa socket dipakai **khusus untuk mereimplementasi HTTP** (pola request line, header, method HTTP) yang seharusnya memakai API standar.

3. **`Socket` polos = otomatis cleartext, tidak perlu analisis lebih lanjut untuk kesimpulan MASWE-0026.** Ini beda dengan `SSLSocket` (perlu verifikasi hostname sesuai MASTG-TEST-0234) — jangan habiskan waktu analisis berlebih untuk kasus yang sudah pasti FAIL secara struktural.

4. **Prioritaskan temuan berdasarkan data yang dibawa**, sama seperti pola di seluruh dokumen MASVS-NETWORK sebelumnya — kredensial/token yang dikirim lewat implementasi ini jauh lebih kritis dibanding data non-sensitif.

5. **Korelasikan dengan skala masalah di industri** (§1.4) untuk konteks laporan — bila organisasi memiliki banyak aplikasi dengan pola serupa, ini indikasi masalah arsitektural/kebijakan tim, bukan sekadar bug titik.

6. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | `Socket` polos membawa kredensial/token/data finansial | **Kritis** |
   | `SSLSocket` untuk HTTP manual tanpa hostname verification (F3) | **Tinggi** (setara MASTG-TEST-0234 FAIL) |
   | Reimplementasi HTTP manual dengan TLS + verifikasi benar, tapi tanpa justifikasi teknis yang jelas | **Rendah/Informational** — catat sebagai MASWE-0047 code quality, bukan kerentanan aktif |
   | `Socket` dipakai untuk protokol non-HTTP legitimate | **Bukan temuan** |

7. **Dokumentasikan:** lokasi kode, jenis socket (`Socket` vs `SSLSocket`), bukti bahwa itu reimplementasi HTTP (bukan protokol lain), data yang dibawa, dan hasil konfirmasi capture jaringan bila dilakukan.

---

## 4. Rekomendasi Perbaikan

### 4.1 Migrasi ke API HTTP Standar

```java
// SEBELUM — reimplementasi manual di atas Socket
Socket socket = new Socket(host, port);
PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
out.println("GET " + path + " HTTP/1.1");
// ...

// SESUDAH — memakai OkHttp, otomatis menangani TLS, NSC, hostname verification
OkHttpClient client = new OkHttpClient();
Request request = new Request.Builder()
    .url("https://" + host + path)
    .addHeader("Authorization", "Bearer " + authToken)
    .build();
Response response = client.newCall(request).execute();
```

### 4.2 Bila Socket Level-Rendah Memang Diperlukan (Protokol Non-HTTP)

Terapkan seluruh praktik keamanan yang biasanya otomatis di API standar secara manual dan lengkap:

```java
SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
SSLSocket socket = (SSLSocket) factory.createSocket(host, port);
socket.startHandshake();
if (!HttpsURLConnection.getDefaultHostnameVerifier().verify(host, socket.getSession())) {
    socket.close();
    throw new SSLPeerUnverifiedException("Hostname verification gagal");
}
// Baru pakai socket setelah verifikasi berhasil
```

### 4.3 Dokumentasikan Justifikasi Teknis untuk Setiap Penggunaan Socket Level-Rendah

Sesuai semangat MASWE-0047, setiap keputusan memakai API non-standar untuk fungsi keamanan-kritis sebaiknya didokumentasikan dengan alasan teknis yang jelas (mis. requirement protokol biner spesifik) dalam code review/ADR (Architecture Decision Record), agar mudah diaudit ulang di masa depan dan tidak dianggap sebagai kelalaian.

### 4.4 Integrasikan ke CI/CD

```bash
#!/bin/bash
# ci-check-raw-socket-http.sh
APK=$1
jadx -d /tmp/decompiled_check "$APK" 2>/dev/null
semgrep -c ./raw-socket-http-rules.yml /tmp/decompiled_check/sources/ --json | jq '.results | length'
```

### 4.5 Checklist Remediasi

- [ ] Seluruh penggunaan `Socket`/`SSLSocket` di codebase sudah diinventarisasi dan diklasifikasi (reimplementasi HTTP vs protokol legitimate lain)
- [ ] Reimplementasi HTTP manual sudah dimigrasi ke `HttpURLConnection`/OkHttp
- [ ] Bila Socket level-rendah tetap diperlukan, hostname verification dan validasi TLS lengkap sudah diterapkan (rujuk MASTG-TEST-0234)
- [ ] Justifikasi teknis untuk setiap penggunaan API non-standar sudah didokumentasikan
- [ ] Capture jaringan sudah mengonfirmasi tidak ada payload HTTP mentah pada koneksi socket kustom
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0239 pada APK release final setelah remediasi

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0239: Using low-level APIs (e.g. Socket) to set up a custom HTTP connection](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0239/)
- [MASTG-TEST-0234: Missing Implementation of Server Hostname Verification with SSLSockets](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0234/)
- [MASTG-TEST-0235: Android App Configurations Allowing Cleartext Traffic](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0235/)
- [MASWE-0026: Network Traffic Not Encrypted](https://mas.owasp.org/MASWE/MASVS-NETWORK/MASWE-0026/)
- [MASWE-0047: Using Non-Standard APIs for Security-Critical Functionality](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0047/)
- [OWASP Mobile Top 10 2024 — M5: Insecure Communication](https://owasp.org/www-project-mobile-top-10/2023-risks/m5-insecure-communication)

### 5.2 Riset Akademik dan Industri

- [USENIX Security — Revisiting TLS (In)Security in Android Applications (Oltrogge et al.)](https://www.usenix.org/system/files/sec21summer_oltrogge.pdf)
- [carloxavier.github.io — Caveats of Network Security Configuration in Android](https://carloxavier.github.io/android/security/network/2024/06/16/Caveats-of-Network-Security-Configuration-in-Android.html)
- [Securing.pl — How to force Android devices to communicate securely?](https://www.securing.pl/en/how-to-force-android-devices-to-communicate-securely/)
- [arXiv — Ghera: A Repository of Android App Vulnerability Benchmarks](https://arxiv.org/pdf/1708.02380)
- [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
- [CWE-296: Improper Following of a Certificate's Chain of Trust](https://cwe.mitre.org/data/definitions/296.html)

### 5.3 Dokumentasi Tools

- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [Frida — Dynamic instrumentation toolkit](https://frida.re/docs/javascript-api/)
- [PCAPdroid](https://github.com/emanuele-f/PCAPdroid)
- [OkHttp — Documentation](https://square.github.io/okhttp/)

---

*Dokumen ini disusun terutama dari riset independen (riset akademik USENIX, artikel keamanan komunitas) karena MASTG-TEST-0239 saat ini berstatus **placeholder** dan hanya menyediakan satu catatan singkat resmi. Catatan tersebut mengungkap insight penting: test ini sebenarnya menggabungkan dua weakness terpisah (MASWE-0026 untuk risiko cleartext, MASWE-0047 untuk risiko arsitektural penggunaan API non-standar pada fungsi keamanan-kritis) yang perlu dievaluasi secara independen — sebuah temuan bisa lolos dari satu weakness namun tetap relevan untuk yang lain.*
