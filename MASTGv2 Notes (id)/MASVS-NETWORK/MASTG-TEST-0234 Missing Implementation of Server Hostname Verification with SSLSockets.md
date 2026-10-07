# MASTG-TEST-0234 Missing Implementation of Server Hostname Verification with SSLSockets

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0234 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-NETWORK (MASVS-NETWORK-2: Aplikasi memverifikasi identitas endpoint server sebelum membangun koneksi terenkripsi) |
| **Weakness** | MASWE-0027 — *Insecure Certificate Validation* |
| **Tipe Pengujian** | Static, Code |
| **Profile** | L1, L2 |
| **Teknik terkait** | MASTG-TECH-0013 (Reverse Engineering), MASTG-TECH-0014 (Static Analysis), MASTG-TECH-0023 (Reviewing Decompiled Java Code) |
| **Test terkait** | **MASTG-TEST-0283** (Incorrect Implementation of Server Hostname Verification) — counterpart yang menguji **apakah `HostnameVerifier` yang ADA diimplementasikan dengan benar**; TEST-0234 menguji apakah `HostnameVerifier`-nya **ada sama sekali** saat memakai `SSLSocket` |
| **Demo terkait** | — (MASTG belum menyediakan demo resmi untuk test ini) |
| **Rule resmi** | `mastg-android-network-hostname-verification.yml` (ada, tapi **secara struktural tidak menguji apa yang diklaim judul test ini** — lihat §3.2) |
| **CWE terkait** | CWE-297 (Improper Validation of Certificate with Host Mismatch), CWE-295 (Improper Certificate Validation) |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Kutipan overview resmi MASTG:

> *"This test checks whether an Android app uses `SSLSocket` without a `HostnameVerifier`, allowing connections to servers presenting certificates with wrong or invalid hostnames."*

Test ini menyasar API level-rendah `javax.net.ssl.SSLSocket` — salah satu dari dua jalur utama Android untuk membangun koneksi TLS (jalur lainnya adalah `HttpsURLConnection`/OkHttp yang **otomatis** melakukan hostname verification). `SSLSocket` **tidak** melakukan validasi hostname secara otomatis:

> *"By default, `SSLSocket` does not perform hostname verification. To enforce it, the app must explicitly invoke `HostnameVerifier.verify()` and implement proper checks."*

Ini adalah **desain API yang disengaja, bukan bug** — `SSLSocket` beroperasi di lapisan transport TLS murni tanpa pengetahuan tentang konteks HTTP/URL, sehingga ia tidak tahu hostname mana yang "seharusnya" divalidasi terhadap sertifikat. Tanggung jawab ini **sepenuhnya dilimpahkan ke developer aplikasi** yang memakai API ini secara langsung.

### 1.2 Mengapa Ini Berbahaya: TLS Berhasil, Tapi Identitas Server Tidak Pernah Diperiksa

Tanpa `HostnameVerifier`, TLS handshake akan **tetap berhasil** — enkripsi tetap terpasang, sertifikat tetap divalidasi rantai kepercayaannya (trust chain) hingga root CA — tetapi **tidak ada langkah yang memastikan sertifikat tersebut benar-benar milik server yang dituju**. Ini artinya:

- Penyerang **Man-in-the-Middle (MITM)** yang memiliki sertifikat valid untuk **domain manapun** yang diterbitkan CA tepercaya (bahkan domain miliknya sendiri) dapat menyodorkan sertifikat itu, dan aplikasi akan menerimanya tanpa keluhan karena hostname yang tercantum di sertifikat tidak pernah dicocokkan dengan hostname tujuan sebenarnya.
- Ini secara fundamental berbeda dari kegagalan validasi rantai sertifikat (mis. `checkServerTrusted` yang dilewati) — di sini **rantai kepercayaan valid**, tapi **identitas endpoint tidak diverifikasi**. Kombinasi "TLS aktif tapi identitas tak terverifikasi" ini yang membuat celah ini mudah lolos dari code review sekilas — koneksi tetap tampak "aman" (ada `SSLSocket`, ada enkripsi) padahal jaminan keamanannya kosong.

### 1.3 Poin Kritis: Network Security Configuration TIDAK Melindungi `SSLSocket`

Ini catatan resmi paling penting dalam test ini dan sering jadi miskonsepsi:

> *"Note: The connection succeeds even if the app has a fully secure Network Security Configuration (NSC) in place because `SSLSocket` is not affected by it."*

Banyak tim developer merasa aman karena sudah menerapkan NSC yang ketat (`cleartextTrafficPermitted="false"`, pinning lewat `<pin-set>`, dll — lihat MASTG-TEST-0235 dan MASTG-TEST-0242) dan menganggap itu cukup untuk seluruh lapisan jaringan aplikasi. **Ini keliru untuk kode yang memakai `SSLSocket` langsung** — NSC bekerja pada lapisan API HTTP/URL Android standar (`HttpsURLConnection`, WebView, sebagian besar library HTTP populer), **bukan** pada socket TLS mentah yang dibangun manual lewat `SSLSocketFactory`. Ini artinya audit keamanan jaringan yang **hanya** memeriksa konfigurasi NSC/manifest (seperti fokus MASTG-TEST-0235) **akan melewatkan** kerentanan ini sepenuhnya bila aplikasi memiliki jalur komunikasi kustom yang memakai `SSLSocket` — sesuatu yang umum ditemukan pada:

- Implementasi **protokol kustom non-HTTP** di atas TLS (mis. protokol chat/messaging proprietary, protokol IoT/perangkat pairing)
- **SDK pihak ketiga lawas** yang ditulis sebelum `HttpsURLConnection`/OkHttp menjadi standar de facto
- Kode yang di-porting dari **Java desktop/server** (yang API socket-nya sama persis) tanpa penyesuaian untuk konteks mobile

### 1.4 Cara Perbaikan yang Benar Menurut Dokumentasi Resmi Android

Android Developers secara eksplisit menyediakan panduan (dirujuk overview resmi) tentang cara memakai `HostnameVerifier` dengan `SSLSocket` secara benar:

```java
SSLSocketFactory sslSocketFactory = ...;
SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket(host, port);

// Wajib: verifikasi hostname secara manual setelah handshake
SSLSession session = sslSocket.getSession();
if (!HttpsURLConnection.getDefaultHostnameVerifier().verify(host, session)) {
    throw new SSLHandshakeException("Hostname tidak cocok dengan sertifikat: " + host);
}
```

Poin krusial dari dokumentasi Android (`getDefaultHostnameVerifier()`): **`HostnameVerifier.verify()` tidak melempar exception saat validasi gagal — ia mengembalikan boolean yang WAJIB diperiksa secara eksplisit oleh kode pemanggil.** Ini pola API yang rawan disalahgunakan (*footgun*) — developer yang memanggil `verify()` tapi lupa memeriksa nilai kembaliannya (atau salah asumsi bahwa exception akan dilempar otomatis) akan tetap rentan meski secara sekilas kode "terlihat" sudah melakukan verifikasi.

### 1.5 Hubungan dengan MASTG-TEST-0283

Dua test ini menguji **kondisi yang berlawanan** namun saling melengkapi:

| | MASTG-TEST-0234 *(dokumen ini)* | MASTG-TEST-0283 |
|---|---|---|
| **Fokus** | `HostnameVerifier` **TIDAK ADA** saat memakai `SSLSocket` | `HostnameVerifier` **ADA**, tapi diimplementasikan secara **tidak aman** |
| **Contoh temuan** | `SSLSocket` dibuat, `getSession()` dipanggil, tapi tidak ada pemanggilan `verify()` sama sekali | `verify()` di-override untuk selalu `return true`, atau logika wildcard yang terlalu longgar |
| **Weakness** | MASWE-0027 (sama persis) | MASWE-0027 (sama persis) |

Alur pengujian yang benar: pertama jalankan TEST-0234 untuk menemukan apakah `HostnameVerifier` ada sama sekali; bila **ada**, lanjutkan ke TEST-0283 untuk menilai apakah implementasinya aman. Catatan resmi TEST-0234 sendiri menegaskan ini:

> *"If a `HostnameVerifier` is present, ensure it's not implemented in an unsafe manner. See MASTG-TEST-0283 for guidance."*

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | MASTG ID | Fungsi |
|---|---|---|
| **jadx** | MASTG-TOOL-0018 | Dekompilasi DEX → Java untuk pencarian pola `SSLSocket`/`HostnameVerifier` |
| **grep / ripgrep** | — | Pencarian pola API — metode utama karena rule resmi memiliki celah signifikan (§3.2) |
| **semgrep** | — | Menjalankan rule resmi sebagai baseline, dilengkapi rule kustom |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **CodeQL** | Menelusuri apakah objek `SSLSocket` yang dibuat benar-benar **tidak pernah** memiliki pemanggilan `verify()` di jalur eksekusi manapun setelahnya — pertanyaan "ketiadaan" ini lebih mudah dijawab lewat analisis alur kontrol/data daripada regex sederhana |
| **MobSF** | Analisis otomatis, kadang menandai pola `SSLSocket` di laporan Code Analysis kategori Network Security |
| **jadx-gui "Find Usage"** | Menelusuri secara interaktif apakah instance `SSLSocket` yang ditemukan diikuti pemanggilan `getSession()` + `verify()` di blok kode yang sama/berdekatan |
| **Frida** | Hooking `SSLSocketFactory.createSocket()` dan `HostnameVerifier.verify()` saat runtime untuk mengonfirmasi apakah verifikasi benar-benar dipanggil, dan apa hasil boolean-nya |
| **grahamedgecombe/android-ssl** (tool riset publik) | Tool deteksi kerentanan validasi sertifikat SSL Android — pendekatan bytecode-level yang dapat melengkapi analisis berbasis dekompilasi |
| **Wireshark / mitmproxy dengan sertifikat sengaja salah domain** | Uji dinamis definitif — sajikan sertifikat valid CA tapi untuk domain yang **berbeda** dari server tujuan, lalu amati apakah koneksi `SSLSocket` tetap berhasil (lihat §3.5) |

### 2.3 Prasyarat Lingkungan

- **Analisis statis tidak butuh device/root** — cukup APK.
- **Uji dinamis (§3.5) butuh device/emulator + proxy MITM** yang dapat menyajikan sertifikat dengan Common Name/SAN yang **sengaja tidak cocok** dengan hostname tujuan, namun tetap ditandatangani oleh CA yang dipercaya sistem (mis. lewat CA kustom yang di-install ke trust store perangkat uji) — ini skenario yang **berbeda** dari uji pinning biasa yang memakai sertifikat self-signed.
- Fokuskan pencarian pada kode yang memakai **API level rendah**: `javax.net.ssl.SSLSocket`, `SSLSocketFactory`, `SSLContext.getSocketFactory()` — bukan `HttpsURLConnection`/OkHttp yang sudah menangani hostname verification secara otomatis di balik layar.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0013** untuk reverse engineer aplikasi.
2. Gunakan **MASTG-TECH-0014** untuk mencari API yang relevan.

### 3.2 Metode A — Rule Semgrep Resmi *(ada, tapi perlu dikritisi cakupannya)*

Rule resmi MASTG untuk test ini:

```yaml
rules:
  - id: mastg-android-network-hostname-verification
    severity: WARNING
    languages:
      - java
    metadata:
      summary: This rule looks for the use of HostnameVerifier in the app
    message: Improper server hostname verification detected
    match:
      any:
        - new HostnameVerifier() {...}
```

```bash
semgrep -c https://raw.githubusercontent.com/OWASP/mastg/master/rules/mastg-android-network-hostname-verification.yml ./decompiled/sources/
```

**Masalah signifikan yang perlu dipahami penguji sebelum mengandalkan rule ini:**

1. **Rule ini mendeteksi keberadaan implementasi `HostnameVerifier` kustom** (`new HostnameVerifier() {...}`) — ini justru **kebalikan** dari apa yang diuji TEST-0234. Test ini menguji **ketiadaan** `HostnameVerifier` saat memakai `SSLSocket`, tapi rule-nya justru mencari kapan `HostnameVerifier` **ada** (dan itupun tanpa menilai apakah implementasinya aman atau tidak, cocoknya untuk skenario TEST-0283, bukan TEST-0234).
2. **Rule ini tidak mencari `SSLSocket` sama sekali.** Tanpa mendeteksi keberadaan `SSLSocket` sebagai prasyarat, rule tidak dapat menyimpulkan kondisi FAIL sesungguhnya dari test ini: "SSLSocket dipakai TANPA HostnameVerifier".
3. **Semantik yang bertolak belakang: sebuah aplikasi yang benar-benar rentan** (memakai `SSLSocket` polos tanpa `HostnameVerifier` apa pun) justru **tidak akan menghasilkan temuan apa pun** dari rule ini, karena tidak ada pola `new HostnameVerifier()` untuk dicocokkan — inilah **false negative paling signifikan** yang bisa terjadi pada rule resmi MASTG yang pernah ditemukan dalam seri dokumen riset ini.

Karena kelemahan struktural ini, **rule resmi tidak boleh dijadikan andalan utama** untuk test ini — Metode B di bawah adalah pendekatan yang benar-benar relevan dengan definisi FAIL resmi.

### 3.3 Metode B — grep/ripgrep + Rule Semgrep Kustom yang Benar Secara Semantik *(metode utama efektif)*

```bash
jadx -d ./decompiled ./target-app.apk
D=./decompiled/sources

# 1. Temukan seluruh lokasi pembuatan SSLSocket
rg -n -B2 -A15 '\(SSLSocket\)|SSLSocketFactory.*createSocket|SSLContext.*getSocketFactory' $D > sslsocket_locations.txt

# 2. Untuk setiap lokasi, periksa manual apakah ada pemanggilan verify() dalam jarak dekat
rg -n -A20 '\(SSLSocket\)\s*\w+\s*=' $D | grep -c "HostnameVerifier\|\.verify("
```

Rule semgrep kustom yang benar-benar menargetkan pola FAIL resmi — `SSLSocket` dibuat tanpa diikuti pemanggilan `verify()`:

```yaml
rules:
  - id: custom-sslsocket-without-hostname-verification
    languages: [java, kotlin]
    severity: WARNING
    message: "[MASVS-NETWORK-2] SSLSocket dibuat tanpa pemanggilan HostnameVerifier.verify() eksplisit yang terdeteksi"
    patterns:
      - pattern-either:
          - pattern: $FACTORY.createSocket($HOST, $PORT)
          - pattern: (SSLSocket) $SOCKET
      - pattern-not-inside: |
          $SESSION = $SOCKET.getSession();
          ...
          $VERIFIER.verify($HOST, $SESSION);
```

> Catatan teknis: pola `pattern-not-inside` dengan jarak antar-statement yang fleksibel (`...`) pada semgrep memiliki keterbatasan mendeteksi verifikasi yang dilakukan di **fungsi terpisah** (bukan blok kode yang sama). Untuk kasus semacam ini, gunakan Metode C (CodeQL) yang mampu melacak lintas fungsi.

### 3.4 Metode C — CodeQL (menjawab pertanyaan "ketiadaan" lintas fungsi)

```ql
import java

class SSLSocketCreation extends Expr {
  SSLSocketCreation() {
    exists(MethodAccess ma |
      ma.getMethod().hasName("createSocket") and
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.net.ssl", "SSLSocketFactory") |
      this = ma
    )
  }
}

from SSLSocketCreation creation, Method enclosing
where
  enclosing = creation.getEnclosingCallable() and
  not exists(MethodAccess verifyCall |
    verifyCall.getMethod().hasName("verify") and
    verifyCall.getMethod().getDeclaringType().hasQualifiedName("javax.net.ssl", "HostnameVerifier") and
    verifyCall.getEnclosingCallable() = enclosing
  )
select creation, "SSLSocket dibuat di " + enclosing.getName() + " tanpa pemanggilan HostnameVerifier.verify() pada method yang sama"
```

> Query ini tetap heuristik — verifikasi yang dilakukan lewat pemanggilan fungsi wrapper terpisah (mis. `validateConnection(socket)` yang di dalamnya baru memanggil `verify()`) memerlukan interprocedural data flow analysis yang lebih kompleks. Gunakan hasil ini sebagai kandidat awal untuk ditinjau manual (MASTG-TECH-0023), bukan kesimpulan final otomatis.

### 3.5 Metode D — Uji Dinamis dengan Sertifikat Domain Tidak Cocok *(konfirmasi definitif)*

Ini metode yang secara langsung membuktikan kerentanan di lapisan jaringan nyata — berbeda dari pinning bypass biasa, di sini sertifikat **valid dan ditandatangani CA tepercaya**, hanya saja untuk **domain yang salah**:

```bash
# 1. Buat sertifikat valid (ditandatangani CA kustom yang akan di-trust perangkat uji)
#    untuk domain yang BERBEDA dari server tujuan aplikasi
openssl req -x509 -newkey rsa:2048 -keyout wrong-domain-key.pem -out wrong-domain-cert.pem \
    -days 365 -nodes -subj "/CN=attacker-controlled-domain.com"

# 2. Install CA kustom ke trust store perangkat uji (root/emulator)
adb push custom-ca.pem /system/etc/security/cacerts/
adb shell chmod 644 /system/etc/security/cacerts/custom-ca.pem

# 3. Jalankan mitmproxy/socat dengan sertifikat "salah domain" tersebut, arahkan traffic SSLSocket ke sana
socat OPENSSL-LISTEN:443,cert=wrong-domain-cert.pem,key=wrong-domain-key.pem,verify=0,fork TCP:target-real-server:443

# 4. Amati: apakah koneksi SSLSocket aplikasi tetap BERHASIL meski sertifikat untuk domain lain?
```

Bila koneksi **berhasil** meski sertifikat secara jelas diterbitkan untuk `attacker-controlled-domain.com` bukan domain server yang sebenarnya dituju aplikasi — ini **bukti definitif** ketiadaan hostname verification.

### 3.6 Metode E — Frida (konfirmasi runtime tanpa perlu setup sertifikat kustom)

```javascript
// hook-sslsocket-verify.js
Java.perform(function () {
    var SSLSocketFactory = Java.use("javax.net.ssl.SSLSocketFactory");
    SSLSocketFactory.createSocket.overload("java.lang.String", "int").implementation = function (host, port) {
        console.log("[SSLSocket] createSocket dipanggil untuk host=" + host + " port=" + port);
        console.log("  Stack:\n" + Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
        return this.createSocket(host, port);
    };

    try {
        var HostnameVerifier = Java.use("javax.net.ssl.HostnameVerifier");
        // Hook implementasi kustom bila ada — untuk mengetahui apakah verify() PERNAH dipanggil sama sekali
    } catch (e) {}

    var DefaultHV = Java.use("javax.net.ssl.HttpsURLConnection");
    // Tandai bila getDefaultHostnameVerifier().verify() tidak pernah muncul di log setelah createSocket
});
```

```bash
frida -U -f com.target.app -l hook-sslsocket-verify.js --no-pause
```

Bila log menunjukkan `createSocket` dipanggil berulang kali namun **tidak pernah ada** log pemanggilan `verify()` yang bersesuaian, ini indikasi kuat kondisi FAIL — dan jauh lebih murah dieksekusi dibanding menyiapkan sertifikat kustom di Metode D.

### 3.7 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Relevan dengan definisi FAIL resmi? | Menjawab ketiadaan lintas fungsi? | Kapan dipakai |
|---|---|---|---|---|
| **A** | Rule semgrep resmi | ❌ **Tidak** — salah target (lihat §3.2) | ❌ | Jangan diandalkan sendirian; jalankan tetap sebagai referensi tapi jangan simpulkan PASS dari hasil kosongnya |
| **B** | grep + rule kustom | ✅ | Terbatas (blok kode sama) | Baseline utama |
| **C** | CodeQL | ✅ | ✅ (dalam satu method; parsial lintas fungsi) | Codebase besar/kompleks |
| **D** | Sertifikat domain salah + socat/mitmproxy | ✅ (bukti definitif) | N/A (uji perilaku nyata) | Konfirmasi final sebelum melaporkan FAIL |
| **E** | Frida | ✅ (indikatif kuat) | N/A | Konfirmasi cepat tanpa setup sertifikat kustom |

**Kombinasi minimum yang aku rekomendasikan:** **B (grep+rule kustom) → C (CodeQL untuk codebase besar) → E (Frida) atau D (uji sertifikat) untuk konfirmasi final**. **Jangan pernah menyimpulkan PASS hanya dari rule resmi (Metode A) yang kosong** — seperti dijelaskan di §3.2, rule tersebut secara struktural tidak dapat mendeteksi kondisi FAIL sesungguhnya dari test ini.

---

### 3.8 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Observation:** *"The output should contain a list of locations where `SSLSocket` and `HostnameVerifier` are used."*
>
> **Evaluation:** *"The test case fails if the app uses `SSLSocket` without a `HostnameVerifier`."*
>
> **Catatan:** *"If a `HostnameVerifier` is present, ensure it's not implemented in an unsafe manner. See MASTG-TEST-0283 for guidance."*

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi | Dasar konfirmasi |
|---|---|---|
| F1 | `SSLSocket` dibuat lewat `SSLSocketFactory.createSocket()` dan **tidak ada** pemanggilan `HostnameVerifier.verify()` di manapun pada jalur eksekusi setelahnya | Metode B/C |
| F2 | `getSession()` dipanggil pada `SSLSocket` tetapi hasil `SSLSession`-nya **tidak pernah diteruskan** ke pemanggilan `verify()` apa pun | Metode B/C — pola "setengah jalan" yang tampak seperti verifikasi tapi tidak lengkap |
| F3 | Kode memanggil `verify()` tetapi **mengabaikan nilai kembaliannya** (boolean hasil `verify()` tidak pernah diperiksa dengan `if`, langsung lanjut memakai socket apa pun hasilnya) | Review manual MASTG-TECH-0023 — sesuai peringatan §1.4 tentang sifat boolean API ini |
| F4 | Konfirmasi dinamis (Metode D/E) menunjukkan koneksi **berhasil** meski sertifikat yang disajikan valid tapi untuk domain yang salah | Bukti runtime definitif |

**Contoh bukti (ilustratif — MASTG belum menyediakan demo resmi untuk test ini):**

```java
// Ditemukan di com/example/target/net/CustomProtocolClient.java (hasil dekompilasi jadx)
public class CustomProtocolClient {
    public void connect(String host, int port) throws IOException {
        SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        SSLSocket socket = (SSLSocket) factory.createSocket(host, port);   // baris 34
        socket.startHandshake();
        // TIDAK ADA pemanggilan getSession() atau verify() di sini
        sendData(socket, buildPayload());   // baris 37 — langsung dipakai kirim data
    }
}
```

```bash
$ rg -n -A10 '\(SSLSocket\)\s*factory\.createSocket' ./decompiled/sources/com/example/target/net/CustomProtocolClient.java
34:        SSLSocket socket = (SSLSocket) factory.createSocket(host, port);
35:        socket.startHandshake();
36:
37:        sendData(socket, buildPayload());
# Tidak ditemukan "verify(" maupun "HostnameVerifier" di 10 baris berikutnya
```

Interpretasi: `SSLSocket` dipakai untuk mengirim data (`sendData`) segera setelah handshake, tanpa langkah verifikasi hostname apa pun — **FAIL** dengan bukti langsung dari struktur kode. Konfirmasi lanjutan dengan Metode D/E akan memperkuat temuan ini.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi | Contoh bukti |
|---|---|---|
| P1 | **Tidak ditemukan** penggunaan `SSLSocket`/`SSLSocketFactory` di codebase sama sekali — aplikasi sepenuhnya memakai `HttpsURLConnection`/OkHttp yang menangani hostname verification secara otomatis | Hasil grep untuk `SSLSocket` kosong |
| P2 | `SSLSocket` dipakai, **dan** diikuti pemanggilan `getSession()` + `HostnameVerifier.verify()` yang hasil boolean-nya **diperiksa secara eksplisit**, dengan exception/penolakan koneksi bila verifikasi gagal | Kode sesuai pola rekomendasi §1.4 |
| P3 | `SSLSocket` dipakai untuk kebutuhan **non-network-sensitive** yang terverifikasi tidak membawa risiko (mis. loopback connection ke proses lokal yang sama, bukan komunikasi ke server eksternal) | Review manual mengonfirmasi endpoint adalah `localhost`/`127.0.0.1` untuk IPC internal |
| P4 | Konfirmasi dinamis (Metode D) menunjukkan koneksi **ditolak/gagal** ketika disajikan sertifikat valid untuk domain yang salah | `SSLHandshakeException: Hostname tidak cocok` terlempar sesuai ekspektasi |

**Contoh output yang menandakan PASS:**

```java
SSLSocket socket = (SSLSocket) factory.createSocket(host, port);
socket.startHandshake();
SSLSession session = socket.getSession();
if (!HttpsURLConnection.getDefaultHostnameVerifier().verify(host, session)) {
    socket.close();
    throw new SSLHandshakeException("Hostname verification gagal untuk: " + host);
}
sendData(socket, buildPayload());  // hanya dieksekusi bila verifikasi berhasil
```

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Jangan mengandalkan hasil kosong dari rule semgrep resmi sebagai bukti PASS.** Ini catatan terpenting dari seluruh dokumen ini — dijelaskan mendalam di §3.2, rule resmi `mastg-android-network-hostname-verification.yml` secara struktural mencari pola yang **berlawanan** dengan kondisi FAIL test ini. Kode yang benar-benar rentan (tidak ada `HostnameVerifier` sama sekali) justru **tidak akan** memicu rule tersebut.

2. **NSC yang ketat tidak memberi jaminan apa pun untuk kode `SSLSocket`.** Sesuai §1.3, jangan biarkan hasil PASS dari MASTG-TEST-0235 (cleartext config) membuat penguji berasumsi aspek jaringan lain sudah aman — keduanya menguji lapisan yang sama sekali berbeda.

3. **Pemanggilan `verify()` yang ada TIDAK otomatis berarti PASS** — periksa juga apakah nilai kembalian booleannya benar-benar diperiksa (F3). Ini kesalahan implementasi yang sangat mudah luput dari pembacaan sekilas karena kode "terlihat" sudah memanggil API yang benar.

4. **Prioritaskan pencarian pada kode komunikasi kustom/protokol proprietary**, bukan kode yang jelas-jelas memakai HTTP standar — sesuai §1.3, `SSLSocket` biasanya muncul di jalur komunikasi non-HTTP (chat, IoT pairing, protokol biner kustom) yang lebih jarang diaudit dibanding kode REST API biasa.

5. **Korelasikan dengan MASTG-TEST-0283 setiap kali `HostnameVerifier` ditemukan ADA.** Temuan `HostnameVerifier` yang ada bukan otomatis PASS untuk keseluruhan aspek verifikasi hostname — ikuti rujukan resmi ke TEST-0283 untuk menilai kebenaran implementasinya.

6. **Severity dimodulasi oleh sensitivitas protokol yang berjalan di atas `SSLSocket` tersebut:**

   | Faktor | Severity |
   |---|---|
   | `SSLSocket` dipakai untuk protokol yang membawa kredensial/data finansial/pesan pribadi, tanpa verifikasi apa pun | **Kritis** |
   | `SSLSocket` dipakai untuk telemetri/analytics non-sensitif tanpa verifikasi | **Menengah** |
   | `SSLSocket` dipakai hanya untuk IPC lokal (`localhost`), tanpa risiko MITM jaringan nyata | **Rendah/Informational** |
   | Verifikasi ada tapi nilai kembalian tidak diperiksa (F3) | **Tinggi** — secara efektif sama parahnya dengan tidak ada verifikasi sama sekali |

7. **Dokumentasikan:** lokasi kode pembuatan `SSLSocket`, ada/tidaknya pemanggilan `verify()` beserta jaraknya dari titik pembuatan socket (blok sama/lintas fungsi), status pemeriksaan nilai kembalian boolean, dan bukti konfirmasi dinamis (Metode D/E) bila dilakukan.

---

## 4. Rekomendasi Perbaikan

### 4.1 Implementasikan Hostname Verification Eksplisit Setiap Kali Memakai `SSLSocket`

```java
SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
SSLSocket socket = (SSLSocket) factory.createSocket(host, port);
socket.startHandshake();

SSLSession session = socket.getSession();
HostnameVerifier verifier = HttpsURLConnection.getDefaultHostnameVerifier();
if (!verifier.verify(host, session)) {
    socket.close();
    throw new SSLPeerUnverifiedException("Hostname verification gagal: " + host
        + " tidak cocok dengan sertifikat yang disajikan server");
}
// Koneksi baru dianggap aman untuk dipakai SETELAH titik ini
```

**Selalu periksa nilai kembalian `verify()` secara eksplisit** — jangan asumsikan exception akan dilempar otomatis (lihat peringatan §1.4).

### 4.2 Migrasi ke API Level Tinggi Bila Memungkinkan

Bila kebutuhan bisnis tidak secara ketat mengharuskan kontrol socket level-rendah, migrasi ke `HttpsURLConnection` atau OkHttp jauh lebih aman karena hostname verification sudah ditangani otomatis oleh framework, mengurangi permukaan kesalahan implementasi manual:

```java
// Alternatif yang menangani hostname verification otomatis
OkHttpClient client = new OkHttpClient.Builder().build();
Request request = new Request.Builder().url("https://" + host + path).build();
Response response = client.newCall(request).execute();
```

### 4.3 Sentralisasi Logika Koneksi TLS Kustom

Bila `SSLSocket` tetap diperlukan (mis. untuk protokol non-HTTP), buat **satu wrapper terpusat** yang selalu menyertakan langkah verifikasi, alih-alih membiarkan setiap bagian kode membuat `SSLSocket` secara independen — ini mengurangi risiko satu titik lupa menambahkan verifikasi di antara banyak titik pembuatan socket:

```java
public final class SecureSocketFactory {
    public static SSLSocket createVerifiedSocket(String host, int port) throws IOException {
        SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        SSLSocket socket = (SSLSocket) factory.createSocket(host, port);
        socket.startHandshake();
        if (!HttpsURLConnection.getDefaultHostnameVerifier().verify(host, socket.getSession())) {
            socket.close();
            throw new SSLPeerUnverifiedException("Hostname verification gagal: " + host);
        }
        return socket;
    }
}
```

### 4.4 Integrasikan ke CI/CD dengan Rule yang Benar Secara Semantik

```bash
#!/bin/bash
# ci-check-sslsocket-hostname.sh — GUNAKAN rule kustom (§3.3), BUKAN rule resmi MASTG yang salah target
APK=$1
jadx -d /tmp/decompiled_check "$APK" 2>/dev/null
semgrep -c ./custom-sslsocket-hostname-rule.yml /tmp/decompiled_check/sources/ --json | jq '.results | length'
```

### 4.5 Checklist Remediasi

- [ ] Seluruh penggunaan `SSLSocket`/`SSLSocketFactory` di codebase sudah diinventarisasi (Metode B/C, **bukan** hanya rule resmi)
- [ ] Setiap pembuatan `SSLSocket` diikuti pemanggilan `getSession()` + `HostnameVerifier.verify()` sebelum socket dipakai mengirim/menerima data
- [ ] Nilai kembalian boolean dari `verify()` diperiksa secara eksplisit, dengan penanganan kegagalan yang menolak koneksi
- [ ] Bila memungkinkan, migrasi ke `HttpsURLConnection`/OkHttp yang menangani verifikasi otomatis
- [ ] Logika koneksi TLS kustom disentralisasi lewat satu factory/wrapper untuk konsistensi
- [ ] Untuk setiap `HostnameVerifier` yang ditemukan ADA, dilanjutkan pengujian MASTG-TEST-0283 untuk menilai keamanan implementasinya
- [ ] Konfirmasi dinamis (Metode D atau E) sudah dilakukan pada jalur komunikasi yang memakai `SSLSocket`
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0234 pada APK release final setelah remediasi

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0234: Missing Implementation of Server Hostname Verification with SSLSockets](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0234/)
- [MASTG-TEST-0283: Incorrect Implementation of Server Hostname Verification](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0283/)
- [MASWE-0027: Insecure Certificate Validation](https://mas.owasp.org/MASWE/MASVS-NETWORK/MASWE-0027/)
- [MASTG-TECH-0013: Reverse Engineering Android Apps](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/)
- [MASTG-TECH-0014: Static Analysis on Android](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/)
- [MASTG-TECH-0023: Reviewing Decompiled Java Code](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/)
- [MASTG Document 0x04f — Testing Network Communication](https://mas.owasp.org/MASTG/0x04f-Testing-Network-Communication/)
- [Rule resmi: mastg-android-network-hostname-verification.yml (GitHub)](https://github.com/OWASP/mastg/blob/master/rules/mastg-android-network-hostname-verification.yml)
- [OWASP Mobile Top 10 2024 — M5: Insecure Communication](https://owasp.org/www-project-mobile-top-10/2023-risks/m5-insecure-communication)

### 5.2 Dokumentasi Resmi Android

- [Android Developers — Security with network protocols (SSLSocket warnings)](https://developer.android.com/privacy-and-security/security-ssl#WarningsSslSocket)
- [Android Developers — `SSLSocket` API reference](https://developer.android.com/reference/javax/net/ssl/SSLSocket)
- [Android Developers — `HostnameVerifier` API reference](https://developer.android.com/reference/javax/net/ssl/HostnameVerifier)
- [Android Developers — `HostnameVerifier.verify()` method reference](https://developer.android.com/reference/javax/net/ssl/HostnameVerifier#verify(java.lang.String,%20javax.net.ssl.SSLSession))
- [Android Developers — Unsafe HostnameVerifier (risks documentation)](https://developer.android.com/privacy-and-security/risks/unsafe-hostname)
- [Android Developers — Security with network protocols](https://developer.android.com/training/articles/security-ssl)

### 5.3 Riset dan Sumber Pihak Ketiga

- [op-co.de — Java/Android SSLSocket Vulnerable to MitM Attacks](https://op-co.de/blog/posts/java_sslsocket_mitm/)
- [Google — How to resolve Insecure HostnameVerifier (Play Console FAQ)](https://support.google.com/faqs/answer/7188426?hl=en)
- [grahamedgecombe/android-ssl — SSL certificate validation vulnerability detection tools](https://github.com/grahamedgecombe/android-ssl)
- [arXiv — An Application Package Configuration Approach to Mitigating Android SSL Vulnerabilities](https://arxiv.org/pdf/1410.7745)
- [arXiv — Ghera: A Repository of Android App Vulnerability Benchmarks](https://arxiv.org/pdf/1708.02380)
- [arXiv — Are Free Android App Security Analysis Tools Effective in Detecting Known Vulnerabilities?](https://arxiv.org/pdf/1806.09059)
- [NowSecure — Fully validate SSL/TLS (Secure Mobile Development Best Practices)](https://books.nowsecure.com/secure-mobile-development/en/sensitive-data/fully-validate-ssl-tls.html)
- [CWE-297: Improper Validation of Certificate with Host Mismatch](https://cwe.mitre.org/data/definitions/297.html)
- [CWE-295: Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)

### 5.4 Dokumentasi Tools

- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [Frida — Dynamic instrumentation toolkit](https://frida.re/docs/javascript-api/)
- [socat — Multipurpose relay (dipakai untuk simulasi server TLS domain salah)](http://www.dest-unreach.org/socat/)
- [mitmproxy](https://mitmproxy.org/)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026), dokumentasi resmi Android Developers, serta riset akademik dan komunitas keamanan seputar kerentanan validasi SSL Android. Test ini belum memiliki demo (MASTG-DEMO) resmi, dan rule semgrep resminya teridentifikasi memiliki celah struktural signifikan (§3.2) — dokumen ini menyediakan rule kustom dan metode alternatif yang secara semantik benar-benar menguji kondisi FAIL yang didefinisikan overview resmi.*
