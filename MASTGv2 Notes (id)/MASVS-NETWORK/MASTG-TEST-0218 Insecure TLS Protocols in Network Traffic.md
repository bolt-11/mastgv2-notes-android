# MASTG-TEST-0218 Insecure TLS Protocols in Network Traffic

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0218 |
| **Platform** | Android |
| **Kategori MASVS** | **MASVS-NETWORK** (MASVS-NETWORK-1: Aplikasi mengamankan seluruh lalu lintas jaringan sesuai praktik terkini) |
| **Weakness** | **MASWE-0026** — *Network Traffic Not Encrypted* |
| **Tipe Pengujian** | **Dynamic**, Network |
| **Profile** | L1, L2 |
| **Teknik terkait** | MASTG-TECH-0005 (Installing Apps), MASTG-TECH-0010 (Basic Network Monitoring/Sniffing) |
| **Demo terkait** | — (MASTG belum menyediakan demo untuk test ini) |
| **Counterpart statis** | **MASTG-TEST-0217** (Insecure TLS Protocols Explicitly Allowed in Code) |
| **CWE terkait** | CWE-326 (Inadequate Encryption Strength), CWE-327 (Use of a Broken or Risky Cryptographic Algorithm), CWE-757 (Algorithm Downgrade), CWE-319 (Cleartext Transmission of Sensitive Information) |
| **Standar acuan** | RFC 8996 (deprecating TLS 1.0/1.1), RFC 8446 (TLS 1.3), NIST SP 800-52 Rev. 2, PCI DSS 4.0 |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Kutipan langsung dari overview MASTG:

> *"While static analysis can identify configurations that allow insecure TLS versions, it may not accurately reflect the actual protocol used during live communications. This is because **TLS version negotiation occurs between the client (app) and the server at runtime**, where they agree on the most secure, mutually supported version."*
>
> *"By capturing and analyzing real network traffic, you can observe the **TLS version actually negotiated and in use**. This approach provides an accurate view of the protocol's security, accounting for the server's configuration, which may enforce or limit specific TLS versions."*
>
> *"In cases where static analysis is either incomplete or infeasible, examining network traffic can reveal instances where insecure TLS versions (e.g., TLS 1.0 or TLS 1.1) are actively in use."*

Test ini adalah **counterpart dinamis resmi dari MASTG-TEST-0217**. Keduanya berbagi weakness (MASWE-0026) dan kriteria evaluasi yang identik secara substansi ("versi TLS tidak aman digunakan"), tetapi menjawab pertanyaan yang berbeda:

| | MASTG-TEST-0217 (statis) | MASTG-TEST-0218 (dinamis) |
|---|---|---|
| Menjawab | "Versi apa yang **diaktifkan** di kode?" | "Versi apa yang **benar-benar dinegosiasikan**?" |
| Sumber kebenaran | Kode aplikasi | Handshake TLS nyata |
| Kelemahan | Tidak tahu apa yang server terima; tidak menjangkau kode dinamis/native/ter-obfuscate | Hanya menangkap alur yang di-*exercise*; tidak memberi lokasi kode |

### 1.2 Mengapa Analisis Statis Saja Tidak Cukup

Ini alasan keberadaan test ini. Versi TLS final adalah hasil **negosiasi dua pihak** — klien mengusulkan rentang versi yang didukungnya (`ClientHello`), server memilih satu (`ServerHello`). Analisis kode hanya melihat sisi klien, dan bisa keliru ke dua arah:

**Arah 1 — Statis bilang FAIL, tapi kenyataannya aman.** Kode mengaktifkan TLS 1.1 (misal demi kompatibilitas warisan), tetapi **server** yang sebenarnya dihubungi hanya menerima TLS 1.2/1.3. Koneksi nyata tidak pernah jatuh ke TLS 1.1. Severity riil lebih rendah — meski kode tetap perlu diperbaiki karena rentan terhadap server MitM jahat yang mau menerima downgrade (CWE-757).

**Arah 2 — Statis bilang PASS, tapi kenyataannya tidak aman.** Ini yang lebih berbahaya dan justru alasan utama test ini penting:

- **Konfigurasi dinamis/remote.** Array `enabledProtocols` bisa dibangun dari nilai yang diambil dari server konfigurasi remote, feature flag, atau file eksternal saat runtime — tidak pernah muncul sebagai literal statis.
- **Kode ter-obfuscate atau dimuat runtime** (DexClassLoader, plugin, JS bundle di React Native) — analisis statis biasa tidak menjangkaunya.
- **Library pihak ketiga / SDK closed-source** yang di-bundle sebagai `.aar`/`.jar` — kadang tidak didekompilasi sepenuhnya atau memakai reflection untuk mengonfigurasi socket.
- **Provider TLS non-default** (custom `Provider`, versi Conscrypt lama, atau stack TLS native `.so`) yang perilaku aktualnya tidak terlihat dari signature API level Java.
- **Downgrade oleh jaringan** — proxy korporat, WiFi publik, atau perangkat MitM transparan yang memaksa fallback ke versi lama tanpa sepengetahuan aplikasi maupun analisis statis.

Kutipan MASTG menegaskan hal ini secara eksplisit: *"In cases where **static analysis is either incomplete or infeasible**, examining network traffic can reveal instances where insecure TLS versions are actively in use."*

### 1.3 Wawasan Kunci: Versi TLS Terlihat Tanpa Perlu Mendekripsi Trafik

Ini poin teknis terpenting yang membedakan test ini dari test jaringan lain seperti **MASTG-TEST-0206** (yang butuh dekripsi TLS penuh via MitM untuk melihat isi payload).

**Handshake TLS — `ClientHello` dan `ServerHello` — dikirim dalam bentuk *cleartext* by design**, karena kedua pihak belum menyepakati kunci sesi saat itu. Field versi protokol berada tepat di handshake ini:

| Pesan | Berisi | Field versi |
|---|---|---|
| `ClientHello` | Rentang versi yang **diusulkan klien** | `legacy_version` (Record layer) + ekstensi `supported_versions` (untuk TLS 1.3) |
| `ServerHello` | Versi yang **dipilih server** — inilah versi final yang dipakai | Sama, tetapi berisi satu nilai final |

Konsekuensi praktis yang sangat menguntungkan untuk pengujian:

- **Tidak perlu memasang sertifikat CA proxy.**
- **Tidak perlu membypass certificate pinning.**
- **Tidak perlu mendekripsi apa pun.**
- Cukup **capture paket mentah** (`tcpdump`/Wireshark) dan baca dua pesan handshake pertama.

Ini membuat test ini jauh lebih mudah dieksekusi daripada MASTG-TEST-0206 — bahkan pada aplikasi dengan pinning paling ketat sekalipun, kamu tetap bisa melihat versi TLS yang dipakai tanpa harus menembus pinning-nya.

> **Nuansa TLS 1.3:** pada TLS 1.3, field `legacy_version` di Record layer dan `ClientHello`/`ServerHello` **selalu** menunjukkan `0x0303` (TLS 1.2) demi kompatibilitas middlebox lama. Versi TLS 1.3 yang sebenarnya disepakati justru muncul di **ekstensi `supported_versions`** pada `ServerHello`. Salah baca field ini adalah sumber kesalahan paling umum saat menganalisis capture — lihat §3.2.

### 1.4 Klasifikasi Versi TLS (Acuan Penilaian)

Identik dengan MASTG-TEST-0217 — keduanya menilai terhadap standar yang sama:

| Versi | Nilai hex (handshake) | Status | Verdict |
|---|---|---|---|
| SSLv3 | `0x0300` | Broken (POODLE) | ❌ Tidak boleh |
| **TLS 1.0** | `0x0301` | **Deprecated (RFC 8996)** | ❌ Insecure |
| **TLS 1.1** | `0x0302` | **Deprecated (RFC 8996)** | ❌ Insecure |
| **TLS 1.2** | `0x0303` | Aktif | ✅ Praktik terbaik |
| **TLS 1.3** | `0x0304` (via ekstensi `supported_versions`) | Aktif | ✅ Praktik terbaik (default Android 10+) |

Rujuk **MASTG-TEST-0217 §1.3** untuk detail kerentanan BEAST/POODLE/downgrade attack pada TLS 1.0/1.1 — landasannya identik.

### 1.5 Cakupan yang Perlu Diuji: Semua Koneksi, Bukan Hanya API Utama

Aplikasi modern membuka banyak koneksi TLS yang independen satu sama lain, dan masing-masing bisa punya konfigurasi/versi berbeda:

| Jenis koneksi | Contoh | Catatan |
|---|---|---|
| API backend utama | `api.example.com` | Biasanya paling terkontrol dan aman |
| SDK analytics/ads | `app-measurement.com`, `graph.facebook.com` | Dikendalikan vendor pihak ketiga — bisa punya konfigurasi TLS berbeda |
| CDN / static asset | `cdn.example.com` | Sering di infrastruktur terpisah dengan kebijakan TLS sendiri |
| WebView (jika ada) | Halaman web yang dimuat | Menggunakan stack TLS sistem WebView, bukan OkHttp aplikasi |
| Push notification | FCM/GCM (lihat MASTG-TECH-0010) | Protokol XMPP/HTTP terpisah, port berbeda (5228-5230, 5235-5236) |
| Update/OTA check | Server update konfigurasi remote | Kadang di-skip dari audit karena dianggap "bukan data sensitif" |
| Koneksi native/NDK | Socket dari library `.so` | Tidak lewat stack Java sama sekali |

**Jangan hanya menguji happy path login.** Endpoint sekunder (analytics, CDN, push) sering luput dari perhatian developer saat hardening TLS, justru karena tidak dianggap kritis — padahal semuanya tetap membawa risiko downgrade attack.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | MASTG ID | Fungsi |
|---|---|---|
| **tcpdump** (Android) | MASTG-TOOL-0080 | Capture paket di device — direkomendasikan MASTG-TECH-0010. Butuh root |
| **Wireshark** | MASTG-TOOL-0081 | Analisis capture, filter `tls.handshake.version` / `supported_versions` |
| **adb** | MASTG-TOOL-0004 | Instalasi aplikasi, port forwarding untuk remote sniffing |
| **netcat (nc)** | — | Pipa `tcpdump` dari device ke Wireshark di host (MASTG-TECH-0010) |

### 2.2 Tools Pendukung

| Tool | Fungsi |
|---|---|
| **tshark** | CLI Wireshark — parsing otomatis untuk laporan/CI, jauh lebih cepat dari GUI untuk banyak flow |
| **mitmproxy / Burp / ZAP** | Alternatif capture — menampilkan versi TLS per flow tanpa perlu membaca hex handshake manual |
| **testssl.sh / sslscan / nmap** | Audit versi TLS dari **sisi server** — melengkapi bukti dari sisi klien |
| **Frida / Objection** | Konfirmasi versi TLS langsung dari objek session di runtime (§3.4) — pelengkap bila capture paket sulit dilakukan |
| **PCAPdroid** | Capture paket **tanpa root**, langsung dari aplikasi Android (VpnService) |
| **Android Studio Network Profiler** | Melihat koneksi jaringan aplikasi selama debugging, termasuk metadata TLS dasar |

### 2.3 Prasyarat Lingkungan

- **Root untuk `tcpdump` di device** (MASTG-TECH-0010) — atau gunakan **PCAPdroid** sebagai alternatif tanpa root (§3.3).
- **Tidak perlu memasang sertifikat CA** dan **tidak perlu bypass certificate pinning** — ini keuntungan unik test ini (§1.3). Bila kamu sudah punya setup MitM dari MASTG-TEST-0206, itu tetap bisa dipakai, tetapi tidak wajib.
- **Exercise aplikasi secara ekstensif** dan mencakup **semua jenis koneksi** (§1.5) — bukan hanya alur login/API utama.
- **Canary/marker waktu** tidak diperlukan di sini (berbeda dari test PII) — cukup pastikan setiap fitur jaringan dipicu setidaknya sekali.
- **Siapkan baseline server** — bila memungkinkan, uji juga endpoint dengan `testssl.sh` untuk tahu versi apa yang **bisa** dinegosiasikan, sebagai pembanding terhadap apa yang **benar-benar** dinegosiasikan aplikasi.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0005** (*Installing Apps*) untuk menginstall aplikasi.
2. Gunakan **MASTG-TECH-0010** (*Basic Network Monitoring/Sniffing*) untuk menangkap trafik aplikasi.
3. **Exercise aplikasi secara ekstensif** untuk memicu sebanyak mungkin alur, masukkan data sensitif di setiap tempat yang memungkinkan.

### 3.2 Metode A — tcpdump di device + Wireshark *(resmi, MASTG-TECH-0010)*

**Langkah 1 — Pasang tcpdump di device (butuh root):**

```bash
adb root
adb remount
adb push ./tcpdump /system/xbin/tcpdump

# Bila "adbd cannot run as root in production builds":
adb push ./tcpdump /data/local/tmp/tcpdump
adb shell
su
mount -o rw,remount /system    # atau: mount -o rw,remount /  bila /system tidak termount
cp /data/local/tmp/tcpdump /system/xbin/
chmod 755 /system/xbin/tcpdump
```

**Langkah 2 — Remote sniffing ke Wireshark di host:**

```bash
# Di device (via adb shell):
tcpdump -i wlan0 -s0 -w - | nc -l -p 11111

# Di host:
adb forward tcp:11111 tcp:11111
nc localhost 11111 | wireshark -k -S -i -
```

**Langkah 3 — Exercise aplikasi** mencakup semua jenis koneksi (§1.5), lalu hentikan capture.

**Langkah 4 — Analisis di Wireshark:**

```
Filter tampilan:
  tls.handshake.type == 1                     # semua ClientHello
  tls.handshake.type == 2                     # semua ServerHello
  tls.handshake.version < 0x0303              # <-- VERSI TIDAK AMAN (TLS < 1.2)
```

**Analisis dengan tshark (lebih cepat, scriptable):**

```bash
# Ekstrak versi handshake dari SEMUA ServerHello (versi yang final dipilih server)
tshark -r capture.pcap -Y "tls.handshake.type==2" -T fields \
  -e ip.dst -e tcp.dstport -e tls.handshake.version

# PENTING: cek juga ekstensi supported_versions untuk TLS 1.3
# (handshake.version akan tetap 0x0303 meski sebenarnya TLS 1.3)
tshark -r capture.pcap -Y "tls.handshake.type==2 && tls.handshake.extensions_supported_version" \
  -T fields -e ip.dst -e tls.handshake.extensions_supported_version

# Rekap per host tujuan — cek SEMUA endpoint, bukan hanya API utama
tshark -r capture.pcap -Y "tls.handshake.type==2" -T fields \
  -e ip.dst -e tls.handshake.version -e tls.handshake.extensions_supported_version \
  | sort -u

# Filter langsung untuk versi tidak aman (SSLv3/TLS1.0/1.1) — hex < 0x0303
tshark -r capture.pcap -Y "tls.handshake.type==2 && tls.handshake.version < 0x0303" \
  -T fields -e ip.dst -e tls.handshake.version
```

> **Cara membaca hasil dengan benar (hindari kesalahan paling umum):** bila `tls.handshake.version == 0x0303` **dan** ekstensi `supported_versions` **kosong/tidak ada**, itu berarti **TLS 1.2 sungguhan**. Bila `tls.handshake.version == 0x0303` **tetapi** ekstensi `supported_versions` berisi `0x0304`, itu berarti **TLS 1.3** (field utama sengaja dipertahankan `0x0303` demi kompatibilitas middlebox). Salah membaca ini bisa membuat kamu keliru melaporkan TLS 1.3 sebagai TLS 1.2.

### 3.3 Metode B — PCAPdroid *(tanpa root, langsung dari device)*

Alternatif ketika root tidak tersedia — PCAPdroid memakai `VpnService` Android untuk menangkap trafik semua aplikasi (atau difilter per-app) tanpa memerlukan akses root maupun modifikasi sistem.

```
1. Install PCAPdroid dari F-Droid/Play Store
2. Pilih target: filter berdasarkan aplikasi yang diuji
3. Start capture -> exercise aplikasi -> Stop
4. Export sebagai .pcap
5. Tarik file dan buka di Wireshark/tshark seperti Metode A
```

```bash
adb pull /sdcard/Download/PCAPdroid/capture.pcap
tshark -r capture.pcap -Y "tls.handshake.type==2" -T fields -e ip.dst -e tls.handshake.version
```

Keunggulan: tidak butuh root, setup jauh lebih cepat. Keterbatasan: performa capture pada beberapa perangkat bisa memengaruhi latensi aplikasi selama pengujian.

### 3.4 Metode C — mitmproxy / Burp / ZAP *(bila sudah ada infrastruktur MitM dari TEST-0206)*

Bila kamu sudah menyiapkan interception proxy untuk MASTG-TEST-0206, ia juga bisa dipakai di sini — **meski tidak wajib** (§1.3). Kelebihannya: versi TLS ditampilkan langsung di UI tanpa perlu membaca field handshake mentah.

```bash
# mitmproxy — tampilkan versi TLS per flow
mitmdump --set flow_detail=3 -s show_tls.py
```

```python
# show_tls.py
from mitmproxy import tls

def tls_established_client(data: tls.TlsData):
    print(f"[{data.context.client.peername}] TLS version: {data.context.client.tls_version}")
```

```bash
mitmdump -s show_tls.py
```

Di **Burp Suite**: Proxy > HTTP history > klik request > tab **TLS** menampilkan versi dan cipher suite yang dipakai per koneksi.

Di **ZAP**: History > klik request > tab **Alerts**/**TLS handshake detail** (via addon).

> Catat: metode ini **membutuhkan** bypass pinning bila aplikasi memvalidasi sertifikat (karena proxy menyisipkan sertifikatnya sendiri) — kelemahan yang tidak dimiliki Metode A/B. Gunakan hanya bila kamu memang sudah punya setup ini untuk keperluan lain.

### 3.5 Metode D — Frida: konfirmasi versi dari objek session runtime

Pelengkap ketika capture paket sulit dilakukan (mis. jaringan korporat yang membatasi), atau untuk mengaitkan versi TLS langsung dengan nama host dan stack trace pemanggil di satu log yang sama.

```javascript
// tls_version_negotiated.js
Java.perform(() => {
    function bt(max = 8) {
        const E = Java.use("java.lang.Exception");
        const st = E.$new().getStackTrace();
        return Array.from({length: Math.min(max, st.length)}, (_, i) => "    " + st[i]).join("\n");
    }

    // Conscrypt (provider TLS default Android modern)
    try {
        const Session = Java.use("com.android.org.conscrypt.ActiveSession");
        Session.getProtocol.implementation = function () {
            const v = this.getProtocol();
            const bad = /SSLv3|TLSv1(?!\.[23])|TLSv1\.1/.test(v);
            console.log(`\n[Negotiated] ${v}${bad ? "  [!! INSECURE !!]" : ""}`);
            console.log(bt());
            return v;
        };
    } catch (e) {}

    // Hook generik lewat SSLSession (bekerja lintas provider)
    try {
        const SSLSocketImpl = Java.use("javax.net.ssl.SSLSession");
        // SSLSession adalah interface; hook lewat instance konkret saat koneksi terbentuk
    } catch (e) {}

    // OkHttp Handshake.tlsVersion() — sangat berguna karena OkHttp paling umum dipakai
    try {
        const Handshake = Java.use("okhttp3.Handshake");
        Handshake.tlsVersion.implementation = function () {
            const v = this.tlsVersion();
            console.log(`\n[OkHttp Negotiated] ${v}`);
            console.log(bt());
            return v;
        };
    } catch (e) {}
});
```

```bash
frida -U -f com.example.target -l tls_version_negotiated.js -o negotiated.log
# Exercise aplikasi, lalu:
grep -B1 "INSECURE" negotiated.log
```

### 3.6 Metode E — Audit sisi server *(pelengkap, mengonfirmasi kapasitas negosiasi)*

Ini melengkapi bukti dari sisi klien dengan mengetahui **apa yang mungkin** dinegosiasikan endpoint tersebut.

```bash
testssl.sh --protocols api.example.com:443
sslscan api.example.com
nmap --script ssl-enum-ciphers -p 443 api.example.com
```

Bila server **hanya** mendukung TLS 1.2/1.3, maka trafik aplikasi **tidak mungkin** jatuh ke versi lebih rendah — memberi keyakinan tambahan atas hasil capture. Sebaliknya, bila server masih mendukung TLS 1.0/1.1 sebagai fallback, ini menandai risiko downgrade meski capture saat ini menunjukkan TLS 1.2/1.3 (server memilih versi teraman yang tersedia — belum tentu klien tidak akan menerima yang lebih rendah bila diusulkan MitM jahat).

### 3.7 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Butuh root? | Butuh bypass pinning? | Memberi lokasi kode? | Kapan dipakai |
|---|---|---|---|---|---|
| **A** | tcpdump + Wireshark/tshark (MASTG) | **Ya** | **Tidak** | ❌ | **Baseline resmi** — paling akurat, membaca handshake langsung |
| **B** | PCAPdroid | **Tidak** | Tidak | ❌ | Device non-root |
| **C** | mitmproxy / Burp / ZAP | Sebagian | **Ya** (bila pinning aktif) | ❌ | Bila infrastruktur MitM sudah ada dari test lain |
| **D** | Frida (objek session) | Ya/gadget | Tidak | Sebagian (backtrace) | Capture paket sulit; ingin korelasi host + kode pemanggil |
| **E** | testssl.sh / sslscan / nmap | Tidak¹ | — | — | Kalibrasi kapasitas negosiasi sisi server |

¹ Metode E butuh akses jaringan ke server, bukan ke device.

**Kombinasi minimum yang aku rekomendasikan:** **A atau B (capture paket) → E (audit server)**.
Capture paket adalah sumber kebenaran untuk versi yang benar-benar dipakai (dan tidak perlu bypass apa pun); audit server memberi konteks apakah risiko downgrade nyata ada. Tambahkan **D (Frida)** bila kamu perlu mengaitkan versi TLS langsung ke stack trace kode pemanggil untuk keperluan remediasi.

---

### 3.8 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Observation:** *"The output should contain the app traffic."*
>
> **Evaluation:** *"The test case **fails** if any insecure TLS version is used."*

Kriterianya sangat lugas — sama semangatnya dengan MASTG-TEST-0217, tetapi sumber kebenarannya kini **negosiasi nyata**, bukan konfigurasi kode.

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi | Contoh bukti |
|---|---|---|
| F1 | `ServerHello` menunjukkan `handshake.version` **< `0x0303`** untuk koneksi mana pun | `tls.handshake.version == 0x0302` (TLS 1.1) ke `api.example.com` |
| F2 | Handshake memakai SSLv3 | `tls.handshake.version == 0x0300` |
| F3 | Koneksi ke **endpoint sekunder** (analytics, CDN, push) memakai versi tidak aman | TLS 1.1 ke `app-measurement.com`, meski API utama sudah TLS 1.3 |
| F4 | Frida mengonfirmasi `Handshake.tlsVersion()` mengembalikan `TLS_1_0`/`TLS_1_1` | `[OkHttp Negotiated] TLS_1_1  [!! INSECURE !!]` |
| F5 | Trafik cleartext (bukan TLS sama sekali) ditemukan pada koneksi yang seharusnya terenkripsi | Tidak ada handshake TLS; data mengalir sebagai plaintext HTTP — pelanggaran MASWE-0026 yang lebih berat |
| F6 | Downgrade dapat direproduksi: memblokir TLS 1.2/1.3 di jaringan pengujian memaksa aplikasi jatuh ke TLS 1.1 tanpa penolakan | Aplikasi tidak menegakkan versi minimum sendiri — bergantung penuh pada server |

**Contoh bukti (ilustratif — MASTG belum menyediakan demo resmi):**

```bash
$ tshark -r capture.pcap -Y "tls.handshake.type==2" -T fields \
    -e ip.dst -e tls.handshake.version -e tls.handshake.extensions_supported_version

192.0.2.10    0x0303
192.0.2.11    0x0302
198.51.100.5  0x0303    0x0304
```

Interpretasi: baris pertama TLS 1.2 (aman), baris kedua `0x0302` = **TLS 1.1 — FAIL**, baris ketiga TLS 1.3 (aman, terlihat dari ekstensi `supported_versions`).

> Karena MASTG belum menerbitkan MASTG-DEMO untuk test ini, contoh di atas disusun berdasarkan struktur output resmi `tshark` dan field TLS standar (RFC 8446), bukan dikutip dari artefak MASTG.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi | Contoh bukti |
|---|---|---|
| P1 | **Semua** koneksi (termasuk endpoint sekunder) menegosiasikan TLS 1.2 atau TLS 1.3 | Seluruh baris `tshark` menunjukkan `0x0303` tanpa `supported_versions` lama, atau `0x0304` |
| P2 | Tidak ditemukan trafik cleartext pada koneksi yang seharusnya terenkripsi | Semua trafik terbungkus TLS |
| P3 | Frida mengonfirmasi `tlsVersion()` selalu `TLS_1_2`/`TLS_1_3` di seluruh sesi exercise | Tidak ada flag `INSECURE` di log |
| P4 | Downgrade tidak dapat direproduksi — aplikasi menolak koneksi saat versi aman tidak tersedia | Aplikasi gagal terhubung (bukan fallback diam-diam) ketika TLS 1.2/1.3 diblokir di jaringan uji |

**Contoh output yang menandakan PASS:**

```bash
$ tshark -r capture.pcap -Y "tls.handshake.type==2 && tls.handshake.version < 0x0303" \
    -T fields -e ip.dst -e tls.handshake.version
# (tidak ada hasil -> tidak ada ServerHello dengan versi < TLS 1.2)
```

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Baca ekstensi `supported_versions`, jangan hanya field `handshake.version` utama.** Ini kesalahan paling umum (§3.2). TLS 1.3 sengaja menampilkan `0x0303` di field utama demi kompatibilitas middlebox — versi asli ada di ekstensi. Salah baca ini bisa membuat TLS 1.3 dilaporkan sebagai "hanya TLS 1.2" (bukan FAIL, tetapi tidak akurat) atau sebaliknya melewatkan downgrade yang sesungguhnya terjadi di ekstensi lain.

2. **Cakup semua endpoint, bukan hanya API utama (§1.5).** Endpoint analytics/CDN/push sering luput dari hardening developer justru karena dianggap "kurang penting" — padahal tetap membawa risiko yang sama.

3. **Output kosong bisa berarti dua hal: PASS, atau alur belum ter-exercise.** Bila suatu fitur (mis. upload dokumen, chat) tidak pernah dijalankan selama capture, koneksinya tidak akan muncul di pcap sama sekali — ini bukan bukti aman, melainkan **belum diuji**. Selalu bandingkan daftar host di capture dengan inventaris fitur aplikasi.

4. **FAIL statis (TEST-0217) + PASS dinamis (TEST-0218) tidak saling meniadakan.** Bila kode mengaktifkan TLS 1.1 tetapi server menolaknya sehingga capture selalu menunjukkan TLS 1.2, **TEST-0217 tetap FAIL** (kode rentan terhadap server MitM jahat) sementara **TEST-0218 PASS untuk sesi pengujian itu**. Laporkan keduanya secara terpisah dengan penjelasan hubungan sebab-akibatnya — jangan biarkan hasil PASS dinamis menutupi temuan statis.

5. **Sebaliknya, PASS statis + FAIL dinamis adalah sinyal serius.** Ini berarti ada sumber downgrade yang **tidak terlihat dari kode** — konfigurasi remote, SDK pihak ketiga, atau downgrade jaringan. Investigasi lebih lanjut wajib: periksa dependency pihak ketiga dan uji ulang di jaringan berbeda untuk menyingkirkan kemungkinan gangguan jaringan pengujian itu sendiri.

6. **Uji di lebih dari satu jaringan** bila memungkinkan (WiFi rumah, data seluler, WiFi publik). Downgrade yang dipicu proxy korporat atau captive portal tidak akan terlihat bila kamu hanya menguji di satu jaringan yang "bersih".

7. **Coba reproduksi downgrade secara aktif** (F6/P4) untuk menilai resiliensi, bukan hanya observasi pasif. Blokir TLS 1.2/1.3 di firewall pengujian (mis. `iptables` menolak cipher suite tertentu, atau proxy MitM yang hanya menawarkan TLS 1.1) dan amati apakah aplikasi menolak koneksi (baik) atau diam-diam melanjutkan dengan versi lemah (FAIL — ini bukti kuat aplikasi tidak menegakkan versi minimum di sisi klien).

8. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | TLS 1.0/1.1 dinegosiasikan pada koneksi yang membawa data sensitif (login, pembayaran) | **Tinggi** |
   | TLS 1.1 hanya pada endpoint sekunder non-sensitif (mis. analytics anonim) | **Menengah** |
   | Trafik cleartext ditemukan (bukan sekadar TLS lemah) | **Kritis** |
   | Downgrade dapat direproduksi secara aktif (aplikasi tidak menegakkan versi minimum) | **Tinggi** — indikasi kerentanan MitM yang eksploitable |
   | Semua koneksi konsisten TLS 1.2/1.3 di berbagai jaringan uji | **Bukan temuan** |

9. **Dokumentasikan:** file capture (`.pcap`) sebagai bukti mentah, daftar host beserta versi TLS yang dinegosiasikan (tabel dari tshark), jaringan pengujian yang dipakai, hasil audit sisi server (testssl.sh) sebagai pembanding, dan — bila ada — hasil uji downgrade aktif. Silangkan dengan temuan MASTG-TEST-0217 untuk narasi lengkap.

---

## 4. Rekomendasi Perbaikan

Karena akar masalahnya sama dengan MASTG-TEST-0217 (MASWE-0026), rekomendasi berikut melengkapi — bukan menggantikan — rekomendasi di dokumen tersebut, dengan penekanan pada aspek yang khusus terlihat lewat pengujian jaringan.

### 4.1 Prinsip Utama

**Prioritas 1 — Perbaiki kode sesuai MASTG-TEST-0217.** Bila FAIL di test ini berasal dari konfigurasi eksplisit (`setEnabledProtocols`, `COMPATIBLE_TLS`, dll.), rujuk rekomendasi lengkap di dokumen tersebut.

**Prioritas 2 — Tegakkan versi minimum di SISI KLIEN, jangan hanya bergantung pada server.** Ini poin yang ditegaskan oleh catatan penilaian #7 di atas: aplikasi yang diam-diam menerima downgrade bukti nyata tidak menegakkan kebijakannya sendiri.

```kotlin
// ✅ Paksa klien MENOLAK bila hanya versi lemah yang tersedia
val spec = ConnectionSpec.Builder(ConnectionSpec.RESTRICTED_TLS)
    .tlsVersions(TlsVersion.TLS_1_3, TlsVersion.TLS_1_2)   // TIDAK ada fallback ke versi lama
    .build()
val client = OkHttpClient.Builder()
    .connectionSpecs(listOf(spec))   // tanpa CLEARTEXT/COMPATIBLE_TLS sebagai fallback
    .build()
```

**Prioritas 3 — Perbaiki konfigurasi TLS di SEMUA endpoint, bukan hanya API utama.** Audit SDK analytics, CDN, push notification, dan koneksi WebView secara terpisah — masing-masing mungkin punya jalur konfigurasi TLS sendiri di luar kendali langsung kode aplikasi (mis. versi SDK vendor yang usang).

**Prioritas 4 — Perbarui SDK/library pihak ketiga.** Bila sumber downgrade adalah SDK vendor (bukan kode sendiri), update ke versi terbaru atau hubungi vendor. Ini kasus di mana FAIL dinamis tidak tertangkap analisis statis kode sendiri (§ catatan penilaian 5).

**Prioritas 5 — Perkuat konfigurasi server.** Nonaktifkan TLS 1.0/1.1 sepenuhnya di sisi server (bukan hanya di sisi klien) sehingga tidak ada jalur negosiasi ke versi lama sama sekali, terlepas dari apa yang diusulkan klien. Audit dengan `testssl.sh` setelah perubahan.

**Prioritas 6 — Uji ulang di berbagai kondisi jaringan** sebagai bagian dari regression testing, karena downgrade yang dipicu jaringan (proxy korporat, captive portal) bisa muncul dan hilang tergantung lingkungan.

**Prioritas 7 — Integrasikan pengujian ini ke pipeline QA/rilis.** Jalankan capture otomatis (mis. via PCAPdroid scripted atau Frida script §3.5) pada smoke test rilis, dan gagalkan rilis bila ditemukan negosiasi versi lama pada endpoint mana pun.

### 4.2 Checklist Remediasi

- [ ] Seluruh koneksi (API utama, analytics, CDN, push, WebView) diaudit — bukan hanya alur login
- [ ] Tidak ada `ServerHello` dengan `handshake.version < 0x0303` pada capture manapun
- [ ] Ekstensi `supported_versions` diperiksa untuk memastikan TLS 1.3 terdeteksi dengan benar
- [ ] Klien menegakkan versi minimum sendiri (`tlsVersions` tanpa fallback ke versi lama) — tidak hanya bergantung pada penolakan server
- [ ] Uji downgrade aktif dilakukan: aplikasi menolak koneksi (bukan fallback diam-diam) ketika hanya versi lemah tersedia
- [ ] SDK pihak ketiga diperbarui bila menjadi sumber downgrade yang tidak terlihat di kode sendiri
- [ ] Server dikonfigurasi menolak TLS 1.0/1.1 sepenuhnya (diverifikasi dengan testssl.sh)
- [ ] Pengujian dilakukan di lebih dari satu jaringan (WiFi rumah, seluler, WiFi publik)
- [ ] Temuan disilangkan dengan MASTG-TEST-0217 untuk narasi akar masalah yang lengkap
- [ ] Pengujian jaringan terintegrasi ke pipeline QA/rilis sebagai regression check
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0218 setelah perbaikan → semua endpoint konsisten TLS 1.2/1.3

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0218: Insecure TLS Protocols in Network Traffic](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0218/)
- [MASTG-TEST-0217: Insecure TLS Protocols Explicitly Allowed in Code](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0217/)
- [MASWE-0026: Network Traffic Not Encrypted](https://mas.owasp.org/MASWE/MASVS-NETWORK/MASWE-0026/)
- [MASTG — Testing Network Communication (Recommended TLS Settings)](https://mas.owasp.org/MASTG/0x04f-Testing-Network-Communication/)
- [MASTG-TECH-0005: Installing Apps](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0005/)
- [MASTG-TECH-0010: Basic Network Monitoring/Sniffing](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0010/)
- [MASTG-TOOL-0080: tcpdump](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0080/)
- [MASTG-TOOL-0081: Wireshark](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0081/)
- [MASVS-NETWORK: Network Communication](https://mas.owasp.org/MASVS/06-MASVS-NETWORK/)
- [OWASP Mobile Top 10 2024 — M5: Insecure Communication](https://owasp.org/www-project-mobile-top-10/2023-risks/m5-insecure-communication.html)

### 5.2 Dokumentasi Wireshark & Analisis Paket

- [Wireshark — TLS dissector documentation](https://www.wireshark.org/docs/dfref/t/tls.html)
- [Ask Wireshark — Where can I find the TLS version in ClientHello?](https://ask.wireshark.org/question/5250/where-can-i-find-the-tls-version-that-is-being-sent-from-the-client-through-the-clienthello-to-the-server/)
- [AnalysisMan — Why TLS version differs in Record Layer and Handshake Protocol](https://www.analysisman.com/2021/06/wireshark-tls1.2.html)
- [F5 — Wireshark may provide misleading TLS version info](https://my.f5.com/manage/s/article/K90932505)
- [tshark — man page](https://www.wireshark.org/docs/man-pages/tshark.html)
- [Android remote sniffing using tcpdump, nc, and Wireshark](https://blog.dornea.nu/2015/02/20/android-remote-sniffing-using-tcpdump-nc-and-wireshark/)
- [androidtcpdump.com — tcpdump binary untuk Android](https://www.androidtcpdump.com/)

### 5.3 Standar Kriptografi & Taksonomi

- [RFC 8996 — Deprecating TLS 1.0 and TLS 1.1](https://www.rfc-editor.org/rfc/rfc8996.html)
- [RFC 8446 — TLS 1.3 (termasuk semantik `legacy_version` & `supported_versions`)](https://www.rfc-editor.org/rfc/rfc8446)
- [RFC 5246 — TLS 1.2](https://tools.ietf.org/html/rfc5246)
- [RFC 7525 / BCP 195 — Recommendations for Secure Use of TLS and DTLS](https://datatracker.ietf.org/doc/bcp195/)
- [NIST SP 800-52 Rev. 2 — Guidelines for TLS Implementations](https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final)
- [CWE-326: Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)
- [CWE-757: Selection of Less-Secure Algorithm During Negotiation](https://cwe.mitre.org/data/definitions/757.html)
- [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
- [PCI DSS — Migrating from SSL and early TLS](https://www.pcisecuritystandards.org/documents/Migrating-from-SSL-Early-TLS-Info-Supp-v1_1.pdf)

### 5.4 Android & Dokumentasi Terkait

- [Android — SSL/Security (TLS 1.3 default sejak Android 10)](https://developer.android.com/privacy-and-security/security-ssl)
- [Android 10 behavior changes — TLS 1.3 enabled by default](https://developer.android.com/about/versions/10/behavior-changes-all#tls-1.3)
- [OkHttp — TLS Configuration History](https://square.github.io/okhttp/security/tls_configuration_history/)
- [OkHttp `Handshake.tlsVersion()` — API reference](https://square.github.io/okhttp/4.x/okhttp/okhttp3/-handshake/tls-version/)
- [Firebase — Cloud Messaging server reference (XMPP/HTTP ports)](https://firebase.google.com/docs/cloud-messaging/server)

### 5.5 Dokumentasi Tools

- [PCAPdroid — packet capture tanpa root](https://github.com/emanuele-f/PCAPdroid)
- [testssl.sh — Testing TLS/SSL encryption](https://testssl.sh/)
- [sslscan](https://github.com/rbsec/sslscan)
- [nmap — ssl-enum-ciphers script](https://nmap.org/nsedoc/scripts/ssl-enum-ciphers.html)
- [mitmproxy — Documentation](https://docs.mitmproxy.org/stable/)
- [mitmproxy — TLS/SSL addon API](https://docs.mitmproxy.org/stable/api/mitmproxy/tls.html)
- [Burp Suite — TLS inspection](https://portswigger.net/burp/documentation/desktop)
- [OWASP ZAP — Documentation](https://www.zaproxy.org/docs/)
- [Frida — Documentation Home](https://frida.re/docs/home/)
- [Objection — runtime mobile exploration](https://github.com/sensepost/objection)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026), dokumentasi resmi Wireshark/tshark, RFC 8446/8996, standar NIST/PCI DSS, serta riset teknis pihak ketiga. Test ini belum memiliki demo (MASTG-DEMO) resmi dari MASTG; contoh output tshark pada dokumen ini disusun berdasarkan struktur field TLS standar untuk keperluan ilustrasi.*
