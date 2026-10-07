# MASTG-TEST-0236 Cleartext Traffic Observed on the Network

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0236 |
| **Platform** | Network (cross-platform — teknik Android dan iOS sama-sama dirujuk) |
| **Kategori MASVS** | MASVS-NETWORK |
| **Weakness** | MASWE-0026 — *Network Traffic Not Encrypted* |
| **Tipe Pengujian** | Dynamic, Network |
| **Teknik terkait** | MASTG-TECH-0010 (Basic Network Monitoring/Sniffing), MASTG-TECH-0011 (Setting Up an Interception Proxy), MASTG-TECH-0012 (Disable Pinning, Android); MASTG-TECH-0062/0063/0064 (ekuivalen iOS) |
| **Test terkait** | **MASTG-TEST-0235** (konfigurasi cleartext native — statis), **MASTG-TEST-0237** (konfigurasi cross-platform framework), **MASTG-TEST-0238** (hooking Frida — memecahkan keterbatasan atribusi test ini) |
| **Rule resmi** | — (tidak ada; test murni capture jaringan, tidak relevan untuk Semgrep) |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian dan Posisinya dalam Trio/Kuartet Cleartext Traffic

Kutipan overview resmi MASTG:

> *"This test intercepts the app's incoming and outgoing network traffic, and checks for any cleartext communication. Whilst the static checks can only show potential cleartext traffic, this dynamic test shows all communication the application definitely makes."*

Ini adalah test ketiga dalam rangkaian pengujian cleartext traffic yang sudah dibahas dalam seri riset ini (bersama TEST-0235, 0237, 0238) — dan secara filosofis **paling berbeda** dari ketiga lainnya karena **tidak melihat kode aplikasi sama sekali**. TEST-0235/0237 memeriksa **konfigurasi** (apakah OS/framework *mengizinkan* cleartext), sedangkan test ini memeriksa **kenyataan di kabel** — apa yang benar-benar melintas di jaringan, terlepas dari apa yang dikatakan konfigurasi atau kode. Ini memberi **bukti paling konklusif** secara teori: bila ditemukan cleartext di capture jaringan, maka cleartext **benar-benar terjadi**, bukan sekadar "mungkin terjadi" seperti simpulan dari audit statis semata.

### 1.2 Dua Keterbatasan Metodologis yang Diakui Secara Eksplisit dan Jujur

Bagian warning resmi secara transparan mengakui dua celah presisi yang signifikan — ini sudah dibahas mendalam di dokumen MASTG-TEST-0238 sebagai masalah yang **dipecahkan** oleh test tersebut, namun perlu ditegaskan kembali di sini sebagai konteks utama:

> *"Intercepting traffic on a network level will show all traffic the device performs, not only the single app. Linking the traffic back to a specific app can be difficult, especially when more apps are installed on the device."*
>
> *"Linking the intercepted traffic back to specific locations in the app can be difficult and requires manual analysis of the code."*

Dua keterbatasan ini — **atribusi aplikasi** dan **atribusi lokasi kode** — adalah alasan utama mengapa MASTG-TEST-0238 (pendekatan berbasis Frida hooking) ada sebagai **pelengkap**, bukan pengganti, test ini. Test ini (capture di level jaringan) dan TEST-0238 (instrumentasi di level proses) **saling melengkapi**: test ini memberi gambaran **menyeluruh** tentang apa yang terjadi di jaringan (termasuk traffic dari komponen yang mungkin terlewat dari hooking, seperti native library yang memanggil syscall langsung), sementara TEST-0238 memberi **presisi atribusi** yang tidak dimiliki test ini.

### 1.3 Keterbatasan Ketiga: Dynamic Testing yang Tidak Pernah Benar-Benar Menyeluruh

> *"Dynamic analysis works best when you interact extensively with the app. But even then there could be corner cases which are difficult or impossible to execute on every device. The results from this test therefore are likely not exhaustive."*

Ini adalah prinsip umum pengujian dinamis yang sudah berulang kali relevan di seluruh seri riset ini — hasil **PASS** dari test ini (tidak ditemukan cleartext) **tidak pernah** menjadi bukti ketidakhadiran cleartext secara absolut, hanya bukti bahwa cleartext tidak teramati **selama sesi pengujian dan alur yang berhasil dipicu**. Alur yang tidak sempat dieksekusi (skenario error tertentu, fitur jarang dipakai, kondisi jaringan spesifik) tetap bisa menyembunyikan panggilan cleartext yang luput dari observasi.

### 1.4 Dua Pendekatan Capture dan Keterbatasan Protokol Non-HTTP

Overview memberi dua pilihan teknik capture dengan karakteristik berbeda:

| Teknik | Cakupan | Keterbatasan |
|---|---|---|
| **Basic Network Sniffing** (tcpdump, Wireshark — MASTG-TECH-0010) | Seluruh traffic level paket, semua protokol | Tidak mendekode isi HTTP(S)/payload aplikasi secara otomatis; butuh analisis manual lebih lanjut |
| **Interception Proxy** (Burp, mitmproxy — MASTG-TECH-0011) | HTTP(S) terdekode otomatis, mudah dibaca | **Hanya** HTTP(S) — protokol lain (XMPP, custom TCP/UDP) tidak tertangkap langsung |

Catatan resmi secara eksplisit mengakui celah ini dan memberi solusi:

> *"Interception proxies will show HTTP(S) traffic only. You can, however, use some tool-specific plugins such as Burp-non-HTTP-Extension or other tools like Wireshark to decode and visualize communication via XMPP and other protocols."*

Ini relevan karena aplikasi modern seringkali memakai **lebih dari HTTP** untuk komunikasi real-time (WebSocket, protokol chat kustom, gRPC via HTTP/2 yang kadang tidak terurai sempurna oleh proxy standar) — mengandalkan hanya interception proxy berisiko melewatkan cleartext yang terjadi lewat jalur protokol non-HTTP ini.

### 1.5 Tantangan Praktis: Certificate Pinning sebagai Penghalang Observasi

> *"Some apps may not function correctly with proxies like Burp and mitmproxy because of certificate pinning. In such a scenario, you can still use basic network sniffing to detect cleartext traffic. Otherwise, you can try to disable pinning."*

Ini memberi nuansa praktis penting — bila aplikasi target memakai certificate pinning yang kuat, **interception proxy berbasis MITM (Metode A) tidak akan berfungsi** untuk traffic HTTPS (koneksi akan gagal/ditolak aplikasi). Namun poin krusialnya: **justru karena test ini secara spesifik mencari CLEARTEXT (bukan HTTPS)**, certificate pinning **tidak relevan** untuk traffic yang memang tidak terenkripsi sama sekali — basic network sniffing (tcpdump/Wireshark) tetap bisa menangkap paket cleartext HTTP biasa tanpa perlu melewati mekanisme TLS/pinning apa pun, karena pinning hanya berlaku untuk koneksi yang **mencoba** menggunakan TLS.

### 1.6 Bukti Nyata: Kredensial WebDAV dan Peta Tile Dikirim via HTTP Cleartext

Riset dan laporan bug nyata mengonfirmasi bahwa skenario yang disasar test ini — temuan cleartext traffic yang **benar-benar membawa kredensial** — bukan sekadar risiko teoretis:

> *"An app permits cleartext HTTP traffic globally, and Nextcloud/Owncloud integrations accept user-supplied http:// server URLs — in which case login credentials are sent via HTTP Basic Auth in cleartext."*

> *"Cleartext HTTP traffic permitted; http:// map tiles and WebDAV credentials"* — dari laporan bug publik yang secara spesifik menandai temuan ini sebagai isu keamanan `[MEDIUM]`.

Kasus-kasus ini menunjukkan pola yang persis cocok dengan metodologi test ini — temuan semacam ini **hanya bisa dikonfirmasi lewat observasi traffic jaringan sesungguhnya**, karena sumber masalahnya seringkali bukan logika aplikasi itu sendiri, melainkan **URL server yang dikonfigurasi pengguna** (misalnya pengguna mengetik `http://` bukan `https://` saat setup integrasi WebDAV) — sesuatu yang **tidak mungkin terdeteksi lewat audit kode statis** karena nilai URL-nya ditentukan di runtime oleh input pengguna, bukan hardcoded di kode.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **tcpdump** (Android) | Capture traffic level paket langsung di device (MASTG-TECH-0010) |
| **Wireshark** | Analisis dan dekoding hasil capture, termasuk protokol non-HTTP (MASTG-TECH-0010, §1.4) |
| **Burp Suite / mitmproxy** | Interception proxy untuk HTTP(S) yang terdekode otomatis (MASTG-TECH-0011) |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **Burp-non-HTTP-Extension** | Dekoding protokol non-HTTP seperti XMPP di dalam Burp (§1.4) |
| **Frida (untuk bypass pinning)** | Menonaktifkan certificate pinning agar traffic HTTPS bisa diperiksa oleh proxy MITM (MASTG-TECH-0012) — namun **tidak diperlukan** untuk traffic cleartext murni (§1.5) |

### 2.3 Prasyarat Lingkungan

- Device/emulator dengan kemampuan root (untuk tcpdump) atau konfigurasi proxy (untuk interception proxy).
- **Isolasi lingkungan uji** — idealnya device uji hanya menjalankan aplikasi target, atau gunakan filtering berdasarkan IP/port aplikasi untuk mengurangi noise dari aplikasi sistem lain (mengurangi keterbatasan atribusi di §1.2).

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

Gunakan salah satu dari dua pendekatan:
- **MASTG-TECH-0010** (basic network sniffing) untuk capture seluruh traffic.
- **MASTG-TECH-0011** (interception proxy) untuk capture HTTP(S) yang terdekode otomatis.

### 3.2 Metode A — tcpdump + Wireshark untuk Capture Menyeluruh

```bash
adb shell tcpdump -i wlan0 -w /sdcard/capture.pcap
# ... jalankan aplikasi, exercise seluruh fitur ...
adb pull /sdcard/capture.pcap
wireshark capture.pcap
```

Filter di Wireshark untuk HTTP cleartext:
```
http and ip.addr == <IP_device>
```

### 3.3 Metode B — Interception Proxy untuk HTTP(S) Terdekode

```bash
mitmproxy --mode transparent
```

Konfigurasikan proxy di device/emulator (MASTG-TECH-0011), lalu amati tab request untuk entri berskema `http://` (bukan `https://`).

### 3.4 Metode C — Bypass Pinning Bila Diperlukan untuk Analisis HTTPS Terkait

```bash
frida -U -f com.example.app -l universal-ssl-pinning-bypass.js --no-pause
```

Catatan: langkah ini **hanya relevan** bila tujuan juga memeriksa isi traffic HTTPS untuk kebutuhan test lain; untuk test cleartext murni ini, cukup pakai Metode A yang tidak terganggu pinning sama sekali (§1.5).

### 3.5 Metode D — Dekoding Protokol Non-HTTP

```bash
# Via Burp dengan ekstensi non-HTTP, atau analisis manual payload di Wireshark
# Filter protokol spesifik, misal XMPP:
xmpp
```

### 3.6 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Kapan dipakai |
|---|---|---|
| **A** | tcpdump + Wireshark | Baseline paling menyeluruh — menangkap semua protokol |
| **B** | Interception proxy | Lebih mudah dibaca untuk traffic HTTP(S) |
| **C** | Frida bypass pinning | Hanya bila perlu memeriksa isi HTTPS, tidak relevan untuk cleartext murni |
| **D** | Burp non-HTTP / Wireshark dekoder | Protokol khusus (XMPP, custom) |

**Kombinasi minimum yang aku rekomendasikan:** **A (menyeluruh) + B (kemudahan baca HTTP)**, dengan **D** sebagai pelengkap bila aplikasi diketahui memakai protokol non-HTTP.

---

### 3.7 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Evaluation:** *"The test case fails if any clear text traffic originates from the target app."*

Dengan catatan realistis:

> *"This can be challenging to determine because traffic can potentially come from any app on the device."*

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Ditemukan traffic cleartext (HTTP tanpa TLS, atau protokol lain tanpa enkripsi) yang **terkonfirmasi** berasal dari aplikasi target |

**Contoh bukti (merefleksikan pola nyata WebDAV §1.6):**

```
GET /webdav/files/document.pdf HTTP/1.1
Host: nas.local
Authorization: Basic YWRtaW46cGFzc3dvcmQxMjM=
```

Interpretasi: kredensial WebDAV (Basic Auth, hanya Base64 — bukan enkripsi) terkirim melalui HTTP cleartext murni. Payload bisa dibaca langsung oleh siapa pun yang menyadap jaringan. **FAIL**.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Seluruh traffic yang teramati dari aplikasi target memakai TLS/enkripsi, setelah exercise yang cukup menyeluruh |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Selalu verifikasi atribusi sumber traffic** — sesuai §1.2, cleartext yang tertangkap di level jaringan tidak otomatis berasal dari aplikasi target; korelasikan dengan timing aktivitas aplikasi, IP/port tujuan yang diketahui terkait backend aplikasi, atau lanjutkan ke MASTG-TEST-0238 untuk konfirmasi atribusi definitif via stack trace.

2. **PASS tidak pernah absolut** — sesuai §1.3, selalu cantumkan alur mana yang berhasil/tidak berhasil dipicu selama sesi pengujian; cleartext yang hanya muncul pada skenario tertentu (error handling, fallback koneksi) mudah terlewat.

3. **Jangan lupakan protokol non-HTTP** — sesuai §1.4, interception proxy standar hanya menangkap HTTP(S); gunakan basic network sniffing untuk cakupan menyeluruh terhadap WebSocket/protokol kustom.

4. **Pinning bukan penghalang untuk test ini secara spesifik** — sesuai §1.5, traffic cleartext murni tetap terlihat di basic network sniffing terlepas dari pinning; jangan buang waktu bypass pinning bila tujuannya hanya mencari cleartext.

5. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | Cleartext membawa kredensial/token/data sensitif, terkonfirmasi dari aplikasi target | **Tinggi** |
   | Cleartext membawa data non-sensitif (metadata publik) | **Sedang** |
   | Tidak ditemukan cleartext setelah exercise menyeluruh | **Bukan temuan** (dengan catatan keterbatasan coverage) |

6. **Dokumentasikan:** protokol dan endpoint yang membawa cleartext, payload yang ditemukan (redaksi kredensial di laporan publik), bukti atribusi ke aplikasi target, dan alur yang dipicu untuk mereproduksi temuan.

---

## 4. Rekomendasi Perbaikan

### 4.1 Paksa HTTPS di Seluruh Konfigurasi Endpoint Pengguna

Untuk kasus seperti WebDAV/integrasi server kustom (§1.6) di mana pengguna mengetik URL server secara manual, validasi dan **tolak** skema `http://`, atau upgrade otomatis ke `https://` sebelum koneksi dibuat.

### 4.2 Audit Komprehensif Sesuai Rangkaian Trio/Kuartet Cleartext

Korelasikan temuan test ini dengan MASTG-TEST-0235 (konfigurasi NSC/manifest) dan MASTG-TEST-0238 (atribusi presisi via Frida) untuk menutup seluruh celah metodologis masing-masing pendekatan.

### 4.3 Checklist Remediasi

- [ ] Tidak ada traffic cleartext yang terkonfirmasi dari aplikasi target setelah exercise menyeluruh
- [ ] Validasi input URL server (bila dikonfigurasi pengguna) menolak/upgrade skema HTTP
- [ ] Protokol non-HTTP (WebSocket, custom) diperiksa terpisah untuk cleartext
- [ ] Hasil dikorelasikan dengan MASTG-TEST-0235/0238 untuk gambaran lengkap

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0236 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/network/MASVS-NETWORK/MASTG-TEST-0236.md)
- [MASTG-TEST-0235: Android App Configurations Allowing Cleartext Traffic (dokumen terkait dalam seri riset ini)](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0235/)
- [MASTG-TEST-0238: Runtime Use of Network APIs Transmitting Cleartext Traffic (dokumen terkait dalam seri riset ini)](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0238/)
- [MASTG-TECH-0010: Basic Network Monitoring/Sniffing](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0010/)
- [MASTG-TECH-0011: Setting Up an Interception Proxy](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0011/)

### 5.2 Riset dan Kasus Nyata

- [GitHub Issue andashi/home#8: Cleartext HTTP Traffic Permitted — http:// Map Tiles and WebDAV Credentials](https://github.com/andashi/home/issues/8)
- [GitHub Issue corona-warn-app/cwa-app-android#2: usesCleartextTraffic Set to True, Allowing HTTP Traffic](https://github.com/corona-warn-app/cwa-app-android/issues/2)
- [ValencyNetworks: Vulnerability Fixation — Cleartext Traffic Enabled in App](https://valencynetworks.com/kb/cleartext-traffic-enabled-iandroidmanifest-xml-security-risks-and-fixes.html)

### 5.3 Dokumentasi Tools

- [tcpdump for Android](https://www.androidtcpdump.com/)
- [Wireshark](https://www.wireshark.org/)
- [Burp-non-HTTP-Extension](https://github.com/summitt/Burp-Non-HTTP-Extension)

---

*Dokumen ini disusun berdasarkan konten resmi OWASP MASTG (`tests-beta/network/MASVS-NETWORK/MASTG-TEST-0236.md`), dilengkapi cross-reference mendalam dengan dokumen MASTG-TEST-0235 dan MASTG-TEST-0238 dalam seri riset ini, serta laporan bug publik nyata tentang kredensial WebDAV yang terkirim via HTTP cleartext. Nuansa metodologis terpenting: test ini memberi bukti paling konklusif secara prinsip (apa yang benar-benar di kabel) namun dengan dua keterbatasan atribusi yang diakui secara jujur oleh MASTG sendiri — dipecahkan oleh pendekatan komplementer MASTG-TEST-0238. Temuan nyata seperti kredensial WebDAV yang bocor justru berasal dari **input pengguna** (URL server yang diketik manual), sebuah kelas kerentanan yang secara struktural **tidak mungkin terdeteksi** lewat audit kode statis semata, menegaskan nilai tambah unik dari observasi traffic jaringan langsung.*
