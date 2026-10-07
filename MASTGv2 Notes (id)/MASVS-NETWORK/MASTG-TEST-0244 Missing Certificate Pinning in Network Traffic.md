# MASTG-TEST-0244 Missing Certificate Pinning in Network Traffic

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0244 |
| **Platform** | Network (implementation-agnostic) |
| **Kategori MASVS** | MASVS-NETWORK |
| **Weakness** | MASWE-0028 — *Insecure Identity Pinning* |
| **Tipe Pengujian** | Dynamic, Network |
| **Knowledge terkait** | MASTG-KNOW-0015 (Certificate Pinning) |
| **Prasyarat** | `identify-first-party-domains` — wajib dipenuhi sebelum test ini valid (sudah dibahas mendalam di dokumen MASTG-TEST-0242) |
| **Teknik terkait** | MASTG-TECH-0005, MASTG-TECH-0011 (Setting Up an Interception Proxy), MASTG-TECH-0009 (Monitoring System Logs) |
| **Test terkait** | **MASTG-TEST-0242** — dokumen terkait dalam seri riset ini; test tersebut menyasar **satu mekanisme spesifik** (NSC `<pin-set>`), test ini **implementation-agnostic** |
| **Rule resmi** | — (tidak ada; murni dinamis via MITM) |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian dan Perbedaan Fundamental dengan MASTG-TEST-0242

Kutipan overview resmi MASTG:

> *"There are multiple ways an application can implement certificate pinning, including via the Android Network Security Config, custom TrustManager implementations, third-party libraries, and native code. Since some implementations might be difficult to identify through static analysis, especially when obfuscation or dynamic code loading is involved, this test uses network interception techniques to determine if certificate pinning is enforced at runtime."*

Perbedaan ini ditegaskan secara eksplisit oleh MASTG sendiri:

> *"Unlike MASTG-TEST-0242, which specifically assesses certificate pinning configured through the Android Network Security Configuration, this test is implementation-agnostic. It verifies at runtime whether pinning is enforced regardless of whether it is implemented through the Network Security Configuration, application code, a third-party library, or native code."*

Ini adalah pola "cakupan sempit statis vs cakupan luas dinamis" yang sudah muncul di beberapa pasangan test lain dalam seri riset ini — namun di sini jurang cakupannya **sangat lebar**: TEST-0242 hanya bisa menilai **satu** dari **empat** kemungkinan mekanisme implementasi (NSC, `TrustManager` kustom, third-party library, native code). Test ini, dengan mendekati masalah dari sudut **hasil akhir** (apakah MITM berhasil atau tidak), secara otomatis mencakup **keempat** mekanisme sekaligus tanpa perlu tahu mekanisme mana yang sesungguhnya dipakai aplikasi.

### 1.2 Logika Pengujian: MITM sebagai Oracle Kebenaran

> *"The goal of this test case is to observe whether a MITM attack can intercept HTTPS traffic from the app. A successful MITM interception indicates that the app is either not using certificate pinning or implementing it incorrectly. If the app is properly implementing certificate pinning, the MITM attack should fail because the app rejects certificates issued by an unauthorized CA, even if the CA is trusted by the system."*

Poin krusial di sini: *"even if the CA is trusted by the system"* — ini adalah nilai tambah inti certificate pinning yang membedakannya dari validasi TLS standar. CA root milik proxy MITM (Burp/mitmproxy) **bisa saja** diinstal dan dipercayai penuh oleh sistem Android (device uji, atau bahkan device production yang dikompromikan via rekayasa sosial menginstal CA palsu) — namun aplikasi dengan pinning yang benar **tetap menolak** koneksi karena **kunci publik spesifik** yang diharapkan tidak cocok, terlepas dari status kepercayaan sistem terhadap CA tersebut. Inilah mengapa "MITM berhasil" menjadi **oracle** yang reliable untuk menyimpulkan ketidakhadiran/kesalahan implementasi pinning — bila pinning benar-benar berfungsi, metode serangan paling umum ini **seharusnya mustahil berhasil**, apa pun mekanisme implementasinya di balik layar.

### 1.3 Sinyal Diagnostik Tambahan: Log Sistem sebagai Bukti Pendukung

Catatan praktis yang berguna untuk interpretasi hasil pengujian yang ambigu:

> *"While performing the MITM attack, it can be useful to monitor the system logs. If a certificate pinning/validation check fails, an event similar to the following log entry might be visible: `I/X509Util: Failed to validate the certificate chain, error: Pin verification failed`"*

Ini memberi **sinyal independen** di luar sekadar observasi "koneksi gagal/berhasil" — log sistem secara eksplisit mengonfirmasi **alasan** kegagalan koneksi (benar-benar karena pin verification gagal, bukan sekadar error jaringan generik yang tidak terkait pinning sama sekali). Ini relevan untuk membedakan dua skenario yang terlihat serupa dari luar: (a) koneksi gagal karena pinning memang berfungsi dengan benar, vs (b) koneksi gagal karena sebab lain (misalnya aplikasi memang hanya berjalan offline/error jaringan tidak terkait MITM).

### 1.4 Prasyarat yang Diwarisi dari MASTG-TEST-0242: Domain First-Party

Prasyarat `identify-first-party-domains` berlaku identik untuk kedua test — sudah dibahas mendalam di dokumen MASTG-TEST-0242. Poin kuncinya ditegaskan ulang secara eksplisit di overview test ini:

> *"This test focuses on relevant first-party domains, which are remote endpoints under the developer's control that support the app's core or security-sensitive functionality. Third-party domains outside the developer's control should not be reported only because their traffic can be intercepted."*

Ini sangat penting secara praktis — **mayoritas** traffic yang berhasil diintersep MITM pada aplikasi modern biasanya berasal dari SDK analytics/advertising/crash-reporting pihak ketiga yang **tidak** mengimplementasikan pinning (dan secara wajar memang tidak perlu, karena mereka bukan milik developer aplikasi). Penguji yang tidak menyaring domain third-party ini akan menghasilkan laporan yang membengkak dengan false positive — setiap domain analytics generik yang berhasil diintersep **bukan** temuan untuk test ini.

### 1.5 Validasi Lanjutan: Tantangan Identifikasi yang Butuh Konteks di Luar Binary

> *"Determining which of the intercepted domains are first-party and security-relevant typically requires information that is not present in the app binary and may require contact with the developers."*

Ini konsisten dengan catatan di dokumen MASTG-TEST-0242 — identifikasi first-party domain **secara inheren** adalah proses yang membutuhkan konteks eksternal (dokumentasi arsitektur, komunikasi dengan tim developer, atau inferensi dari branding/bundle identifier bila informasi resmi tidak tersedia).

### 1.6 Bukti Nyata: Kesalahan Implementasi Pinning pada Aplikasi Perbankan

Riset keamanan mengonfirmasi bahwa kesalahan implementasi pinning — bukan hanya ketidakhadirannya — adalah masalah nyata dan berulang pada kategori aplikasi yang paling membutuhkannya:

> *"A vulnerability in the mobile apps of several major banks exposed customers to potential data theft, with certificate pinning errors leaving customers susceptible to man-in-the-middle attacks that put their credentials — usernames, passwords, personal information, and banking info — at risk. Research found that many banks offer certificate pinning as a security feature, but fail to authenticate the hostname, leaving systems open to man-in-the-middle attacks."*

Kasus ini sangat relevan untuk menegaskan poin dari §1.2 — bank-bank tersebut **tidak kekurangan** fitur pinning sama sekali (mereka "menawarkan certificate pinning sebagai fitur keamanan"), namun implementasinya **cacat** (gagal memvalidasi hostname dengan benar) sehingga MITM tetap berhasil meski secara permukaan pinning "ada". Ini secara persis mengilustrasikan mengapa pendekatan test ini (mengamati **hasil** MITM, bukan sekadar mengonfirmasi **keberadaan** kode pinning) jauh lebih reliable — audit statis yang hanya mengonfirmasi "ada pemanggilan API pinning" bisa sepenuhnya terlewat dari kesalahan implementasi semacam ini, sementara test dinamis ini akan tetap menangkapnya karena MITM yang dicoba akan **tetap berhasil** pada aplikasi yang cacat implementasinya.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **Burp Suite / mitmproxy** | Interception proxy untuk melancarkan percobaan MITM (MASTG-TECH-0011) |
| **ADB (`adb logcat`)** | Monitoring log sistem untuk sinyal diagnostik pin verification failure (MASTG-TECH-0009) |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **Frida** | Verifikasi tambahan — mencoba bypass pinning secara aktif untuk membedakan "tidak ada pinning sama sekali" vs "pinning ada namun bisa di-bypass dengan hooking" (nuansa kekuatan implementasi) |

### 2.3 Prasyarat Lingkungan

- Device/emulator dengan sertifikat CA proxy MITM terinstal dan dipercayai sistem.
- **Daftar domain first-party** yang sudah diidentifikasi sesuai prasyarat §1.4, sebelum memulai sesi pengujian.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0005** untuk instalasi aplikasi.
2. Gunakan **MASTG-TECH-0011** untuk menyiapkan interception proxy dan mengintersepsi komunikasi.

### 3.2 Metode A — MITM Dasar via Interception Proxy

```bash
# Konfigurasi proxy di device, instal CA cert proxy sebagai trusted
mitmproxy --mode regular
```

Jalankan aplikasi, exercise seluruh alur yang menghubungi domain first-party yang sudah diidentifikasi. Amati di proxy: apakah traffic domain tersebut berhasil terintersep (muncul dengan isi yang terbaca) atau koneksi gagal/ditolak aplikasi.

### 3.3 Metode B — Monitoring Log Sistem Paralel (Sesuai §1.3)

```bash
adb logcat | grep -iE "pin.*verification|X509Util|certificate.*pin"
```

Jalankan bersamaan dengan Metode A untuk mengonfirmasi **alasan** kegagalan koneksi bila terjadi.

### 3.4 Metode C — Verifikasi Silang dengan Frida Bypass (Pelengkap, Menilai Kekuatan)

```bash
frida -U -f com.example.app -l universal-ssl-pinning-bypass.js --no-pause
```

Bila MITM dasar (Metode A) **gagal** (mengindikasikan PASS awal), coba ulangi dengan bypass Frida aktif — bila MITM **baru berhasil** setelah bypass eksplisit, ini mengonfirmasi pinning memang ada dan berfungsi (PASS kuat). Bila MITM tetap gagal meski sudah mencoba bypass umum, pertimbangkan implementasi pinning yang lebih non-standar/kuat (PASS sangat kuat) atau confounding factor lain.

### 3.5 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Kapan dipakai |
|---|---|---|
| **A** | Interception proxy | Baseline wajib — oracle utama keberhasilan/kegagalan MITM |
| **B** | adb logcat | Sinyal diagnostik pendukung untuk memastikan alasan kegagalan |
| **C** | Frida bypass | Pelengkap — menilai kekuatan relatif implementasi pinning |

**Kombinasi minimum yang aku rekomendasikan:** **A + B (wajib)**, dengan **C** sebagai pelengkap untuk penilaian kekuatan lebih mendalam.

---

### 3.6 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Evaluation:** *"The test case fails if any relevant first-party domain appears in the intercepted traffic capture. The test case should not fail only because unrelated third-party domains are intercepted."*

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Traffic HTTPS ke domain **first-party** berhasil diintersep dan dibaca isinya via MITM, terlepas dari mekanisme pinning apa yang (seharusnya) diimplementasikan |

**Contoh bukti (merefleksikan pola nyata kesalahan hostname validation §1.6):**

```
[Burp Proxy] Intercepted: https://api.bankingapp.com/v1/login
Request body: {"username":"budi","password":"s3cr3t"}
```

Log sistem tidak menunjukkan error pin verification apa pun. Interpretasi: pinning tidak efektif untuk domain backend autentikasi — kredensial login terbaca penuh via MITM. **FAIL**.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Seluruh domain first-party **gagal** diintersep (koneksi ditolak aplikasi), **dan** |
| P2 | *(Pendukung)* Log sistem mengonfirmasi kegagalan tersebut memang disebabkan pin verification failure, bukan sebab lain |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Jangan laporkan domain third-party sebagai temuan** — sesuai §1.4, ini adalah sumber false positive paling umum untuk test ini; selalu saring hasil MITM hanya terhadap domain yang sudah diidentifikasi sebagai first-party.

2. **"MITM gagal" adalah oracle yang kuat terlepas dari mekanisme** — sesuai §1.1-1.2, test ini tidak perlu tahu *bagaimana* pinning diimplementasikan untuk menyimpulkan hasilnya; ini nilai tambah utamanya dibanding TEST-0242.

3. **Waspadai kasus "pinning ada tapi cacat implementasi"** — sesuai bukti nyata §1.6, jangan berasumsi aplikasi "pasti aman" hanya karena tim developer mengonfirmasi mereka "sudah menerapkan pinning"; test dinamis ini tetap wajib dijalankan karena implementasi yang cacat (misalnya gagal validasi hostname) tetap akan menunjukkan MITM berhasil.

4. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | MITM berhasil pada domain autentikasi/finansial, kredensial/token terbaca | **Tinggi** |
   | MITM berhasil pada domain first-party non-kredensial | **Sedang** |
   | Seluruh domain first-party gagal diintersep | **Bukan temuan** |

5. **Dokumentasikan:** daftar domain yang diuji (first-party vs third-party), hasil intersepsi per domain, log sistem terkait pin verification, dan hasil verifikasi bypass Frida bila dilakukan.

---

## 4. Rekomendasi Perbaikan

### 4.1 Pastikan Validasi Hostname Diterapkan Bersamaan dengan Pinning (Mengatasi Kasus Nyata §1.6)

```java
// Pastikan TrustManager/HostnameVerifier kustom TIDAK melewatkan validasi hostname
// hanya karena pin cocok — kedua validasi harus berjalan independen
HostnameVerifier hostnameVerifier = HttpsURLConnection.getDefaultHostnameVerifier();
if (!hostnameVerifier.verify(expectedHost, session)) {
    throw new SSLException("Hostname mismatch");
}
```

### 4.2 Uji Pinning Secara Rutin dengan MITM Dasar sebagai Bagian CI/Regression Testing

Jadikan pengujian MITM dasar (Metode A) sebagai bagian siklus rilis rutin — bukan hanya audit satu kali — mengingat perubahan kecil pada konfigurasi TLS/library bisa secara tidak sengaja melemahkan implementasi pinning yang sebelumnya berfungsi.

### 4.3 Checklist Remediasi

- [ ] Seluruh domain first-party terkonfirmasi menolak MITM dasar
- [ ] Validasi hostname berjalan independen dan tidak dilewati oleh logika pinning
- [ ] Log sistem dikonfirmasi menunjukkan pin verification failure yang sesuai
- [ ] Pengujian MITM dimasukkan ke siklus regresi rutin, bukan hanya audit satu kali
- [ ] Dikorelasikan dengan hasil MASTG-TEST-0242 untuk memahami mekanisme implementasi yang sesungguhnya dipakai

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0244 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/network/MASVS-NETWORK/MASTG-TEST-0244.md)
- [MASTG-TEST-0242: Missing Certificate Pinning in Network Security Configuration (dokumen terkait dalam seri riset ini)](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0242/)
- [MASTG-KNOW-0015: Certificate Pinning](https://mas.owasp.org/MASTG/knowledge/android/MASVS-NETWORK/MASTG-KNOW-0015/)
- [Prerequisite: Identifying First-Party Domains](https://github.com/OWASP/mastg/blob/master/prerequisites/identify-first-party-domains.md)
- [MASTG-TECH-0009: Monitoring System Logs](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0009/)

### 5.2 Riset dan Kasus Nyata

- [TheSSLStore: Banking Apps Vulnerability — Man-In-The-Middle Flaw in Certificate Pinning](https://www.thesslstore.com/blog/banking-apps-vulnerability-mitm/)
- [OWASP: Certificate and Public Key Pinning](https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning)
- [Schneier on Security: Security Vulnerabilities in Certificate Pinning](https://www.schneier.com/blog/archives/2017/12/security_vulner_10.html)

### 5.3 Dokumentasi Tools

- [Burp Suite Documentation](https://portswigger.net/burp/documentation)
- [mitmproxy Documentation](https://docs.mitmproxy.org/stable/)
- [Frida — Dynamic Instrumentation Toolkit](https://frida.re/docs/home/)

---

*Dokumen ini disusun berdasarkan konten resmi OWASP MASTG (`tests-beta/network/MASVS-NETWORK/MASTG-TEST-0244.md`, `MASTG-KNOW-0015`), dilengkapi cross-reference mendalam dengan dokumen MASTG-TEST-0242 (counterpart NSC-spesifik) dalam seri riset ini, serta riset nyata tentang kesalahan implementasi pinning pada aplikasi perbankan (kegagalan validasi hostname meski fitur pinning "ada"). Nuansa metodologis terpenting: test ini bersifat implementation-agnostic — menjadikan "keberhasilan/kegagalan MITM" sebagai oracle kebenaran yang tidak memerlukan pengetahuan tentang mekanisme implementasi di balik layar, sehingga mampu menangkap kasus "pinning ada namun cacat implementasinya" yang secara struktural tidak terdeteksi oleh audit statis yang hanya mengonfirmasi keberadaan kode pinning semata.*
