# MASTG-TEST-0206 Undeclared PII in Network Traffic Capture

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0206 |
| **Platform** | Android |
| **Kategori MASVS** | **MASVS-PRIVACY** (MASVS-PRIVACY-3: Aplikasi transparan mengenai pengumpulan dan penggunaan data) |
| **Weakness** | MASWE-0073 — *Inadequate Data Collection Declarations* |
| **Tipe Pengujian** | **Dynamic**, **Network** |
| **Profile** | **P** (Privacy) — *bukan* L1/L2 |
| **Prerequisites** | `identify-sensitive-data`, **`privacy-policy`**, **`app-store-privacy-declarations`** |
| **Teknik terkait** | MASTG-TECH-0005 (Installing Apps), MASTG-TECH-0100 (Logging Sensitive Data from Network Traffic) |
| **Tools yang dirujuk** | MASTG-TOOL-0097 (mitmproxy), MASTG-TOOL-0077 (Burp Suite), MASTG-TOOL-0079 (ZAP), MASTG-TOOL-0081 (Wireshark) |
| **Demo terkait** | MASTG-DEMO-0009 (Detecting Undeclared PII in Network Traffic) |
| **Test pelengkap** | MASTG-TEST-0318 (References to SDK APIs Known to Handle Sensitive User Data — statis), MASTG-TEST-0319 (Runtime Use of SDK APIs... — dinamis/hooks) |
| **CWE terkait** | CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor), CWE-200 (Exposure of Sensitive Information), CWE-201 (Insertion of Sensitive Information Into Sent Data), CWE-497 (Exposure of Sensitive System Information) |
| **Regulasi terkait** | GDPR Art. 5 & 13 (transparansi & informasi kepada subjek data), UU PDP Indonesia, CCPA §1798.100, Google Play Data safety policy |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Test ini bertujuan memverifikasi bahwa **data sensitif — khususnya PII (Personally Identifiable Information) — tidak dikirimkan melalui jaringan tanpa dideklarasikan**, dengan cara menangkap dan mendekripsi lalu lintas jaringan aplikasi.

Kutipan langsung dari overview MASTG:

> *"Attackers may capture network traffic from Android devices using an intercepting proxy, such as mitmproxy, Burp Suite, or ZAP, to analyze the data being transmitted by the app. **This works even if the app uses HTTPS**, as the attacker can install a custom root certificate on the Android device to decrypt the traffic. Inspecting traffic that is not encrypted with HTTPS is even easier and can be done without installing a custom root certificate for example by using Wireshark."*
>
> *"The goal of this test is to verify that sensitive data, specifically PII, is not being sent over the network, **even if the traffic is encrypted**. This test is especially important for apps that handle sensitive data, such as financial or health data, and **should be performed in conjunction with a review of the app's privacy policy and the app's marketplace privacy declarations** (e.g., Data Safety section in Google Play)."*

### 1.2 Pergeseran Paradigma: Ini Test Privasi, Bukan Test Keamanan

Ini **perbedaan konseptual terpenting** yang harus dipahami sebelum mengerjakan test ini, dan yang membedakannya dari semua test yang sudah kita bahas sebelumnya.

Perhatikan tiga petunjuk dari metadata dan dokumentasinya:

1. **Profile-nya hanya `P` (Privacy)** — bukan L1/L2. Test ini tidak masuk dalam profil verifikasi keamanan standar.
2. **Frasa kunci di overview:** *"even if the traffic is encrypted"*.
3. **Catatan eksplisit di MASTG-DEMO-0009:**

   > *"Note that **both the request and the response are encrypted using TLS, so they can be considered secure**. However, this **might represent a privacy issue** depending on the relevant privacy regulations and the app's privacy policy. You should now check the privacy policy and the App Store Privacy declarations to see if the app is allowed to send this data to a third-party."*

Artinya: **aplikasi yang menerapkan TLS dengan benar, certificate pinning yang kuat, dan seluruh kontrol keamanan jaringan yang sempurna, masih bisa GAGAL test ini.** Yang diuji bukan apakah datanya terlindungi dari penyerang, melainkan apakah pengumpulan datanya **dideklarasikan secara jujur kepada pengguna**.

Bandingkan dengan test-test sebelumnya:

| Test | Yang dinilai | Kontrol yang diperiksa |
|---|---|---|
| MASTG-TEST-0200/0201/0202 | Apakah data sensitif terekspos ke pihak tak berwenang | Enkripsi, sandbox, permission |
| MASTG-TEST-0203 | Apakah data sensitif bocor ke log | Penghapusan/redaksi log |
| MASTG-TEST-0204/0205 | Apakah nilai acak dapat diprediksi | CSPRNG |
| **MASTG-TEST-0206** | **Apakah pengumpulan data dideklarasikan dengan jujur** | **Transparansi & consent** |

Konsekuensi praktisnya: **kamu tidak bisa menyelesaikan test ini hanya dengan menangkap lalu lintas.** Kamu wajib punya dokumen pembanding — inilah sebabnya test ini punya prerequisites `privacy-policy` dan `app-store-privacy-declarations`. Tanpa keduanya, hasil terbaik yang bisa kamu produksi adalah **inventaris data** (daftar PII yang terkirim), bukan keputusan PASS/FAIL.

### 1.3 Mengapa Ini Penting: Skala Masalahnya

Ketidaksesuaian antara deklarasi dan perilaku nyata aplikasi bukan kasus langka, melainkan masalah sistemik:

- Sebuah studi terhadap **7.770 game mobile populer** menemukan ketidaksesuaian antara privacy policy dan Data safety declaration pada **hampir 53% kasus**; angkanya naik menjadi **61%** pada 1.711 aplikasi generik yang banyak dipakai.
- Analisis kode statis menunjukkan privacy policy hanya mengungkapkan **66,8%** dari potensi akses ke data sensitif (lokasi, finansial), sementara Data safety declaration hanya **36,4%** pada game mobile.
- **Analisis lalu lintas jaringan terhadap 500 aplikasi menemukan lebih dari seperempatnya mengirimkan data tracking yang tidak dideklarasikan** di Data safety label mereka. Ini persis metodologi test ini.

**Konsekuensi bagi developer:** ketidaksesuaian antara apa yang dikumpulkan kode dan apa yang dideklarasikan di form adalah dasar untuk **policy strike dan penghapusan aplikasi** dari Google Play, serta pelanggaran kewajiban pengungkapan di bawah **GDPR Art. 13** dan **CCPA §1798.100**. Google menyatakan bila mereka mengetahui adanya ketidaksesuaian antara perilaku aplikasi dan deklarasinya, mereka dapat mengambil tindakan penegakan.

### 1.4 Landasan: Apa yang Dimaksud PII dan Data Sensitif

Untuk test ini, acuan paling praktis adalah **daftar tipe data Google Play Data safety section**, karena itulah dokumen yang akan kamu bandingkan. Kategorinya:

| Kategori | Contoh tipe data |
|---|---|
| **Location** | Approximate location, **Precise location** |
| **Personal info** | Nama, alamat email, **User IDs**, alamat, nomor telepon, ras & etnis, keyakinan politik/agama, orientasi seksual, info personal lainnya |
| **Financial info** | Info pembayaran user, riwayat pembelian, riwayat kredit, skor kredit, info finansial lainnya |
| **Health and fitness** | **Health info**, fitness info |
| **Messages** | Email, SMS/MMS, pesan in-app lainnya |
| **Photos and videos** | Foto, video |
| **Audio files** | Rekaman suara/suara, file musik, file audio lainnya |
| **Files and docs** | File & dokumen |
| **Calendar** | Event kalender |
| **Contacts** | Kontak |
| **App activity** | Interaksi app, riwayat pencarian in-app, app terinstall, konten buatan user, pencarian lainnya |
| **Web browsing** | Riwayat browsing web |
| **App info and performance** | Crash log, diagnostik, performa lainnya |
| **Device or other IDs** | **Device or other IDs** (Advertising ID, Android ID, dll.) |

Untuk setiap tipe data, deklarasi harus mencakup: apakah **dikumpulkan** (collected), apakah **dibagikan** (shared) ke pihak ketiga, apakah **dienkripsi saat transit**, apakah opsional, dan **tujuan** penggunaannya. Ketidaksesuaian bisa terjadi di dimensi mana pun — misalnya data dideklarasikan "collected" tetapi kenyataannya juga "shared" ke pihak ketiga.

Selain itu, pertimbangkan juga **kategori khusus** menurut GDPR Art. 9 (data kesehatan, biometrik, genetik, keyakinan agama/politik, orientasi seksual, keanggotaan serikat) dan data sensitif menurut UU PDP Indonesia — data ini menuntut basis hukum yang lebih kuat, bukan hanya deklarasi.

### 1.5 Posisi Test Ini dalam Rangkaian MASWE-0073

MASTG punya tiga test di bawah weakness MASWE-0073, yang saling melengkapi:

| Test | Pendekatan | Menjawab | Kekuatan | Kelemahan |
|---|---|---|---|---|
| **MASTG-TEST-0206** *(dokumen ini)* | **Dinamis — network interception** | "**Data apa** yang benar-benar **keluar dari perangkat**, ke **host mana**?" | Bukti paling langsung dan meyakinkan; menangkap seluruh trafik termasuk dari SDK pihak ketiga tanpa perlu tahu API-nya | **Tidak memberi lokasi kode**; terhalang certificate pinning; hanya alur yang di-*exercise*; buta terhadap payload yang di-enkripsi di lapisan aplikasi |
| **MASTG-TEST-0318** | Statis — pattern matching | "**API SDK mana** yang direferensikan?" | Cakupan menyeluruh, cepat, CI-friendly | Hanya mendeteksi **potensi**, bukan konfirmasi; perlu tahu dulu API entry point tiap SDK |
| **MASTG-TEST-0319** | Dinamis — method hooking | "**Nilai apa** yang dikirim ke SDK, dari **baris kode mana**?" | Memberi **backtrace + nilai argumen**; menangkap data sebelum dienkripsi/di-encode | Perlu tahu API SDK; bisa dihalangi anti-instrumentation |

MASTG menyatakan hubungan ini eksplisit di bagian Evaluation:

> *"Note that this test does not provide any code locations where the sensitive data is being sent over the network. In order to identify the code locations you can use MASTG-TECH-0014 or MASTG-TECH-0015. Consult MASTG-TEST-0318 and MASTG-TEST-0319, respectively, for more details."*

**Strategi yang direkomendasikan:**

```
TEST-0206 (network capture)  ──►  inventaris PII + daftar host tujuan
        │                              (bukti KUAT, tanpa lokasi kode)
        │
        ├── bandingkan dengan ──►  Privacy Policy + Data safety section
        │                                    │
        │                                    ▼
        │                          keputusan PASS / FAIL
        │
        └── untuk remediasi ──►  TEST-0318 (statis) / TEST-0319 (hooks)
                                      untuk menemukan LOKASI KODE-nya
```

Dan perlu dicatat: **TEST-0319 menangkap apa yang TEST-0206 lewatkan.** Bila aplikasi menerapkan certificate pinning yang tidak bisa di-bypass, atau meng-enkripsi payload di lapisan aplikasi sebelum mengirim (sehingga isi body tidak terbaca meski TLS sudah didekripsi), hooking pada API SDK tetap bisa memperlihatkan data sebelum diproses. Keduanya saling menutup titik buta.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | MASTG ID | Fungsi dalam test ini |
|---|---|---|
| **mitmproxy / mitmdump** | MASTG-TOOL-0097 | **Tool utama** — yang dipakai MASTG-TECH-0100 dan MASTG-DEMO-0009. Keunggulannya: dapat diskrip dengan Python, sehingga penyaringan PII otomatis dan logging terstruktur jadi mudah |
| **Burp Suite** | MASTG-TOOL-0077 | Intercepting proxy alternatif. Unggul untuk eksplorasi manual, match-and-replace, dan ekstensi (mis. mencari PII lewat Bambdas/BApp) |
| **ZAP (Zed Attack Proxy)** | MASTG-TOOL-0079 | Alternatif open-source |
| **Wireshark** | MASTG-TOOL-0081 | Untuk lalu lintas **non-HTTPS** — **tanpa perlu memasang root certificate**. Juga penting untuk memetakan protokol non-HTTP (MQTT, DNS, QUIC) dan mendeteksi trafik cleartext |
| **adb** | MASTG-TOOL-0004 | Instalasi aplikasi (MASTG-TECH-0005), konfigurasi proxy, manajemen sertifikat |
| **Android emulator dengan `-writable-system`** | MASTG-TOOL-0003 | Diperlukan untuk memasang sertifikat proxy sebagai **system CA** — lihat §2.3 |

### 2.2 Tools Pendukung (Sangat Diperlukan dalam Praktik)

| Tool | Fungsi |
|---|---|
| **Frida** | MASTG-TOOL-0001. **Hampir selalu diperlukan** — untuk bypass certificate pinning agar lalu lintas dapat didekripsi. Juga untuk MASTG-TEST-0319 |
| **Objection** | MASTG-TOOL-0038. `android sslpinning disable` — bypass pinning cepat tanpa menulis script |
| **frida-script "Universal Android SSL Pinning Bypass"** | Script komunitas siap pakai untuk berbagai implementasi pinning (OkHttp, TrustManager, Conscrypt, Netty, WebView) |
| **apktool + apksigner** | Patch `network_security_config.xml` agar mempercayai user CA dan menghapus `<pin-set>`, lalu repackaging. Alternatif bila Frida terhalang |
| **objection patchapk / frida-gadget** | Untuk device non-rooted |
| **jadx** | MASTG-TOOL-0018. Menelusuri lokasi kode setelah temuan (bersama TEST-0318) |
| **`mitmproxy2swagger` / `mitmdump -w`** | Menyimpan flow untuk analisis ulang (offline) — penting agar tidak perlu mengulang seluruh sesi *exercise* |
| **`jq`, `protoc --decode_raw`, `gzip -d`, `base64 -d`** | **Krusial.** Untuk menormalisasi payload agar PII terbaca: JSON, Protobuf, gzip, Base64 |
| **PolarProxy / SSLsplit** | Interception untuk protokol non-HTTP berbasis TLS |
| **Burp Sequencer / grep-and-match kustom** | Pemindaian PII pada kumpulan flow |
| **Google Play Console / halaman Play Store aplikasi** | **Bukan tool teknis, tetapi wajib** — sumber Data safety declaration untuk pembanding |

### 2.3 Prasyarat Lingkungan — Bagian Tersulit dari Test Ini

Menyiapkan interception yang berfungsi adalah bagian yang paling banyak menghabiskan waktu. Ada tiga rintangan berlapis:

**Rintangan 1 — Aplikasi yang menargetkan Android 7 (API 24) ke atas tidak mempercayai user CA secara default.**

Sejak API 24, aplikasi hanya mempercayai system CA kecuali dinyatakan lain di `network_security_config.xml`. Memasang sertifikat mitmproxy lewat *Settings → Security → Install certificate* **tidak cukup**. Opsinya:

```bash
# Opsi A (dipakai MASTG-DEMO-0009): emulator dengan sistem yang writable,
#         lalu pasang sertifikat sebagai SYSTEM CA
emulator -avd Pixel_3a_API_33_arm64-v8a -writable-system

adb root
adb shell "mount -o rw,remount /"          # pada API 29+: mount /apex/... sesuai kebutuhan
# Hitung hash subject sertifikat mitmproxy
openssl x509 -inform PEM -subject_hash_old -in ~/.mitmproxy/mitmproxy-ca-cert.pem | head -1
# -> mis. c8750f0d
cp ~/.mitmproxy/mitmproxy-ca-cert.pem c8750f0d.0
adb push c8750f0d.0 /system/etc/security/cacerts/
adb shell "chmod 644 /system/etc/security/cacerts/c8750f0d.0"
adb reboot
```

```xml
<!-- Opsi B: patch network_security_config.xml lalu repackaging
     (berguna bila tidak bisa memodifikasi sistem) -->
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />   <!-- percayai sertifikat proxy -->
        </trust-anchors>
    </base-config>
    <!-- hapus seluruh blok <pin-set> bila ada -->
</network-security-config>
```

```bash
# Opsi C: Frida — tidak perlu memodifikasi sistem maupun APK
objection -g com.example.target explore
# lalu: android sslpinning disable
```

**Rintangan 2 — Certificate pinning.** Bila aplikasi melakukan pinning (umum pada aplikasi finansial dan kesehatan — justru yang paling perlu diuji), koneksi akan gagal meski sertifikat proxy sudah terpasang sebagai system CA. Diperlukan bypass via Frida/Objection atau penghapusan `<pin-set>` lewat repackaging.

> **Catat ini sebagai temuan positif tersendiri**, bukan sebagai kegagalan pengujian. Certificate pinning yang berfungsi adalah kontrol MASVS-NETWORK yang baik. Tetapi jangan lalu melaporkan TEST-0206 sebagai PASS — statusnya **Inconclusive** sampai kamu berhasil melihat isi trafiknya, atau sampai kamu melengkapinya dengan MASTG-TEST-0319 (hooking, yang melihat data **sebelum** masuk ke lapisan TLS).

**Rintangan 3 — Protokol dan encoding yang tidak terbaca proxy HTTP.**

| Tantangan | Penanganan |
|---|---|
| **QUIC / HTTP/3** | Banyak proxy belum menanganinya penuh. Paksa fallback ke HTTP/2 dengan memblokir UDP/443 di firewall/emulator, atau matikan QUIC lewat konfigurasi aplikasi bila memungkinkan |
| **gRPC / Protobuf** | Payload biner. Gunakan `protoc --decode_raw` atau addon mitmproxy untuk protobuf |
| **WebSocket** | mitmproxy mendukung, tetapi pastikan flow WS ikut diproses (event `websocket_message`) |
| **MQTT / protokol TCP kustom** | Perlu SSLsplit/PolarProxy, atau analisis dengan Wireshark + kunci sesi TLS |
| **Enkripsi di lapisan aplikasi** | Payload sudah dienkripsi aplikasi sebelum TLS. **Titik buta total test ini** → wajib dilengkapi MASTG-TEST-0319 |
| **Kompresi (gzip/brotli)** | Normalisasi sebelum pencarian PII — lihat §3.4 |

**Prasyarat non-teknis (dan ini yang menentukan):**

- **Privacy policy aplikasi** — unduh dan simpan versinya beserta tanggal aksesnya.
- **Data safety declaration** dari halaman Google Play aplikasi — screenshot/salin seluruh tabelnya.
- **Daftar PII canary** yang unik dan mudah dicari. Ini teknik kunci test ini: gunakan nilai yang tidak mungkin muncul secara kebetulan.

```
Nama         : Mastg Canarytest
Email        : mastg.canary.7f3a@example.com
Telepon      : +6281234567890
Alamat       : Jl. Canary Mastg No. 7F3A, Jakarta
Kartu        : 4111 1111 1111 1111   (nomor uji, bukan kartu nyata)
Lokasi       : 37.7749 / -122.4194
Tanggal lahir: 1990-07-03
NIK          : 3201077F3A000001      (format uji, bukan NIK nyata)
```

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0005** (*Installing Apps*) untuk menginstall aplikasi.
2. Gunakan **MASTG-TECH-0100** (*Logging Sensitive Data from Network Traffic*) untuk menangkap dan mencatat lalu lintas jaringan aplikasi.
3. **Jalankan dan gunakan aplikasi melalui berbagai alur kerja** sambil memasukkan data sensitif di setiap tempat yang memungkinkan — **terutama di tempat yang kamu tahu akan memicu lalu lintas jaringan**.

### 3.2 Implementasi Praktis (MASTG-DEMO-0009)

**Langkah 0 — Siapkan dokumen pembanding (lakukan SEBELUM menangkap trafik)**

```bash
mkdir -p ./evidence
# Simpan privacy policy
curl -s "https://example.com/privacy" -o ./evidence/privacy-policy-$(date +%F).html
# Catat Data safety declaration dari halaman Play Store (manual/screenshot)
#   -> ./evidence/data-safety-$(date +%F).md
```

Buat tabel deklarasi yang akan jadi baseline perbandingan:

| Tipe data | Collected? | Shared? | Terenkripsi saat transit? | Tujuan (menurut deklarasi) |
|---|---|---|---|---|
| Precise location | ? | ? | ? | ? |
| Email address | ? | ? | ? | ? |
| Phone number | ? | ? | ? | ? |
| Payment info | ? | ? | ? | ? |
| Health info | ? | ? | ? | ? |
| Device or other IDs | ? | ? | ? | ? |

**Langkah 1 — Jalankan emulator dengan sistem writable**

```bash
emulator -avd Pixel_3a_API_33_arm64-v8a -writable-system
```

**Langkah 2 — Pasang sertifikat, konfigurasi proxy, install aplikasi**

```bash
# Pasang sertifikat mitmproxy sebagai system CA (lihat §2.3 Opsi A)

# Arahkan trafik device ke proxy
adb shell settings put global http_proxy 10.0.2.2:8080
# (atau jalankan emulator dengan -http-proxy http://127.0.0.1:8080)

adb install -g ./target-app.apk
```

**Langkah 3 — Jalankan mitmproxy dengan script pencatat PII**

Script resmi MASTG (`mitm_sensitive_logger.py`):

```python
from mitmproxy import http

# This data would come from another file and should be defined after identifying the data
# that is considered sensitive for this application.
# For example by using the Google Play Store Data Safety section.
SENSITIVE_DATA = {
    "precise_location_latitude": "37.7749",
    "precise_location_longitude": "-122.4194",
    "name": "John Doe",
    "email_address": "john.doe@example.com",
    "phone_number": "+11234567890",
    "credit_card_number": "1234 5678 9012 3456"
}

SENSITIVE_STRINGS = SENSITIVE_DATA.values()

def contains_sensitive_data(string):
    return any(sensitive in string for sensitive in SENSITIVE_STRINGS)

def process_flow(flow):
    url = flow.request.pretty_url
    request_headers = flow.request.headers
    request_body = flow.request.text
    response_headers = flow.response.headers if flow.response else "No response"
    response_body = flow.response.text if flow.response else "No response"

    if (contains_sensitive_data(url) or
        contains_sensitive_data(request_body) or
        contains_sensitive_data(response_body)):
        with open("sensitive_data.log", "a") as file:
            if flow.response:
                file.write(f"RESPONSE URL: {url}\n")
                file.write(f"Response Headers: {response_headers}\n")
                file.write(f"Response Body: {response_body}\n\n")
            else:
                file.write(f"REQUEST URL: {url}\n")
                file.write(f"Request Headers: {request_headers}\n")
                file.write(f"Request Body: {request_body}\n\n")

def request(flow: http.HTTPFlow):
    process_flow(flow)

def response(flow: http.HTTPFlow):
    process_flow(flow)
```

Jalankan (`run.sh` dari demo):

```bash
mitmdump -s mitm_sensitive_logger.py
```

> **Catatan penting dari MASTG** tentang daftar `SENSITIVE_DATA`: *"the script is preconfigured with data that's already considered sensitive for this application. When running this test in a real-world scenario, you should determine what is considered sensitive data based on the app's privacy policy and relevant privacy regulations. One recommended way to do this is by checking the app's privacy policy and the App Store Privacy declarations."*

**Langkah 4 — Exercise aplikasi secara ekstensif**

Fokuskan pada alur yang memicu lalu lintas jaringan, dan masukkan canary value di setiap input:

- **Onboarding & first launch** — sering mengirim device fingerprint & Advertising ID sebelum user menyetujui apa pun
- Registrasi, login, logout, login ulang, social login
- Lengkapi profil: nama, email, telepon, alamat, tanggal lahir, upload foto/dokumen identitas
- **Izinkan permission lokasi**, lalu gerakkan lokasi di emulator (Extended controls → Location)
- Izinkan permission kontak, kalender, kamera, mikrofon, penyimpanan
- Tambah metode pembayaran, lakukan transaksi, unduh invoice
- Fitur pencarian (riwayat pencarian termasuk tipe data App activity)
- Chat/pesan, komentar, konten buatan user
- Fitur kesehatan/kebugaran bila ada (Health info = kategori khusus)
- **Picu crash** (crash log adalah tipe data yang harus dideklarasikan)
- Background/foreground berulang, biarkan idle beberapa menit (beacon analytics periodik)
- Navigasi ke seluruh layar — beberapa SDK mengirim screen-view event per layar
- **Buka Settings aplikasi**, matikan semua toggle "analytics"/"personalisasi", lalu ulangi alur — periksa apakah pengumpulan benar-benar berhenti
- Uninstall lalu install ulang (memeriksa apakah ID persisten dikirim ulang)

**Langkah 5 — Analisis hasil**

### 3.3 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Observation:** *"The output should contain a network traffic log that includes the decrypted HTTPS traffic."*
>
> **Evaluation:** *"The test case **fails** if you can find the PII you entered in the app that is **not declared** in the app's marketplace privacy declarations (e.g., Data Safety section in Google Play) **and/or** in its privacy policy."*

Perhatikan struktur kalimat evaluasinya. Yang membuat FAIL adalah **kombinasi dua kondisi**:

1. PII yang kamu masukkan **ditemukan** dalam lalu lintas jaringan, **DAN**
2. PII itu **tidak dideklarasikan** di Data safety section dan/atau privacy policy.

Ini berarti: **PII yang terkirim tetapi sudah dideklarasikan dengan benar → PASS** (dari perspektif test ini). Dan sebaliknya, **PII yang dideklarasikan tetapi ternyata dikirim ke pihak/tujuan yang tidak disebutkan → FAIL.**

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi | Contoh bukti |
|---|---|---|
| F1 | **Tipe data yang sama sekali tidak dideklarasikan** ditemukan di trafik | Body request memuat `precise_location_latitude=37.7749` padahal Data safety tidak mencantumkan "Precise location" |
| F2 | Data dideklarasikan sebagai **"collected" saja**, tetapi kenyataannya **"shared"** ke domain pihak ketiga | Email canary dikirim ke `api.thirdparty-analytics.com`, bukan hanya ke backend aplikasi |
| F3 | PII dikirim ke **host pihak ketiga yang tidak disebutkan** di privacy policy | Nama & telepon canary muncul di request ke SDK attribution/ads |
| F4 | **Kategori data khusus** (kesehatan, biometrik, agama, orientasi seksual, data anak) dikirim tanpa deklarasi & basis hukum yang memadai | `blood_type=O` dikirim ke endpoint analytics |
| F5 | PII dikirim **sebelum user memberikan consent** atau sebelum layar privasi ditampilkan | Advertising ID + device fingerprint terkirim pada request pertama saat *first launch* |
| F6 | Pengumpulan **tetap berjalan setelah user menolak/menonaktifkan** opsi analytics/personalisasi | Toggle "Analytics" = OFF, tetapi event masih terkirim |
| F7 | **Device/other IDs** (Advertising ID, Android ID, IMEI, MAC) dikirim tanpa dideklarasikan | Request memuat `adid=...`, `android_id=...` |
| F8 | PII muncul di **URL / query string** (juga masalah keamanan: tercatat di log server & proxy, tersimpan di riwayat) | `GET /api/user?email=mastg.canary.7f3a@example.com` |
| F9 | PII dikirim melalui **HTTP cleartext** (terlihat di Wireshark tanpa sertifikat) | **Naikkan severity** — ini sekaligus temuan MASVS-NETWORK |
| F10 | PII muncul di **header** yang tidak seharusnya (mis. `User-Agent`, `Referer`, custom header) | `X-User-Email: mastg.canary.7f3a@example.com` |
| F11 | Data dikumpulkan **lebih luas dari tujuan yang dideklarasikan** (pelanggaran prinsip minimisasi data) | Deklarasi menyebut "approximate location untuk konten lokal", kenyataannya mengirim koordinat presisi tinggi secara berkala |
| F12 | Deklarasi menyatakan data **"encrypted in transit"**, tetapi kenyataannya tidak | Terlihat cleartext di Wireshark |
| F13 | PII dikirim ke **endpoint di yurisdiksi** yang tidak disebutkan, padahal relevan secara regulasi | Data warga Uni Eropa dikirim ke server tanpa mekanisme transfer yang sah |

**Contoh output yang menandakan FAIL — MASTG-DEMO-0009:**

Kode sampel (`MastgTest.kt`) — mengirim PII via `HttpURLConnection` ke `https://httpbin.org/post`:

```kotlin
val SENSITIVE_DATA = mapOf(
    "precise_location_latitude" to "37.7749",
    "precise_location_longitude" to "-122.4194",
    "name" to "John Doe",
    "email_address" to "john.doe@example.com",
    "phone_number" to "+11234567890",
    "credit_card_number" to "1234 5678 9012 3456"
)

val url = URL("https://httpbin.org/post")
val httpURLConnection = url.openConnection() as HttpURLConnection
httpURLConnection.requestMethod = "POST"
httpURLConnection.doOutput = true
httpURLConnection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded")

val postData = SENSITIVE_DATA.map { (key, value) ->
    "${URLEncoder.encode(key, "UTF-8")}=${URLEncoder.encode(value, "UTF-8")}"
}.joinToString("&")
// ... dikirim via BufferedWriter
```

Output `sensitive_data.log`:

```
REQUEST URL: https://httpbin.org/post
Request Headers: Headers[(b'Content-Type', b'application/x-www-form-urlencoded'), (b'User-Agent', b'Dalvik/2.1.0 (Linux; U; Android 13; sdk_gphone64_arm64 Build/TE1A.220922.021)'), (b'Host', b'httpbin.org'), ...]
Request Body: precise_location_latitude=37.7749&precise_location_longitude=-122.4194&name=John+Doe&email_address=john.doe%40example.com&phone_number=%2B11234567890&credit_card_number=1234+5678+9012+3456

RESPONSE URL: https://httpbin.org/post
Response Headers: Headers[(b'Date', b'Fri, 19 Jan 2024 10:17:44 GMT'), (b'Content-Type', b'application/json'), ...]
Response Body: {
  "form": {
    "credit_card_number": "1234 5678 9012 3456",
    "email_address": "john.doe@example.com",
    "name": "John Doe",
    "phone_number": "+11234567890",
    "precise_location_latitude": "37.7749",
    "precise_location_longitude": "-122.4194"
  },
  ...
  "origin": "148.141.65.87",
  "url": "https://httpbin.org/post"
}
```

MASTG mengidentifikasi dua instance: request POST yang memuat PII di body, dan response yang memuat PII di body (karena `httpbin.org` mengembalikan data yang diterimanya).

Evaluasi MASTG: *"After reviewing the captured network traffic, we can conclude that the test **fails** because the sensitive data is sent over the network. ... in a real-world scenario, you should identify which reported instances are relevant to privacy and require remediation **because they are not included in the app's privacy policy or the App Store privacy declaration**."*

**Dan catatan kunci yang menegaskan sifat test ini:**

> *"Note that **both the request and the response are encrypted using TLS, so they can be considered secure**. However, this might represent a **privacy issue**..."*

---

**⚠️ Temuan penting: script resmi MASTG melewatkan 4 dari 6 nilai PII di request body.**

Ini keterbatasan nyata yang perlu kamu ketahui sebelum memakai script tersebut apa adanya. Fungsi `contains_sensitive_data()` melakukan **pencocokan substring eksak**, sementara body request sudah **URL-encoded**. Mari bandingkan nilai yang dicari dengan yang benar-benar ada di body:

| Nilai di `SENSITIVE_STRINGS` | Bentuk di request body (URL-encoded) | Cocok? |
|---|---|---|
| `37.7749` | `37.7749` | ✅ |
| `-122.4194` | `-122.4194` | ✅ |
| `John Doe` | `John+Doe` (spasi → `+`) | ❌ |
| `john.doe@example.com` | `john.doe%40example.com` (`@` → `%40`) | ❌ |
| `+11234567890` | `%2B11234567890` (`+` → `%2B`) | ❌ |
| `1234 5678 9012 3456` | `1234+5678+9012+3456` | ❌ |

Jadi flow tersebut tercatat **hanya karena koordinat lokasi kebetulan tidak berubah** saat di-encode. Seandainya aplikasi hanya mengirim nama, email, telepon, dan nomor kartu — **script akan melaporkan nol temuan** dan kamu bisa salah menyimpulkan PASS.

Pada demo ini kebocoran empat nilai lainnya tetap terlihat, tetapi itu **kebetulan**: `httpbin.org` mengembalikan data dalam bentuk JSON yang tidak di-URL-encode, sehingga nilai aslinya muncul di response body. Pada aplikasi nyata tidak ada endpoint echo semacam itu — kamu hanya punya request, dan empat nilai itu akan lolos.

**Kesimpulan praktis:** jangan pakai script demo apa adanya untuk pengujian nyata. Gunakan versi yang menormalisasi payload (§3.4).

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi | Contoh bukti |
|---|---|---|
| P1 | **Tidak ada PII canary** yang ditemukan dalam seluruh lalu lintas yang ditangkap, setelah aplikasi di-exercise ekstensif dan payload dinormalisasi | `sensitive_data.log` kosong; pencarian pada seluruh flow dump juga bersih |
| P2 | PII **ditemukan**, tetapi **setiap tipe data sudah dideklarasikan dengan akurat** di Data safety section **dan** privacy policy — mencakup collected/shared, tujuan, dan enkripsi transit | Tabel perbandingan (§3.5) menunjukkan kesesuaian penuh |
| P3 | PII hanya dikirim ke **backend milik aplikasi sendiri**, dan ini sesuai deklarasi (tidak ada "shared" yang tidak diakui) | Seluruh host tujuan yang menerima PII ada di daftar yang dideklarasikan |
| P4 | Pengumpulan hanya terjadi **setelah consent eksplisit**, dan **berhenti** ketika user menolak/menonaktifkannya | Sebelum consent: tidak ada PII di trafik. Setelah toggle OFF: pengumpulan berhenti |
| P5 | Data yang terkirim sudah **di-minimisasi / di-pseudonimisasi** sesuai deklarasi | Lokasi dikirim sebagai `city=Jakarta` (approximate) sesuai deklarasi "Approximate location", bukan koordinat presisi |
| P6 | Tidak ada PII di **URL/query string maupun header**; semuanya di body request atas HTTPS | Sesuai praktik yang benar |
| P7 | Tidak ada trafik **cleartext** yang memuat PII | Wireshark tidak menemukan PII pada port 80 atau protokol tanpa TLS |

**Contoh output yang menandakan PASS:**

```bash
$ mitmdump -s mitm_sensitive_logger_improved.py
# ... exercise aplikasi secara ekstensif dengan canary value ...
^C
$ wc -l sensitive_data.log
0 sensitive_data.log

# Verifikasi silang pada dump seluruh flow (bukan hanya yang ter-match)
$ mitmdump -nr flows.mitm --set flow_detail=3 | \
    grep -iE "mastg.canary.7f3a|Mastg[ +]Canarytest|6281234567890|4111" 
# (tidak ada hasil)

# Verifikasi cleartext
$ tshark -r capture.pcap -Y 'http' -T fields -e http.file_data | \
    grep -iE "mastg.canary|4111"
# (tidak ada hasil)
```

Atau — PII ditemukan, tetapi terdeklarasi lengkap:

| Tipe data ditemukan | Host tujuan | Dideklarasikan (Data safety)? | Dideklarasikan (Privacy policy)? | Verdict |
|---|---|---|---|---|
| Email address | `api.myapp.com` | ✅ Collected, not shared, encrypted | ✅ Disebut, tujuan: autentikasi | ✅ |
| Phone number | `api.myapp.com` | ✅ Collected, not shared, encrypted | ✅ Disebut, tujuan: verifikasi 2FA | ✅ |
| Device or other IDs | `api.myapp.com` | ✅ Collected, not shared | ✅ Disebut, tujuan: anti-fraud | ✅ |
| Crash logs | `crashlytics.googleapis.com` | ✅ Collected, **shared** | ✅ Menyebut Firebase Crashlytics | ✅ |

→ **PASS** untuk TEST-0206.

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Tanpa dokumen pembanding, test ini TIDAK BISA diselesaikan.** Ini konsekuensi langsung dari prerequisites `privacy-policy` dan `app-store-privacy-declarations`. Yang bisa kamu hasilkan tanpanya hanyalah **inventaris data** — daftar PII yang terkirim dan ke host mana. Itu berguna, tetapi laporkan sebagai *inventory/informational*, bukan sebagai FAIL. Menyatakan FAIL tanpa membandingkan deklarasi adalah kesalahan metodologis.

2. **TLS yang benar tidak menyelamatkan test ini.** Diulang karena ini paling sering disalahpahami: MASTG-DEMO-0009 secara eksplisit menyatakan trafiknya "can be considered secure" namun tetap FAIL. Jangan menutup temuan dengan alasan "tapi sudah HTTPS".

3. **Certificate pinning yang memblokir interception ≠ PASS.** Statusnya **Inconclusive**. Catat pinning sebagai kontrol MASVS-NETWORK yang baik, lalu selesaikan penilaian privasi lewat **MASTG-TEST-0319** (hooking SDK API — melihat data sebelum masuk lapisan TLS) dan **MASTG-TEST-0318** (statis).

4. **Output kosong ≠ otomatis PASS.** Penyebab false pass pada test ini banyak dan spesifik:
   - **Pencocokan substring gagal** karena encoding (lihat temuan di §3.3 — script resmi melewatkan 4 dari 6 nilai)
   - Payload **ter-kompresi** (gzip/brotli), **ter-encode** (Base64), atau **biner** (Protobuf/gRPC)
   - Aplikasi meng-**enkripsi payload di lapisan aplikasi** sebelum TLS
   - PII dikirim dalam bentuk **hash** (`sha256(email)`) — tidak akan cocok dengan canary, **tetapi tetap merupakan pengumpulan data** dan sering masih dapat di-identifikasi ulang
   - Protokol yang tidak ditangkap proxy (**QUIC/HTTP3**, MQTT, TCP kustom)
   - **Alur pemicu belum di-exercise** — banyak beacon analytics bersifat periodik atau hanya terpicu pada kondisi tertentu
   - Aplikasi **mendeteksi proxy** dan mengubah perilaku
   
   **Mitigasi:** selalu simpan **seluruh flow** (bukan hanya yang ter-match) dengan `mitmdump -w flows.mitm`, lalu review manual daftar host tujuan dan sampel payload. Kombinasikan dengan Wireshark untuk memetakan protokol yang tidak lewat proxy.

5. **Waspadai PII dalam bentuk hash atau derivasi.** `sha256("mastg.canary.7f3a@example.com")` tidak akan cocok dengan canary polos, tetapi pengiriman email yang di-hash **tetap merupakan pengumpulan data** yang harus dideklarasikan (praktik umum di SDK ads untuk *matching*). Tambahkan hash dari setiap canary ke daftar pencarian — lihat §3.4.

6. **Perhatikan host tujuan, bukan hanya isi payload.** Sering kali temuan terpenting bukan "PII terkirim", melainkan "**PII terkirim ke pihak ketiga yang tidak diakui**". Buat inventaris domain lengkap dan petakan masing-masing ke SDK/vendornya. Trafik ke `graph.facebook.com`, `app-measurement.com`, `*.adjust.com`, `*.appsflyer.com`, atau `*.branch.io` yang memuat PII hampir selalu berarti kategori "shared" yang perlu dideklarasikan.

7. **Periksa timing terhadap consent.** Pengumpulan data **sebelum** user menyetujui apa pun adalah pelanggaran yang lebih berat daripada pengumpulan yang tidak dideklarasikan. Rekam urutan waktu: request mana yang terjadi sebelum layar consent ditampilkan?

8. **Uji juga jalur "opt-out".** Matikan setiap toggle privasi/analytics di aplikasi, ulangi alur, dan periksa apakah pengumpulan benar-benar berhenti. Deklarasi yang menyebut data bersifat "optional" tetapi tetap terkumpul saat dinonaktifkan adalah FAIL.

9. **Severity dimodulasi oleh beberapa faktor:**

   | Faktor | Severity |
   |---|---|
   | Kategori data khusus (kesehatan, biometrik, agama, orientasi seksual) tanpa deklarasi | **Kritis** — implikasi regulasi terberat (GDPR Art. 9) |
   | Data anak / aplikasi yang menyasar anak | **Kritis** — COPPA / Play Families policy |
   | PII dikirim ke pihak ketiga tanpa deklarasi "shared" | **Tinggi** — dasar policy strike Google Play |
   | Pengumpulan sebelum consent | **Tinggi** |
   | Pengumpulan berlanjut setelah opt-out | **Tinggi** |
   | Data finansial (nomor kartu, rekening) tanpa deklarasi | **Tinggi** |
   | PII dikirim cleartext (HTTP) | **Naik** — sekaligus temuan MASVS-NETWORK |
   | PII di URL/query string | Naik — tercatat di log server/proxy |
   | Device/other IDs tanpa deklarasi | Menengah |
   | Data terdeklarasi tetapi deskripsi tujuannya tidak akurat/terlalu kabur | Rendah–Menengah |
   | PII terkirim **dan** terdeklarasi lengkap & akurat | **Bukan temuan** (untuk test ini) |

10. **Dokumentasikan bukti lengkap per temuan:** tipe data (gunakan terminologi Google Play Data safety agar langsung dapat dibandingkan), nilai canary yang ditemukan (redaksi sebagian), **URL/host tujuan penuh**, metode HTTP, lokasi dalam pesan (URL/header/body), timestamp relatif terhadap consent, **kutipan deklarasi yang relevan (atau pernyataan bahwa deklarasinya tidak ada)**, versi privacy policy beserta tanggal akses, langkah reproduksi, dan batasan pengujian (mis. pinning belum di-bypass pada host tertentu, trafik QUIC tidak tertangkap).

11. **Sertakan tabel perbandingan di laporan.** Ini deliverable paling berguna dari test ini — lihat format di §3.5. Tabel inilah yang akan dipakai tim legal/privasi dan tim produk untuk memperbaiki deklarasi.

### 3.4 Script yang Diperbaiki (Menutup Celah Encoding)

Script berikut mengatasi keterbatasan yang ditemukan di §3.3: normalisasi URL-encoding, Base64, gzip, JSON escaping, pencocokan case-insensitive, deteksi PII yang di-hash, deteksi berbasis pola (bukan hanya canary eksak), serta **inventaris seluruh host** — bukan hanya flow yang ter-match.

```python
# mitm_sensitive_logger_improved.py
import base64, gzip, hashlib, json, re, urllib.parse, zlib
from collections import defaultdict
from mitmproxy import http, ctx

# ---- 1. Canary value: tentukan dari privacy policy + Data safety section ----
SENSITIVE_DATA = {
    "name":              "Mastg Canarytest",
    "email_address":     "mastg.canary.7f3a@example.com",
    "phone_number":      "+6281234567890",
    "street_address":    "Jl. Canary Mastg No. 7F3A",
    "credit_card":       "4111 1111 1111 1111",
    "precise_lat":       "37.7749",
    "precise_lon":       "-122.4194",
    "date_of_birth":     "1990-07-03",
    "national_id":       "3201077F3A000001",
}

# ---- 2. Varian setiap canary: polos, tanpa spasi, hash (SDK ads sering mengirim hash) ----
def variants(value: str):
    out = {value, value.lower(), value.replace(" ", ""), value.replace(" ", "").lower()}
    for v in list(out):
        out.add(hashlib.md5(v.encode()).hexdigest())
        out.add(hashlib.sha1(v.encode()).hexdigest())
        out.add(hashlib.sha256(v.encode()).hexdigest())
    return {v for v in out if len(v) >= 5}

NEEDLES = {}
for label, val in SENSITIVE_DATA.items():
    for v in variants(val):
        NEEDLES[v.lower()] = label

# ---- 3. Pola generik: menangkap PII yang BUKAN canary (mis. ID perangkat asli) ----
PATTERNS = {
    "email":            re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "credit_card":      re.compile(r"\b(?:\d[ -]?){13,19}\b"),
    "coordinates":      re.compile(r"\b-?\d{1,3}\.\d{4,}\b"),
    "advertising_id":   re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"),
    "imei":             re.compile(r"\b\d{15}\b"),
    "android_id":       re.compile(r"\b[0-9a-f]{16}\b"),
    "jwt":              re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
}

# ---- 4. Normalisasi payload agar PII terbaca ----
def normalize(raw: bytes | str) -> str:
    if raw is None:
        return ""
    data = raw.encode("utf-8", "ignore") if isinstance(raw, str) else raw
    layers = [data]

    # Dekompresi
    for fn in (gzip.decompress, zlib.decompress):
        try:
            layers.append(fn(data))
        except Exception:
            pass

    texts = []
    for b in layers:
        t = b.decode("utf-8", "ignore")
        texts.append(t)
        texts.append(urllib.parse.unquote_plus(t))          # URL-decode (%40 -> @, + -> spasi)
        texts.append(t.encode().decode("unicode_escape", "ignore"))  # JSON escape
        # Base64 di dalam payload
        for m in re.findall(r"[A-Za-z0-9+/=]{16,}", t):
            try:
                texts.append(base64.b64decode(m + "==", validate=False).decode("utf-8", "ignore"))
            except Exception:
                pass
    return "\n".join(texts).lower()

def find_hits(text_norm: str):
    hits = set()
    for needle, label in NEEDLES.items():
        if needle in text_norm:
            hits.add(("canary", label))
    for label, rx in PATTERNS.items():
        if rx.search(text_norm):
            hits.add(("pattern", label))
    return hits

# ---- 5. Inventaris host: SELALU dicatat, bahkan bila tidak ada hit ----
HOSTS = defaultdict(lambda: {"count": 0, "hits": set()})

def process(flow: http.HTTPFlow):
    if not flow.response:
        return
    host = flow.request.pretty_host
    parts = {
        "url":      flow.request.pretty_url,
        "req_hdr":  str(flow.request.headers),
        "req_body": flow.request.get_content(strict=False),
        "res_hdr":  str(flow.response.headers),
        "res_body": flow.response.get_content(strict=False),
    }
    all_hits = {}
    for where, raw in parts.items():
        h = find_hits(normalize(raw))
        if h:
            all_hits[where] = h

    HOSTS[host]["count"] += 1
    for h in all_hits.values():
        HOSTS[host]["hits"] |= h

    if all_hits:
        with open("sensitive_data.log", "a", encoding="utf-8") as f:
            f.write("=" * 78 + "\n")
            f.write(f"HOST   : {host}\n")
            f.write(f"URL    : {flow.request.pretty_url}\n")
            f.write(f"METHOD : {flow.request.method}\n")
            for where, h in all_hits.items():
                f.write(f"HITS@{where}: {sorted(h)}\n")
            f.write(f"REQ HEADERS:\n{parts['req_hdr']}\n")
            f.write(f"REQ BODY:\n{flow.request.get_text(strict=False)}\n")
            f.write(f"RES BODY:\n{(flow.response.get_text(strict=False) or '')[:4000]}\n\n")

def response(flow: http.HTTPFlow):
    process(flow)

def websocket_message(flow):
    # WebSocket sering luput — periksa juga
    for msg in flow.websocket.messages[-1:]:
        h = find_hits(normalize(msg.content))
        if h:
            with open("sensitive_data.log", "a", encoding="utf-8") as f:
                f.write(f"[WS] {flow.request.pretty_url} HITS: {sorted(h)}\n")
                f.write(f"{msg.content[:2000]}\n\n")

def done():
    # Inventaris lengkap: penting untuk menemukan host pihak ketiga
    with open("host_inventory.log", "w", encoding="utf-8") as f:
        for host, info in sorted(HOSTS.items(), key=lambda x: -x[1]["count"]):
            flag = "  <== PII" if info["hits"] else ""
            f.write(f"{info['count']:5d}  {host}{flag}\n")
            if info["hits"]:
                f.write(f"        {sorted(info['hits'])}\n")
    ctx.log.info(f"[*] {len(HOSTS)} host tercatat -> host_inventory.log")
```

Jalankan dengan penyimpanan flow lengkap agar bisa dianalisis ulang tanpa mengulang sesi:

```bash
mitmdump -s mitm_sensitive_logger_improved.py -w flows.mitm

# Analisis ulang offline (tanpa perlu device)
mitmdump -nr flows.mitm -s mitm_sensitive_logger_improved.py

# Inventaris host — sering di sinilah temuan terpenting berada
cat host_inventory.log
```

**Pemeriksaan pelengkap:**

```bash
# 1. Trafik cleartext (tanpa perlu sertifikat) — bukti langsung
tshark -i any -Y 'http.request or http.response' -T fields -e http.host -e http.file_data \
  | grep -iE "mastg.canary|4111|6281234567890"

# 2. Protokol yang TIDAK lewat proxy HTTP (QUIC, MQTT, DNS-over-X)
tshark -r capture.pcap -Y 'quic or mqtt' -T fields -e ip.dst -e udp.dstport | sort -u

# 3. Resolusi DNS — memetakan SDK pihak ketiga yang dihubungi
tshark -r capture.pcap -Y 'dns.flags.response == 0' -T fields -e dns.qry.name | sort -u

# 4. Cek apakah aplikasi melakukan pinning (sebelum mulai)
grep -rn "pin-set\|certificatePinner\|CertificatePinner\|checkServerTrusted" ./decompiled/sources/
grep -n "pin-set" ./out/res/xml/network_security_config.xml
```

### 3.5 Format Tabel Perbandingan (Deliverable Utama)

Inilah keluaran yang membuat test ini bernilai. Susun untuk setiap tipe data yang ditemukan:

| # | Tipe data (terminologi Play) | Nilai ditemukan | Host tujuan | Lokasi | Sebelum consent? | Data safety: collected | Data safety: shared | Privacy policy | **Verdict** |
|---|---|---|---|---|---|---|---|---|---|
| 1 | Precise location | `37.7749 / -122.4194` | `api.myapp.com` | req body | Tidak | ❌ tidak dideklarasikan | ❌ | ❌ tidak disebut | **FAIL (F1)** |
| 2 | Email address | `mastg.canary…@example.com` | `api.myapp.com` | req body | Tidak | ✅ | ❌ not shared | ✅ | PASS |
| 3 | Email address (SHA-256) | `a3f1…` | `graph.facebook.com` | req body | Tidak | ✅ collected | ❌ **not shared** | ❌ tidak menyebut Meta | **FAIL (F2/F3)** |
| 4 | Device or other IDs | `AdID 8f2c-…` | `app-measurement.com` | query | **Ya** | ❌ | ❌ | ❌ | **FAIL (F5/F7)** |
| 5 | Payment info | `4111 1111 1111 1111` | `api.myapp.com` | req body | Tidak | ✅ | ❌ | ✅ | PASS |

Lampirkan juga **inventaris host** lengkap (dari `host_inventory.log`), dengan pemetaan ke SDK/vendor:

| Host | Jumlah request | SDK/Vendor | Memuat PII? | Disebut di privacy policy? |
|---|---|---|---|---|
| `api.myapp.com` | 142 | Backend sendiri | Ya | ✅ |
| `app-measurement.com` | 38 | Firebase/Google Analytics | Ya | ❌ |
| `graph.facebook.com` | 11 | Meta SDK | Ya (hash) | ❌ |
| `crashlytics.googleapis.com` | 6 | Firebase Crashlytics | Crash log | ✅ |

---

### 3.6 Metode Pengujian Alternatif (Multi-Tool)

MASTG memakai mitmproxy, tetapi setiap intercepting proxy bisa dipakai — dan sebagian tantangan (pinning, protokol non-HTTP) menuntut tool yang berbeda. Berikut jalur alternatifnya.

#### Metode B — Burp Suite *(interception + deteksi PII semi-otomatis)*

Burp unggul untuk eksplorasi manual dan punya ekosistem ekstensi untuk deteksi PII otomatis.

```
1. Proxy > Options > tambahkan listener di 0.0.0.0:8080 (all interfaces)
2. Arahkan proxy device:  adb shell settings put global http_proxy <IP-host>:8080
3. Pasang CA Burp sebagai system CA (lihat §2.3 untuk API 24+)
4. Exercise aplikasi dengan canary value
5. Proxy > HTTP history  ->  filter & cari PII
```

**Deteksi PII otomatis dengan Bambda** (Burp 2023.10+, tab *Proxy > HTTP history > Bambda*):

```java
// Sorot request/response yang memuat canary value atau pola PII
var body = requestResponse.request().bodyToString()
         + requestResponse.response().bodyToString();
var url  = requestResponse.request().url();
var patterns = java.util.List.of(
    "MASTG_CANARY_PWD_7f3a", "mastg.canary.7f3a@example.com", "6281234567890",
    "4111111111111111", "37.7749");
return patterns.stream().anyMatch(p -> body.contains(p) || url.contains(p));
```

Ekstensi yang membantu (BApp Store): **Reflected Parameters**, **Piper** (integrasi tool eksternal), **Logger++** (filter & ekspor lanjutan dengan regex PII). Untuk decode otomatis payload ter-encode, gabungkan dengan ekstensi **Hackvertor**.

#### Metode C — OWASP ZAP *(open-source, scripting pasif)*

```bash
# Jalankan ZAP dalam mode daemon dengan proxy
zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true
```

Passive scan script (ZAP > Scripts > Passive Rules) untuk menandai PII:

```javascript
// pii-detector.js — ZAP passive script
function scan(ps, msg, src) {
    var body = msg.getRequestBody().toString() + msg.getResponseBody().toString();
    var needles = ["MASTG_CANARY_PWD_7f3a", "mastg.canary.7f3a@example.com", "4111111111111111"];
    needles.forEach(function(n) {
        if (body.indexOf(n) !== -1) {
            ps.raiseAlert(3, 1, "PII in traffic", "Ditemukan: " + n,
                msg.getRequestHeader().getURI().toString(),
                "", "", "", "", "", 0, 0, msg);
        }
    });
}
```

Keunggulan ZAP: gratis, bisa diotomatisasi penuh via API/CLI untuk CI, dan mendukung ekspor HAR untuk analisis lanjutan.

#### Metode D — HTTP Toolkit *(setup tercepat, terutama untuk emulator)*

```bash
# HTTP Toolkit punya integrasi ADB satu-klik yang menangani proxy + CA otomatis
# Untuk emulator/rooted device: injeksi sertifikat sistem dilakukan otomatis
```

Alur: buka HTTP Toolkit → **Android device via ADB** → pilih device → aplikasi langsung ter-intercept. Keunggulan: menghilangkan seluruh kerumitan setup CA manual (§2.3 Rintangan 1) untuk device yang didukung, dan punya UI pencarian/filter yang baik plus rewrite rules bawaan. Sangat menghemat waktu pada fase setup yang biasanya paling lama.

#### Metode E — Frida untuk bypass pinning + capture *(ketika proxy diblokir)*

Bila certificate pinning menghalangi (Rintangan 2 di §2.3), ini jalur paling andal.

```bash
# 1. Bypass pinning universal (menangani OkHttp, TrustManager, Conscrypt, dll.)
frida -U -f com.example.target \
  -l https://codeshare.frida.re/@pcipolloni/universal-android-ssl-pinning-bypass-with-frida/

# atau via objection (satu perintah):
objection -g com.example.target explore
android sslpinning disable

# 2. Setelah pinning mati, trafik mengalir ke proxy (Burp/mitmproxy/ZAP) seperti biasa
```

Alternatif: **hook langsung di titik enkripsi/dekripsi**, sehingga kamu melihat plaintext **sebelum** TLS — ini menembus pinning **dan** enkripsi lapisan aplikasi sekaligus:

```javascript
// Lihat data sebelum masuk ke SSL/TLS
Java.perform(() => {
    const SSLOut = Java.use("com.android.org.conscrypt.ConscryptFileDescriptorSocket$SSLOutputStream");
    // atau hook OkHttp Interceptor, HttpURLConnection.getOutputStream, dsb.
});
```

Ini bertaut langsung dengan **MASTG-TEST-0319** (hooking SDK API), yang melihat data bahkan sebelum masuk ke lapisan jaringan.

#### Metode F — PolarProxy / mitmproxy mode transparan *(protokol non-HTTP berbasis TLS)*

Untuk MQTT, gRPC, XMPP, atau protokol TCP kustom yang tidak lewat proxy HTTP.

```bash
# PolarProxy — TLS interception yang menyimpan traffic terdekripsi ke PCAP
PolarProxy -p 10443,80,443 -x ./ca.cer -f ./decrypted.pcap
#   -> buka decrypted.pcap di Wireshark untuk inspeksi protokol apa pun

# mitmproxy mode transparan (menangkap lebih dari HTTP)
mitmdump --mode transparent --showhost -s pii_logger.py
```

#### Metode G — tcpdump + Wireshark *(cleartext + pemetaan protokol, tanpa proxy)*

Ini metode yang **tidak butuh CA sama sekali** dan menangkap **semua** trafik, termasuk yang tidak mau lewat proxy.

```bash
# Tangkap di device (butuh root) atau via emulator
adb shell "su -c 'tcpdump -i any -s0 -w /sdcard/capture.pcap'"
adb pull /sdcard/capture.pcap

# --- Analisis dengan tshark ---
# 1. Trafik cleartext yang memuat PII (bukti langsung, tanpa dekripsi)
tshark -r capture.pcap -Y 'http.request or http.response' \
  -T fields -e http.host -e http.file_data | grep -iE "MASTG_CANARY|4111|6281234567890"

# 2. Petakan SEMUA host tujuan (termasuk yang pakai protokol non-HTTP)
tshark -r capture.pcap -Y 'dns.flags.response==0' -T fields -e dns.qry.name | sort -u

# 3. Deteksi QUIC/HTTP3 yang luput dari proxy
tshark -r capture.pcap -Y 'quic' -T fields -e ip.dst -e udp.dstport | sort -u

# 4. Untuk mendekripsi TLS: set SSLKEYLOGFILE lalu load ke Wireshark
#    (Edit > Preferences > TLS > (Pre)-Master-Secret log filename)
```

Keunggulan: `tcpdump` menangkap trafik yang aplikasi kirim lewat channel yang **sengaja menghindari proxy** (mis. hardcoded proxy bypass, atau protokol non-HTTP) — sesuatu yang tidak akan terlihat di Burp/mitmproxy.

#### Metode H — MobSF Dynamic Analyzer *(otomatis + captured traffic)*

```bash
docker run -it --rm -p 8000:8000 -p 1337:1337 \
  opensecurity/mobile-security-framework-mobsf:latest
```

MobSF menjalankan aplikasi dengan proxy + CA terpasang otomatis, lalu menyediakan bagian **HTTP(S) Traffic** yang bisa dicari. Ia juga menandai domain pihak ketiga dan trackers yang dikenal. Keunggulan: pass awal cepat yang sekaligus menghasilkan daftar host tujuan. Keterbatasan: exercise dangkal, tidak bisa login — pelengkap, bukan pengganti exercise manual.

#### Metode I — Analisis statis SDK: MASTG-TEST-0318 *(menemukan lokasi kode)*

Network capture tidak memberi lokasi kode. Untuk itu, jalankan counterpart statisnya.

```bash
jadx -d ./decompiled ./target-app.apk
D=./decompiled/sources

# API SDK yang dikenal menangani data sensitif
rg -n --no-heading "FirebaseAnalytics|logEvent|setUserId|setUserProperty" $D
rg -n --no-heading "AppsFlyerLib|Adjust\.|Branch\.|Amplitude|mixpanel|Segment" $D
rg -n --no-heading "getSystemService.*LOCATION|getLastKnownLocation|requestLocationUpdates" $D
rg -n --no-heading "getDeviceId|getImei|ANDROID_ID|AdvertisingIdClient" $D

# Semgrep registry untuk trackers
semgrep --config "p/trailofbits" ./decompiled/sources/
```

#### Metode J — Exodus Privacy / trackers analysis *(inventaris SDK pelacak)*

```bash
# Exodus — deteksi tracker yang dikenal dari APK
# Via https://reports.exodus-privacy.eu.org/ (upload APK) atau CLI:
pip install exodus-core
exodus-core analyze ./target-app.apk

# ClassyShark / classyshark3xodus untuk inventaris library
```

Berguna untuk **mengetahui SDK pelacak apa yang ada** sebelum menangkap trafik — memberi daftar host yang harus kamu perhatikan di §3.5 (inventaris host).

---

### 3.7 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Butuh CA/root? | Tembus pinning? | Protokol non-HTTP? | Memberi lokasi kode? | Kapan dipakai |
|---|---|---|---|---|---|---|
| **A** | mitmproxy (MASTG) | CA + (root utk API24+) | ❌ (perlu bypass terpisah) | Sebagian | ❌ | **Baseline resmi** — scriptable |
| **B** | Burp Suite | CA + root | ❌ | ❌ | ❌ | Eksplorasi manual + Bambda/ekstensi PII |
| **C** | OWASP ZAP | CA + root | ❌ | ❌ | ❌ | Open-source; otomatisasi CI via API |
| **D** | HTTP Toolkit | Otomatis (didukung) | ❌ | ❌ | ❌ | **Setup tercepat** — menghindari kerumitan CA |
| **E** | Frida (bypass pinning) | — | ✅ **(kunci)** | — | Sebagian (backtrace) | **Ketika pinning menghalangi** |
| **F** | PolarProxy / mitm transparan | CA + root | ❌ | ✅ **(kunci)** | ❌ | MQTT/gRPC/TCP kustom |
| **G** | tcpdump + Wireshark | root (bukan CA) | — (lihat cleartext) | ✅ **(semua)** | ❌ | **Cleartext + trafik yang hindari proxy**; QUIC |
| **H** | MobSF Dynamic | Otomatis | ❌ | Sebagian | ❌ | Pass awal + inventaris host |
| **I** | Analisis statis (TEST-0318) | Tidak | — | — | ✅ **(kunci)** | Menemukan LOKASI KODE pengumpulan data |
| **J** | Exodus / trackers | Tidak | — | — | ❌ | **Inventaris SDK pelacak** sebelum capture |

**Kombinasi minimum yang aku rekomendasikan:** **J (Exodus) → A/B/D (proxy pilihanmu) → E (bila pinning) → I (statis)**.
J memberi peta SDK pelacak yang harus diperhatikan; proxy apa pun (A/B/D — pilih sesuai kenyamanan) menangkap trafiknya; E membuka pinning bila menghalangi; I menemukan lokasi kodenya untuk remediasi. Tambahkan **G (tcpdump)** selalu untuk aplikasi privasi tinggi — ia menangkap jalur yang sengaja menghindari proxy dan trafik cleartext yang justru paling berbahaya.

> **Ingat sifat test ini (§1.2):** semua metode di atas hanya menghasilkan **inventaris data yang keluar**. Keputusan PASS/FAIL tetap menuntut perbandingan dengan privacy policy + Data safety declaration — tidak ada tool yang bisa menggantikan langkah itu.

---

## 4. Rekomendasi Perbaikan

Karena ini test privasi, remediasinya punya **dua jalur yang sama-sama valid**: kurangi pengumpulan data, **atau** perbaiki deklarasinya. Keduanya sah — tetapi jalur pertama hampir selalu lebih baik.

### 4.1 Prinsip Utama (urutan prioritas)

**Prioritas 1 — Minimisasi data: jangan kirim yang tidak dibutuhkan.** Ini perbaikan terkuat karena menghilangkan risiko, bukan hanya mengungkapkannya. Untuk setiap tipe data dalam inventaris, tanyakan: *apakah fitur ini benar-benar tidak bisa berjalan tanpanya?*

- Hapus field PII yang dikirim "untuk sementara" atau warisan versi lama.
- Ganti **precise location** dengan **approximate location** bila fiturnya hanya butuh kota/wilayah.
- Kirim **turunan** alih-alih data mentah: rentang usia bukan tanggal lahir, kelompok umur bukan NIK, `city` bukan koordinat.
- **Agregasi di perangkat** sebelum mengirim — kirim statistik, bukan event per-user.
- Hapus PII dari **crash log** dan payload diagnostik.

**Prioritas 2 — Jangan pernah menaruh PII di URL, query string, atau header.**

```kotlin
// ❌ SALAH — tercatat di log server, log proxy, riwayat browser, referrer
val url = URL("https://api.myapp.com/user?email=$email&phone=$phone")

// ✅ BENAR — di body request, atas HTTPS
val body = JSONObject().apply { put("email", email) }.toString()
// POST dengan Content-Type: application/json
```

**Prioritas 3 — Audit dan kendalikan SDK pihak ketiga.** Dalam praktik, **inilah sumber temuan terbesar** pada test ini — dan sering di luar kesadaran developer.

- Buat inventaris SDK beserta data yang masing-masing kirimkan (gunakan `host_inventory.log` sebagai titik awal).
- Matikan pengumpulan otomatis yang tidak dibutuhkan:

```xml
<!-- AndroidManifest.xml — matikan pengumpulan otomatis Firebase Analytics -->
<meta-data android:name="firebase_analytics_collection_enabled" android:value="false" />
<meta-data android:name="google_analytics_default_allow_ad_personalization_signals"
           android:value="false" />
<meta-data android:name="firebase_crashlytics_collection_enabled" android:value="false" />
```

```kotlin
// Aktifkan hanya setelah consent
FirebaseAnalytics.getInstance(context).setAnalyticsCollectionEnabled(consentGiven)
FirebaseCrashlytics.getInstance().isCrashlyticsCollectionEnabled = consentGiven
```

- **Jangan kirim PII sebagai parameter event/user property.** Ini melanggar kebijakan Google Analytics sekaligus menciptakan temuan privasi:

```kotlin
// ❌ SALAH — PII ke analytics (ini yang dideteksi MASTG-TEST-0319)
analytics.setUserProperty("email", userEmail)
analytics.logEvent("profile_saved", bundleOf("blood_type" to bloodType))

// ✅ BENAR — identifier pseudonim, tanpa PII, tanpa kategori data khusus
analytics.setUserId(pseudonymousId)      // ID acak internal, bukan email/telepon
analytics.logEvent("profile_saved", bundleOf("has_health_data" to true))
```

- Gunakan **Advertising ID** sesuai kebijakan, dan hormati *Limit Ad Tracking*/`isLimitAdTrackingEnabled`.
- Bila SDK tidak dapat dikendalikan, pertimbangkan menggantinya atau memproksikan datanya lewat backend sendiri sehingga kamu mengendalikan apa yang keluar.

**Prioritas 4 — Terapkan consent yang benar (dan hormati).**

- **Jangan kumpulkan apa pun sebelum consent** — termasuk pada *first launch*. Inisialisasi SDK analytics/ads **setelah** user memutuskan.
- Consent harus **granular** (per tujuan), **spesifik**, dan **dapat ditarik** dengan mudah.
- Ketika user menarik consent atau menonaktifkan toggle, **pengumpulan harus benar-benar berhenti** — verifikasi ulang dengan test ini.
- Untuk pasar Uni Eropa, pertimbangkan Google **Consent Mode** dan kepatuhan TCF bila memakai SDK ads.
- Simpan catatan consent (waktu, versi kebijakan, pilihan) untuk keperluan audit.

**Prioritas 5 — Selaraskan deklarasi dengan perilaku nyata.** Ini jalur remediasi kedua: bila pengumpulan datanya memang dibutuhkan dan sah, **deklarasikan dengan akurat**.

- Perbarui **Google Play Data safety section**: untuk setiap tipe data, isi dengan benar *collected*, *shared*, *processed ephemerally*, *required or optional*, *encrypted in transit*, dan **tujuan**-nya.
- Perbarui **privacy policy**: sebutkan tipe data, tujuan, **penerima pihak ketiga secara nama**, dasar hukum, masa retensi, transfer lintas yurisdiksi, dan hak-hak subjek data.
- Pastikan keduanya **konsisten satu sama lain** — studi menunjukkan ketidaksesuaian antara privacy policy dan Data safety declaration terjadi pada ~53% game dan ~61% aplikasi generik, dan ini sendiri merupakan temuan.
- Jangan gunakan bahasa yang kabur ("kami dapat mengumpulkan informasi tertentu"). MASWE-0073 mencantumkan *"Vague or unclear language about data collection scope"* sebagai salah satu mode introduksi kelemahan ini.
- **Perbarui setiap kali perilaku berubah** — termasuk saat SDK di-update. Penambahan SDK baru hampir selalu mengubah profil pengumpulan data.

**Prioritas 6 — Perkuat perlindungan teknis (pelengkap, bukan pengganti deklarasi).**

- TLS 1.2+ untuk semua koneksi; `cleartextTrafficPermitted="false"`.
- Certificate pinning untuk endpoint yang menangani PII.
- Enkripsi payload di lapisan aplikasi untuk data paling sensitif (kesehatan, finansial) sebagai pertahanan berlapis.
- Pseudonimisasi/tokenisasi PII sebelum dikirim ke pihak ketiga bila memungkinkan.
- Jangan pernah catat PII di log server yang berasal dari URL (konsekuensi Prioritas 2).

> Perlu ditegaskan: langkah-langkah ini **tidak membuat test ini PASS**. Test ini menilai transparansi, bukan proteksi — data yang terlindungi sempurna tetapi tidak dideklarasikan masih FAIL.

**Prioritas 7 — Tegakkan secara berkelanjutan.**

- Jadikan test ini bagian dari **regression test**: jalankan mitmproxy + script PII pada emulator di pipeline bersama UI test, dan gagalkan build bila muncul **host tujuan baru** atau **PII baru** di luar allowlist. Ini mencegah regresi saat SDK di-update — penyebab paling umum deklarasi menjadi kedaluwarsa.
- Pelihara **inventaris data (data map)** sebagai artefak hidup: tipe data → tujuan → penerima → dasar hukum → retensi.
- Lakukan **review privasi** setiap kali menambah SDK atau fitur baru.
- Lengkapi dengan **MASTG-TEST-0318** di CI (statis, cepat, tanpa device) untuk mendeteksi penambahan API SDK yang menangani data sensitif.

### 4.2 Checklist Remediasi

- [ ] Inventaris lengkap tipe data yang dikirim + host tujuan sudah dibuat dan ditinjau
- [ ] Setiap tipe data dipetakan ke terminologi Google Play Data safety section
- [ ] Setiap host tujuan dipetakan ke SDK/vendor dan diverifikasi keperluannya
- [ ] Tabel perbandingan (trafik vs Data safety vs privacy policy) lengkap tanpa gap
- [ ] Data yang tidak dibutuhkan fitur sudah **dihapus** dari payload (minimisasi)
- [ ] Precise location diganti approximate bila fiturnya tidak menuntut presisi
- [ ] PII dikirim sebagai turunan/agregat bila memungkinkan (rentang usia, kota)
- [ ] Tidak ada PII di URL, query string, maupun header
- [ ] Tidak ada PII (termasuk kategori khusus) dikirim ke SDK analytics/ads sebagai event parameter atau user property
- [ ] `setUserId` memakai identifier pseudonim, bukan email/telepon/NIK
- [ ] Pengumpulan otomatis SDK dimatikan secara default (`firebase_analytics_collection_enabled=false`, dst.)
- [ ] **Tidak ada data apa pun dikumpulkan sebelum consent** — diverifikasi ulang dengan test ini
- [ ] Consent bersifat granular per tujuan, dan **penarikan consent benar-benar menghentikan pengumpulan** (diverifikasi)
- [ ] Limit Ad Tracking / Advertising ID reset dihormati
- [ ] PII dihapus dari crash log dan payload diagnostik
- [ ] Google Play **Data safety section** diperbarui: collected/shared/tujuan/enkripsi transit/required-optional akurat untuk setiap tipe data
- [ ] **Privacy policy** diperbarui: tipe data, tujuan, **penerima pihak ketiga disebut namanya**, dasar hukum, retensi, transfer lintas yurisdiksi, hak subjek data
- [ ] Privacy policy dan Data safety section **konsisten satu sama lain**
- [ ] Bahasa deklarasi spesifik, tidak kabur
- [ ] Kategori data khusus (kesehatan, biometrik, agama, orientasi seksual, data anak) punya dasar hukum & perlindungan tambahan
- [ ] TLS 1.2+ untuk semua koneksi; `cleartextTrafficPermitted="false"`; pinning untuk endpoint PII
- [ ] Proses review privasi wajib untuk setiap penambahan SDK/fitur
- [ ] Inventaris data (data map) dipelihara sebagai artefak hidup
- [ ] Test ini terintegrasi di CI/CD dengan allowlist host & tipe data
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0206 → tidak ada PII tak terdeklarasi, tidak ada host baru
- [ ] **Verifikasi silang:** jalankan MASTG-TEST-0318 (statis) dan MASTG-TEST-0319 (hooks) untuk menemukan lokasi kode dan menutup titik buta (pinning / enkripsi lapisan aplikasi)

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0206: Undeclared PII in Network Traffic Capture](https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/MASTG-TEST-0206/)
- [MASTG-TEST-0318: References to SDK APIs Known to Handle Sensitive User Data](https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/MASTG-TEST-0318/)
- [MASTG-TEST-0319: Runtime Use of SDK APIs Known to Handle Sensitive User Data](https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/MASTG-TEST-0319/)
- [MASWE-0073: Inadequate Data Collection Declarations](https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-0073/)
- [MASTG-DEMO-0009: Detecting Undeclared PII in Network Traffic](https://mas.owasp.org/MASTG/demos/android/MASVS-PRIVACY/MASTG-DEMO-0009/MASTG-DEMO-0009/)
- [MASTG-DEMO-0081: Sensitive User Data Sent to Firebase Analytics with Frida](https://mas.owasp.org/MASTG/demos/android/MASVS-PRIVACY/MASTG-DEMO-0081/MASTG-DEMO-0081/)
- [MASTG-TECH-0100: Logging Sensitive Data from Network Traffic](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0100/)
- [MASTG-TECH-0005: Installing Apps](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0005/)
- [MASTG-TECH-0014: Static Analysis on Android](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/)
- [MASTG-TECH-0043: Method Hooking](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/)
- [MASTG-TOOL-0097: mitmproxy](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0097/)
- [MASTG-TOOL-0077: Burp Suite](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0077/)
- [MASTG-TOOL-0079: ZAP (Zed Attack Proxy)](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0079/)
- [MASTG-TOOL-0081: Wireshark](https://mas.owasp.org/MASTG/tools/network/MASTG-TOOL-0081/)
- [MASTG-TOOL-0001: Frida](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0001/)
- [MASTG-TOOL-0038: Objection](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0038/)
- [MASVS-PRIVACY: Privacy](https://mas.owasp.org/MASVS/07-MASVS-PRIVACY/)
- [OWASP MASTG — Identifying Sensitive Data](https://mas.owasp.org/MASTG/0x04b-Mobile-App-Security-Testing/#identifying-sensitive-data)
- [OWASP MASTG Repository (GitHub)](https://github.com/OWASP/mastg)
- [OWASP Mobile Top 10 2024 — M6: Inadequate Privacy Controls](https://owasp.org/www-project-mobile-top-10/2023-risks/m6-inadequate-privacy-controls.html)
- [OWASP Mobile Top 10 2024 — M5: Insecure Communication](https://owasp.org/www-project-mobile-top-10/2023-risks/m5-insecure-communication.html)

### 5.2 Kebijakan Platform & Deklarasi Privasi

- [Provide information for Google Play's Data safety section — Play Console Help](https://support.google.com/googleplay/android-developer/answer/10787469?hl=en)
- [Google Play Data safety — daftar tipe data](https://support.google.com/googleplay/android-developer/answer/10787469?hl=en#types)
- [Google Play — User Data policy](https://support.google.com/googleplay/android-developer/answer/10144311)
- [Google Play — Permissions and APIs that Access Sensitive Information](https://support.google.com/googleplay/android-developer/answer/9888170)
- [Google Play — Families policy requirements](https://support.google.com/googleplay/android-developer/answer/9893335)
- [Google Play — Advertising ID policy](https://support.google.com/googleplay/android-developer/answer/6048248)
- [Google — Consent Mode (EU user consent policy)](https://support.google.com/analytics/answer/9976101)
- [Apple — App Privacy Details (sebagai pembanding lintas platform)](https://developer.apple.com/app-store/app-privacy-details/)

### 5.3 Dokumentasi Resmi Android / Google

- [Android — Privacy best practices](https://developer.android.com/privacy-and-security/best-practices)
- [Android — Data and privacy](https://developer.android.com/privacy)
- [Android — Best practices for unique identifiers](https://developer.android.com/training/articles/user-data-ids)
- [Android — Network security configuration](https://developer.android.com/privacy-and-security/security-config)
- [Android — Security with HTTPS and SSL](https://developer.android.com/privacy-and-security/security-ssl)
- [Android — Advertising ID](https://developer.android.com/training/articles/ad-id)
- [Android — App permissions best practices](https://developer.android.com/training/permissions/usage-notes)
- [Android — Data access auditing](https://developer.android.com/guide/topics/data/audit-access)
- [Android 12+ — Privacy Dashboard](https://developer.android.com/about/versions/12/behavior-changes-12#privacy-dashboard)
- [Firebase Analytics — `setUserId`, `setUserProperty`, `logEvent`](https://firebase.google.com/docs/reference/android/com/google/firebase/analytics/FirebaseAnalytics)
- [Firebase — Configure Analytics data collection and usage](https://firebase.google.com/docs/analytics/configure-data-collection)
- [Firebase Crashlytics — Enable/disable collection](https://firebase.google.com/docs/crashlytics/customize-crash-reports)

### 5.4 Regulasi & Standar

- [GDPR Art. 5 — Principles relating to processing of personal data](https://gdpr-info.eu/art-5-gdpr/)
- [GDPR Art. 9 — Processing of special categories of personal data](https://gdpr-info.eu/art-9-gdpr/)
- [GDPR Art. 13 — Information to be provided where personal data are collected](https://gdpr-info.eu/art-13-gdpr/)
- [CCPA §1798.100 — General duties of businesses that collect personal information](https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?sectionNum=1798.100&lawCode=CIV)
- [UU No. 27 Tahun 2022 tentang Pelindungan Data Pribadi (UU PDP) — JDIH](https://peraturan.bpk.go.id/Details/229798/uu-no-27-tahun-2022)
- [CWE-359: Exposure of Private Personal Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/359.html)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [CWE-201: Insertion of Sensitive Information Into Sent Data](https://cwe.mitre.org/data/definitions/201.html)
- [CWE-497: Exposure of Sensitive System Information to an Unauthorized Control Sphere](https://cwe.mitre.org/data/definitions/497.html)
- [NIST Privacy Framework](https://www.nist.gov/privacy-framework)
- [NIST SP 800-122 — Guide to Protecting the Confidentiality of PII](https://csrc.nist.gov/publications/detail/sp/800-122/final)
- [ISO/IEC 27701 — Privacy Information Management](https://www.iso.org/standard/71670.html)
- [OWASP Privacy Risks (Top 10)](https://owasp.org/www-project-top-10-privacy-risks/)

### 5.5 Riset Keamanan & Artikel Teknis

- [Zenodo — Studi ketidaksesuaian privacy policy vs data safety declaration](https://zenodo.org/records/7088557)
- [AuditBuffet — Google Data Safety form accuracy (pattern catalog)](https://auditbuffet.com/patterns/ab-000465)
- [NasrTech — Google Play Data Safety Section Explained](https://www.nasrtech.dev/blog/google-play-data-safety-explained/)
- [Respectlytics — Google Play Data Safety Section: Step-by-Step Guide](https://respectlytics.com/blog/google-play-data-safety-guide/)
- [Approov — Bypassing Certificate Pinning: Techniques and MitM Attack Prevention](https://approov.io/blog/bypassing-certificate-pinning)
- [Approov — Certificate Pinning Bypassing: Setup with Frida, mitmproxy and Android Emulator (gist)](https://gist.github.com/approovm/e550374428065ff1ecafca6a0488d384)
- [Oguzhan Oztaskin — SSL Pinning Bypass: Network Security Config](https://oguzhanstech.com/2025/08/25/ssl-pinning-bypass-network-security-config.html)
- [v0x.nl — Bypassing SSL certificate pinning on Android for MITM attacks](https://v0x.nl/articles/bypass-ssl-pinning-android/)
- [UPM SSE — Bypassing certificate pinning in Android applications](https://blogs.upm.es/sse/2020/08/03/bypassing-certificate-pinning-in-android-applications)
- [arXiv — Dissecting contact tracing apps in the Android platform](https://arxiv.org/pdf/2008.00214)
- [HackTricks — Android Applications Pentesting](https://book.hacktricks.wiki/en/mobile-pentesting/android-app-pentesting/index.html)

### 5.6 Dokumentasi Tools

- [mitmproxy — Documentation](https://docs.mitmproxy.org/stable/)
- [mitmproxy — Addons & scripting API](https://docs.mitmproxy.org/stable/addons-overview/)
- [mitmproxy — Android setup (certificate installation)](https://docs.mitmproxy.org/stable/howto-install-system-trusted-ca-android/)
- [Burp Suite — Mobile testing (Android) documentation](https://portswigger.net/burp/documentation/desktop/mobile/config-android-device)
- [ZAP — Documentation](https://www.zaproxy.org/docs/)
- [Wireshark — User's Guide](https://www.wireshark.org/docs/wsug_html_chunked/)
- [tshark — man page](https://www.wireshark.org/docs/man-pages/tshark.html)
- [Frida — Documentation Home](https://frida.re/docs/home/)
- [Objection — runtime mobile exploration](https://github.com/sensepost/objection)
- [Frida CodeShare — Universal Android SSL Pinning Bypass](https://codeshare.frida.re/@pcipolloni/universal-android-ssl-pinning-bypass-with-frida/)
- [apktool — Reverse engineering Android APK files](https://apktool.org/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026), kebijakan Google Play, dokumentasi resmi Android dan mitmproxy, regulasi GDPR/CCPA/UU PDP, serta riset keamanan dan privasi pihak ketiga.*
