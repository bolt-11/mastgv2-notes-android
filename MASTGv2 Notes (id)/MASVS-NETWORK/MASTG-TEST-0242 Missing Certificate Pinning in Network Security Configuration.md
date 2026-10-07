# MASTG-TEST-0242 Missing Certificate Pinning in Network Security Configuration

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0242 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-NETWORK (MASVS-NETWORK-2: Aplikasi memverifikasi identitas endpoint server) |
| **Weakness** | MASWE-0028 — *Insecure Identity Pinning* |
| **Tipe Pengujian** | Static, Code |
| **Profile** | **L2 saja** (bukan L1 — pinning adalah *hardening practice* tambahan, bukan baseline keamanan dasar) |
| **Knowledge** | MASTG-KNOW-0014 (Android Network Security Configuration), MASTG-KNOW-0015 (Certificate Pinning) |
| **Prasyarat** | `identify-first-party-domains` — **wajib** dipenuhi sebelum test ini dapat dijalankan secara valid (lihat §1.3) |
| **Teknik terkait** | MASTG-TECH-0013 (Reverse Engineering), MASTG-TECH-0117 (Obtaining AndroidManifest), MASTG-TECH-0150 (Analyzing AndroidManifest), MASTG-TECH-0151 (Analyzing NSC), MASTG-TECH-0022 (Information Gathering - Network Communication), MASTG-TECH-0023 (Reviewing Decompiled Java Code) |
| **Test terkait** | **MASTG-TEST-0244** (Missing Certificate Pinning in Network Traffic — counterpart dinamis, **implementation-agnostic**, tidak terbatas pada NSC saja) |
| **Demo terkait** | — (tidak ada) |
| **Rule resmi** | — (tidak ada rule semgrep resmi MASTG; CodeQL memiliki query publik siap pakai — lihat §3.4) |
| **CWE terkait** | CWE-295 (Improper Certificate Validation) |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Kutipan overview resmi MASTG:

> *"Apps can configure certificate pinning using the Network Security Configuration (NSC)... This test checks whether the app configures certificate pinning in the NSC for the relevant first-party domains it connects to."*

Test ini murni menyasar **satu mekanisme spesifik** dari sekian banyak cara mengimplementasikan certificate pinning di Android: deklarasi `<pin-set>` di dalam file Network Security Configuration. Ini penting dipahami sejak awal — test ini **bukan** pemeriksaan menyeluruh "apakah aplikasi memakai pinning dengan cara apa pun", melainkan spesifik "apakah pinning dikonfigurasi lewat NSC untuk domain yang relevan".

### 1.2 Mekanisme Certificate Pinning via NSC

Sesuai MASTG-KNOW-0015, ketika NSC mendeklarasikan `<pin-set>` untuk suatu domain, sistem akan melakukan proses berikut setiap kali mencoba membangun koneksi:

1. Mengambil dan memvalidasi rantai sertifikat yang masuk.
2. Mengekstrak public key dari sertifikat.
3. Menghitung digest (SHA-256) atas public key yang diekstrak.
4. Membandingkan digest tersebut dengan himpunan pin lokal yang dideklarasikan.

Koneksi hanya dianggap valid bila **minimal satu** pin yang dideklarasikan cocok dengan digest yang dihitung — inilah yang membuat pinning jauh lebih ketat dibanding validasi TLS standar (yang hanya memastikan sertifikat diterbitkan oleh CA tepercaya manapun, tanpa peduli CA spesifik mana).

```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <domain-config>
        <domain includeSubdomains="true">owasp.org</domain>
        <pin-set expiration="2028-12-31">
            <pin digest="SHA-256">YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=</pin>
            <pin digest="SHA-256">Vjs8r4z+80wjNcr1YKepWQboSIRi63WsWXhIMN+eWys=</pin>
        </pin-set>
    </domain-config>
</network-security-config>
```

**Cakupan penting yang perlu dipahami**: NSC hanya berlaku untuk **koneksi yang dikelola framework Android** — `HttpsURLConnection` dan library yang dibangun di atasnya, serta `WebView` (kecuali memakai `TrustManager` kustom). **Untuk komunikasi dari kode native, NSC tidak berlaku** dan mekanisme lain harus dipertimbangkan (lihat §1.5).

### 1.3 Prasyarat Krusial: Identifikasi Domain First-Party — Bukan Sekadar "Domain yang Muncul di Traffic"

Ini bagian paling penting dan paling mudah disalahartikan dari seluruh test ini. Overview resmi menegaskan:

> *"Relevant domains are remote endpoints under the developer's control that support the app's core or security-sensitive functionality. Third-party domains outside the developer's control should not be reported as missing pins only because they appear in app traffic."*

Dokumen prasyarat resmi (`identify-first-party-domains`) memberi kriteria konkret:

**Domain first-party** (relevan untuk dievaluasi pinning-nya):
- Endpoint autentikasi/identitas (login, penerbitan token, manajemen sesi)
- API akun dan konten pengguna (baca/tulis data pengguna)
- API backend spesifik aplikasi yang menyediakan fungsi inti

**Domain third-party** (di luar cakupan test ini, **jangan dilaporkan** hanya karena tidak di-pin):
- Analitik, crash-reporting, iklan, SDK media sosial

Alasan pembedaan ini sangat praktis: **domain third-party dikelola pihak eksternal** yang sertifikat/kuncinya bisa dirotasi kapan saja tanpa pemberitahuan ke developer aplikasi — memaksakan pinning pada domain semacam ini justru **berisiko mematahkan konektivitas** aplikasi ketika provider melakukan rotasi sertifikat rutin, tanpa memberi manfaat keamanan yang signifikan (karena data yang dipertukarkan dengan SDK pihak ketiga umumnya bukan data paling sensitif milik aplikasi itu sendiri).

**Konsekuensi metodologis**: dokumen prasyarat secara eksplisit mengakui bahwa informasi ini **umumnya tidak dapat diturunkan hanya dari binary aplikasi**:

> *"This information is generally not derivable from the app binary alone. Compile a list of first-party domains and services the app is expected to contact, ideally in cooperation with the development team or from architecture and infrastructure documentation. When such information is unavailable, infer likely first-party domains from the app's branding, bundle identifier, and observed traffic, and document the assumptions made."*

Ini menempatkan test ini dalam kategori pengujian yang **secara struktural membutuhkan konteks eksternal** (kerja sama dengan tim developer, dokumentasi arsitektur) — sebuah penguji blackbox murni tanpa akses tersebut harus **secara eksplisit mendokumentasikan asumsi** yang dipakai untuk menentukan domain mana yang dianggap first-party, dan tidak boleh menyimpulkan FAIL/PASS tanpa kualifikasi ini.

### 1.4 Nuansa Penting: "Tidak Ditemukan di NSC" ≠ "Tidak Ada Pinning Sama Sekali"

Overview resmi memberi catatan yang sangat spesifik dan sering terlewat:

> *"Note that the app may implement certificate pinning through other mechanisms covered in other tests."*

Dan pada bagian Evaluation:

> *"If another certificate pinning implementation is identified for the same domains, such as a custom `TrustManager` or a third-party library, the result should be treated as **not covered by NSC pinning** rather than as a **confirmed absence** of certificate pinning."*

Ini nuansa evaluasi yang halus namun krusial. Sesuai MASTG-KNOW-0015, ada **empat mekanisme pinning berbeda** yang mungkin dipakai aplikasi:

| Mekanisme | Dicakup MASTG-TEST-0242? |
|---|---|
| **Network Security Configuration** (`<pin-set>`) | ✅ Ya — inilah yang diperiksa test ini |
| **Custom `TrustManager`** (`javax.net.ssl`) | ❌ Tidak — di luar cakupan; dicek test statis lain (kode Java/Kotlin) |
| **Library pihak ketiga** (mis. OkHttp `CertificatePinner`) | ❌ Tidak — sama, cakupannya kode, bukan NSC |
| **Kode native** (C/C++/Rust) | ❌ Tidak — NSC tidak berlaku sama sekali untuk native code |

Artinya, sebuah aplikasi bisa **"gagal" MASTG-TEST-0242** (tidak ada `<pin-set>` di NSC) namun tetap memiliki pinning yang solid lewat `OkHttp.CertificatePinner` yang dikonfigurasi di kode Kotlin. Kesimpulan yang tepat untuk kasus ini **bukan** "FAIL — tidak ada pinning", melainkan **"tidak tercakup mekanisme NSC — periksa mekanisme lain sebelum menyimpulkan"**. Ini konsisten dengan mengapa test **dinamis** MASTG-TEST-0244 dirancang *implementation-agnostic* — untuk menjawab pertanyaan sesungguhnya ("apakah pinning benar-benar diberlakukan, apa pun mekanismenya?") secara definitif.

### 1.5 Cakupan per Konteks Teknologi (dari MASTG-KNOW-0015)

Untuk memandu triase, berikut ringkasan bagaimana NSC berinteraksi dengan berbagai konteks teknologi dalam aplikasi:

| Konteks | Apakah NSC berlaku? |
|---|---|
| `HttpsURLConnection` dan library di atasnya | ✅ Ya |
| `WebView` (tanpa `TrustManager` kustom) | ✅ Ya — NSC otomatis diterapkan ke traffic WebView dalam aplikasi yang sama |
| Kode native (JNI, C/C++/Rust) | ❌ Tidak — mekanisme terpisah diperlukan |
| **Cross-platform framework** (Flutter, React Native, Cordova) | **Bervariasi** — Flutter memakai `dart:io HttpClient` dengan BoringSSL sendiri (lihat pembahasan mendalam soal ini di dokumen MASTG-TEST-0237), sehingga NSC **tidak selalu berlaku**; Cordova beroperasi lewat JavaScript di WebView sehingga umumnya tunduk NSC |

### 1.6 Sifat Pinning sebagai *Hardening*, Bukan Kontrol Absolut

MASTG-KNOW-0015 secara jujur mengakui keterbatasan pinning:

> *"Certificate pinning is a hardening practice, but it is not foolproof."*

Penyerang dengan akses ke APK dapat **memodifikasi logika validasi sertifikat di `TrustManager`**, **mengganti sertifikat yang di-pin** di `res/raw/`/`assets/`, atau **menghapus pin** di NSC — namun ini **membatalkan tanda tangan APK**, memaksa penyerang untuk **repackage dan menandatangani ulang** APK tersebut. Inilah mengapa MASTG-KNOW-0015 merujuk perlunya **integrity checks, runtime verification, dan obfuscation tambahan** (MASTG-TECH-0012) sebagai pelengkap pinning — bukan pinning itu sendiri sebagai satu-satunya lapisan pertahanan.

### 1.7 Kasus Nyata: Kegagalan Validasi Sertifikat pada Aplikasi Finansial

Dua CVE terbaru (2025) menggambarkan dampak nyata dari kelemahan terkait area ini:

- **CVE-2025-56146** (aplikasi perbankan IndSMART, India): kombinasi WebView yang tidak aman (JavaScript diaktifkan, memuat URL langsung dari Intent tanpa validasi memadai) dan **tidak ada penanganan error TLS/SSL** — memungkinkan penyerang MITM di jaringan yang sama mengintersepsi alur login, OTP, dan pembayaran UPI.
- **CVE-2025-63432** (Xtool AnyScan, aplikasi diagnostik kendaraan): aplikasi **gagal memvalidasi sertifikat TLS** dari server update-nya, memungkinkan MITM untuk mengintersepsi, mendekripsi, dan memodifikasi traffic pembaruan aplikasi.

Meski kedua kasus ini lebih tepat digolongkan sebagai kegagalan validasi sertifikat dasar (bukan spesifik "tidak ada pinning"), keduanya menggambarkan **konsekuensi nyata** dari kategori risiko yang lebih luas (MASWE-0028/CWE-295) yang coba dicegah pinning sebagai lapisan pertahanan tambahan — terutama untuk endpoint yang menangani data finansial/kredensial seperti dicontohkan pada kedua kasus ini.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **jadx / apktool** | Ekstraksi AndroidManifest.xml dan NSC (sama seperti MASTG-TEST-0235) |
| **grep / xmlstarlet / yq** | Pencarian dan parsing elemen `<pin-set>`, `<domain>` di NSC |
| **jadx (full decompile)** | Mencari referensi domain hardcoded di kode untuk identifikasi first-party (MASTG-TECH-0022) |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **CodeQL** (`java-android-missing-certificate-pinning` — query publik) | Query siap pakai dari GitHub Security Lab yang mendeteksi koneksi jaringan **tanpa pinning apa pun** (mencakup NSC, `CertificatePinner`, dan `TrustManager` kustom sekaligus) — cakupan lebih luas dari MASTG-TEST-0242 murni, berguna sebagai cross-check menyeluruh |
| **apkleaks / MASTG-TOOL untuk ekstraksi string** | Mengumpulkan seluruh domain yang direferensikan di APK sebagai kandidat first-party (MASTG-TECH-0022) |
| **MobSF** | Menampilkan daftar domain yang ditemukan di APK beserta indikasi ada/tidaknya NSC dan pinning |
| **Frida** | Hooking `CertificatePinner`/`X509TrustManager`/`HostnameVerifier` untuk konfirmasi dinamis pinning yang benar-benar aktif (melengkapi MASTG-TEST-0244) |
| **mitmproxy / Burp Suite dengan CA yang tidak dipercaya sistem** | Uji dinamis definitif — bila MITM dengan CA yang **tidak** ada di trust anchor pinning berhasil, pinning tidak diberlakukan (ini metodologi inti MASTG-TEST-0244) |
| **testssl.sh** | Sebagai pelengkap untuk memeriksa validitas/karakteristik sertifikat server first-party dari sisi eksternal |

### 2.3 Prasyarat Lingkungan

- **Analisis statis NSC tidak butuh device/root** — cukup APK.
- **Kerja sama dengan tim developer/dokumentasi arsitektur sangat dianjurkan** sebelum menyimpulkan hasil final, sesuai §1.3 — tanpa ini, penguji harus eksplisit mendokumentasikan asumsi first-party domain yang dipakai.
- **Uji dinamis (Frida/mitmproxy) membutuhkan device** untuk konfirmasi lapisan pinning non-NSC (§1.4) sebelum menyimpulkan FAIL final.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0013** untuk reverse engineer aplikasi.
2. Gunakan **MASTG-TECH-0117** untuk memperoleh `AndroidManifest.xml`.
3. Gunakan **MASTG-TECH-0150** untuk memeriksa apakah `networkSecurityConfig` diset di tag `<application>`.
4. Gunakan **MASTG-TECH-0151** untuk mengekstrak seluruh domain dari `<domain-config>` yang memiliki `<pin-set>`.
5. Gunakan **MASTG-TECH-0022** untuk mengidentifikasi domain first-party yang dihubungi aplikasi.

### 3.2 Metode A — Ekstraksi NSC + Korelasi dengan Domain First-Party *(metode resmi utama)*

```bash
jadx --no-src -d ./out target-app.apk
MANIFEST=./out/resources/AndroidManifest.xml

# 1. Cek apakah NSC diset
grep -i "networkSecurityConfig" "$MANIFEST"

# 2. Ekstrak seluruh domain yang memiliki pin-set
NSC_FILE=$(grep -oP 'networkSecurityConfig="@xml/\K[^"]+' "$MANIFEST")
yq -p=xml -o=json './out/resources/res/xml/'"${NSC_FILE}"'.xml' | jq '.["network-security-config"]["domain-config"]'

# 3. Kumpulkan SELURUH domain yang direferensikan di kode (kandidat first-party)
jadx -d ./decompiled target-app.apk
rg -ohI '([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}' ./decompiled/sources/ | sort -u > all_domains_found.txt

# 4. Bandingkan domain berpin vs domain yang ditemukan di kode
diff <(sort all_domains_found.txt) <(yq -p=xml -o=json "./out/resources/res/xml/${NSC_FILE}.xml" | jq -r '.. | .domain? // empty' | sort)
```

**Langkah krusial berikutnya (bukan otomatis)**: dari daftar domain di `all_domains_found.txt`, **klasifikasikan manual** mana yang first-party (autentikasi, API akun, backend inti) vs third-party (analytics, iklan, SDK) sesuai kriteria §1.3 — jangan menyamaratakan semua domain yang muncul di kode sebagai kandidat "wajib di-pin".

### 3.3 Metode B — Kontekstualisasi via MASTG-TECH-0022 (Klasifikasi Domain dengan Konteks Kode)

```bash
# Cari domain BESERTA konteks pemanggilannya — kelas/method yang mereferensikannya
rg -n -B5 '([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}' ./decompiled/sources/ | grep -B5 "login\|auth\|token\|account\|payment"
```

Domain yang muncul di konteks kelas/fungsi bernama `AuthManager`, `LoginActivity`, `PaymentService`, dsb. adalah kandidat kuat first-party — sementara domain yang muncul di kelas/paket vendor pihak ketiga yang dikenal (`com.google.firebase.analytics`, `com.facebook.ads`) adalah kandidat kuat third-party.

### 3.4 Metode C — CodeQL Query Publik (Cakupan Lebih Luas dari NSC Saja)

```bash
codeql database create ./cqldb --language=java --command="./gradlew assembleRelease"
codeql database analyze ./cqldb java/android-missing-certificate-pinning --format=sarif-latest --output=result.sarif
```

Query publik ini (dari CodeQL Query Help, CWE-295) mendeteksi koneksi jaringan yang **tidak menerapkan pinning dengan cara apa pun** — baik lewat NSC, `OkHttp CertificatePinner`, maupun `TrustManager` kustom — sehingga hasilnya berguna sebagai **pembanding cakupan penuh** terhadap hasil Metode A yang murni menyasar NSC. Bila CodeQL menemukan koneksi tanpa pinning yang **tidak** tertangkap sebagai "missing" oleh Metode A, ini indikasi domain tersebut mungkin memakai mekanisme non-NSC yang justru **berhasil menerapkan** pinning (kasus PASS lewat mekanisme lain, §1.4) — atau sebaliknya, benar-benar tanpa pinning sama sekali lewat jalur mana pun.

### 3.5 Metode D — Pemeriksaan Mekanisme Non-NSC (Melengkapi, Bukan Menggantikan)

Karena hasil "tidak ada di NSC" tidak serta-merta berarti FAIL absolut (§1.4), periksa juga keberadaan mekanisme lain sebelum menyimpulkan:

```bash
# Custom TrustManager
rg -n 'class \w+ implements X509TrustManager|extends X509TrustManager' ./decompiled/sources/

# OkHttp CertificatePinner
rg -n 'CertificatePinner\.Builder\(\)|new CertificatePinner' ./decompiled/sources/

# Native code — cek keberadaan library native yang mungkin menangani TLS sendiri
find . -name "*.so" | xargs -I{} sh -c 'rabin2 -zz {} | grep -i "pin\|sha256\|certificate"' 2>/dev/null
```

Bila salah satu ditemukan untuk domain first-party yang sama, ubah kesimpulan dari "FAIL — tidak ada pinning" menjadi "tidak tercakup NSC — periksa keamanan implementasi mekanisme lain tersebut" (lanjutkan analisis kualitas implementasinya, bukan berhenti di "ditemukan ada").

### 3.6 Metode E — Verifikasi Dinamis (Korelasi dengan MASTG-TEST-0244)

```bash
# Setup mitmproxy dengan CA yang TIDAK ada di pin-set aplikasi
mitmproxy --mode transparent
# Pantau logcat untuk indikasi pinning berfungsi
adb logcat | grep -i "X509Util\|Pin verification failed\|CertificatePinner"
```

Bila log sistem menampilkan `Pin verification failed` atau serupa, dan koneksi aplikasi **gagal** — pinning terbukti aktif dan berfungsi (PASS definitif untuk domain tersebut, apa pun mekanismenya). Bila koneksi **berhasil** meski CA proxy tidak sah — pinning tidak diberlakukan untuk domain tersebut (FAIL, melengkapi hasil statis).

### 3.7 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Cakupan | Menjawab first-party classification? | Kapan dipakai |
|---|---|---|---|
| **A** | NSC murni | ❌ (perlu klasifikasi manual terpisah) | Baseline resmi wajib |
| **B** | Kontekstualisasi kode | ✅ (membantu klasifikasi) | Pelengkap wajib untuk Metode A |
| **C** | Seluruh mekanisme (CodeQL) | ❌ | Cross-check cakupan menyeluruh |
| **D** | Mekanisme non-NSC spesifik | ❌ | Sebelum menyimpulkan FAIL final (§1.4) |
| **E** | Runtime, implementation-agnostic | ❌ | **Konfirmasi akhir wajib** — jawaban paling definitif |

**Kombinasi minimum yang aku rekomendasikan:** **A+B (baseline + klasifikasi first-party) → D (cek mekanisme lain sebelum simpulkan FAIL) → E (konfirmasi dinamis final, idealnya via MASTG-TEST-0244)**. Jangan pernah melaporkan FAIL murni dari hasil Metode A saja tanpa langkah D dan E, sesuai peringatan eksplisit overview resmi soal risiko kesimpulan prematur (§1.4).

---

### 3.8 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Observation:** *"The output should contain a list of domains that enable certificate pinning. The output should also identify any relevant first-party domains that were found in the app but do not have a pin set."*
>
> **Evaluation:** *"The test case fails if the app connects to relevant first-party domains but no `networkSecurityConfig` is set, or if `networkSecurityConfig` is set but does not enable certificate pinning for those domains. The test case should not fail only because unrelated third-party domains are not pinned."*

Dengan klausul **Further Validation Required** resmi:

> *"Before reporting a missing pin, confirm that the app actually establishes connections to the relevant first-party domains"* — baik lewat penelusuran statis (MASTG-TECH-0023) maupun capture/hooking dinamis.

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi | Sesuai klausul resmi |
|---|---|---|
| F1 | Aplikasi terkonfirmasi terhubung ke domain first-party yang relevan, **tapi tidak ada** `networkSecurityConfig` sama sekali | Klausul utama |
| F2 | `networkSecurityConfig` ada, **tapi tidak ada** `<pin-set>` untuk domain first-party tersebut | Klausul utama |
| F3 | `<pin-set>` ada untuk domain first-party, **dan** dikonfirmasi tidak ada mekanisme pinning lain (custom TrustManager/library/native) yang menutupinya (Metode D) | Klausul utama + "Further Validation" |
| F4 | Verifikasi dinamis (Metode E/MASTG-TEST-0244) mengonfirmasi MITM **berhasil** menembus koneksi ke domain first-party tersebut | Bukti definitif |

**Contoh bukti (ilustratif — MASTG belum menyediakan demo resmi untuk test ini):**

```xml
<!-- res/xml/network_security_config.xml -->
<network-security-config>
    <domain-config>
        <domain includeSubdomains="true">cdn.example.com</domain>  <!-- CDN aset statis, third-party-ish -->
        <pin-set><pin digest="SHA-256">...</pin></pin-set>
    </domain-config>
    <!-- TIDAK ADA domain-config untuk api-auth.example.com -->
</network-security-config>
```

```bash
$ rg -n 'api-auth\.example\.com' ./decompiled/sources/com/example/target/auth/AuthManager.java
com/example/target/auth/AuthManager.java:22:    private static final String AUTH_ENDPOINT = "https://api-auth.example.com/v2/token";
```

Interpretasi: `api-auth.example.com` — endpoint autentikasi yang jelas first-party dan security-sensitive — **tidak memiliki pin-set** di NSC, sementara `cdn.example.com` (kandidat third-party/kurang sensitif) justru yang di-pin. **FAIL**, dengan catatan pinning yang ada justru salah sasaran prioritas.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Seluruh domain first-party yang terkonfirmasi dihubungi aplikasi memiliki `<pin-set>` valid di NSC |
| P2 | Domain first-party tidak memiliki `<pin-set>` di NSC, **tapi** terkonfirmasi memakai mekanisme pinning lain yang berfungsi dengan baik (custom TrustManager/OkHttp CertificatePinner, dikonfirmasi Metode D+E) |
| P3 | Domain yang tidak di-pin **terkonfirmasi murni third-party** (analytics/iklan/SDK) sesuai kriteria §1.3 — tidak dianggap temuan |
| P4 | Verifikasi dinamis (Metode E) mengonfirmasi MITM **gagal** menembus koneksi ke seluruh domain first-party |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Klasifikasi first-party vs third-party adalah langkah paling menentukan dan paling mudah disalahartikan di seluruh test ini.** Jangan pernah melaporkan domain sebagai "missing pin" hanya karena ia muncul di traffic/kode — lakukan klasifikasi eksplisit sesuai kriteria §1.3, dan **dokumentasikan asumsi** bila informasi otoritatif dari tim developer tidak tersedia.

2. **"Tidak ada di NSC" harus diverifikasi lebih lanjut sebelum disimpulkan FAIL** — sesuai §1.4, mekanisme pinning lain (custom TrustManager, OkHttp `CertificatePinner`, native code) bisa saja menutupi domain yang sama. Laporan yang menyimpulkan FAIL murni dari ketiadaan `<pin-set>` tanpa memeriksa mekanisme lain **tidak memenuhi standar evaluasi resmi test ini**.

3. **Klausul "Further Validation Required" bersifat wajib**, bukan opsional — konfirmasi bahwa aplikasi benar-benar terhubung ke domain first-party yang diduga (lewat MASTG-TECH-0023 statis atau capture/hooking dinamis) sebelum melaporkan pin yang hilang.

4. **Test ini hanya profile L2** — bukan berarti tidak penting, tapi mencerminkan bahwa pinning adalah *hardening* tambahan di atas baseline TLS yang sudah benar (MASTG-TEST-0217/0218/0234/0235), relevan terutama untuk aplikasi dengan kebutuhan keamanan lebih tinggi (finansial, kesehatan, data sangat sensitif).

5. **Jangan menuntut pinning pada domain third-party** — ini eksplisit dilarang oleh evaluasi resmi ("should not fail only because unrelated third-party domains are not pinned") dan juga praktik yang tidak realistis secara operasional (risiko downtime akibat rotasi sertifikat provider eksternal).

6. **Cross-platform framework butuh perhatian khusus** (§1.5) — untuk aplikasi Flutter, ketiadaan `<pin-set>` di NSC mungkin sepenuhnya tidak relevan bila traffic Dart tidak tunduk NSC sama sekali (lihat pembahasan mendalam soal ini di dokumen MASTG-TEST-0237) — pinning untuk Flutter kemungkinan perlu diimplementasikan di level `dio`/`http` package langsung.

7. **Severity dimodulasi oleh sensitivitas fungsi domain first-party yang tidak di-pin:**

   | Faktor | Severity |
   |---|---|
   | Endpoint autentikasi/pembayaran/transfer dana tidak di-pin sama sekali (tanpa mekanisme alternatif) | **Tinggi** |
   | Endpoint API akun/data pengguna umum tidak di-pin | **Menengah** |
   | Pin-set ada tapi kedaluwarsa (`expiration` terlewati) tanpa pembaruan | **Menengah-Tinggi** — berpotensi membuat pinning gagal-terbuka (*fail-open*) tergantung implementasi |
   | Domain third-party tidak di-pin | **Bukan temuan** |

8. **Dokumentasikan:** daftar lengkap domain yang ditemukan di kode, klasifikasi first-party/third-party beserta justifikasinya (termasuk sumber — dokumentasi tim/asumsi mandiri), status pin-set untuk setiap domain first-party, hasil pemeriksaan mekanisme non-NSC, dan hasil verifikasi dinamis.

---

## 4. Rekomendasi Perbaikan

### 4.1 Terapkan Pin-Set untuk Seluruh Domain First-Party

```xml
<network-security-config>
    <domain-config>
        <domain includeSubdomains="true">api-auth.example.com</domain>
        <domain includeSubdomains="true">api.example.com</domain>
        <pin-set expiration="2027-06-30">
            <pin digest="SHA-256">[digest public key sertifikat leaf/intermediate saat ini]</pin>
            <pin digest="SHA-256">[digest cadangan — mis. dari CA/intermediate lain, WAJIB ada]</pin>
        </pin-set>
    </domain-config>
</network-security-config>
```

**Selalu sertakan pin cadangan (backup pin)** — sesuai MASTG-KNOW-0015, ini krusial untuk menjaga konektivitas bila sertifikat utama berubah tak terduga (rotasi darurat, kompromi CA) tanpa memerlukan update aplikasi mendesak.

### 4.2 Kelola Siklus Hidup Pin Secara Proaktif

Tetapkan proses operasional untuk memperbarui pin **sebelum** tanggal `expiration` terlewati, dan sebelum sertifikat produksi benar-benar dirotasi — pin yang kedaluwarsa berpotensi menyebabkan gangguan layanan atau, tergantung implementasi, membuat pinning berhenti berfungsi tanpa disadari.

### 4.3 Pertimbangkan Pinning Berlapis untuk Konteks Non-NSC

Untuk komponen yang tidak tercakup NSC (kode native, cross-platform framework tertentu), implementasikan mekanisme pinning terpisah yang sesuai konteksnya — mis. OkHttp `CertificatePinner` untuk kode Kotlin/Java non-`HttpsURLConnection`, atau solusi pinning tingkat plugin untuk Flutter (`http_certificate_pinning`, `dio` interceptor kustom).

### 4.4 Lengkapi dengan Integrity Check dan Obfuscation

Sesuai MASTG-KNOW-0015, pinning saja rentan terhadap modifikasi APK (repackage). Kombinasikan dengan pemeriksaan integritas runtime (MASTG-TECH-0012) dan obfuscation untuk mempersulit upaya bypass.

### 4.5 Integrasikan ke CI/CD

```bash
#!/bin/bash
# ci-check-cert-pinning.sh
APK=$1
jadx --no-src -d /tmp/nsc_check "$APK" 2>/dev/null
NSC=$(grep -oP 'networkSecurityConfig="@xml/\K[^"]+' /tmp/nsc_check/resources/AndroidManifest.xml)
if [ -z "$NSC" ]; then
    echo "[PERINGATAN] Tidak ada networkSecurityConfig — verifikasi manual domain first-party"
else
    grep -c "pin-set" "/tmp/nsc_check/resources/res/xml/${NSC}.xml"
fi
```

### 4.6 Checklist Remediasi

- [ ] Daftar domain first-party sudah disusun berdasarkan kerja sama dengan tim developer/dokumentasi arsitektur (atau asumsi terdokumentasi bila tidak tersedia)
- [ ] Seluruh domain first-party memiliki `<pin-set>` di NSC dengan minimal satu pin cadangan
- [ ] Domain yang tidak tercakup NSC sudah diperiksa untuk mekanisme pinning alternatif (TrustManager/library/native)
- [ ] Proses pembaruan pin sebelum kedaluwarsa sudah ditetapkan sebagai bagian operasional rutin
- [ ] Verifikasi dinamis (MASTG-TEST-0244) sudah dilakukan untuk mengonfirmasi pinning benar-benar berfungsi
- [ ] Pinning dilengkapi integrity check/obfuscation untuk aplikasi dengan kebutuhan keamanan tinggi
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0242 pada APK release final setelah remediasi

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0242: Missing Certificate Pinning in Network Security Configuration](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0242/)
- [MASTG-TEST-0244: Missing Certificate Pinning in Network Traffic](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0244/)
- [MASWE-0028: Insecure Identity Pinning](https://mas.owasp.org/MASWE/MASVS-NETWORK/MASWE-0028/)
- [MASTG-KNOW-0014: Android Network Security Configuration](https://mas.owasp.org/MASTG/knowledge/android/MASVS-NETWORK/MASTG-KNOW-0014/)
- [MASTG-KNOW-0015: Certificate Pinning](https://mas.owasp.org/MASTG/knowledge/android/MASVS-NETWORK/MASTG-KNOW-0015/)
- [MASTG-TECH-0022: Information Gathering - Network Communication](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0022/)
- [MASTG Prerequisite: Identifying First-Party Domains](https://mas.owasp.org/MASTG/prerequisites/identify-first-party-domains/)
- [OWASP Mobile Top 10 2024 — M5: Insecure Communication](https://owasp.org/www-project-mobile-top-10/2023-risks/m5-insecure-communication)

### 5.2 Dokumentasi Resmi Android

- [Android Developers — Network Security Configuration (Certificate Pinning section)](https://developer.android.com/privacy-and-security/security-config#CertificatePinning)
- [Android Developers — Security with network protocols](https://developer.android.com/training/articles/security-ssl)

### 5.3 Riset dan Kasus Nyata

- [Securevale — Deep Dive into Certificate Pinning on Android](https://securevale.blog/articles/deep-dive-into-certificate-pinning-on-android/)
- [CodeQL Query Help — Android Missing Certificate Pinning](https://codeql.github.com/codeql-query-help/java/java-android-missing-certificate-pinning/)
- [CVE-2025-56146 — Missing SSL Certificate Validation in Indian Bank IndSMART Android App](https://medium.com/@parvbajaj2000/cve-2025-56146-missing-ssl-certificate-validation-in-indian-bank-indsmart-android-app-9db200ac1c69)
- [CVE-2025-63432 — Xtool AnyScan Missing SSL Certificate Validation](https://api.osv.dev/v1/vulns/CVE-2025-63432)
- [Approov — How to Protect Against Certificate Pinning Bypassing](https://approov.io/blog/how-to-protect-against-certificate-pinning-bypassing)
- [CWE-295: Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)

### 5.4 Dokumentasi Tools

- [OkHttp CertificatePinner — Documentation](https://square.github.io/okhttp/features/https/#certificate-pinning-kotlinjava)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [Frida — Dynamic instrumentation toolkit](https://frida.re/docs/javascript-api/)
- [mitmproxy](https://mitmproxy.org/)
- [testssl.sh](https://testssl.sh/)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026), dokumentasi resmi Android Developers, query CodeQL publik, serta riset dan kasus CVE nyata terkait validasi sertifikat pada aplikasi Android. Nuansa terpenting dari test ini adalah keharusan mengklasifikasikan domain first-party vs third-party sebelum melaporkan temuan, dan memastikan ketiadaan pin di NSC tidak serta-merta disimpulkan sebagai ketiadaan pinning secara absolut — mekanisme lain (custom TrustManager, library pihak ketiga, native code) harus diperiksa terlebih dahulu sesuai klausul resmi "Further Validation Required".*
