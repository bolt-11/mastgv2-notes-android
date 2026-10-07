# MASTG-TEST-0233 Hardcoded HTTP URLs

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0233 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-NETWORK (MASVS-NETWORK-1: Seluruh lalu lintas jaringan dienkripsi memakai TLS) |
| **Weakness** | MASWE-0026 — *Network Traffic Not Encrypted* |
| **Tipe Pengujian** | Static, Code |
| **Profile** | L1, L2 |
| **Teknik terkait** | MASTG-TECH-0013 (Reverse Engineering), MASTG-TECH-0019 (Retrieving Strings) |
| **Test terkait** | **MASTG-TEST-0235** (Cleartext Traffic Config — konfigurasi yang menentukan apakah HTTP benar-benar bisa jalan), **MASTG-TEST-0236** (Cleartext Traffic dalam Network Traffic Capture — bukti dinamis), **MASTG-TEST-0238** (Runtime Use of Networking APIs) |
| **Demo terkait** | — (MASTG belum menyediakan demo resmi untuk test ini) |
| **Rule resmi** | — (tidak ada rule semgrep resmi; deteksi URL literal cukup sederhana untuk grep/regex biasa) |
| **CWE terkait** | CWE-295, CWE-296, CWE-297 (terkait validasi sertifikat — relevan karena HTTP menghilangkan TLS sepenuhnya, bukan hanya validasi yang lemah) |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Kutipan overview resmi MASTG:

> *"An Android app may have hardcoded HTTP URLs embedded in the app binary, library binaries, or other resources within the APK. These URLs may indicate potential locations where the app communicates with servers over an unencrypted connection."*

Test ini murni **statis**: mencari string literal `http://` (bukan `https://`) di mana pun ia berada dalam APK — kode aplikasi, library pihak ketiga yang di-bundle, file resource (XML, JSON, config), bahkan library native (`.so`).

### 1.2 Peringatan Resmi yang Sangat Penting: Keberadaan ≠ Penggunaan

MASTG secara eksplisit menyertakan blok **Limitations** di overview resminya — ini bagian krusial yang membedakan test ini dari kebanyakan test statis lain:

> *"The presence of HTTP URLs alone does not necessarily mean they are actively used for communication. Their usage may depend on runtime conditions, such as how the URLs are invoked and whether cleartext traffic is allowed in the app's configuration. For example, HTTP requests may fail if cleartext traffic is disabled in the AndroidManifest.xml or restricted by the Network Security Configuration."*

Ini nuansa yang sangat mudah disalahpahami penguji pemula. Ada **tiga kemungkinan skenario** ketika string `http://` ditemukan dalam kode:

| Skenario | Apakah URL benar-benar dipakai untuk request? | Apakah request akan berhasil? |
|---|---|---|
| **A** | URL hanya konstanta yang tidak pernah dipakai (dead code, kode lama, komentar, placeholder dokumentasi) | Tidak relevan — tidak pernah dieksekusi |
| **B** | URL dipakai aktif untuk membuat HTTP request (`HttpURLConnection`, `OkHttp`, dsb.) | **Tergantung konfigurasi cleartext** — sejak Android 9 (API 28), cleartext HTTP **diblokir secara default** oleh Network Security Configuration (NSC) bawaan sistem |
| **C** | URL dipakai aktif, dan cleartext **diizinkan** secara eksplisit (`usesCleartextTraffic="true"` atau `cleartextTrafficPermitted="true"` di NSC) | Request akan **benar-benar berhasil** dalam plaintext — inilah kondisi FAIL sesungguhnya |

Sejak **Android 9 (API level 28)**, sistem operasi memblokir cleartext HTTP secara default melalui Network Security Configuration bawaan. Artinya, string `http://` yang ditemukan di kode pada aplikasi modern **belum tentu benar-benar bisa mengirim data** — request tersebut bisa saja gagal secara diam-diam (exception `CleartextNotPermittedException`) kecuali developer secara eksplisit mengizinkan cleartext. Inilah mengapa MASTG memisahkan test ini (menemukan **lokasi** URL) dari MASTG-TEST-0235 (memverifikasi **apakah konfigurasi mengizinkan** cleartext) sebagai dua test yang saling melengkapi dan wajib dibaca bersamaan.

### 1.3 Mengapa Tetap Penting Meski Ada Proteksi Default OS

Meski proteksi default Android 9+ mengurangi risiko, test ini tetap relevan karena:

- **Aplikasi dengan `minSdkVersion` rendah** atau yang secara eksplisit menurunkan `targetSdkVersion` mungkin tidak terlindungi proteksi ini di semua kondisi.
- **Developer sering menambahkan pengecualian domain** di Network Security Configuration untuk kebutuhan development/staging yang lupa dihapus saat rilis produksi (`<domain-config cleartextTrafficPermitted="true">` untuk domain internal).
- **Library pihak ketiga (SDK iklan, analitik, crash reporter)** yang di-bundle ke APK bisa membawa endpoint HTTP hardcoded dari kode lama yang belum dimigrasi ke HTTPS — ini di luar kendali langsung tim developer aplikasi.
- **WebView** dapat memuat URL HTTP yang tidak selalu tunduk pada NSC dengan cara yang sama seperti API networking native, tergantung versi WebView dan konfigurasi.
- **Redirect chain**: URL awal berupa `https://` bisa saja me-redirect ke `http://` di suatu titik dalam alur, dan hardcoded URL menengah/API kedua dalam chain tersebut yang justru berupa HTTP.

### 1.4 Hubungan dengan Trio Test MASVS-NETWORK

Test ini adalah bagian dari rangkaian empat test yang saling melengkapi untuk menjawab pertanyaan "apakah aplikasi mengirim data lewat cleartext":

```
TEST-0233 (statis)  ──► Temukan SEMUA lokasi string http:// di APK
        │
        ▼
TEST-0235 (statis)  ──► Periksa apakah KONFIGURASI (manifest/NSC) mengizinkan cleartext
        │                (jika TIDAK diizinkan → request http:// akan gagal di runtime)
        ▼
TEST-0238 (dinamis)  ──► Hook API networking saat runtime untuk lihat URL APA
        │                 yang benar-benar dipanggil aplikasi
        ▼
TEST-0236 (dinamis)  ──► Tangkap lalu lintas jaringan NYATA — bukti definitif
                          apakah paket HTTP plaintext benar-benar terkirim di kabel
```

Dokumen ini (**TEST-0233**) hanya menjawab **langkah pertama** — inventarisasi lokasi. Kesimpulan FAIL/PASS yang solid menuntut korelasi dengan ketiga test lainnya.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | MASTG ID | Fungsi |
|---|---|---|
| **jadx** | MASTG-TOOL-0018 | Dekompilasi DEX → Java untuk pencarian string di kode aplikasi |
| **apktool** | MASTG-TOOL-0011 | Ekstraksi resource (XML, assets) untuk pencarian string di luar kode |
| **grep / ripgrep** | — | Pencarian pola `http://` — metode utama karena tidak ada rule resmi |
| **strings (Unix)** / **rabin2** | MASTG-TOOL-0129 | Ekstraksi string dari binary native (`.so`) sesuai MASTG-TECH-0019 |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **semgrep** | Tidak ada rule resmi — rule kustom sederhana (§3.3) untuk deteksi pola URL di kode Java/Kotlin dengan konteks pemanggilan API |
| **MobSF** | Analisis otomatis, biasanya menandai kategori "Hardcoded HTTP connection" atau "Insecure connection" dalam laporan |
| **apkleaks** | Dirancang untuk ekstraksi rahasia/endpoint dari APK, termasuk URL — dapat dikombinasikan dengan filter untuk pola `http://` |
| **jadx-gui "Find Usage"** | Menelusuri secara interaktif apakah suatu konstanta URL benar-benar dipanggil oleh fungsi networking (menjawab pertanyaan §1.2 skenario A vs B) |
| **CodeQL** | Taint/reachability analysis — melacak apakah string URL literal benar-benar mengalir ke parameter fungsi seperti `HttpURLConnection`, `OkHttpClient.newCall()`, `Retrofit.Builder().baseUrl()` |
| **Frida** | Hooking runtime pada `URL.openConnection()`, `OkHttpClient`, dsb. (MASTG-TEST-0238) untuk konfirmasi eksekusi nyata |
| **Burp Suite / mitmproxy / Wireshark** | Bukti definitif di lapisan jaringan (MASTG-TEST-0236) |

### 2.3 Prasyarat Lingkungan

- **Tidak butuh device/root** untuk test statis ini — cukup file APK.
- Fase korelasi (§1.4) membutuhkan device untuk MASTG-TEST-0235/0236/0238.
- Periksa **seluruh isi APK**, bukan hanya `classes.dex` — termasuk `assets/`, `res/raw/`, file konfigurasi JSON/XML yang di-bundle, dan pustaka native `.so`.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0013** untuk reverse engineer aplikasi.
2. Gunakan **MASTG-TECH-0019** untuk mencari URL `http://`.

### 3.2 Metode A — grep/ripgrep menyeluruh pada seluruh isi APK *(metode utama)*

```bash
# Ekstrak APK sepenuhnya (bukan hanya dekompilasi kode)
mkdir -p ./apk_extracted && cd ./apk_extracted && unzip -o ../target-app.apk >/dev/null
jadx -d ../decompiled ../target-app.apk

# 1. Cari di kode hasil dekompilasi (Java/Kotlin)
rg -n 'http://[a-zA-Z0-9./_-]+' ../decompiled/sources/ | grep -v 'http://schemas\.\|http://www\.w3\.org\|http://xml\.'

# 2. Cari di resource XML (strings.xml, network_security_config.xml, dll.)
rg -n 'http://' ./res/ 2>/dev/null

# 3. Cari di assets dan file konfigurasi yang di-bundle (JSON, properties)
rg -n 'http://' ./assets/ 2>/dev/null

# 4. Cari di string DEX secara langsung (menangkap string yang mungkin luput dari dekompilasi jadx)
for dex in $(find . -name "*.dex"); do
  strings "$dex" | grep -oE 'http://[a-zA-Z0-9./?=&_-]+'
done | sort -u

# 5. Cari di library native (.so) sesuai MASTG-TECH-0019
find . -name "*.so" -exec sh -c 'echo "=== $1 ==="; rabin2 -zz "$1" | grep -oE "http://[a-zA-Z0-9./?=&_-]+"' _ {} \;
```

**Filter noise umum** — banyak `http://` yang ditemukan bukan endpoint komunikasi aplikasi, melainkan:
- Namespace XML (`http://schemas.android.com/apk/res/android`, `http://www.w3.org/...`)
- Lisensi/komentar di kode pustaka open-source (`http://www.apache.org/licenses/LICENSE-2.0`)
- Dokumentasi Javadoc yang tersisa di metadata

Selalu terapkan filter ini di awal sebelum melakukan triase manual, agar tidak membuang waktu meninjau false positive struktural.

### 3.3 Metode B — Semgrep Kustom dengan Konteks Pemanggilan API *(menjawab §1.2 skenario A vs B)*

Karena pertanyaan inti test ini bukan "apakah string `http://` ada" tapi "apakah string tersebut **dipakai untuk membuat request**", rule berikut menargetkan pola di mana literal HTTP langsung menjadi argumen API networking:

```yaml
rules:
  - id: custom-hardcoded-http-url-active-use
    languages: [java, kotlin]
    severity: WARNING
    message: "[MASVS-NETWORK-1] URL HTTP hardcoded dipakai LANGSUNG sebagai argumen API networking — kandidat kuat untuk komunikasi cleartext aktif"
    pattern-either:
      - pattern: new URL("http://...")
      - pattern: new java.net.URL("http://...")
      - pattern: $CLIENT.newCall(new Request.Builder().url("http://...").build())
      - pattern: Retrofit.Builder().baseUrl("http://...")
      - pattern: Uri.parse("http://...")

  - id: custom-hardcoded-http-url-constant
    languages: [java, kotlin]
    severity: INFO
    message: "[MASVS-NETWORK-1] Konstanta URL HTTP ditemukan — telusuri apakah benar-benar dipakai (lihat pattern active-use)"
    pattern-regex: '(public|private|internal)?\s*(static\s+)?final\s+String\s+\w+\s*=\s*"http://[^"]+"'
```

```bash
semgrep -c ./http-url-rules.yml ./decompiled/sources/ --json -o findings.json
jq '[.results[] | select(.check_id | contains("active-use"))] | length' findings.json
```

Rule `active-use` memberi sinyal prioritas jauh lebih tinggi dibanding rule `constant` — sesuai peringatan resmi §1.2, string yang hanya dideklarasikan sebagai konstanta tanpa dipakai langsung di pemanggilan API adalah kandidat lemah untuk FAIL.

### 3.4 Metode C — CodeQL (reachability: konstanta → API networking)

Untuk kasus di mana URL disimpan sebagai konstanta terpisah lalu diteruskan lewat beberapa variabel sebelum sampai ke fungsi networking (tidak tertangkap pola langsung Metode B):

```ql
import java
import semmle.code.java.dataflow.DataFlow

class HttpUrlLiteral extends DataFlow::Node {
  HttpUrlLiteral() {
    exists(StringLiteral s | s.getValue().matches("http://%") | this.asExpr() = s)
  }
}

class NetworkingApiSink extends DataFlow::Node {
  NetworkingApiSink() {
    exists(MethodAccess ma |
      ma.getMethod().hasName(["openConnection", "newCall", "baseUrl", "url"]) |
      this.asExpr() = ma.getAnArgument()
    )
    or
    exists(ClassInstanceExpr c |
      c.getConstructedType().hasQualifiedName("java.net", "URL") |
      this.asExpr() = c.getAnArgument()
    )
  }
}

from DataFlow::Node source, DataFlow::Node sink
where DataFlow::localFlow(source, sink)
select source, "URL HTTP literal ini mengalir ke API networking di " + sink.getLocation()
```

```bash
codeql database create ./cqldb --language=java --command="./gradlew assembleRelease"
codeql database analyze ./cqldb ./http-url-reachability.ql --format=sarif-latest --output=result.sarif
```

### 3.5 Metode D — MobSF

```bash
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
```

Laporan MobSF biasanya mencantumkan temuan kategori *"App can read/write to External Storage"* untuk hal tak terkait, tetapi untuk kategori jaringan carilah *"Insecure Connection"*, *"Files/Folders/URLs found"*, atau bagian **Domain Malware Check / URLs** yang mencantumkan seluruh string URL ditemukan berikut skema (`http`/`https`) masing-masing.

### 3.6 Metode E — apkleaks

```bash
apkleaks -f target-app.apk -o apkleaks-results.txt
grep "http://" apkleaks-results.txt
```

`apkleaks` dirancang untuk menemukan endpoint dan rahasia yang bocor dari APK, sehingga secara alami turut menangkap URL HTTP di antara hasil temuannya — berguna sebagai cross-check kedua terhadap hasil grep manual.

### 3.7 Metode F — Frida (konfirmasi eksekusi nyata, melengkapi MASTG-TEST-0238)

```javascript
// hook-url-connections.js
Java.perform(function () {
    var URL = Java.use("java.net.URL");
    URL.openConnection.overload().implementation = function () {
        var urlStr = this.toString();
        if (urlStr.indexOf("http://") === 0) {
            console.log("[!] Cleartext HTTP connection dibuka: " + urlStr);
        }
        return this.openConnection();
    };

    try {
        var OkHttpClient = Java.use("okhttp3.OkHttpClient");
        var Request = Java.use("okhttp3.Request");
        // Hook di level Call/Request untuk klien yang memakai OkHttp
    } catch (e) { /* OkHttp mungkin tidak dipakai / di-obfuscate */ }
});
```

```bash
frida -U -f com.target.app -l hook-url-connections.js --no-pause
```

Ini adalah cara paling langsung menjawab pertanyaan inti §1.2 — bila hook ini **tidak pernah terpicu** selama sesi pengujian menyeluruh, ini indikasi kuat (meski tidak 100% konklusif tanpa cakupan pengujian sempurna) bahwa URL HTTP yang ditemukan secara statis **tidak aktif dipakai**.

### 3.8 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Menemukan lokasi? | Membedakan konstanta vs aktif dipakai? | Kapan dipakai |
|---|---|---|---|---|
| **A** | grep/ripgrep menyeluruh | ✅ | ❌ | **Baseline wajib** — cakupan penuh seluruh isi APK |
| **B** | semgrep kustom | ✅ | ✅ (pola langsung) | Prioritisasi awal temuan mana yang layak ditelusuri lebih dulu |
| **C** | CodeQL | ✅ | ✅ (reachability lewat variabel perantara) | Codebase besar dengan banyak lapisan abstraksi networking |
| **D** | MobSF | ✅ | Sebagian | Triase cepat, laporan siap kutip |
| **E** | apkleaks | ✅ | ❌ | Cross-check kedua, terutama untuk endpoint API tersembunyi |
| **F** | Frida | Hanya yang tereksekusi | ✅ (definitif untuk yang tertangkap) | Konfirmasi runtime — jawaban pasti untuk kandidat prioritas tinggi dari B/C |

**Kombinasi minimum yang aku rekomendasikan:** **A (grep menyeluruh) → B/C (prioritisasi active-use) → MASTG-TEST-0235 (cek konfigurasi cleartext) → F/MASTG-TEST-0238 (konfirmasi runtime) → MASTG-TEST-0236 (bukti definitif di jaringan)**. Jangan berhenti di langkah A saja — sesuai peringatan resmi §1.2, kesimpulan FAIL yang solid menuntut korelasi minimal hingga MASTG-TEST-0235.

---

### 3.9 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Observation:** *"The output should contain a list of URLs and their locations within the app."*
>
> **Evaluation:** *"The test case fails if any HTTP URLs are confirmed to be used for communication."*

Kata kunci di sini adalah **"confirmed to be used"** — bukan sekadar ditemukan.

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi | Dasar konfirmasi |
|---|---|---|
| F1 | URL `http://` ditemukan **langsung sebagai argumen** API networking (`new URL("http://...")`, `Retrofit.Builder().baseUrl("http://...")`) | Metode A/B — pola pemanggilan langsung |
| F2 | URL `http://` (konstanta) terbukti **mengalir** ke API networking lewat reachability analysis | Metode C (CodeQL) |
| F3 | Hooking runtime (Frida/MASTG-TEST-0238) menangkap **pemanggilan nyata** ke koneksi berskema `http://` | Metode F |
| F4 | Capture lalu lintas jaringan (MASTG-TEST-0236) menunjukkan **paket HTTP plaintext benar-benar terkirim** ke server saat aplikasi dipakai | Bukti definitif tingkat jaringan |
| F5 | Konfigurasi mengizinkan cleartext (MASTG-TEST-0235 FAIL) **dan** ditemukan URL HTTP aktif dipakai — kombinasi ini memastikan request benar-benar akan berhasil terkirim dalam plaintext | Korelasi F1/F2 dengan TEST-0235 |

**Contoh bukti (ilustratif — MASTG belum menyediakan demo resmi untuk test ini):**

```java
// Ditemukan di com/example/target/api/LegacyApiClient.java (hasil dekompilasi jadx)
public class LegacyApiClient {
    private static final String LEGACY_ENDPOINT = "http://api-legacy.example.com/v1/sync";  // baris 12

    public void syncData(String payload) throws IOException {
        URL url = new URL(LEGACY_ENDPOINT);   // baris 22 — DIPAKAI LANGSUNG untuk membuka koneksi
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        // ... mengirim payload
    }
}
```

```bash
$ rg -n 'http://' ./decompiled/sources/com/example/target/api/LegacyApiClient.java
12:    private static final String LEGACY_ENDPOINT = "http://api-legacy.example.com/v1/sync";
$ semgrep -c ./http-url-rules.yml ./decompiled/sources/com/example/target/api/LegacyApiClient.java
custom-hardcoded-http-url-active-use: baris 22 — new URL(LEGACY_ENDPOINT) [reachability dari konstanta baris 12]
```

Interpretasi: konstanta di baris 12 mengalir langsung ke `new URL()` di baris 22 yang dipakai untuk `openConnection()` — **kandidat FAIL kuat**. Konfirmasi final tetap memerlukan MASTG-TEST-0235 (apakah cleartext diizinkan) dan idealnya MASTG-TEST-0236/0238 (apakah benar-benar tereksekusi).

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi | Contoh bukti |
|---|---|---|
| P1 | **Tidak ditemukan** string `http://` yang relevan (setelah difilter dari noise namespace XML/lisensi) di seluruh isi APK | Hasil grep menyeluruh kosong setelah filtering |
| P2 | URL `http://` ditemukan, tetapi **hanya sebagai konstanta yang tidak pernah dipakai** (dead code, sisa refactoring) — dikonfirmasi lewat "Find Usage" jadx-gui atau CodeQL reachability yang menunjukkan tidak ada aliran ke API networking manapun | Konstanta `OLD_ENDPOINT` yang dideklarasikan tapi tidak pernah direferensikan di tempat lain |
| P3 | URL `http://` dipakai aktif, **tetapi** MASTG-TEST-0235 mengonfirmasi cleartext **diblokir** oleh konfigurasi (tidak ada `usesCleartextTraffic="true"`, tidak ada NSC yang mengizinkan) — request akan gagal di runtime, **dan** dikonfirmasi lewat MASTG-TEST-0236/0238 bahwa tidak ada lalu lintas HTTP nyata terkirim | `CleartextNotPermittedException` terlempar saat dicoba dipanggil |
| P4 | URL `http://` hanya muncul di dalam **komentar kode**, dokumentasi Javadoc, atau contoh error message (bukan nilai yang benar-benar dipakai sebagai URL request) | `// Deprecated: dulu memakai http://old-api.example.com, sudah dimigrasi` |
| P5 | Semua endpoint komunikasi aplikasi (dikonfirmasi lewat MASTG-TEST-0236 capture menyeluruh) menggunakan `https://` — string `http://` yang ada hanya milik library pihak ketiga yang terbukti tidak aktif dipanggil aplikasi target | Hasil capture lalu lintas selama sesi pengujian penuh hanya menunjukkan koneksi TLS |

**Contoh output yang menandakan PASS (skenario dead code):**

```bash
$ rg -n 'http://' ./decompiled/sources/ | grep -v 'schemas\.\|w3\.org'
com/example/target/legacy/OldSyncManager.java:8:    private static final String OLD_URL = "http://deprecated.example.com";

$ jadx-gui  # "Find Usage" pada OLD_URL → 0 hasil referensi di luar deklarasinya sendiri
```

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Ini adalah aturan paling eksplisit di MASTG tentang "jangan simpulkan FAIL hanya dari keberadaan pola statis."** Overview resmi secara khusus menyertakan blok "Limitations" — sebuah sinyal kuat bahwa MASTG sendiri mengantisipasi false positive yang tinggi pada test ini bila dilakukan secara dangkal. Laporan yang hanya berisi "ditemukan N string http://" tanpa analisis lanjutan **tidak memenuhi standar evaluasi resmi**.

2. **Urutan investigasi yang benar: lokasi → penggunaan aktif → konfigurasi cleartext → bukti runtime.** Jangan melompat langsung ke kesimpulan FAIL dari hasil grep Metode A saja — ikuti alur §1.4.

3. **Prioritaskan triase berdasarkan konteks endpoint**, bukan jumlah kemunculan. Satu URL HTTP yang dipakai aktif untuk mengirim kredensial jauh lebih signifikan dibanding sepuluh URL HTTP di dalam file lisensi pihak ketiga.

4. **Waspadai library pihak ketiga yang membawa endpoint HTTP legacy.** Tanggung jawab remediasi berbeda — bila SDK vendor pihak ketiga yang membawa masalah ini, langkah mitigasi realistis adalah memperbarui versi SDK atau menghubungi vendor, bukan mengedit kode vendor secara langsung.

5. **Redirect HTTP→HTTPS di sisi server tidak menghilangkan risiko sepenuhnya.** Meski server mengembalikan `301/302` redirect dari HTTP ke HTTPS, **permintaan awal** tetap terkirim dalam cleartext sebelum redirect terjadi — cukup untuk membocorkan header (termasuk cookie/token bila di-attach di request awal) ke penyerang MITM. Jangan menganggap ini otomatis PASS hanya karena "toh nanti di-redirect ke HTTPS".

6. **Severity dimodulasi oleh jenis data yang berpotensi dikirim lewat endpoint tersebut:**

   | Faktor | Severity |
   |---|---|
   | URL HTTP aktif dipakai untuk mengirim kredensial/token/PII, dan cleartext diizinkan konfigurasi | **Kritis** |
   | URL HTTP aktif dipakai untuk endpoint non-sensitif (mis. cek versi aplikasi, health check publik) | **Menengah/Rendah** |
   | URL HTTP ditemukan sebagai konstanta dead code, tidak pernah dipanggil | **Informational** |
   | URL HTTP aktif dipakai tapi cleartext diblokir konfigurasi (dikonfirmasi TEST-0235 & TEST-0236) | **Rendah** — tetap catat sebagai code smell/technical debt, bukan kerentanan aktif |

7. **Dokumentasikan:** lokasi kode (file + baris) tempat URL dideklarasikan **dan** tempat ia dipakai (bila berbeda), hasil reachability analysis, status korelasi dengan MASTG-TEST-0235 (apakah cleartext diizinkan), status korelasi dengan MASTG-TEST-0236/0238 (apakah benar-benar tereksekusi dan terkirim), serta klasifikasi data yang berpotensi dikirim lewat endpoint tersebut.

---

## 4. Rekomendasi Perbaikan

### 4.1 Migrasi Seluruh Endpoint ke HTTPS

Solusi paling langsung — pastikan seluruh komunikasi jaringan aplikasi, termasuk endpoint pihak ketiga yang di-bundle, menggunakan `https://`:

```java
// SEBELUM
private static final String API_ENDPOINT = "http://api.example.com/v1/sync";

// SESUDAH
private static final String API_ENDPOINT = "https://api.example.com/v1/sync";
```

### 4.2 Terapkan Network Security Configuration yang Ketat sebagai Lapisan Pertahanan Kedua

Meski migrasi kode sudah dilakukan, tetapkan **Network Security Configuration** eksplisit untuk memastikan sistem menolak cleartext secara paksa, sehingga kesalahan hardcode HTTP di masa depan (termasuk dari SDK pihak ketiga baru) tidak akan pernah benar-benar terkirim:

```xml
<!-- res/xml/network_security_config.xml -->
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
</network-security-config>
```

```xml
<!-- AndroidManifest.xml -->
<application
    android:networkSecurityConfig="@xml/network_security_config"
    android:usesCleartextTraffic="false"
    ... >
```

Ini secara langsung menutup celah yang diperingatkan di §1.2 — bahkan bila hardcoded HTTP URL lolos dari code review di masa depan, sistem akan tetap memblokir request-nya.

### 4.3 Hindari Pengecualian Domain Cleartext untuk Kebutuhan Development yang Tertinggal di Rilis Produksi

Bila pengecualian cleartext diperlukan untuk domain internal/staging, **pisahkan build variant** development dan production dengan file NSC yang berbeda, dan verifikasi lewat CI/CD bahwa build variant production **tidak pernah** menyertakan pengecualian tersebut:

```gradle
android {
    buildTypes {
        debug {
            manifestPlaceholders = [networkSecurityConfig: "@xml/network_security_config_debug"]
        }
        release {
            manifestPlaceholders = [networkSecurityConfig: "@xml/network_security_config_release"]
        }
    }
}
```

### 4.4 Audit Dependency Pihak Ketiga Secara Berkala

Jalankan pemeriksaan Metode A/E (grep menyeluruh + apkleaks) sebagai bagian dari proses **audit dependency** setiap kali menambahkan SDK/library baru, bukan hanya menjelang rilis — endpoint HTTP legacy dari SDK vendor cenderung luput dari perhatian karena berada di luar kode yang ditulis tim sendiri.

### 4.5 Integrasikan ke CI/CD

```bash
#!/bin/bash
# ci-check-hardcoded-http.sh
APK=$1
mkdir -p /tmp/apk_check && cd /tmp/apk_check && unzip -o "$APK" >/dev/null
jadx -d /tmp/decompiled_check "$APK" 2>/dev/null

FOUND=$(rg -c 'http://' /tmp/decompiled_check/sources/ 2>/dev/null | grep -v 'schemas\.\|w3\.org' | awk -F: '{sum+=$2} END {print sum+0}')
if [ "$FOUND" -gt "0" ]; then
    echo "[PERINGATAN] Ditemukan $FOUND referensi http:// — verifikasi apakah aktif dipakai (lihat semgrep active-use rule)"
fi
```

### 4.6 Checklist Remediasi

- [ ] Seluruh string `http://` di kode, resource, assets, dan library native sudah diinventarisasi (Metode A menyeluruh)
- [ ] Setiap temuan sudah dikategorikan: dead code / konstanta tak terpakai vs aktif dipakai untuk request (Metode B/C)
- [ ] Endpoint yang aktif dipakai sudah dimigrasi ke `https://`
- [ ] Network Security Configuration eksplisit sudah diterapkan dengan `cleartextTrafficPermitted="false"` di `<base-config>`
- [ ] Tidak ada pengecualian domain cleartext yang tertinggal dari build development di variant production
- [ ] Dependency pihak ketiga sudah diaudit untuk endpoint HTTP legacy
- [ ] Korelasi dengan MASTG-TEST-0235 (konfigurasi), MASTG-TEST-0236 (capture jaringan), dan MASTG-TEST-0238 (runtime API) sudah dilakukan sebelum menyimpulkan status akhir
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0233 pada APK release final setelah remediasi

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0233: Hardcoded HTTP URLs](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0233/)
- [MASTG-TEST-0235: Android App Configurations Allowing Cleartext Traffic](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0235/)
- [MASTG-TEST-0236: Cleartext Traffic in Network Traffic Capture](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0236/)
- [MASTG-TEST-0238: Runtime Use of Networking APIs](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0238/)
- [MASWE-0026: Network Traffic Not Encrypted](https://mas.owasp.org/MASWE/MASVS-NETWORK/MASWE-0026/)
- [MASTG-TECH-0013: Reverse Engineering Android Apps](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/)
- [MASTG-TECH-0019: Retrieving Strings](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0019/)
- [MASTG Document 0x05g — Testing Network Communication](https://mas.owasp.org/MASTG/0x05g-Testing-Network-Communication/)
- [OWASP Mobile Top 10 2024 — M5: Insecure Communication](https://owasp.org/www-project-mobile-top-10/2023-risks/m5-insecure-communication)

### 5.2 Dokumentasi Resmi Android

- [Android Developers — Network Security Configuration](https://developer.android.com/privacy-and-security/security-config)
- [Android Developers — `usesCleartextTraffic` attribute reference](https://developer.android.com/guide/topics/manifest/application-element#usesCleartextTraffic)
- [Android Developers — Changes in network security in Android 9 (Behavior changes: apps targeting API 28+)](https://developer.android.com/about/versions/pie/android-9.0-changes-28#device-security)
- [Android Developers — App security best practices](https://developer.android.com/privacy-and-security/security-best-practices)

### 5.3 Standar dan Riset Lain

- [CWE-295: Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)
- [CWE-296: Improper Following of a Certificate's Chain of Trust](https://cwe.mitre.org/data/definitions/296.html)
- [CWE-297: Improper Validation of Certificate with Host Mismatch](https://cwe.mitre.org/data/definitions/297.html)
- [OWASP Transport Layer Protection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)

### 5.4 Dokumentasi Tools

- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [apktool](https://apktool.org/)
- [apkleaks](https://github.com/dwisiswant0/apkleaks)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
- [radare2 / rabin2](https://github.com/radareorg/radare2)
- [Frida — Dynamic instrumentation toolkit](https://frida.re/docs/javascript-api/)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026) dan dokumentasi resmi Android Developers. Test ini belum memiliki demo (MASTG-DEMO) maupun rule semgrep resmi. Overview resmi MASTG secara eksplisit memperingatkan bahwa keberadaan URL HTTP saja tidak cukup untuk menyimpulkan FAIL — dokumen ini menekankan alur korelasi dengan MASTG-TEST-0235/0236/0238 sebagai bagian tak terpisahkan dari evaluasi yang valid.*
