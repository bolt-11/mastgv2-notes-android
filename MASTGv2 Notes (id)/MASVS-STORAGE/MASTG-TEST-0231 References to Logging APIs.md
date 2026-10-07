# MASTG-TEST-0231 References to Logging APIs

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0231 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-STORAGE (MASVS-STORAGE-2: Aplikasi mencegah kebocoran data sensitif yang tidak diperlukan) |
| **Weakness** | MASWE-0005 — *Insertion of Sensitive Data into Logs* |
| **Tipe Pengujian** | **Static**, Code |
| **Profile** | L1, L2, **P** (Privacy) |
| **Knowledge** | MASTG-KNOW-0049 (Logs) |
| **Best Practice** | MASTG-BEST-0002 (Remove Logging Code) |
| **APIs yang disorot** | `android.util.Log`, `Log`, `Logger`, `System.out.print`, `System.err.print`, `java.lang.Throwable#printStackTrace` |
| **Teknik terkait** | MASTG-TECH-0013 (Reverse Engineering Android Apps), MASTG-TECH-0014 (Static Analysis on Android), MASTG-TECH-0023 (Reviewing Decompiled Java Code) |
| **Demo terkait** | — (MASTG belum menyediakan demo untuk test ini) |
| **Test bersaudara** | **MASTG-TEST-0203** (Runtime Use of Logging APIs) — counterpart dinamis, weakness dan API yang sama persis |
| **Menggantikan** | MASTG-TEST-0003 (*Testing Logs for Sensitive Data* — status **deprecated**, `covered_by: [MASTG-TEST-0203, MASTG-TEST-0231]`) |
| **CWE terkait** | CWE-532 (Insertion of Sensitive Information into Log File), CWE-200 (Exposure of Sensitive Information), CWE-312 (Cleartext Storage of Sensitive Information), CWE-359 (Exposure of Private Personal Information) |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Kutipan langsung dari overview MASTG:

> *"This test verifies if an app uses logging APIs like `android.util.Log`, `Log`, `Logger`, `System.out.print`, `System.err.print`, and `java.lang.Throwable#printStackTrace`."*

Test ini adalah **counterpart statis persis** dari MASTG-TEST-0203 yang sudah dibahas sebelumnya. Keduanya berbagi weakness (MASWE-0005), knowledge (MASTG-KNOW-0049), best practice (MASTG-BEST-0002), dan **daftar API yang identik**. Perbedaannya murni pada pendekatan:

| | MASTG-TEST-0203 | MASTG-TEST-0231 *(dokumen ini)* |
|---|---|---|
| **Pendekatan** | Dinamis — hooking (Frida) atau `adb logcat` | **Statis** — reverse engineering + pattern matching |
| **Menjawab** | "Nilai apa yang **benar-benar** dicatat saat runtime?" | "Di mana saja API logging **direferensikan** di kode?" |
| **Kekuatan** | Melihat nilai runtime sebenarnya — inti dari kriteria evaluasi ("data sensitif *tercatat*") | **Cakupan menyeluruh** atas seluruh kode yang ada, termasuk jalur yang jarang di-*exercise* (handler error, fitur premium) |
| **Kelemahan** | Hanya menangkap alur yang benar-benar dijalankan penguji | Tidak tahu **nilai** yang dicatat — hanya tahu **bahwa** ada pemanggilan API di suatu lokasi |

Karena rincian lengkap tentang mengapa logging berbahaya, jalur kebocoran, dan peta API sudah dibahas mendalam di dokumen MASTG-TEST-0203, dokumen ini akan **merujuk** bagian tersebut dan fokus pada **apa yang unik** dari sisi analisis statis: bagaimana menemukan referensi API secara menyeluruh, dan bagaimana kriteria evaluasinya berbeda secara halus dari test dinamisnya.

### 1.2 Nilai Unik Pendekatan Statis: Cakupan, Bukan Kedalaman

Test dinamis (MASTG-TEST-0203) hanya melihat apa yang **benar-benar dieksekusi** selama sesi pengujian. Ini titik buta yang signifikan:

- **Log di dalam `catch` block untuk exception yang jarang terjadi** (mis. kegagalan jaringan spesifik, race condition) tidak akan pernah terpicu kecuali penguji berhasil mereproduksi kondisi tersebut.
- **Log pada fitur yang di-*gate* oleh flag** (akun premium, A/B testing, region tertentu) tidak akan terlihat bila penguji tidak memiliki akses ke kondisi tersebut.
- **Log di modul yang jarang dipakai** (halaman pengaturan lanjutan, alur onboarding yang hanya muncul sekali) mudah terlewat dalam sesi pengujian manual yang terbatas waktu.

Analisis statis **melihat semuanya sekaligus** — setiap baris kode yang memanggil API logging akan ditemukan, terlepas apakah baris itu pernah dieksekusi selama pengujian atau tidak. Inilah nilai unik test ini: ia memberi **peta lengkap** permukaan logging aplikasi, yang kemudian dapat dipakai untuk mengarahkan pengujian dinamis secara lebih efisien (lihat §1.4).

### 1.3 Mengapa Kriteria Evaluasinya Secara Halus Berbeda dari MASTG-TEST-0203

Ini nuansa penting yang mudah terlewat karena kedua test terlihat sangat mirip. Bandingkan kedua kriteria evaluasi resmi:

> **MASTG-TEST-0203 (dinamis):** *"The test case fails if **you can find sensitive data being logged** using those APIs."*
>
> **MASTG-TEST-0231 (statis, dokumen ini):** *"The test case fails if **an app logs sensitive information** from any of the listed locations."*

Secara tekstual keduanya tampak menyatakan hal yang sama, tetapi implikasi praktisnya berbeda karena **sifat data yang tersedia untuk masing-masing pendekatan**:

- Pada test **dinamis**, penguji **melihat nilai literal** yang tercatat saat runtime — sehingga "menemukan data sensitif" berarti secara harfiah melihat string canary/kredensial di output log.
- Pada test **statis**, penguji **tidak melihat nilai runtime** — ia hanya melihat *kode* yang memanggil API logging, seperti `Log.d(TAG, "token: " + accessToken)`. Untuk menyimpulkan bahwa ini "mencatat informasi sensitif", penguji harus **menganalisis kode** di sekitar pemanggilan tersebut: variabel apa yang di-interpolasi ke dalam string log, dari mana asalnya, dan apakah itu benar-benar bernilai sensitif.

Inilah mengapa MASTG secara konsisten meminta langkah **MASTG-TECH-0023** (*Reviewing Decompiled Java Code*) sebagai bagian tak terpisahkan dari evaluasi test statis semacam ini — analisis statis logging **tidak pernah selesai** hanya dengan menemukan lokasi pemanggilan API; ia harus dilanjutkan dengan menelusuri **variabel** yang masuk ke dalamnya.

### 1.4 Alur Kerja yang Direkomendasikan: Statis Sebagai Peta, Dinamis Sebagai Konfirmasi

Karena keduanya saling melengkapi, urutan kerja yang paling efisien adalah:

```
TEST-0231 (statis)  ──►  Peta LENGKAP lokasi pemanggilan API logging
        │                (termasuk yang jarang di-exercise)
        ▼
   Analisis variabel yang di-interpolasi ke dalam setiap pemanggilan
   (MASTG-TECH-0023) — tandai kandidat yang MUNGKIN sensitif
        │
        ▼
TEST-0203 (dinamis)  ──►  KONFIRMASI nilai runtime sebenarnya
        │                 pada kandidat yang ditandai, plus canary value
        ▼
   Keputusan PASS / FAIL dengan bukti nilai runtime aktual
```

Pendekatan ini menghindari dua jebakan sekaligus: **false positive** dari analisis statis murni (menyimpulkan sensitif hanya dari nama variabel yang terlihat mencurigakan, padahal nilainya generik), dan **false negative** dari analisis dinamis murni (melewatkan jalur kode yang tidak sempat di-*exercise*).

---

## 2. Tools yang Dipakai untuk Pengujian

Karena test ini murni statis dan berbagi target API dengan MASTG-TEST-0203, sebagian besar tooling di sini melengkapi (bukan menggantikan) apa yang sudah dibahas untuk pasangan dinamisnya.

### 2.1 Tools Wajib (Core)

| Tool | MASTG ID | Fungsi |
|---|---|---|
| **jadx** | MASTG-TOOL-0018 | **Dekompilasi DEX → Java** (MASTG-TECH-0013). Wajib untuk MASTG-TECH-0023 — menelusuri variabel yang di-log |
| **grep / ripgrep** | — | Pencarian pola API logging. **Metode utama** karena MASTG tidak menyediakan rule semgrep resmi untuk test ini |
| **apktool** | MASTG-TOOL-0011 | Alternatif dekompilasi; analisis smali bila diperlukan |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **semgrep** | Tidak ada rule resmi MASTG — rule kustom (§3.3) diperlukan untuk mencakup keenam API sekaligus varian yang tidak disebut eksplisit (Timber, dsb.) |
| **CodeQL** | Taint analysis — dapat melacak apakah variabel yang di-log benar-benar berasal dari sumber sensitif (field bertanda password/token, parameter API response, dsb.) secara terprogram, mengurangi beban review manual |
| **MobSF** | Analisis otomatis, menandai pemanggilan API logging dalam laporan Code Analysis |
| **jadx-gui** | Navigasi interaktif dengan fitur "Find Usage" — untuk melacak dari mana nilai variabel yang di-log berasal |
| **ProGuard mapping / R8 rules inspector** | Memeriksa apakah aturan `-assumenosideeffects` untuk `android.util.Log` sudah diterapkan pada build release (lihat MASTG-BEST-0002 dan pembahasan detail di dokumen MASTG-TEST-0203 §4.1) |

### 2.3 Prasyarat Lingkungan

- **Tidak butuh device dan tidak butuh root** — cukup file APK. Sepenuhnya dapat diotomatisasi di CI/CD.
- **Uji APK build RELEASE**, bukan debug build — sama seperti catatan penting pada MASTG-TEST-0203, logging berlebih pada debug build adalah hal wajar dan tidak representatif untuk risiko produksi. Namun untuk test **statis**, penting dicatat: **keberadaan referensi API logging di kode release TIDAK secara otomatis berarti API tersebut akan tereksekusi** — bila ProGuard/R8 sudah mem-strip pemanggilan `Log.*` sesuai MASTG-BEST-0002, referensi tersebut mungkin sudah hilang dari bytecode hasil dekompilasi. Verifikasi ini penting agar tidak salah menyimpulkan (lihat §3.7 catatan 3).
- **Waspadai obfuscation.** Nama API framework (`Log`, `Logger`, `System.out`) tidak di-obfuscate ProGuard/R8 karena API sistem, sehingga deteksi tetap efektif meski nama kelas/metode aplikasi sendiri sudah diacak.
- **Perhatikan library logging pihak ketiga** yang tidak disebut eksplisit di daftar API resmi (Timber, SLF4J, dll.) — lihat MASTG-TEST-0203 §1.4 untuk peta lengkap API Kelompok B yang perlu diperiksa tambahan.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0013** (*Reverse Engineering Android Apps*) untuk me-reverse engineer aplikasi.
2. Gunakan **MASTG-TECH-0014** (*Static Analysis on Android*) untuk mencari API yang relevan.

Untuk evaluasi, meski tidak disebut eksplisit dalam langkah resmi test ini, praktik yang konsisten dengan test-test statis lain di MASTG mengharuskan **MASTG-TECH-0023** untuk meninjau setiap lokasi temuan.

### 3.2 Metode A — grep/ripgrep pada kode dekompilasi *(metode utama)*

```bash
jadx -d ./decompiled ./target-app.apk
D=./decompiled/sources

# --- Enam API yang disebut EKSPLISIT oleh overview MASTG ---
rg -n --no-heading "android\.util\.Log|Log\.(v|d|i|w|e|wtf|println)\(" $D
rg -n --no-heading "java\.util\.logging\.Logger|\.severe\(|\.warning\(|\.info\(|\.fine\(|\.config\(" $D
rg -n --no-heading "System\.out\.print" $D
rg -n --no-heading "System\.err\.print" $D
rg -n --no-heading "printStackTrace\(\)" $D

# --- Rekap jumlah temuan per file untuk triase awal ---
rg -c --no-heading "Log\.(v|d|i|w|e|wtf)\(" $D | sort -t: -k2 -rn | head -20
```

**Langkah wajib berikutnya — telusuri variabel yang di-log (MASTG-TECH-0023):**

```bash
# Untuk setiap hasil, periksa konteks penuh baris tersebut
rg -n -B3 -A1 "Log\.(d|e|w|i)\(" $D | grep -B3 -A1 "token\|password\|secret\|key\|email\|credential" -i

# Cari pola interpolasi string yang membawa variabel ke dalam pemanggilan log
rg -n 'Log\.\w+\([^,]+,\s*"[^"]*"\s*\+' $D          # concatenation string + variabel
rg -n 'Log\.\w+\([^,]+,\s*\w+\)' $D                  # variabel langsung sebagai argumen kedua
```

### 3.3 Metode B — semgrep dengan rule kustom *(gate CI/CD, mencakup keenam API)*

MASTG tidak menyediakan rule resmi untuk test ini. Berikut rule yang mencakup keenam API yang disebut eksplisit, plus varian yang sering luput:

```yaml
rules:
  - id: custom-logging-api-android-log
    severity: WARNING
    languages: [java, kotlin]
    message: "[MASVS-STORAGE-2] Pemanggilan android.util.Log ditemukan — verifikasi variabel yang di-log"
    pattern-either:
      - pattern: android.util.Log.$METHOD(...)

  - id: custom-logging-api-logger
    severity: WARNING
    languages: [java, kotlin]
    message: "[MASVS-STORAGE-2] Pemanggilan java.util.logging.Logger ditemukan"
    pattern-either:
      - pattern: $LOGGER.severe(...)
      - pattern: $LOGGER.warning(...)
      - pattern: $LOGGER.info(...)
      - pattern: $LOGGER.fine(...)
      - pattern: $LOGGER.config(...)

  - id: custom-logging-api-system-print
    severity: WARNING
    languages: [java, kotlin]
    message: "[MASVS-STORAGE-2] System.out/err.print ditemukan"
    pattern-either:
      - pattern: System.out.print(...)
      - pattern: System.out.println(...)
      - pattern: System.err.print(...)
      - pattern: System.err.println(...)

  - id: custom-logging-api-stacktrace
    severity: WARNING
    languages: [java, kotlin]
    message: "[MASVS-STORAGE-2] printStackTrace() ditemukan — exception message/stack trace berpotensi berisi data sensitif"
    pattern: $EX.printStackTrace(...)

  - id: custom-logging-api-thirdparty
    severity: INFO
    languages: [java, kotlin]
    message: "[MASVS-STORAGE-2] Library logging pihak ketiga ditemukan — tidak dicakup daftar API resmi MASTG, tetap perlu diperiksa"
    pattern-either:
      - pattern: timber.log.Timber.$METHOD(...)
      - pattern: org.slf4j.Logger $X = ...
```

```bash
semgrep -c ./logging-rules.yml ./decompiled/sources/ --json -o findings.json
jq '.results | length' findings.json
```

### 3.4 Metode C — CodeQL *(taint analysis — mengurangi beban review manual)*

Ini metode yang paling menjawab tantangan inti test statis ini (§1.3): membedakan pemanggilan log yang membawa data sensitif dari yang tidak, secara terprogram.

```ql
/**
 * @name Sensitive-looking variable flows into logging API
 * @kind path-problem
 * @problem.severity warning
 */
import java
import semmle.code.java.dataflow.TaintTracking

class SensitiveSource extends DataFlow::Node {
  SensitiveSource() {
    exists(Variable v |
      v.getName().toLowerCase().regexpMatch(".*(password|token|secret|apikey|credential|auth|session).*") and
      this.asExpr() = v.getAnAccess()
    )
  }
}

class LoggingSink extends DataFlow::Node {
  LoggingSink() {
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("android.util", "Log") or
      ma.getMethod().getDeclaringType().hasQualifiedName("java.util.logging", "Logger") or
      ma.getMethod().getDeclaringType().hasQualifiedName("java.io", "PrintStream") |
      this.asExpr() = ma.getAnArgument()
    )
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink
where TaintTracking::localFlow(source, sink)
select sink, source, sink, "Variabel bernama mencurigakan mengalir ke API logging"
```

```bash
codeql database create ./cqldb --language=java --command="./gradlew assembleRelease"
codeql database analyze ./cqldb ./sensitive-logging-query.ql --format=sarif-latest --output=result.sarif
```

> Perlu dicatat: pendekatan berbasis **nama variabel** ini tetap heuristik — variabel bernama `data` atau `result` yang sebenarnya berisi token tidak akan tertangkap, sementara variabel bernama `passwordHint` yang berisi teks non-sensitif bisa menjadi false positive. Untuk hasil yang lebih presisi, kombinasikan dengan pelacakan taint dari sumber API yang diketahui sensitif (mis. return value dari fungsi otentikasi) — namun ini menuntut kustomisasi lebih lanjut sesuai basis kode spesifik aplikasi yang diuji.

### 3.5 Metode D — MobSF

```bash
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
```

Upload APK → bagian **Code Analysis** mencari temuan terkait *"Application logs information"* atau sejenisnya, dengan daftar lokasi kode. Sama seperti scanner otomatis lainnya, hasil MobSF **hanya menunjukkan lokasi**, tidak menilai sensitivitas nilai yang dicatat — verifikasi manual (§1.3) tetap wajib.

### 3.6 Metode E — Verifikasi konfigurasi ProGuard/R8 *(melengkapi hasil pattern matching)*

Ini langkah yang sering terlewat tetapi penting untuk interpretasi hasil yang akurat (lihat §3.7 catatan 3): temuan referensi API logging di kode **sumber** tidak berarti API tersebut benar-benar ada di **bytecode rilis final**.

```bash
# Periksa apakah aturan strip logging sudah ada di konfigurasi proyek
find . -name "proguard-rules.pro" -exec grep -A10 "android.util.Log" {} \;

# Pada APK hasil build release, verifikasi apakah pemanggilan Log MASIH ADA
# setelah shrinking/obfuscation — bila konfigurasi ProGuard sudah benar,
# hasil ini seharusnya jauh lebih sedikit dari hasil dekompilasi source asli
jadx -d ./decompiled_release ./target-app-release.apk
rg -c "Log\.(v|d|i|w|e)\(" ./decompiled_release/sources/ | awk -F: '{sum+=$2} END {print sum}'
```

Bila hasil pada APK release final menunjukkan **jauh lebih sedikit** (atau nol) pemanggilan dibanding source code asli, ini indikasi kuat bahwa `-assumenosideeffects` sudah diterapkan dengan benar — meskipun, sesuai catatan MASTG-BEST-0002 yang dibahas mendalam di dokumen MASTG-TEST-0203, **string yang dibangun secara dinamis untuk parameter log yang sudah di-strip bisa saja tetap tertinggal di bytecode** meski pemanggilan `Log.v()`-nya sendiri sudah hilang.

### 3.7 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Menemukan lokasi? | Menilai sensitivitas nilai? | Cocok untuk CI/CD? | Kapan dipakai |
|---|---|---|---|---|---|
| **A** | grep/ripgrep | ✅ | Manual (wajib) | Sedang | **Baseline utama** — tidak ada rule resmi |
| **B** | semgrep kustom | ✅ | ❌ | ✅ | Gate CI/CD; penyaring awal lokasi |
| **C** | CodeQL | ✅ | Sebagian (heuristik nama variabel) | ✅ | Mengurangi beban review manual pada codebase besar |
| **D** | MobSF | ✅ | ❌ | Sebagian | Triase awal cepat, laporan siap kutip |
| **E** | Verifikasi ProGuard/R8 | — | — | ✅ | **Interpretasi hasil yang akurat** — cek apakah temuan source relevan untuk release final |

**Kombinasi minimum yang aku rekomendasikan:** **A (grep) → E (verifikasi ProGuard) → review manual (MASTG-TECH-0023)**.
A memberi cakupan lokasi lengkap, E memastikan kamu menilai bytecode yang relevan (bukan source yang sudah di-strip di build final), dan review manual pada setiap kandidat menjawab pertanyaan inti test ini: apakah nilai yang di-log benar-benar sensitif. Tambahkan **C (CodeQL)** untuk codebase besar guna mempersempit kandidat yang perlu direview manual.

---

### 3.8 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Observation:** *"The output should contain a list of locations where logging APIs are used."*
>
> **Evaluation:** *"The test case **fails** if an app logs sensitive information from any of the listed locations."*

Sama seperti disinggung di §1.3, kriteria ini menuntut **penilaian atas isi**, bukan sekadar keberadaan pemanggilan API.

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi | Contoh bukti |
|---|---|---|
| F1 | Ditemukan pemanggilan `Log.*` yang membawa variabel berisi **kredensial/token** ke dalam string log | `Log.d(TAG, "token=" + accessToken)` |
| F2 | Ditemukan pemanggilan yang membawa **PII** (email, NIK, nomor telepon) | `Logger.getLogger("X").info("user email: " + user.getEmail())` |
| F3 | Ditemukan pemanggilan yang membawa **material kriptografi** (kunci, IV, seed) | `Log.v(TAG, "key bytes: " + Arrays.toString(secretKey.getEncoded()))` |
| F4 | `printStackTrace()` dipanggil pada exception yang **message atau causal chain-nya** kemungkinan memuat data sensitif (mis. URL lengkap dengan parameter token, isi respons API gagal) | `catch (Exception e) { e.printStackTrace(); }` pada blok yang menangani response HTTP berisi payload otentikasi |
| F5 | `System.out.print`/`System.err.print` dipakai untuk mencetak nilai sensitif — pola yang jarang tapi tetap perlu diperiksa, terutama pada kode yang di-porting dari CLI/library non-Android | `System.out.println("Session ID: " + sessionId)` |
| F6 | Ditemukan pemanggilan log dengan variabel yang **namanya secara jelas mengindikasikan sensitivitas** (`password`, `token`, `secret`, `apiKey`) meski nilai literalnya tidak terlihat langsung di kode statis — cukup kuat sebagai indikasi bila tidak dapat dikonfirmasi lebih lanjut secara dinamis | `Log.e(TAG, "auth failed for: " + password)` |
| F7 | Referensi API logging **masih ada di bytecode APK release final** (dikonfirmasi via Metode E) padahal seharusnya sudah di-strip, mengindikasikan konfigurasi ProGuard/R8 yang tidak diterapkan dengan benar | Jumlah pemanggilan `Log.*` di APK release tidak berkurang signifikan dari source asli |

**Contoh bukti (ilustratif — MASTG belum menyediakan demo resmi untuk test ini):**

```java
// Ditemukan di com/example/target/AuthManager.java (hasil dekompilasi jadx)
public class AuthManager {
    private static final String TAG = "AuthManager";

    public void login(String username, String password) {
        Log.d(TAG, "Attempting login for user=" + username + " pass=" + password);  // baris 42
        // ...
        try {
            performLogin(username, password);
        } catch (IOException e) {
            e.printStackTrace();   // baris 47 — periksa apakah exception membawa payload sensitif
        }
    }
}
```

```bash
$ rg -n "Log\.\w+\(" ./decompiled/sources/com/example/target/AuthManager.java
42:        Log.d(TAG, "Attempting login for user=" + username + " pass=" + password);
$ rg -n "printStackTrace" ./decompiled/sources/com/example/target/AuthManager.java
47:            e.printStackTrace();
```

Interpretasi: baris 42 secara eksplisit meng-concatenate variabel `password` ke dalam pesan log — **FAIL** dengan bukti kuat langsung dari kode sumber, tanpa perlu konfirmasi runtime karena variabelnya sudah jelas dari namanya **dan** konteks fungsinya (`login`).

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi | Contoh bukti |
|---|---|---|
| P1 | **Tidak ditemukan** pemanggilan API logging apa pun di kode (setelah verifikasi bahwa ProGuard/R8 sudah mem-strip semuanya untuk build release) | Hasil `rg` pada APK release final kosong atau sudah ter-strip |
| P2 | Ditemukan pemanggilan API logging, tetapi variabel yang dicatat **hanya berisi data operasional non-sensitif** | `Log.i(TAG, "Network request completed in " + elapsed + "ms")` |
| P3 | `printStackTrace()` ditemukan, tetapi hanya dipanggil pada exception yang **terbukti tidak membawa data sensitif** dalam pesan/causal chain-nya | Exception timeout jaringan generik tanpa payload |
| P4 | Pemanggilan logging **dibungkus** kondisi `BuildConfig.DEBUG` dan terbukti benar-benar hilang di build release (diverifikasi Metode E) | `if (BuildConfig.DEBUG) { Log.d(TAG, "token=" + token); }` **dan** referensi ini terkonfirmasi ter-strip pada APK release final |
| P5 | Semua nilai yang di-log sudah melalui mekanisme **redaksi/masking** sebelum dicatat | `Log.d(TAG, "user=" + user.toString())` di mana `toString()` di-override mengembalikan `"User(email=XX)"` |

**Contoh output yang menandakan PASS:**

```bash
$ rg -n "Log\.\w+\(|System\.(out|err)\.print|printStackTrace" ./decompiled_release/sources/
# (tidak ada hasil — semua sudah ter-strip di build release, dikonfirmasi Metode E)
```

Atau — ditemukan pemanggilan, tetapi bersih dari data sensitif:

```java
Log.i(TAG, "onCreate: activity started");
Log.e(TAG, "Network error", genericIOException);   // pesan exception generik, terverifikasi tidak membawa payload
```

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Ini test yang menuntut analisis konteks — bukan sekadar keberadaan API.** Sama seperti ditekankan di §1.3, temuan lokasi pemanggilan API hanyalah **langkah pertama**. Kriteria FAIL/PASS bergantung sepenuhnya pada apa yang dibawa variabel ke dalam pemanggilan tersebut — ini menuntut MASTG-TECH-0023 sebagai bagian tak terpisahkan dari evaluasi, meski tidak disebutkan sebagai langkah formal terpisah di overview test ini.

2. **Nama variabel adalah petunjuk kuat, tetapi bukan bukti mutlak.** Variabel bernama `password` yang di-log hampir pasti temuan sah. Namun variabel bernama generik (`data`, `value`, `result`) yang sebenarnya berisi token tetap harus diperiksa isinya melalui penelusuran alur data (MASTG-TECH-0023 atau CodeQL Metode C) — jangan menyaring hanya berdasarkan pencarian kata kunci nama variabel.

3. **Perbedaan source code vs bytecode release sangat memengaruhi validitas temuan.** Test statis idealnya dijalankan pada **APK release final**, bukan source code development. Bila kamu hanya memiliki akses ke source code (audit white-box) tanpa APK release yang sudah di-build, catat secara eksplisit di laporan bahwa temuan ini **berpotensi tidak relevan** bila tim developer sudah menerapkan `-assumenosideeffects` sesuai MASTG-BEST-0002 — verifikasi ini penting agar tidak melebih-lebihkan risiko.

4. **`printStackTrace()` sering diabaikan karena tidak terlihat langsung membawa "variabel sensitif".** Namun exception message dan causal chain-nya bisa memuat detail yang tidak terduga — URL lengkap dengan query parameter berisi token, potongan payload request/response yang disisipkan library HTTP ke dalam pesan error. Jangan meremehkan temuan `printStackTrace()` hanya karena argumennya kosong (`e.printStackTrace()` tanpa parameter eksplisit).

5. **Lengkapi dengan MASTG-TEST-0203 untuk konfirmasi nilai runtime.** Test statis ini unggul dalam cakupan tetapi lemah dalam kepastian nilai. Untuk temuan yang ambigu dari sisi statis (variabel dengan nama tidak jelas, alur data kompleks), jalankan MASTG-TEST-0203 dengan canary value untuk mendapatkan bukti runtime yang definitif — lihat alur kerja gabungan di §1.4.

6. **Jangan lupa varian API yang tidak disebut eksplisit di overview (Timber, SLF4J, dll.).** Sama seperti dijelaskan mendalam di MASTG-TEST-0203 §1.4 Kelompok B, daftar enam API resmi MASTG bukan daftar lengkap seluruh permukaan logging aplikasi modern. Rule kustom (§3.3) sudah mencakup Timber sebagai contoh, tetapi sesuaikan dengan library yang benar-benar dipakai aplikasi target (diperiksa lewat dependency manifest/build.gradle bila tersedia).

7. **Output kosong tidak selalu berarti PASS murni tanpa kualifikasi.** Bila hasil grep kosong karena **obfuscation berat**, kode yang **dimuat secara dinamis** (DexClassLoader), atau **kode native** yang memanggil `__android_log_print` langsung (di luar cakupan analisis Java/Kotlin), catat sebagai keterbatasan analisis, bukan kesimpulan PASS tanpa syarat.

8. **Severity dimodulasi oleh jenis data dan konteks eksekusi kode:**

   | Faktor | Severity |
   |---|---|
   | Password/token/kunci kriptografi dicatat pada kode yang pasti dieksekusi di alur utama (login, transaksi) | **Tinggi** |
   | PII dicatat pada alur utama | **Tinggi** (+ dimensi privasi, profile P) |
   | Data sensitif dicatat hanya pada `catch` block untuk error yang jarang terjadi | **Menengah** — tetap FAIL, tetapi kemungkinan tereksploitasi lebih rendah |
   | Referensi API ditemukan di source tetapi terbukti ter-strip sempurna di build release (Metode E) | **Bukan temuan untuk risiko produksi** — catat sebagai potential jika `-assumenosideeffects` dicabut di masa depan |
   | Hanya pesan operasional generik (lifecycle, timing) yang dicatat | **Bukan temuan** |

9. **Dokumentasikan:** lokasi kode (file + baris) hasil dekompilasi, **kutipan variabel yang di-interpolasi** beserta penelusuran asalnya, apakah dikonfirmasi lewat MASTG-TEST-0203 (nilai runtime aktual) atau hanya lewat inferensi statis (nama variabel/konteks), status build yang diuji (source/debug/release), dan hasil verifikasi konfigurasi ProGuard/R8 bila relevan.

---

## 4. Rekomendasi Perbaikan

Karena akar masalahnya identik dengan MASTG-TEST-0203 (MASWE-0005 yang sama), seluruh rekomendasi mendalam — termasuk strategi stripping ProGuard/R8, custom logging facility, teknik redaksi/masking, dan peringatan penting tentang string yang tertinggal di bytecode meski pemanggilan `Log` sudah di-strip — **sudah dibahas lengkap di dokumen MASTG-TEST-0203 §4**. Rujuk dokumen tersebut untuk detail implementasi penuh.

Ringkasan prioritas yang relevan secara khusus untuk sudut pandang **statis**:

**Prioritas 1 — Jangan catat data sensitif sejak awal** (lihat MASTG-TEST-0203 §4.1 untuk daftar lengkap kategori yang harus dihindari).

**Prioritas 2 — Terapkan `-assumenosideeffects` di ProGuard/R8**, dan **verifikasi hasilnya** dengan Metode E di atas — jangan hanya mengasumsikan konfigurasi sudah bekerja karena tertulis di `proguard-rules.pro`. Bandingkan jumlah referensi API logging antara source code dan bytecode APK release final.

**Prioritas 3 — Untuk string yang dibangun dinamis, gunakan custom logging facility** dengan argumen sederhana yang dapat di-strip sepenuhnya, sesuai contoh detail di MASTG-TEST-0203 §4.1 (`SecureLog.v("prefix: ", key)` sebagai pengganti concatenation langsung).

**Prioritas 4 — Integrasikan test statis ini ke CI/CD** sebagai regression check, dijalankan pada setiap build **release** (bukan hanya debug), untuk menangkap regresi yang muncul dari perubahan dependency atau kode baru sebelum sampai ke produksi:

```bash
#!/bin/bash
# ci-check-logging-refs.sh — jalankan pada APK RELEASE hasil build
APK=$1
jadx -d /tmp/decompiled_check "$APK" 2>/dev/null
COUNT=$(rg -c "Log\.(v|d|i|w|e|wtf)\(|printStackTrace\(\)" /tmp/decompiled_check/sources/ 2>/dev/null | awk -F: '{sum+=$2} END {print sum+0}')
if [ "$COUNT" -gt "0" ]; then
    echo "[PERINGATAN] Ditemukan $COUNT referensi API logging di APK RELEASE — verifikasi apakah ini sudah sesuai kebijakan (log operasional non-sensitif) atau perlu di-strip lebih lanjut"
fi
```

**Prioritas 5 — Audit library pihak ketiga** yang dependency-nya dimuat ke dalam APK, karena referensi logging dari SDK vendor tidak selalu terlihat jelas sebagai bagian dari kode aplikasi sendiri saat pertama kali membaca hasil dekompilasi.

### 4.2 Checklist Remediasi

- [ ] Seluruh referensi API logging (`Log`, `Logger`, `System.out/err.print`, `printStackTrace`) di kode sudah diidentifikasi lewat analisis statis menyeluruh
- [ ] Setiap referensi sudah ditinjau dengan MASTG-TECH-0023 untuk menentukan variabel yang di-interpolasi dan asalnya
- [ ] Referensi yang membawa data sensitif (kredensial, PII, kunci) sudah dihapus atau dibungkus mekanisme redaksi
- [ ] Konfigurasi ProGuard/R8 `-assumenosideeffects` untuk `android.util.Log` sudah diterapkan dan **diverifikasi** pada bytecode APK release final (bukan hanya diasumsikan dari file konfigurasi)
- [ ] String yang dibangun dinamis untuk parameter log sudah dipastikan tidak tertinggal di bytecode setelah stripping (custom logging facility diterapkan bila perlu)
- [ ] `printStackTrace()` sudah ditinjau untuk memastikan exception yang ditangani tidak membawa payload sensitif dalam message/causal chain
- [ ] Library pihak ketiga (Timber, SLF4J, dll.) turut diperiksa untuk referensi logging tambahan
- [ ] Temuan statis sudah disilangkan dengan MASTG-TEST-0203 untuk konfirmasi nilai runtime pada kasus yang ambigu
- [ ] Test statis ini diintegrasikan sebagai regression check di CI/CD, dijalankan pada build release
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0231 pada APK release final setelah setiap perubahan kode/dependency
- [ ] **Verifikasi silang:** jalankan MASTG-TEST-0203 (dinamis) untuk memastikan tidak ada nilai sensitif yang benar-benar tercatat saat runtime

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0231: References to Logging APIs](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0231/)
- [MASTG-TEST-0203: Runtime Use of Logging APIs](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0203/)
- [MASTG-TEST-0003: Testing Logs for Sensitive Data](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0003/) *(deprecated — digantikan MASTG-TEST-0203 & 0231)*
- [MASWE-0005: Insertion of Sensitive Data into Logs](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0005/)
- [MASTG-KNOW-0049: Logs](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0049/)
- [MASTG-BEST-0002: Remove Logging Code](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0002/)
- [MASTG-TECH-0013: Reverse Engineering Android Apps](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/)
- [MASTG-TECH-0014: Static Analysis on Android](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/)
- [MASTG-TECH-0023: Reviewing Decompiled Java Code](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/)
- [MASTG-TOOL-0022: ProGuard](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0022/)
- [MASVS-STORAGE: Storage](https://mas.owasp.org/MASVS/05-MASVS-STORAGE/)
- [OWASP MASTG Repository (GitHub)](https://github.com/OWASP/mastg)
- [OWASP Mobile Top 10 2024 — M9: Insecure Data Storage](https://owasp.org/www-project-mobile-top-10/2023-risks/m9-insecure-data-storage)
- [OWASP Mobile Top 10 2024 — M1: Improper Credential Usage](https://owasp.org/www-project-mobile-top-10/2023-risks/m1-improper-credential-usage.html)

### 5.2 Dokumentasi Resmi Android / Google

- [Log Info Disclosure — Android Security Risks](https://developer.android.com/privacy-and-security/risks/log-info-disclosure)
- [`android.util.Log` — API reference](https://developer.android.com/reference/kotlin/android/util/Log)
- [`java.util.logging.Logger` — API reference](https://developer.android.com/reference/java/util/logging/Logger)
- [Shrink, obfuscate, and optimize your app (R8/ProGuard)](https://developer.android.com/build/shrink-code)
- [ProGuard manual — example of removing logging code (Guardsquare)](https://www.guardsquare.com/en/products/proguard/manual/examples#logging)
- [App security best practices](https://developer.android.com/privacy-and-security/security-best-practices)

### 5.3 Standar, Taksonomi, dan Guideline Lain

- [CWE-532: Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
- [CWE-359: Exposure of Private Personal Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/359.html)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [NIST SP 800-163 Rev.1 — Vetting the Security of Mobile Applications](https://csrc.nist.gov/publications/detail/sp/800-163/rev-1/final)

### 5.4 Dokumentasi Tools

- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [apktool — Reverse engineering Android APK files](https://apktool.org/)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
- [mobsfscan](https://github.com/MobSF/mobsfscan)
- [Timber — logging library (JakeWharton)](https://github.com/JakeWharton/timber)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026), dokumentasi resmi Android Developers. Test ini belum memiliki demo (MASTG-DEMO) resmi dari MASTG, dan merupakan counterpart statis dari MASTG-TEST-0203 — rujuk dokumen tersebut untuk pembahasan mendalam tentang lanskap risiko logging, jalur kebocoran, dan strategi remediasi lengkap.*
