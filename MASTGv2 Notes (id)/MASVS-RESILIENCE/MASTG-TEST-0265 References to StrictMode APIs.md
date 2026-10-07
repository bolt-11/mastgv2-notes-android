# MASTG-TEST-0265 References to StrictMode APIs

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0265 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-RESILIENCE |
| **Weakness** | MASWE-0061 — *Debug Artifacts Not Removed* |
| **API yang disorot** | `StrictMode` |
| **Tipe Pengujian** | **Static, Code** |
| **Profile** | **R (Resilience) saja** |
| **Teknik terkait** | MASTG-TECH-0013 (Reverse Engineering), MASTG-TECH-0014 (Static Analysis) |
| **Test terkait** | **MASTG-TEST-0263** (Logging of StrictMode Violations — dynamic/logs), **MASTG-TEST-0264** (Runtime Use of StrictMode APIs — dynamic/hooks). Ketiga test membentuk **trio lengkap** yang menyasar risiko sama (MASWE-0061) dari tiga sudut metodologi berbeda: statis, dinamis-hooking, dinamis-logging |
| **Demo terkait** | — (tidak ada) |
| **Rule resmi** | `mastg-android-strictmode.yml` — hanya mencocokkan `setVmPolicy(...)`, tidak mencakup `setThreadPolicy` (sama seperti dibahas di dokumen MASTG-TEST-0263 §3.2) |
| **CWE terkait** | CWE-215, CWE-489 |

---

## 1. Penjelasan

### 1.1 Posisi Test Ini dalam Trio Lengkap MASWE-0061

Bersama MASTG-TEST-0263 dan MASTG-TEST-0264, test ini melengkapi **trio metodologi lengkap** untuk satu weakness yang sama (MASWE-0061 — Debug Artifacts Not Removed) diterapkan pada `StrictMode`:

| Test | Tipe | Yang Diperiksa |
|---|---|---|
| **MASTG-TEST-0265** *(dokumen ini)* | Static | Apakah **kode sumber/bytecode** mengandung referensi API `StrictMode` sama sekali? |
| **MASTG-TEST-0264** | Dynamic, Hooks | Apakah API `StrictMode` **benar-benar dipanggil** saat aplikasi berjalan? |
| **MASTG-TEST-0263** | Dynamic, Logs | Apakah `StrictMode` yang aktif **benar-benar menghasilkan** log pelanggaran yang bisa dieksploitasi? |

Ketiganya bergerak dari **cakupan terluas namun paling tidak pasti** (statis — bisa saja hanya kode mati/tak tereksekusi) menuju **cakupan tersempit namun paling pasti** (logs — bukti langsung dampak nyata). Seluruh konteks konseptual mendalam tentang mengapa `StrictMode` berbahaya (kebocoran stack trace, nama kelas, baris kode yang mempermudah reverse engineering) sudah dibahas lengkap di dokumen **MASTG-TEST-0263** — dokumen ini fokus pada nuansa yang **spesifik untuk pendekatan statis**.

### 1.2 Nuansa Terpenting: Objek Analisis Menentukan Validitas Hasil — Source Code vs Bytecode APK Release

Ini adalah nuansa metodologis paling signifikan yang unik untuk test statis ini, dan **tidak berlaku** untuk MASTG-TEST-0263/0264 (yang keduanya secara inheren sudah menguji build produksi sungguhan karena sifatnya dinamis). Pertanyaannya: **objek apa** yang sedang dianalisis penguji?

**Skenario 1 — Whitebox, menganalisis source code proyek:**

```kotlin
class MyApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        if (BuildConfig.DEBUG) {
            StrictMode.setVmPolicy(...)  // <-- referensi ini SELALU ADA di source code
        }
    }
}
```

Bila penguji melakukan `grep`/pencarian pola langsung pada **source code** proyek, referensi `StrictMode.setVmPolicy` akan **selalu ditemukan** — terlepas dari apakah guard `BuildConfig.DEBUG` sudah diterapkan dengan benar atau tidak. Ini karena guard adalah **kondisi yang dievaluasi saat kompilasi/runtime**, bukan sesuatu yang menghilangkan teks kode dari source itu sendiri. **Menyimpulkan FAIL murni dari hasil pencarian source code semacam ini berpotensi salah** — kode tersebut mungkin **tidak pernah benar-benar masuk** ke build produksi.

**Skenario 2 — Blackbox, menganalisis bytecode hasil dekompilasi APK RELEASE:**

Di sinilah letak mekanisme yang menentukan validitas evaluasi test ini secara nyata: **R8** (shrinker/optimizer resmi Android untuk build release) melakukan **dead-code elimination**. Bila `BuildConfig.DEBUG` sudah dikompilasi sebagai konstanta `false` pada build release (perilaku standar Android Gradle Plugin), R8 **mampu mengenali** bahwa blok `if (BuildConfig.DEBUG) { ... }` tidak akan pernah tereksekusi, dan **menghapus seluruh blok tersebut** — termasuk pemanggilan `StrictMode.setVmPolicy()` di dalamnya — dari bytecode `classes.dex` final yang benar-benar dikemas ke dalam APK.

**Implikasi krusial**: hasil test ini **hanya valid dan bermakna** bila dilakukan terhadap **bytecode hasil dekompilasi APK release final** (via jadx/apktool), **bukan** terhadap source code proyek. Menganalisis source code akan menghasilkan **false positive sistematis** untuk setiap aplikasi yang sudah benar menerapkan guard `BuildConfig.DEBUG` — kode tersebut ada di source, tapi **tidak pernah** benar-benar sampai ke tangan pengguna/penyerang dalam bentuk yang bisa dieksekusi.

### 1.3 Mengapa Ketiadaan Referensi di Bytecode Release adalah Sinyal PASS yang Kuat

Justru karena mekanisme R8 di atas, **hasil PASS dari test statis ini (pada bytecode release) adalah sinyal yang sangat meyakinkan** — jauh lebih kuat dibanding sekadar "tidak ditemukan pelanggaran pada satu sesi pengujian" (MASTG-TEST-0263) atau "tidak terpicu hook pada satu sesi pengujian" (MASTG-TEST-0264), yang keduanya tetap rentan terhadap keterbatasan cakupan interaksi (jalur kode yang tidak sempat dipicu selama sesi pengujian). Bila `grep`/dekompilasi APK release **sama sekali tidak menemukan** simbol `StrictMode` di seluruh `classes.dex`, ini berarti API tersebut **secara struktural tidak mungkin dipanggil** — tidak peduli skenario interaksi seperti apa pun yang dicoba penguji dalam sesi dinamis mana pun.

### 1.4 Namun Sebaliknya — Ditemukannya Referensi di Bytecode Release adalah Sinyal FAIL yang Sangat Kuat

Kebalikannya juga berlaku dengan kekuatan yang sama: bila `StrictMode.setVmPolicy` (atau simbol terkait lainnya) **masih ditemukan** di bytecode hasil dekompilasi APK release, ini sinyal FAIL yang **tidak bisa dibantah** oleh argumen "tapi kebetulan tidak terpicu saat pengujian dinamis" — karena keberadaannya di bytecode final **membuktikan** guard `BuildConfig.DEBUG` **gagal** menghilangkannya (baik karena guard tidak diterapkan sama sekali, diterapkan secara salah, atau konfigurasi build/shrinking tidak berjalan sebagaimana mestinya). Inilah keunggulan unik pendekatan statis dibanding kedua pendekatan dinamis dalam trio ini — ia memberi **kepastian struktural**, bukan hanya "bukti dari satu sesi observasi".

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **jadx** | Dekompilasi DEX → Java dari **APK release final** (bukan source proyek) — krusial sesuai §1.2 |
| **grep / ripgrep** | Pencarian pola API `StrictMode` |
| **semgrep** | Menjalankan rule resmi sebagai baseline |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **rabin2 / strings** | Ekstraksi string langsung dari `classes.dex` tanpa dekompilasi penuh — cara cepat memeriksa keberadaan simbol `StrictMode` di bytecode mentah |
| **CodeQL** | Untuk whitebox testing pada source code — bila dipakai, **wajib** dikombinasikan dengan verifikasi guard `BuildConfig.DEBUG` (lihat §3.4) untuk menghindari false positive sesuai §1.2 |
| **diff antara build debug dan release** | Membandingkan hasil dekompilasi kedua varian build untuk mengonfirmasi secara empiris bahwa R8 benar-benar menghapus kode `StrictMode` pada build release |

### 2.3 Prasyarat Lingkungan

- **Tidak butuh device/root** — sepenuhnya dapat dilakukan dari file APK.
- **WAJIB menganalisis APK release final**, bukan source code proyek atau APK debug — ini prasyarat paling kritis sesuai §1.2, berbeda dari kebanyakan test statis lain dalam seri riset ini yang lebih fleksibel soal objek analisis.
- Bila hanya source code yang tersedia (whitebox murni tanpa APK release), **wajib** melengkapi hasil dengan verifikasi guard `BuildConfig.DEBUG` (§3.4) sebelum menyimpulkan apa pun.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0013** untuk reverse engineer aplikasi.
2. Gunakan **MASTG-TECH-0014** untuk mencari API yang relevan.

### 3.2 Metode A — Rule Semgrep Resmi pada Bytecode Release *(metode utama)*

```yaml
rules:
  - id: mastg-android-strictmode
    severity: WARNING
    languages: [java]
    message: "[MASVS-RESILIENCE] Detected usage of StrictMode"
    patterns:
      - pattern: StrictMode.setVmPolicy(...)
```

```bash
# WAJIB: dekompilasi dari APK RELEASE, bukan source proyek
jadx -d ./decompiled_release target-app-release.apk
semgrep --config https://raw.githubusercontent.com/OWASP/mastg/master/rules/mastg-android-strictmode.yml ./decompiled_release/sources/
```

**Celah cakupan yang sama seperti dibahas di dokumen MASTG-TEST-0263**: rule ini hanya mencakup `setVmPolicy()`, tidak `setThreadPolicy()`. Lengkapi dengan Metode B.

### 3.3 Metode B — grep/ripgrep dan Ekstraksi String Bytecode Langsung

```bash
D=./decompiled_release/sources

# Cakupan menyeluruh kedua API konfigurasi
rg -n 'StrictMode\.setVmPolicy\(|StrictMode\.setThreadPolicy\(|penaltyLog\(\)' $D

# Verifikasi langsung pada bytecode mentah TANPA dekompilasi penuh (lebih cepat, sulit dihindari obfuscation nama kelas)
unzip -o target-app-release.apk classes.dex -d /tmp/dex_check
strings /tmp/dex_check/classes.dex | grep -i "strictmode\|StrictMode"
```

**Catatan penting**: pencarian string langsung pada `classes.dex` (bukan hasil dekompilasi) memiliki keunggulan — nama kelas sistem seperti `android.os.StrictMode` **tidak pernah di-obfuscate** oleh ProGuard/R8 (karena merupakan API framework, bukan kode aplikasi sendiri), sehingga pencarian string sederhana ini **cukup andal** bahkan pada APK yang sudah di-obfuscate secara agresif.

### 3.4 Metode C — Verifikasi Guard `BuildConfig.DEBUG` (Wajib untuk Whitebox Source Code)

Bila analisis dilakukan pada source code (bukan APK release), verifikasi **wajib** bahwa setiap referensi ditemukan dalam kondisi guard yang benar:

```bash
rg -n -B5 'StrictMode\.setVmPolicy\(' ./src/ | grep -B5 "BuildConfig.DEBUG"
```

```ql
// CodeQL — pastikan SETIAP pemanggilan StrictMode berada di dalam guard BuildConfig.DEBUG
import java

class StrictModeCall extends MethodAccess {
  StrictModeCall() {
    this.getMethod().hasName(["setVmPolicy", "setThreadPolicy"]) and
    this.getMethod().getDeclaringType().hasQualifiedName("android.os", "StrictMode")
  }
}

from StrictModeCall call
where not exists(IfStmt guard |
  guard.getCondition().toString().matches("%BuildConfig.DEBUG%") and
  guard.getAChild*() = call.getEnclosingStmt())
select call, "Pemanggilan StrictMode TANPA guard BuildConfig.DEBUG — berpotensi lolos ke build release"
```

### 3.5 Metode D — Perbandingan Empiris Build Debug vs Release

Untuk memvalidasi secara langsung bahwa mekanisme R8 dead-code elimination benar-benar bekerja sesuai harapan (§1.2):

```bash
./gradlew assembleDebug assembleRelease

jadx -d ./out_debug app-debug.apk
jadx -d ./out_release app-release.apk

echo "=== Referensi StrictMode di build DEBUG ==="
rg -c 'StrictMode\.setVmPolicy' ./out_debug/sources/ | awk -F: '{sum+=$2} END {print sum+0}'

echo "=== Referensi StrictMode di build RELEASE ==="
rg -c 'StrictMode\.setVmPolicy' ./out_release/sources/ | awk -F: '{sum+=$2} END {print sum+0}'
```

Bila hasil build debug menunjukkan jumlah **>0** sementara build release menunjukkan **0**, ini bukti empiris langsung bahwa guard dan konfigurasi shrinking bekerja dengan benar — inilah pola PASS yang paling meyakinkan untuk test ini.

### 3.6 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Objek analisis | Kapan dipakai |
|---|---|---|---|
| **A** | Rule semgrep resmi | Bytecode APK release | Baseline, tapi cakupan API sempit |
| **B** | grep + strings pada dex | Bytecode APK release | **Baseline utama wajib**, robust terhadap obfuscation |
| **C** | CodeQL pada source | Source code | Hanya bermakna bila dikombinasikan dengan verifikasi guard |
| **D** | Perbandingan debug vs release | Kedua build | **Bukti empiris terkuat**, memvalidasi mekanisme end-to-end |

**Kombinasi minimum yang aku rekomendasikan:** **B (pada APK release final) → D (perbandingan empiris debug vs release)** sebagai bukti paling meyakinkan. Metode C hanya relevan sebagai pelengkap bila hanya source code yang tersedia, dan hasilnya **harus** dikualifikasi dengan status verifikasi guard, bukan disimpulkan berdiri sendiri.

---

### 3.7 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Observation:** *"The output should identify all instances of `StrictMode` usage in the app."*
>
> **Evaluation:** *"The test case fails if the app uses `StrictMode` APIs."*

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Referensi `StrictMode.setVmPolicy`/`setThreadPolicy` **ditemukan pada bytecode hasil dekompilasi APK RELEASE** — sinyal FAIL yang tidak bisa dibantah (§1.4) |
| F2 | Perbandingan build debug-release (Metode D) menunjukkan jumlah referensi **tidak berkurang** di build release — indikasi guard/shrinking gagal berfungsi |
| F3 | Analisis source code (whitebox) menemukan pemanggilan `StrictMode` **tanpa** guard `BuildConfig.DEBUG` sama sekali |

**Contoh bukti (ilustratif — MASTG belum menyediakan demo resmi untuk test ini):**

```bash
$ jadx -d ./decompiled_release target-app-release.apk
$ rg -n 'StrictMode\.setVmPolicy' ./decompiled_release/sources/
com/target/app/MyApplication.java:22:    StrictMode.setVmPolicy(policy)
```

Interpretasi: referensi ditemukan pada bytecode **APK release** yang sudah melalui proses build produksi penuh — ini bukti definitif bahwa guard (bila ada) gagal mencegah kode ini masuk ke build final. **FAIL**, terlepas dari hasil MASTG-TEST-0263/0264 pada sesi pengujian dinamis mana pun.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | **Tidak ditemukan** referensi `StrictMode` apa pun pada bytecode hasil dekompilasi APK release final (dikonfirmasi Metode B) — sinyal PASS terkuat sesuai §1.3 |
| P2 | Perbandingan build debug-release (Metode D) mengonfirmasi jumlah referensi berkurang menjadi nol tepat di build release |
| P3 | Untuk analisis source code semata (tanpa akses APK release): seluruh pemanggilan `StrictMode` yang ditemukan berada di dalam guard `BuildConfig.DEBUG` yang benar (namun kualifikasikan kesimpulan ini sebagai "PASS bersyarat" — rujuk §1.2) |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Ini catatan terpenting di seluruh dokumen ini: objek analisis menentukan validitas hasil.** Menjalankan pencarian pola pada source code proyek dan menyimpulkan FAIL murni dari situ, tanpa memverifikasi apakah kode tersebut benar-benar sampai ke bytecode release, adalah **kesalahan metodologis paling umum** untuk test ini. Selalu prioritaskan analisis terhadap **APK release final**.

2. **Hasil PASS pada bytecode release adalah bukti paling kuat di antara ketiga test trio** (0263/0264/0265) — karena sifatnya struktural (tidak ada API yang bisa dipanggil karena tidak ada di bytecode), bukan hanya "tidak teramati pada satu sesi pengujian".

3. **Nama simbol `StrictMode` tidak pernah di-obfuscate** (§3.3) — manfaatkan ini untuk melakukan pencarian string cepat dan andal langsung pada `classes.dex`, bahkan pada aplikasi dengan obfuscation nama kelas aplikasi yang agresif.

4. **Selalu korelasikan ketiga test dalam trio ini untuk laporan yang paling meyakinkan** — statis (struktural), hooking (konfirmasi pemanggilan), logs (konfirmasi dampak nyata). Ketiganya bersama-sama memberi gambaran yang jauh lebih lengkap dibanding satu test saja.

5. **Severity mengikuti pola yang sama seperti MASTG-TEST-0263/0264.**

6. **Dokumentasikan:** objek analisis yang dipakai (source code vs APK release — WAJIB dicatat eksplisit), hasil perbandingan build debug vs release bila dilakukan, lokasi referensi yang ditemukan, dan status guard `BuildConfig.DEBUG` bila menganalisis source code.

---

## 4. Rekomendasi Perbaikan

Rekomendasi identik dengan **dokumen MASTG-TEST-0263 §4** — bungkus seluruh pemanggilan `StrictMode` dengan guard `BuildConfig.DEBUG`.

Tambahan spesifik untuk validasi statis:

### 4.1 Verifikasi Konfigurasi Shrinking/R8 Aktif untuk Build Release

```gradle
// app/build.gradle
android {
    buildTypes {
        release {
            minifyEnabled true  // WAJIB aktif agar R8 dead-code elimination berjalan
            proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-rules.pro'
        }
    }
}
```

Tanpa `minifyEnabled true`, R8 shrinking **tidak berjalan sama sekali**, dan blok `if (BuildConfig.DEBUG)` — meski secara logis tidak akan pernah `true` di runtime — **tetap tertinggal secara tekstual** di bytecode release (meski secara fungsional tidak berbahaya karena kondisinya tidak akan pernah terpenuhi saat runtime, ia tetap akan terdeteksi oleh pencarian pola statis test ini).

### 4.2 Integrasikan Verifikasi Empiris ke CI/CD

```bash
#!/bin/bash
# ci-verify-strictmode-removed-from-release.sh
./gradlew assembleRelease
jadx -d /tmp/release_check app-release.apk 2>/dev/null
COUNT=$(rg -c 'StrictMode\.(setVmPolicy|setThreadPolicy)' /tmp/release_check/sources/ 2>/dev/null | awk -F: '{sum+=$2} END {print sum+0}')
if [ "$COUNT" -gt "0" ]; then
    echo "[GAGAL] StrictMode masih ditemukan di bytecode APK RELEASE ($COUNT referensi)!"
    exit 1
fi
echo "[OK] Tidak ada referensi StrictMode di APK release."
```

### 4.3 Checklist Remediasi

- [ ] Seluruh pemanggilan `StrictMode` dibungkus guard `BuildConfig.DEBUG`
- [ ] `minifyEnabled true` aktif untuk build type release
- [ ] Verifikasi empiris (Metode D) mengonfirmasi referensi hilang total di bytecode release
- [ ] CI/CD menyertakan gate otomatis untuk mendeteksi regresi (§4.2)
- [ ] Hasil dikorelasikan dengan MASTG-TEST-0263/0264 untuk validasi menyeluruh
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0265 pada APK release final setiap rilis

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0265: References to StrictMode APIs](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0265/)
- [MASTG-TEST-0263: Logging of StrictMode Violations](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0263/)
- [MASTG-TEST-0264: Runtime Use of StrictMode APIs](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0264/)
- [MASWE-0061: Debug Artifacts Not Removed](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0061/)
- [MASTG-TECH-0013: Reverse Engineering Android Apps](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/)
- [MASTG-TECH-0014: Static Analysis on Android](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/)
- [Rule resmi: mastg-android-strictmode.yml (GitHub)](https://github.com/OWASP/mastg/blob/master/rules/mastg-android-strictmode.yml)

### 5.2 Dokumentasi Resmi Android

- [Android Developers — `StrictMode` API reference](https://developer.android.com/reference/android/os/StrictMode)
- [Android Developers — Shrink, obfuscate, and optimize your app (R8)](https://developer.android.com/build/shrink-code)
- [Android Developers — `BuildConfig` reference](https://developer.android.com/reference/tools/gradle-api/8.0/com/android/build/api/variant/BuildConfigField)

### 5.3 Dokumentasi Tools

- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [radare2 / rabin2](https://github.com/radareorg/radare2)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026) dan dokumentasi resmi Android Developers seputar R8/ProGuard. Sebagai bagian ketiga dari trio lengkap yang menyasar MASWE-0061 pada `StrictMode` (bersama MASTG-TEST-0263 dan 0264), nuansa terpenting dokumen ini adalah bahwa **objek analisis menentukan validitas hasil secara fundamental** — pencarian pola pada source code proyek dapat menghasilkan false positive sistematis bila guard `BuildConfig.DEBUG` sudah diterapkan dengan benar, karena R8 dead-code elimination akan menghapus kode tersebut sepenuhnya dari bytecode APK release. Evaluasi yang valid menuntut analisis dilakukan terhadap **bytecode hasil dekompilasi APK release final**, bukan source code semata.*
