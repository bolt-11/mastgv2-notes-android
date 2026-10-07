# MASTG-TEST-0291 References to Screen Capturing Prevention APIs

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0291 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-PLATFORM |
| **Weakness** | MASWE-0038 — *Insufficient Protection of Sensitive Data from Screenshots or Screen Recordings* (sama seperti MASTG-TEST-0289) |
| **API yang disorot** | `Window.addFlags()`, `Window.setFlags()`, `Window.clearFlags()`, konstanta `WindowManager.LayoutParams.FLAG_SECURE` |
| **Tipe Pengujian** | Static, Code |
| **Knowledge** | MASTG-KNOW-0053 |
| **Best Practice** | MASTG-BEST-0014 (Preventing Screenshots and Screen Recording) |
| **Teknik terkait** | MASTG-TECH-0013, MASTG-TECH-0014 |
| **Test terkait** | **MASTG-TEST-0289** (Runtime Verification of Sensitive Content Exposure in Screenshots — counterpart dinamis; test tersebut membuktikan **hasil visual nyata**, test ini memetakan **lokasi kode** yang mengontrol `FLAG_SECURE`) |
| **Demo terkait** | — (tidak ada) |
| **Rule resmi** | `mastg-android-flag-secure-enable-flags.yml` (ID sesuai isi: `mastg-android-flag-secure-enable-flags`) — **hanya mendeteksi pengaktifan**, sama sekali tidak mencakup `clearFlags()` yang justru menjadi separuh dari definisi FAIL resmi (lihat §3.2) |
| **CWE terkait** | CWE-200, CWE-311 |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian dan Hubungannya dengan MASTG-TEST-0289

Kutipan overview resmi MASTG:

> *"This test verifies whether an app references Android screen capture prevention APIs... Developers typically apply the flag with `addFlags()` or `setFlags()`."*

Test ini adalah **counterpart statis** dari **MASTG-TEST-0289** yang sudah dibahas mendalam dalam seri riset ini. Seluruh konteks konseptual inti — mengapa Android mengambil screenshot otomatis saat backgrounding, mekanisme `FLAG_SECURE`, dan **celah timing race condition** yang membuat audit statis saja tidak cukup — sudah dijelaskan lengkap di dokumen tersebut. Dokumen ini berfokus pada nilai unik pendekatan statis: **memetakan konsistensi penerapan** `FLAG_SECURE` di seluruh basis kode, sebuah pertanyaan yang secara inheren lebih mudah dijawab lewat analisis kode menyeluruh dibanding pengujian dinamis yang terbatas pada skenario yang benar-benar dipicu penguji.

### 1.2 Dua Mode Kegagalan yang Secara Eksplisit Disebut Overview Resmi

Ini bagian paling penting dari overview test ini — ia secara eksplisit menyebut **dua pola kegagalan berbeda**, bukan hanya satu:

> *"Common failure modes include **not setting** `FLAG_SECURE` on all sensitive screens **or clearing the flag** during transitions e.g., using `clearFlags()` or `setFlags()`."*

| Mode Kegagalan | Deskripsi | Contoh |
|---|---|---|
| **1. Tidak konsisten diterapkan** | `FLAG_SECURE` diterapkan pada **sebagian** layar sensitif, tapi terlewat pada layar lain yang setara sensitivitasnya | Layar "Konfirmasi Pembayaran" dilindungi, tapi layar "Riwayat Transaksi" (menampilkan data yang sama sensitifnya) tidak |
| **2. Sengaja dihapus di tengah alur** | Kode secara eksplisit memanggil `clearFlags(FLAG_SECURE)` pada suatu titik dalam siklus hidup Activity yang sama, menonaktifkan proteksi yang tadinya sudah aktif | Developer menghapus flag sementara untuk menampilkan dialog "Bagikan" yang butuh screenshot, namun lupa mengaktifkannya kembali setelah dialog ditutup |

Mode kegagalan kedua ini secara khusus menarik karena ia adalah **regresi yang disengaja** — bukan kelalaian tidak menambahkan proteksi sejak awal, melainkan **penghapusan proteksi yang sudah ada** untuk kebutuhan fungsional tertentu (mis. memungkinkan fitur "screenshot untuk berbagi" pada bagian layar tertentu), yang kemudian **berisiko tidak dipulihkan** dengan benar pada seluruh jalur kode yang mungkin dilalui pengguna setelahnya.

### 1.3 Kriteria Evaluasi yang Menuntut Analisis Konsistensi, Bukan Sekadar Keberadaan

Klausul Evaluation resmi test ini dirumuskan dengan cermat untuk menangkap kedua mode kegagalan sekaligus:

> *"The test case fails if the relevant APIs are **missing** or **inconsistently applied** on any UI component that displays sensitive data, or if code paths **clear the protection without an adequate justification**."*

Frasa **"inconsistently applied"** dan **"clear the protection without an adequate justification"** menegaskan bahwa test ini menuntut **pemahaman holistik atas seluruh basis kode** — penguji tidak cukup menemukan satu pemanggilan `FLAG_SECURE` dan menyimpulkan PASS; ia harus **memetakan setiap layar sensitif** (hasil prasyarat `identify-sensitive-screens`, sama seperti MASTG-TEST-0289) dan memverifikasi **masing-masing** memiliki proteksi yang konsisten sepanjang siklus hidupnya, termasuk memeriksa **apakah ada justifikasi yang memadai** untuk setiap pemanggilan `clearFlags()` yang ditemukan.

Frasa "without an adequate justification" ini secara implisit **mengakui** bahwa ada skenario legitimate untuk menghapus `FLAG_SECURE` sementara (mis. fitur bagikan tangkapan layar yang memang disengaja untuk konten yang **saat itu** sudah tidak sensitif) — namun ini menuntut **penilaian kontekstual manual** atas setiap kasus `clearFlags()` yang ditemukan, bukan aturan biner sederhana "clearFlags() = selalu FAIL".

### 1.4 Sifat Cross-Cutting `FLAG_SECURE`: Mengapa Konsistensi Sulit Dicapai dalam Praktik

Berbeda dari banyak kontrol keamanan lain yang bisa diterapkan sekali secara terpusat (mis. interceptor jaringan tunggal, satu lapisan enkripsi database), `FLAG_SECURE` bersifat **per-window/per-Activity** — ia harus **secara eksplisit diterapkan di setiap tempat yang relevan**, tidak ada mekanisme bawaan Android untuk "menerapkan secara global ke seluruh aplikasi sekaligus". Ini menciptakan **cross-cutting concern** klasik dalam rekayasa perangkat lunak: sebuah kekhawatiran keamanan yang **tersebar** di banyak lokasi kode yang tidak saling terhubung secara struktural, sehingga **sangat rentan terhadap inkonsistensi** seiring aplikasi berkembang — developer baru yang menambahkan Activity baru untuk fitur finansial baru bisa dengan mudah **lupa** menyalin pola `FLAG_SECURE` dari Activity serupa yang sudah ada, karena tidak ada mekanisme compiler/lint yang secara otomatis memaksanya.

Inilah **nilai unik pendekatan statis** dibanding pendekatan dinamis (MASTG-TEST-0289): analisis statis dapat **membangun peta lengkap** dari seluruh Activity/Fragment yang ada dalam aplikasi dan mengidentifikasi mana yang **seharusnya** memiliki `FLAG_SECURE` (berdasarkan konten yang ditampilkan) namun **tidak memilikinya** — sebuah perbandingan sistematis yang jauh lebih sulit dicapai lewat pengujian dinamis yang bergantung pada penguji secara manual mengunjungi setiap layar satu per satu.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **jadx** | Dekompilasi DEX → Java untuk pencarian pola `FLAG_SECURE` |
| **grep / ripgrep** | Pencarian pola API dan analisis konteks penghapusan flag |
| **semgrep** | Menjalankan rule resmi sebagai baseline (dengan catatan celah cakupan, §3.2) |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **CodeQL** | Membangun **peta lengkap** seluruh `Activity`/`Fragment` dalam aplikasi, mengorelasikan dengan keberadaan `FLAG_SECURE`, dan mendeteksi `clearFlags()` yang tidak diikuti pemulihan `addFlags()` sebelum Activity berpindah state — kunci untuk menjawab kriteria "inconsistently applied" (§1.3) |
| **jadx-gui "Find Usage"** | Menelusuri seluruh Activity yang ada dalam manifest untuk membangun daftar lengkap kandidat "layar yang seharusnya dilindungi" berdasarkan nama/konten (`PaymentActivity`, `PinEntryActivity`, dsb.) |
| **MobSF** | Kadang menampilkan status penggunaan `FLAG_SECURE` di ringkasan Code Analysis |
| **Frida** | Hooking `addFlags()`/`clearFlags()` untuk konfirmasi runtime urutan pemanggilan pada Activity spesifik, melengkapi hasil statis dengan bukti dinamis (jembatan ke MASTG-TEST-0289) |

### 2.3 Prasyarat Lingkungan

- **Tidak butuh device/root** untuk analisis statis inti.
- **Identifikasi seluruh layar sensitif terlebih dahulu** (prasyarat `identify-sensitive-screens`) sebagai daftar acuan lengkap yang harus dicek — bukan hanya mencari pola `FLAG_SECURE` secara pasif dan berhenti di situ.
- **Pahami struktur navigasi aplikasi** (Activity/Fragment/Compose Navigation) untuk menilai apakah `clearFlags()` yang ditemukan benar-benar dipulihkan pada semua jalur kembali yang mungkin.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0013** untuk reverse engineer aplikasi.
2. Gunakan **MASTG-TECH-0014** untuk mencari API yang relevan.

### 3.2 Metode A — Rule Semgrep Resmi *(ada, tapi hanya menutup separuh definisi FAIL)*

```yaml
rules:
  - id: mastg-android-flag-secure-enable-flags
    severity: INFO
    languages: [java]
    metadata:
      summary: Window uses FLAG_SECURE to block screenshots.
    message: "[MASVS-PLATFORM] Make sure you use this flag for all screens with sensitive data"
    pattern-either:
      - patterns:
          - pattern: $W.addFlags($F)
          - metavariable-regex: { metavariable: $F, regex: ^(FLAG_SECURE|8192|0x2000)$ }
      - patterns:
          - pattern: $W.setFlags($FLAGS, $FLAGS)
          - metavariable-regex: { metavariable: $FLAGS, regex: ^(FLAG_SECURE|8192|0x2000)$ }
```

```bash
semgrep --config https://raw.githubusercontent.com/OWASP/mastg/master/rules/mastg-android-sensitive-data-in-screenshot.yml ./decompiled/sources/
```

**Celah cakupan yang signifikan**: rule ini secara eksplisit **hanya mendeteksi pola pengaktifan** (`addFlags`/`setFlags` dengan `FLAG_SECURE`) — sama sekali **tidak ada pattern** untuk `clearFlags()`. Ini berarti rule resmi **hanya menjawab separuh** dari definisi FAIL resmi (§1.2/§1.3) — ia dapat membantu menemukan mode kegagalan #1 (screen yang tidak memiliki `FLAG_SECURE` sama sekali, secara tidak langsung lewat hasil kosong pada file tersebut), namun **sama sekali tidak dapat mendeteksi** mode kegagalan #2 (`clearFlags()` yang menghapus proteksi tanpa justifikasi). Pesan `summary` rule ini sendiri secara jujur konsisten dengan cakupannya (*"Window uses FLAG_SECURE to block screenshots"* — hanya klaim mendeteksi penggunaan, tidak mengklaim menilai kekonsistenan), berbeda dari beberapa rule lain dalam seri riset ini yang klaimnya menyesatkan.

### 3.3 Metode B — grep/ripgrep untuk Mode Kegagalan #2 (clearFlags)

```bash
D=./decompiled/sources

# Temukan seluruh pemanggilan clearFlags dengan FLAG_SECURE
rg -n 'clearFlags\(.*FLAG_SECURE|clearFlags\(8192\)|clearFlags\(0x2000\)' $D

# Untuk setiap kemunculan, periksa apakah ada pemulihan (addFlags) di jalur kode berikutnya
rg -n -A20 'clearFlags\(.*FLAG_SECURE' $D | grep -A20 "clearFlags" | grep -c "addFlags.*FLAG_SECURE"
```

### 3.4 Metode C — CodeQL untuk Peta Lengkap Konsistensi Activity

```ql
import java

class ActivityClass extends Class {
  ActivityClass() {
    this.getASupertype*().hasQualifiedName("android.app", "Activity")
  }
}

class FlagSecureAdd extends MethodAccess {
  FlagSecureAdd() {
    this.getMethod().hasName(["addFlags", "setFlags"]) and
    this.getAnArgument().toString().matches("%FLAG_SECURE%")
  }
}

class FlagSecureClear extends MethodAccess {
  FlagSecureClear() {
    this.getMethod().hasName("clearFlags") and
    this.getAnArgument().toString().matches("%FLAG_SECURE%")
  }
}

// Bagian 1: Activity yang namanya mengindikasikan sensitivitas TAPI tidak ada FLAG_SECURE
from ActivityClass activity
where activity.getName().toLowerCase().regexpMatch(".*(payment|pin|password|card|wallet|otp).*")
  and not exists(FlagSecureAdd add | add.getEnclosingCallable().getDeclaringType() = activity)
select activity, "Activity dengan nama mengindikasikan data sensitif TANPA FLAG_SECURE ditemukan"
```

```ql
// Bagian 2: clearFlags tanpa pemulihan addFlags pada method yang sama
from FlagSecureClear clear
where not exists(FlagSecureAdd add |
  add.getEnclosingCallable() = clear.getEnclosingCallable() and
  add.getControlFlowNode().getASuccessor*() = clear.getControlFlowNode())
select clear, "clearFlags(FLAG_SECURE) ditemukan tanpa pemulihan addFlags yang jelas pada method yang sama"
```

### 3.5 Metode D — Frida untuk Konfirmasi Urutan Runtime (Jembatan ke MASTG-TEST-0289)

```javascript
// hook-flag-secure-sequence.js
Java.perform(function () {
    var Window = Java.use("android.view.Window");
    var FLAG_SECURE = 0x00002000;

    Window.addFlags.overload("int").implementation = function (flags) {
        if ((flags & FLAG_SECURE) !== 0) console.log("[+] FLAG_SECURE ditambahkan");
        return this.addFlags(flags);
    };
    Window.clearFlags.overload("int").implementation = function (flags) {
        if ((flags & FLAG_SECURE) !== 0) console.log("[-] FLAG_SECURE DIHAPUS");
        return this.clearFlags(flags);
    };
});
```

```bash
frida -U -f com.target.app -l hook-flag-secure-sequence.js --no-pause
```

### 3.6 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Mode kegagalan #1 (missing)? | Mode kegagalan #2 (clearFlags)? | Kapan dipakai |
|---|---|---|---|---|
| **A** | Rule semgrep resmi | Sebagian (tidak langsung) | ❌ | Baseline cepat, cakupan terbatas |
| **B** | grep clearFlags | ❌ | ✅ | Menutup celah rule resmi |
| **C** | CodeQL | ✅ (peta lengkap) | ✅ | **Paling bernilai** — kedua mode kegagalan sekaligus |
| **D** | Frida | N/A (statis→dinamis) | ✅ (urutan nyata) | Konfirmasi runtime |

**Kombinasi minimum yang aku rekomendasikan:** **C (CodeQL untuk peta lengkap kedua mode kegagalan) → B (pelengkap grep cepat) → D (konfirmasi dinamis, korelasi dengan MASTG-TEST-0289)**. Rule resmi (A) dapat dipakai sebagai referensi awal tapi tidak cukup untuk kesimpulan lengkap.

---

### 3.7 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Evaluation:** *"The test case fails if the relevant APIs are missing or inconsistently applied on any UI component that displays sensitive data, or if code paths clear the protection without an adequate justification."*

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Layar yang teridentifikasi sensitif (prasyarat) **sama sekali tidak** memiliki pemanggilan `FLAG_SECURE` |
| F2 | `FLAG_SECURE` diterapkan **tidak konsisten** — beberapa layar sensitif terlindungi, layar lain dengan sensitivitas setara tidak |
| F3 | Ditemukan `clearFlags(FLAG_SECURE)` **tanpa justifikasi yang jelas** dan **tanpa pemulihan** proteksi sebelum konten sensitif kembali ditampilkan |

**Contoh bukti (ilustratif — MASTG belum menyediakan demo resmi untuk test ini):**

```java
// PaymentConfirmationActivity.java — TERLINDUNGI
protected void onCreate(Bundle savedInstanceState) {
    getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
    super.onCreate(savedInstanceState);
}
```

```java
// TransactionHistoryActivity.java — TIDAK ADA FLAG_SECURE sama sekali
protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    // Menampilkan riwayat transaksi lengkap dengan nominal dan deskripsi
}
```

Interpretasi: `PaymentConfirmationActivity` terlindungi, namun `TransactionHistoryActivity` — yang sama-sama menampilkan data finansial sensitif — **tidak memiliki proteksi apa pun**. **FAIL** sesuai kriteria "inconsistently applied" (§1.2 mode kegagalan #1).

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | **Seluruh** layar yang teridentifikasi sensitif memiliki `FLAG_SECURE` diterapkan secara konsisten |
| P2 | Setiap kemunculan `clearFlags(FLAG_SECURE)` yang ditemukan disertai justifikasi jelas (mis. transisi ke layar non-sensitif) **dan** dipulihkan sebelum kembali menampilkan konten sensitif |
| P3 | Peta CodeQL (Metode C) tidak menemukan Activity dengan indikasi konten sensitif yang kekurangan proteksi |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Jangan berhenti setelah menemukan satu contoh `FLAG_SECURE` yang benar** — kriteria "inconsistently applied" menuntut pemetaan **seluruh** layar sensitif, bukan sampel tunggal. Satu Activity yang terlindungi dengan baik tidak menjamin Activity lain yang setara sensitivitasnya juga terlindungi.

2. **Rule resmi hanya menutup separuh definisi FAIL** — wajib melengkapi dengan pencarian `clearFlags()` secara terpisah (Metode B/C), karena rule resmi sama sekali tidak mencakup mode kegagalan ini.

3. **Nilai "adequate justification" pada `clearFlags()` menuntut penilaian kontekstual manual** — tidak semua `clearFlags()` otomatis FAIL; periksa apakah konten pada titik tersebut benar-benar sudah tidak sensitif dan proteksi dipulihkan dengan benar sebelum konten sensitif kembali tampil.

4. **Korelasikan dengan MASTG-TEST-0289 untuk pembuktian definitif** — hasil statis di sini menunjukkan lokasi kode kandidat, tapi bukti visual nyata (screenshot yang benar-benar bocor) tetap membutuhkan pengujian dinamis, terutama mengingat celah timing race condition yang dibahas mendalam di dokumen tersebut.

5. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | Layar finansial/kredensial sama sekali tanpa `FLAG_SECURE` | **Tinggi** |
   | `clearFlags()` tanpa pemulihan pada jalur yang bisa kembali ke konten sensitif | **Tinggi** |
   | Inkonsistensi antar-layar dengan sensitivitas setara | **Menengah-Tinggi** |
   | `clearFlags()` dengan justifikasi jelas dan pemulihan benar | **Bukan temuan** |

6. **Dokumentasikan:** daftar lengkap layar sensitif beserta status `FLAG_SECURE` masing-masing (peta konsistensi), lokasi dan konteks setiap `clearFlags()` yang ditemukan, dan penilaian justifikasi untuk masing-masing.

---

## 4. Rekomendasi Perbaikan

Rujuk **dokumen MASTG-TEST-0289 §4** untuk rekomendasi implementasi teknis lengkap (`FLAG_SECURE` sejak `onCreate()`, granularitas per-Activity).

Tambahan spesifik untuk konsistensi lintas-kode:

### 4.1 Sentralisasi Logika Proteksi Lewat Base Activity/Fragment

```kotlin
abstract class SecureActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        super.onCreate(savedInstanceState)
    }
}

// Seluruh Activity sensitif WAJIB extend SecureActivity, bukan Activity/AppCompatActivity langsung
class PaymentConfirmationActivity : SecureActivity() { /* ... */ }
class TransactionHistoryActivity : SecureActivity() { /* ... */ }
```

Pola ini mengubah cross-cutting concern (§1.4) menjadi **kewajiban struktural** — developer baru yang lupa memilih base class yang benar akan lebih mudah terdeteksi lewat code review, dan lint rule kustom dapat ditambahkan untuk memaksa seluruh Activity yang menampilkan data tertentu mewarisi `SecureActivity`.

### 4.2 Audit dan Dokumentasikan Setiap `clearFlags()`

```kotlin
// SELALU sertakan komentar yang menjelaskan mengapa aman menghapus proteksi di titik ini
fun showShareableReceiptView() {
    window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)  // Aman: konten sudah di-redact sebelum titik ini
    // ...
    window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)  // WAJIB pulihkan sebelum Activity ini menampilkan data lain
}
```

### 4.3 Integrasikan Peta Konsistensi ke CI/CD

```bash
#!/bin/bash
# ci-check-flag-secure-consistency.sh
codeql database analyze ./cqldb ./flag-secure-consistency.ql --format=sarif-latest --output=result.sarif
if grep -q "FLAG_SECURE" result.sarif; then
    echo "[PERINGATAN] Ditemukan inkonsistensi FLAG_SECURE — tinjau hasil CodeQL"
fi
```

### 4.4 Checklist Remediasi

- [ ] Seluruh layar sensitif hasil pemetaan prasyarat memiliki `FLAG_SECURE` yang diterapkan konsisten
- [ ] Pola sentralisasi (base Activity/Fragment) diterapkan untuk mencegah inkonsistensi di masa depan
- [ ] Setiap `clearFlags(FLAG_SECURE)` didokumentasikan dengan justifikasi jelas dan dipulihkan dengan benar
- [ ] CodeQL/lint kustom diintegrasikan ke CI/CD untuk mendeteksi Activity baru yang kekurangan proteksi
- [ ] Hasil dikorelasikan dengan MASTG-TEST-0289 untuk pembuktian dinamis
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0291 setiap penambahan Activity/layar baru

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0291: References to Screen Capturing Prevention APIs](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0291/)
- [MASTG-TEST-0289: Runtime Verification of Sensitive Content Exposure in Screenshots During App Backgrounding](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0289/)
- [MASWE-0038: Insufficient Protection of Sensitive Data from Screenshots or Screen Recordings](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0038/)
- [MASTG-BEST-0014: Preventing Screenshots and Screen Recording](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0014/)
- [Rule resmi: mastg-android-sensitive-data-in-screenshot.yml (GitHub)](https://github.com/OWASP/mastg/blob/master/rules/mastg-android-sensitive-data-in-screenshot.yml)

### 5.2 Dokumentasi Resmi Android

- [Android Developers — Secure Sensitive Activities (Fraud Prevention)](https://developer.android.com/security/fraud-prevention/activities)
- [Android Developers — `Window#addFlags()`](https://developer.android.com/reference/android/view/Window#addFlags(int))
- [Android Developers — `Window#setFlags()`](https://developer.android.com/reference/android/view/Window#setFlags(int,int))
- [Android Developers — `Window#clearFlags()`](https://developer.android.com/reference/android/view/Window#clearFlags(int))

### 5.3 Dokumentasi Tools

- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [Frida — Dynamic instrumentation toolkit](https://frida.re/docs/javascript-api/)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)

### 5.4 CWE

- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [CWE-311: Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026) dan dokumentasi resmi Android Developers. Sebagai counterpart statis dari MASTG-TEST-0289, nilai unik test ini adalah kemampuan membangun **peta konsistensi menyeluruh** atas seluruh layar sensitif dalam aplikasi — sesuatu yang sulit dicapai lewat pengujian dinamis semata. Rule semgrep resmi ditemukan hanya menutup separuh dari dua mode kegagalan yang secara eksplisit disebut overview resmi (missing vs clearFlags tanpa justifikasi) — CodeQL dengan analisis struktural menyeluruh menjadi metode yang paling bernilai untuk menjawab kriteria evaluasi "inconsistently applied" yang menuntut pemahaman holistik atas basis kode, bukan sekadar deteksi pola lokal.*
