# MASTG-TEST-0372 Implicit Intents Used for Internal App Communication

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0372 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-CODE |
| **Weakness** | MASWE-0032 |
| **Tipe Pengujian** | Static, Code, **Manual** |
| **Teknik terkait** | MASTG-TECH-0013, MASTG-TECH-0014, MASTG-TECH-0023 |
| **Knowledge terkait** | MASTG-KNOW-0025 (Explicit vs Implicit Intents) |
| **Best Practice terkait** | MASTG-BEST-0056 (Use Explicit Intents for Internal IPC) |
| **Test terkait** | Berkaitan erat dengan MASTG-TEST-0364/0365/0366 (exported component) — temuan test ini sering menjadi **sumber** yang mengaktifkan risiko di test-test tersebut dari sisi pengirim |
| **Rule resmi** | `mastg-android-implicit-intent-internal-communication.yml` — ditemukan **kesenjangan cakupan signifikan**, lihat §1.5 |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Kutipan overview resmi MASTG:

> *"An implicit intent is an Intent that does not name a concrete target component. Instead, it declares an action, and optionally data or categories, and Android resolves it to an installed component with a matching `<intent-filter>`."*

Penting dicatat: implicit intent **bukan secara inheren berbahaya**. Overview secara eksplisit mengakui penggunaan sah yang luas:

> *"Android apps commonly use implicit intents when they intentionally delegate an action to another app selected by the system or the user. Typical legitimate uses include opening a web page or map location with ACTION_VIEW, sharing content with ACTION_SEND, requesting a file or image with ACTION_GET_CONTENT."*

Masalah muncul secara spesifik ketika mekanisme yang dirancang untuk **delegasi lintas-aplikasi yang disengaja** dipakai secara keliru untuk **komunikasi yang seharusnya tetap internal**.

### 1.2 Mekanisme Intent Hijacking: Dua Skenario Berbeda Tergantung Jumlah Pencocok

> *"If the system presents a chooser, the user may select the third-party app; if only one matching handler exists or a default handler has been set, the intent may be delivered without an explicit user decision."*

Ini mengungkap dua jalur eksploitasi yang berbeda tingkat keterlibatan pengguna:

| Skenario | Mekanisme | Peran Pengguna |
|---|---|---|
| **Banyak pencocok, tidak ada default** | Sistem menampilkan chooser dialog | Pengguna **bisa** secara tidak sadar memilih aplikasi berbahaya (rekayasa sosial via nama/ikon yang menipu) |
| **Hanya satu pencocok (app berbahaya terinstal lebih dulu/satu-satunya), atau default handler sudah diset** | Sistem mengirim otomatis **tanpa dialog** | **Tidak ada keterlibatan pengguna sama sekali** — penyerang cukup menginstal aplikasi dengan `<intent-filter>` yang cocok |

Skenario kedua jauh lebih berbahaya karena **tidak memerlukan interaksi/kelengahan pengguna apa pun** — intersepsi terjadi sepenuhnya diam-diam di level sistem.

### 1.3 Daftar API yang Relevan: Cakupan Lebih Luas dari Sekadar startActivity

Overview secara eksplisit mendaftar banyak API yang relevan, melampaui yang biasa dipikirkan orang:

> *"Relevant creation and dispatch patterns include `Intent(String)`, `Intent().setAction(...)`, `startActivity`, `startActivityForResult`, `ActivityResultLauncher.launch`, `startService`, `bindService`, `sendBroadcast`, and related APIs."*

Ini menegaskan bahwa risiko ini **melampaui Activity** — `startService`/`bindService` (menghubungkan ke risiko Service di TEST-0365) dan `sendBroadcast` (menghubungkan ke TEST-0366) sama-sama relevan di sini, karena **ketiga jenis komponen** dapat menjadi target implicit intent yang salah arah.

### 1.4 Perlindungan Platform Modern: Android 14 Melarang Implicit Intent Internal Secara Total

Ini adalah informasi paling penting untuk konteks severity dan rekomendasi — MASTG-KNOW-0025 mengungkap perubahan platform yang sangat signifikan:

> *"If the application targets Android 14 (API level 34) or higher, implicit intents will never be sent to internal components. This feature forces developers to implement explicit intents for internal communication, as otherwise the application would not function correctly while testing."*

Ini berarti bagi aplikasi yang **sudah** menargetkan API 34+, kesalahan ini **akan terdeteksi otomatis saat testing fungsional biasa** (aplikasi akan gagal berfungsi, bukan sekadar rentan secara diam-diam) — sebuah bentuk "fail-safe by design" dari platform. Namun ini juga berarti **temuan test ini jauh lebih relevan untuk aplikasi dengan `targetSdkVersion` di bawah 34** yang masih bisa menjalankan kode bermasalah ini tanpa pernah menyadarinya lewat testing fungsional normal.

### 1.5 Temuan Analitis Kritis: Rule Resmi Hanya Mencakup Satu dari Enam API Dispatch yang Disebut Overview

Perhatikan pola rule `mastg-android-implicit-intent-internal-communication.yml`:

```yaml
patterns:
  - pattern: |
      $INTENT = new Intent(...);
      ...
      $INTENT.setAction($ACTION);
      ...
      $CONTEXT.startActivity($INTENT);
  # (pattern-not untuk setPackage/setComponent/explicit constructor)
languages: [java]
```

Rule ini **secara eksklusif** hanya mencocokkan pola yang diakhiri `startActivity()`. Namun overview resmi (§1.3) secara eksplisit mendaftar **enam** API dispatch yang relevan: `startActivity`, `startActivityForResult`, `ActivityResultLauncher.launch`, `startService`, `bindService`, `sendBroadcast`. Rule resmi **hanya mencakup satu dari enam** — implicit intent yang dikirim lewat `startService()`/`bindService()` (risiko langsung terhubung ke TEST-0365) atau `sendBroadcast()` (terhubung ke TEST-0366) **sama sekali tidak akan terdeteksi** oleh rule ini, meski keduanya disebut secara eksplisit sebagai vektor yang relevan di overview test ini sendiri.

Kesenjangan kedua: rule ini **hanya berbahasa Java** (`languages: [java]`), sementara seluruh contoh kode resmi di MASTG-KNOW-0025 dan MASTG-BEST-0056 justru ditulis dalam **Kotlin**. Ini berarti basis kode Kotlin modern (yang menjadi standar de facto pengembangan Android baru) akan sepenuhnya lolos dari rule ini terlepas dari pola implicit intent yang dipakai.

### 1.6 Bukti Nyata: Dari Tampering Database Firewall hingga Kebocoran ICCID/IMSI di Aplikasi Vendor Besar

Riset keamanan mendokumentasikan beberapa CVE nyata yang persis mengilustrasikan risiko ini:

> *"An implicit intent hijacking vulnerability in Firewall application (CVE-2023-42552) allows 3rd party application to tamper the database of Firewall."*

> *"Implicit Intent hijacking vulnerability in AppLinker allows attackers to launch certain activities with privilege of AppLinker."*

Yang paling mengkhawatirkan — kerentanan serupa ditemukan pada aplikasi **vendor besar**, bukan hanya aplikasi niche:

> *"Xiaomi's Phone Services app was vulnerable to implicit intent hijacking that exposed system values such as ICCID or IMSI of virtual SIMs."*

Mekanisme eksploitasi umum yang terdokumentasi menjelaskan secara teknis bagaimana hijacking terjadi lewat manipulasi prioritas:

> *"When multiple services have the same intent-filter, the service with higher priority is chosen to process corresponding intents. A malicious app has a service X with the same intent-filter as that of the service Y in a benign app and with higher priority than Y... service X in the malicious app will be started."*

Ini menambah nuansa penting — penyerang tidak hanya mengandalkan "menjadi satu-satunya pencocok", tapi juga bisa secara aktif **memenangkan kompetisi** melawan komponen internal yang sah lewat `android:priority` yang lebih tinggi pada `<intent-filter>` miliknya.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **jadx** | Dekompilasi DEX → Java/Kotlin (MASTG-TECH-0013) |
| **Semgrep** + rule resmi | Deteksi dasar `startActivity` dengan implicit intent (cakupan terbatas, §1.5) |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **grep/ripgrep** | **Wajib** — menutup celah lima API dispatch lain (`startService`, `bindService`, `sendBroadcast`, `startActivityForResult`, `ActivityResultLauncher.launch`) dan kode Kotlin |
| **MobSF** | Laporan otomatis yang kadang menyertakan deteksi dasar intent |

### 2.3 Prasyarat Lingkungan

- Tidak butuh device/root — murni analisis statis.
- Catat `targetSdkVersion` aplikasi di awal (§1.4) untuk kalibrasi severity.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0013** untuk reverse engineer aplikasi.
2. Gunakan **MASTG-TECH-0014** untuk mencari API yang relevan.

### 3.2 Metode A — Semgrep dengan Rule Resmi (Cakupan Terbatas)

```bash
semgrep --config mastg-android-implicit-intent-internal-communication.yml ./decompiled/sources
```

### 3.3 Metode B — grep/ripgrep untuk Menutup Celah Lima API Dispatch Lain dan Kotlin (Wajib)

```bash
D=./decompiled/sources

# Konstruksi implicit intent di Kotlin maupun Java
rg -n 'Intent\("|setAction\(' $D

# Lima API dispatch yang TIDAK tercakup rule resmi
rg -n '\.startService\(|\.bindService\(|\.sendBroadcast\(|\.startActivityForResult\(|ActivityResultLauncher.*\.launch\(' $D

# Verifikasi apakah ada setPackage/setComponent/setClass sebagai mitigasi
rg -n -B10 'startService\(|sendBroadcast\(' $D | grep -E 'setPackage|setComponent|setClass'
```

### 3.4 Metode C — Review Manual (Wajib, Sesuai MASTG-TECH-0023)

Untuk setiap hasil Metode A/B, verifikasi:

1. Apakah intent memiliki `setPackage`/`setComponent`/konstruktor explicit — bila tidak, lanjutkan.
2. Apakah action yang dipakai adalah action **kustom aplikasi** (mis. `com.example.app.INTERNAL_ACTION`) yang jelas dimaksudkan internal, bukan action standar Android (`ACTION_VIEW`, dsb.) yang memang sengaja didelegasikan ke aplikasi eksternal.
3. Untuk broadcast, periksa apakah ada permission pengirim yang membatasi penerima.

### 3.5 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Kapan dipakai |
|---|---|---|
| **A** | Semgrep + rule resmi | Baseline, hanya `startActivity` + Java |
| **B** | grep/ripgrep manual | **Wajib** — cakupan lengkap lima API lain + Kotlin |
| **C** | Review manual | **Wajib** — membedakan action internal vs delegasi eksternal yang sah |

**Kombinasi minimum yang aku rekomendasikan:** **B (baseline sesungguhnya) → C (wajib)**, dengan Metode A hanya pelengkap kecil.

---

### 3.6 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Evaluation:** *"The test case fails if an intent used for app-internal or trusted-component communication is implicit and another app can declare or register a matching component to receive it."*

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Intent dimaksudkan untuk komunikasi internal/trusted-component, bersifat implicit (tanpa `setPackage`/`setComponent`/constructor explicit), **dan** aplikasi lain dapat mendaftarkan `<intent-filter>` yang cocok |

**Contoh bukti (merefleksikan pola nyata CVE-2023-42552 §1.6):**

```kotlin
val intent = Intent("com.example.firewall.UPDATE_RULES").apply {
    putExtra("rule_data", sensitiveRuleConfig)
}
sendBroadcast(intent) // implicit, tidak tercakup rule Semgrep resmi (§1.5)
```

Interpretasi: broadcast internal untuk update konfigurasi firewall dikirim secara implicit — aplikasi berbahaya dapat mendaftarkan receiver dengan action yang sama untuk mencegat/memanipulasi data konfigurasi. **FAIL**.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Intent internal memakai `setPackage`/`setComponent`/konstruktor explicit `Intent(context, Class)`, **atau** |
| P2 | Intent implicit memang dimaksudkan untuk delegasi ke aplikasi eksternal pilihan pengguna/sistem (ACTION_VIEW, ACTION_SEND, dsb.) — bukan kategori temuan untuk test ini |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Jangan hanya mengandalkan rule resmi** — sesuai §1.5, lima dari enam API dispatch yang disebut overview tidak tercakup, dan rule hanya berbahasa Java meski contoh resmi memakai Kotlin.

2. **Bedakan action kustom internal vs action standar sistem** — action seperti `"com.example.app.*"` yang jelas milik aplikasi sendiri adalah kandidat kuat, berbeda dari `ACTION_VIEW`/`ACTION_SEND` standar yang memang didesain untuk delegasi eksternal.

3. **Pertimbangkan `targetSdkVersion`** — temuan pada aplikasi dengan target API 34+ kemungkinan sudah "self-correcting" karena platform melarang pengiriman implicit intent ke komponen internal (§1.4); temuan ini jauh lebih kritis pada aplikasi dengan target API di bawah itu.

4. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | Implicit intent internal membawa data sensitif (kredensial, konfigurasi keamanan) pada `targetSdkVersion` < 34 | **Tinggi** |
   | Implicit intent internal tanpa data sensitif | **Sedang** |
   | `targetSdkVersion` ≥ 34 (platform sudah memitigasi secara otomatis) | **Rendah** (tetap dicatat sebagai code smell) |

5. **Dokumentasikan:** lokasi kode, action yang dipakai, API dispatch, ada/tidaknya `setPackage`/`setComponent`, data yang dibawa (extras), dan `targetSdkVersion` aplikasi.

---

## 4. Rekomendasi Perbaikan

### 4.1 Gunakan Explicit Intent untuk Komunikasi Internal (Sesuai MASTG-BEST-0056)

```kotlin
// SEBELUM — implicit, rentan hijacking
val intent = Intent("com.example.app.PROCESS_DATA").apply {
    putExtra("key", "value")
}
startActivity(intent)

// SESUDAH — explicit by component, paling ketat
val intent = Intent(context, TargetActivity::class.java).apply {
    putExtra("key", "value")
}
startActivity(intent)
```

### 4.2 Checklist Remediasi

- [ ] Seluruh intent untuk komunikasi internal memakai `setComponent`/konstruktor explicit atau minimal `setPackage`
- [ ] Verifikasi mencakup kelima API dispatch (`startService`, `bindService`, `sendBroadcast`, `startActivityForResult`, `ActivityResultLauncher.launch`), tidak hanya `startActivity`
- [ ] Tidak ada data sensitif (token, kredensial) dibawa lewat implicit intent
- [ ] Broadcast internal memakai permission pengirim bila tidak bisa dibuat explicit

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0372 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-CODE/MASTG-TEST-0372.md)
- [MASTG-KNOW-0025: Explicit vs Implicit Intents](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0025/)
- [MASTG-BEST-0056: Use Explicit Intents for Internal IPC](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0056.md)

### 5.2 Riset dan Kasus Nyata

- [GitHub Advisory: CVE-2023-42552 — Implicit Intent Hijacking in Firewall Application](https://github.com/advisories/GHSA-qcqr-cxwj-882p)
- [Oversecured: Interception of Android Implicit Intents](https://blog.oversecured.com/Interception-of-Android-implicit-intents/)
- [Medium: Intent Hijacking in Android — What It Is and How to Prevent It](https://medium.com/@iam_azhar/intent-hijacking-in-android-what-it-is-and-how-to-prevent-it-ebb5a075f229)
- [CWE-927: Use of Implicit Intent for Sensitive Communication](https://exploit-intel.com/cwe/CWE-927)

### 5.3 Dokumentasi Tools

- [Semgrep Documentation](https://semgrep.dev/docs/)
- [Android Developers: Safer Intents (Android 14 Behavior Changes)](https://developer.android.com/about/versions/14/behavior-changes-14#safer-intents)

---

*Dokumen ini disusun berdasarkan konten resmi OWASP MASTG (`tests-beta/android/MASVS-CODE/MASTG-TEST-0372.md`, `MASTG-KNOW-0025`, `MASTG-BEST-0056`), analisis rule `mastg-android-implicit-intent-internal-communication.yml`, serta riset keamanan yang mendokumentasikan CVE nyata (CVE-2023-42552 tampering database Firewall app, kebocoran ICCID/IMSI pada Xiaomi Phone Services). Nuansa metodologis terpenting: rule resmi hanya mencakup satu dari enam API dispatch yang disebut eksplisit di overview test ini sendiri (`startActivity` saja, melewatkan `startService`/`bindService`/`sendBroadcast`/`startActivityForResult`/`ActivityResultLauncher.launch`), dan hanya berbahasa Java meski seluruh contoh kode resmi MASTG untuk topik ini ditulis dalam Kotlin — pencarian manual yang mencakup kelima API lain dan sintaks Kotlin adalah kewajiban, bukan pelengkap opsional. Android 14+ memberi mitigasi platform otomatis untuk kasus activity internal, menjadikan temuan ini jauh lebih kritis pada aplikasi dengan target API di bawah itu.*
