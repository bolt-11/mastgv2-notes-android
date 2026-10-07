# MASTG-TEST-0394 Missing Input Validation in Custom URL Scheme Handlers

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0394 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-PLATFORM |
| **Weakness** | MASWE-0029 |
| **Tipe Pengujian** | Static, Code, **Manual** |
| **API terkait** | `getData`, `getQueryParameter` |
| **Teknik terkait** | MASTG-TECH-0013, MASTG-TECH-0014, MASTG-TECH-0023, MASTG-TECH-0173 (Monitoring Deep Link Handlers at Runtime with Frida) |
| **Knowledge terkait** | MASTG-KNOW-0019 (Deep Links) |
| **Best Practice terkait** | MASTG-BEST-0071 (Validate Input Parameters in Deep Link and Custom URL Scheme Handlers) |
| **Test terkait** | **MASTG-TEST-0393** — dokumen terkait dalam seri riset ini (App Links yang terverifikasi); test ini menyasar **custom URL scheme** yang secara desain **tidak pernah** diverifikasi OS sama sekali |
| **Rule resmi** | `mastg-android-deeplink-unvalidated-parameter.yml` — rule "jujur" yang murni observasional, lihat §1.4 |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian dan Perbedaan Fundamental dengan MASTG-TEST-0393

Kutipan overview resmi MASTG:

> *"Apps register custom URL schemes by declaring an `<intent-filter>`... with a `<data>` element whose `android:scheme` is a custom (non-http/https) value... Apps must validate and sanitize these URL parameters before using them in security-sensitive operations."*

Perbedaan krusial dengan MASTG-TEST-0393 yang sudah dibahas dalam seri riset ini: App Links (`http`/`https`) **bisa** diverifikasi lewat mekanisme `autoVerify` + Digital Asset Links. **Custom URL scheme tidak memiliki mekanisme verifikasi serupa sama sekali** — ini bukan soal "lupa mengaktifkan verifikasi", melainkan **keterbatasan arsitektural permanen**. Konsekuensinya, test ini tidak menyasar *apakah skema terverifikasi* (tidak relevan, karena memang tidak bisa), melainkan menyasar **bagaimana aplikasi menangani fakta bahwa siapa pun bisa memanggilnya** — yaitu lewat validasi input yang memadai.

### 1.2 Tiga Contoh Payload Konkret yang Mencerminkan Tiga Kelas Kerentanan Berbeda

Overview memberi tiga contoh yang masing-masing mewakili kelas kerentanan web klasik, kini diterjemahkan ke konteks parameter deep link:

| Payload | Kelas Kerentanan | Dampak |
|---|---|---|
| `myapp://transfer?amount=-1` atau `amount=9999999` | **Business logic bypass** | Melewati batas nilai transaksi yang sah |
| `myapp://open?path=../../data/sensitive.txt` | **Path traversal** | Akses file di luar direktori yang dimaksud |
| `myapp://search?q=<script>alert(1)</script>` | **Script injection (XSS)** | Eksekusi JavaScript bila dirender di WebView |

Ketiga contoh ini menegaskan bahwa parameter deep link **bukan sekadar risiko navigasi**, melainkan **titik masuk input yang setara dengan form HTTP** — setiap kelas kerentanan web klasik yang biasa diuji di aplikasi web punya padanannya di konteks parameter deep link mobile.

### 1.3 Nuansa Fundamental: Android Tidak Memiliki Mekanisme Identifikasi Pengirim

Ini adalah batasan arsitektural yang membuat validasi input menjadi **satu-satunya** garis pertahanan yang tersedia, bukan sekadar praktik baik tambahan:

> *"Unlike iOS, Android provides no mechanism to identify which app sent the Intent. There is no equivalent to iOS's sourceApplication property, so the handler cannot verify the caller's identity, and every custom URL scheme handler is effectively reachable by any app on the device."*

Ini berarti tidak ada cara bagi handler untuk "mempercayai" pengirim tertentu berdasarkan identitasnya — **setiap** permintaan yang masuk lewat custom URL scheme harus diperlakukan setara, datang dari sumber yang sepenuhnya tidak tepercaya, terlepas dari seberapa yakin developer bahwa permintaan tersebut "biasanya" datang dari komponen internal aplikasi sendiri atau mitra terpercaya.

### 1.4 Analisis Rule Resmi: Desain "Jujur" yang Murni Observasional

Rule `mastg-android-deeplink-unvalidated-parameter.yml` memiliki karakteristik yang **secara sengaja terbatas** dan transparan tentang keterbatasannya:

```yaml
pattern-either:
  - pattern: $INTENT.getData()
  - pattern: $URI.getQueryParameter(...)
message: 'A deep link handler reads the incoming URI... Verify each value is validated... before it is used.'
```

Rule ini **tidak mencoba** menilai apakah validasi benar-benar ada atau tidak — ia **hanya menunjukkan lokasi** di mana parameter dibaca, lalu secara eksplisit mendelegasikan penilaian sesungguhnya ke manusia lewat kata "Verify" di pesannya sendiri. Ini adalah desain yang **jujur** dibanding beberapa rule lain dalam seri riset ini yang mengklaim kapabilitas evaluasi lebih dari yang sebenarnya mereka lakukan — rule ini tidak berpretensi mendeteksi "missing validation" secara otomatis (yang memang mustahil dilakukan pattern-matching semata, karena validasi bisa berbentuk apa saja: type conversion, bounds check, sanitasi, allowlist — empat bentuk berbeda yang disebut eksplisit di §1.6). Ini konsisten dengan tipe `manual` test ini — rule hanya berfungsi sebagai **peta lokasi** untuk mempercepat review manusia, bukan pengganti penilaian manusia itu sendiri.

### 1.5 Pengecualian Penting: Tidak Semua Parameter Butuh Validasi Ketat

Catatan resmi memberi nuansa pengecualian yang penting untuk menghindari over-flagging:

> *"If the app intentionally accepts arbitrary parameter values (for example, a search scheme that passes user-typed text to a search UI), input validation may not be required and this test may not apply."*

Ini relevan — parameter `q` pada skema pencarian (`myapp://search?q=apapun`) **secara desain** memang dimaksudkan menerima teks bebas dari pengguna; "validasi" yang dibutuhkan di sini bukan membatasi isi teksnya, melainkan memastikan **tujuan pemrosesan selanjutnya** (misalnya rendering di WebView) aman terhadap teks bebas tersebut — yang mengarah balik ke pertanyaan XSS di §1.2, bukan soal "menolak" parameter semata.

### 1.6 Empat Kategori Validasi yang Hilang (Kerangka Diagnostik)

Bagian "Further Validation Required" memberi kerangka empat kategori kegagalan validasi yang konkret:

> *"Missing type conversion... Missing bounds or range checks... Missing sanitization... Missing allowlist checks: a parameter that selects a resource or action is not validated against an allowlist."*

Kategori keempat (allowlist) sering terlewat namun penting — bila parameter dipakai untuk **memilih** resource/aksi dari himpunan terbatas (misalnya `myapp://action?type=share` vs `type=delete`), validasi yang benar bukan sekadar "menyaring karakter berbahaya", melainkan **menolak seluruh nilai yang tidak ada dalam daftar putih** yang diketahui sah — pendekatan allowlist secara inheren lebih kuat dibanding pendekatan denylist/sanitasi karakter yang selalu berisiko ada kasus yang terlewat.

### 1.7 Bukti Nyata: CVE-2026-23866 pada WhatsApp

Ini adalah bukti nyata yang sangat relevan — kerentanan terbaru pada **WhatsApp**, salah satu aplikasi dengan basis pengguna terbesar di dunia, yang secara persis melibatkan validasi tidak lengkap terhadap penanganan custom URL scheme:

> *"CVE-2026-23866 is a medium-severity input validation flaw affecting WhatsApp for iOS and Android, residing in the handling of AI rich response messages for Instagram Reels. Incomplete validation of these messages allowed a remote user to trigger processing of media content from an arbitrary URL on another user's device, with the flaw also permitting invocation of operating-system controlled custom URL scheme handlers."*

Ini menunjukkan bahwa **kurangnya validasi** terhadap sumber URL yang disematkan dalam pesan dapat dieksploitasi untuk memicu aplikasi memproses/mengambil konten dari URL yang sepenuhnya dikendalikan penyerang, **sekaligus** memicu pemanggilan custom URL scheme handler lain di sistem. Konteks tambahan tentang skala dampak serupa secara umum:

> *"Custom URL scheme vulnerabilities in real-world attack scenarios may allow threat actors to redirect users to phishing sites and launch other apps and services on the device via URL schemes such as facetime:, tel:, itms-apps:, or custom app deep links."*

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **jadx** | Dekompilasi DEX → Java untuk review manual handler (MASTG-TECH-0013, MASTG-TECH-0023) |
| **Semgrep** + rule resmi | Lokasi cepat pemanggilan `getData()`/`getQueryParameter()` (MASTG-TECH-0014) |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **Frida + Android Deep Link Observer** | Verifikasi dinamis — mengamati handler method dan parameter yang benar-benar diproses saat runtime (MASTG-TECH-0173) |
| **ADB (`am start -a VIEW -d`)** | Mengirim payload uji (negative amount, path traversal, script injection) langsung ke handler |

### 2.3 Prasyarat Lingkungan

- Analisis statis tidak butuh device/root.
- Verifikasi dinamis (Frida) butuh device rooted/emulator dengan aplikasi target terinstal.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0013** untuk reverse engineer aplikasi.
2. Gunakan **MASTG-TECH-0014** untuk mencari API yang relevan.

### 3.2 Metode A — Semgrep dengan Rule Resmi (Lokasi, Bukan Evaluasi)

```bash
semgrep --config mastg-android-deeplink-unvalidated-parameter.yml ./decompiled/sources
```

### 3.3 Metode B — Review Manual Berdasarkan Empat Kategori Diagnostik (Wajib, Sesuai §1.6)

Untuk setiap lokasi hasil Metode A:

```bash
D=./decompiled/sources
rg -n -A10 'getQueryParameter\(' $D
```

Verifikasi masing-masing:
1. **Type conversion** — apakah ada `toIntOrNull()`/`toLongOrNull()`/parsing dengan penanganan error?
2. **Bounds check** — apakah ada perbandingan `<`/`>`/range setelah konversi?
3. **Sanitization** — apakah nilai string dipakai langsung di operasi file/SQL/WebView tanpa escaping/parameterisasi?
4. **Allowlist** — bila parameter memilih aksi/resource, apakah dicocokkan terhadap daftar nilai sah yang diketahui?

### 3.4 Metode C — Verifikasi Dinamis dengan Frida dan Payload Uji (Sesuai MASTG-TECH-0173)

```bash
frida -U -f com.example.app -l android_deep_link_observer.js --no-pause
```

```bash
# Uji business logic bypass
adb shell am start -a android.intent.action.VIEW -d "myapp://transfer?amount=-1"

# Uji path traversal
adb shell am start -a android.intent.action.VIEW -d "myapp://open?path=../../data/sensitive.txt"

# Uji script injection
adb shell am start -a android.intent.action.VIEW -d "myapp://search?q=<script>alert(1)</script>"
```

Amati hasil hook untuk melihat handler method yang terpanggil dan apakah payload berbahaya berhasil memengaruhi perilaku aplikasi.

### 3.5 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Kapan dipakai |
|---|---|---|
| **A** | Semgrep + rule resmi | Baseline — hanya menunjukkan lokasi, bukan hasil evaluasi |
| **B** | Review manual | **Wajib** — inti pengujian, menilai empat kategori validasi |
| **C** | Frida + payload uji | Verifikasi dinamis konklusif dengan payload nyata |

**Kombinasi minimum yang aku rekomendasikan:** **A (lokasi) → B (wajib) → C (verifikasi konklusif)**.

---

### 3.6 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Evaluation:** *"The test case fails if a custom URL scheme handler uses URL parameter values without performing adequate validation before acting on them."*

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Parameter dari custom URL scheme dipakai di operasi sensitif (finansial, file, WebView, query) tanpa satu pun dari empat kategori validasi (§1.6) yang relevan |

**Contoh bukti (merefleksikan skenario resmi §1.2):**

```kotlin
override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    val amount = intent.data?.getQueryParameter("amount") // String mentah, tidak dikonversi
    processTransfer(amount) // langsung diteruskan tanpa validasi tipe/batas
}
```

**FAIL** — tidak ada type conversion maupun bounds check; `amount=-1` atau `amount=9999999` dapat langsung memengaruhi logika transfer.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Parameter numerik dikonversi dengan penanganan error (`toLongOrNull()`), **dan** divalidasi batas nilainya, **atau** |
| P2 | Parameter string disanitasi sesuai sink tujuannya (path canonicalization, parameterized query, escaping WebView), **atau** |
| P3 | Parameter pemilih aksi/resource dicocokkan terhadap allowlist, **atau** |
| P4 | Parameter memang dimaksudkan menerima nilai bebas (search text) **dan** sink tujuannya sudah aman terhadap nilai bebas tersebut (§1.5) |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Jangan mengandalkan rule resmi sebagai indikator FAIL/PASS** — sesuai §1.4, rule ini secara desain hanya menunjukkan lokasi, bukan hasil evaluasi; setiap lokasi **wajib** direview manual terhadap empat kategori §1.6.

2. **Bedakan "parameter bebas yang disengaja" dari "parameter yang seharusnya dibatasi"** — sesuai §1.5, jangan menandai skema pencarian/teks bebas sebagai temuan hanya karena menerima nilai apa pun; fokus pada apakah sink tujuan pemrosesan aman.

3. **Uji dengan payload nyata, bukan hanya membaca kode** — sesuai Metode C, verifikasi dinamis dengan payload uji konkret memberi bukti paling kuat bahwa validasi (atau ketidakhadirannya) benar-benar berdampak pada perilaku aplikasi.

4. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | Path traversal/script injection/business logic bypass pada operasi finansial berhasil dikonfirmasi dinamis | **Tinggi** |
   | Missing validation pada parameter non-kritis | **Sedang** |
   | Parameter bebas yang disengaja dengan sink aman | **Bukan temuan** |

5. **Dokumentasikan:** lokasi handler, parameter yang dibaca, kategori validasi yang hilang/ada, dan hasil payload uji dinamis (bila dilakukan).

---

## 4. Rekomendasi Perbaikan

### 4.1 Terapkan Keempat Kategori Validasi Sesuai Konteks (MASTG-BEST-0071)

```kotlin
// Type conversion + bounds check
val amount = uri.getQueryParameter("amount")?.toLongOrNull() ?: return
if (amount <= 0 || amount > 10_000) return

// Path traversal prevention
val requestedFile = File(baseDir, uri.getQueryParameter("path") ?: return)
if (!requestedFile.canonicalPath.startsWith(baseDir.canonicalPath)) return

// Allowlist untuk parameter pemilih aksi
val action = uri.getQueryParameter("action")
if (action !in setOf("share", "view", "edit")) return
```

### 4.2 Checklist Remediasi

- [ ] Parameter numerik dikonversi dengan penanganan error dan divalidasi batas nilainya
- [ ] Parameter path/file dicek canonical path-nya tetap di dalam direktori yang diizinkan
- [ ] Parameter yang dirender di WebView disanitasi/di-escape sesuai konteks
- [ ] Parameter pemilih aksi/resource dicocokkan terhadap allowlist
- [ ] Diverifikasi dengan payload uji dinamis (negative amount, `../`, `<script>`)
- [ ] Flow sensitif dipertimbangkan dimigrasikan ke App Links terverifikasi (MASTG-BEST-0070) daripada custom URL scheme

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0394 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0394.md)
- [MASTG-TEST-0393 (dokumen terkait dalam seri riset ini)](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0393/)
- [MASTG-KNOW-0019: Deep Links](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0019/)
- [MASTG-BEST-0071: Validate Input Parameters in Deep Link and Custom URL Scheme Handlers](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0071.md)
- [MASTG-TECH-0173: Monitoring Deep Link Handlers at Runtime with Frida](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0173/)

### 5.2 Riset dan Kasus Nyata

- [SentinelOne: CVE-2026-23866 — WhatsApp Custom URL Scheme Input Validation Flaw](https://www.sentinelone.com/vulnerability-database/cve-2026-23866/)
- [Ines Martins: Exploiting Deep Links in Android — Part 1](https://inesmartins.github.io/exploiting-deep-links-in-android-part1/index.html)

### 5.3 Dokumentasi Tools

- [Frida CodeShare: Android Deep Link Observer](https://codeshare.frida.re/@leolashkevych/android-deep-link-observer/)
- [Semgrep Documentation](https://semgrep.dev/docs/)

---

*Dokumen ini disusun berdasarkan konten resmi OWASP MASTG (`tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0394.md`, `MASTG-KNOW-0019`, `MASTG-BEST-0071`, `MASTG-TECH-0173`), analisis rule `mastg-android-deeplink-unvalidated-parameter.yml` yang secara desain jujur hanya berfungsi sebagai peta lokasi tanpa klaim evaluasi otomatis, serta CVE-2026-23866 pada WhatsApp sebagai bukti nyata terbaru dan sangat relevan. Nuansa metodologis terpenting: berbeda dari App Links (TEST-0393) yang bisa diverifikasi OS, custom URL scheme **secara arsitektural tidak pernah** memiliki mekanisme verifikasi pengirim — validasi input di level handler adalah **satu-satunya** garis pertahanan yang tersedia, bukan sekadar praktik baik tambahan. Empat kategori validasi (type conversion, bounds check, sanitasi, allowlist) harus dinilai satu per satu secara manual, karena tidak ada cara otomatis untuk memverifikasi "kecukupan" validasi semata dari pattern-matching kode.*
