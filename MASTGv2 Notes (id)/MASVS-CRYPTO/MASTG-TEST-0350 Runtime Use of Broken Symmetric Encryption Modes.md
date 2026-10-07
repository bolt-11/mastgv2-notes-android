# MASTG-TEST-0350 Runtime Use of Broken Symmetric Encryption Modes

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0350 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-CRYPTO |
| **Weakness** | MASWE-0007 — *Improper Encryption* |
| **Tipe Pengujian** | Dynamic, Hooks, **Manual** |
| **Teknik terkait** | MASTG-TECH-0005 (Installing Apps), MASTG-TECH-0043 (Method Hooking), MASTG-TECH-0023 (Reviewing Decompiled Java Code) |
| **Best Practice terkait** | MASTG-BEST-0005 (Use Secure Encryption Modes) |
| **Test terkait** | **MASTG-TEST-0232** — counterpart **statis** yang menganalisis transformation string di kode; test ini adalah **konfirmasi runtime** (lihat §1.2 untuk nilai tambah spesifiknya) |
| **Rule resmi** | — (tidak ada; test murni dinamis, konsisten dengan sifat test lain dalam kategori ini) |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Kutipan overview resmi MASTG:

> *"If the app configures cryptographic operations with broken encryption modes at runtime, sensitive data can be exposed to pattern leakage and other cryptographic weaknesses. This test checks whether the running app sets insecure block modes, such as ECB, in security-relevant cryptographic flows."*

Ini adalah pasangan dinamis dari **MASTG-TEST-0232** yang sudah dibahas sebelumnya dalam seri riset ini — fokus kedua test sama (mode operasi block cipher, khususnya ECB), namun **metode verifikasinya berbeda secara fundamental**.

### 1.2 Nilai Tambah Spesifik Dibanding Analisis Statis: Menangkap Transformation String yang Tidak Hardcoded

Ini adalah alasan utama mengapa test dinamis ini diperlukan sebagai pelengkap TEST-0232, bukan duplikasi. Analisis statis (TEST-0232) bekerja dengan mencari **literal string** seperti `"AES/ECB/PKCS5Padding"` di kode terdekompilasi. Namun bila transformation string **dibangun secara dinamis** — misalnya diambil dari file konfigurasi remote, digabung dari beberapa variabel, atau di-decode dari Base64/obfuskasi saat runtime — pattern matching statis **tidak akan pernah menemukannya**, karena literal string tersebut **tidak pernah muncul secara utuh** di bytecode yang didekompilasi.

Test dinamis ini menutup celah tersebut secara elegan: dengan meng-hook `Cipher.getInstance()` langsung, penguji menangkap **nilai transformation string sesungguhnya** tepat pada saat dipanggil saat runtime — tidak peduli apakah string tersebut berasal dari literal, hasil concatenation, decode, atau nilai yang diterima dari server. Ini adalah pola nilai tambah yang konsisten dengan pasangan static/dynamic lain dalam seri riset ini (mis. TEST-0318/0319) — statis menemukan kandidat yang *terlihat* di kode, dinamis menangkap apa yang *benar-benar terjadi*, termasuk kasus yang sengaja/tidak sengaja tersembunyi dari pembacaan kode sumber.

### 1.3 Struktur Observasi: Transformation String Beserta Backtrace

> **Observation:** *"The output should contain a list of calls to encryption configuration APIs, including the transformation string argument and backtraces of each call."*

Backtrace (call stack) di sini memiliki peran yang sama pentingnya seperti pada test-test hooking lain dalam seri riset ini (mis. TEST-0319, TEST-0350 sejenis) — ia menunjukkan **jalur kode** yang memicu pemanggilan `Cipher.getInstance()` dengan mode bermasalah, memudahkan penguji melompat langsung ke lokasi kode yang relevan untuk investigasi lanjutan (§1.4), tanpa perlu menelusuri seluruh basis kode dari awal.

### 1.4 Validasi Lanjutan Wajib: Bukan Semua Penggunaan ECB Sama Bahayanya

> **Further Validation Required:** *"Using the backtraces from the hook output, inspect the code locations using MASTG-TECH-0023 to determine whether the encryption is applied to sensitive data: Determine whether the data being encrypted or decrypted is sensitive (e.g., personal data, authentication tokens, cryptographic keys, or session identifiers)."*

Ini konsisten dengan prinsip yang sudah dibahas di TEST-0232 — ECB secara teknis "rusak" tanpa syarat (deterministik, bocor pola), namun **relevansi keamanan temuan** bergantung pada **apa yang dienkripsi**. Menemukan `Cipher.getInstance("AES/ECB/NoPadding")` dipanggil terhadap data yang sepenuhnya non-sensitif (misalnya checksum internal yang tidak mengandung informasi rahasia) memiliki urgensi jauh lebih rendah dibanding ditemukan pada aliran yang mengenkripsi token autentikasi atau data personal pengguna.

### 1.5 Mengapa Test Ini juga Diberi Tipe "Manual"

Sama seperti beberapa test hooking lain dalam seri riset ini (mis. TEST-0334, TEST-0338), tipe `manual` di sini menandakan bahwa **hasil hook mentah saja tidak cukup** untuk menyimpulkan FAIL final — output hook hanya memberi **kandidat** (pemanggilan API dengan mode tertentu); keputusan final tentang relevansi keamanan menuntut penilaian manusia terhadap backtrace dan konteks data yang diproses, sesuai §1.4.

### 1.6 Relevansi Kasus Nyata yang Sudah Dibahas: MEGA App dan CVE-2026-22906

Kedua kasus nyata yang sudah dibahas mendalam di dokumen **MASTG-TEST-0232** — kesalahan konfigurasi `Cipher.getInstance("AES")` pada aplikasi MEGA (jatuh ke ECB secara default tanpa disadari developer) dan **CVE-2026-22906** (AES-ECB dikombinasikan dengan hardcoded key, mengekspos kredensial pengguna) — relevan secara langsung untuk memahami **mengapa verifikasi dinamis penting**: kasus MEGA secara spesifik adalah contoh di mana developer **tidak menyadari** bahwa kode mereka jatuh ke ECB karena hanya menulis `"AES"` tanpa embel-embel mode eksplisit. Verifikasi dinamis terhadap transformation string yang **benar-benar dipakai saat runtime** (bukan hanya menduga dari literal string di kode) adalah cara paling pasti untuk mengonfirmasi kasus tersembunyi semacam ini — termasuk kasus di mana default provider JCA yang dipakai mungkin berbeda bergantung pada versi Android atau security provider yang aktif saat itu (lihat pembahasan GMS Security Provider di TEST-0295 dalam seri riset ini).

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **Frida** | Hooking `Cipher.getInstance()` untuk menangkap transformation string dan backtrace (MASTG-TECH-0043) |
| **ADB** | Instalasi app (MASTG-TECH-0005) |
| **jadx** | Review manual lokasi kode dari backtrace (MASTG-TECH-0023) |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **Objection** | Hooking cepat tanpa script kustom untuk eksplorasi awal |
| **mitmproxy/Burp** | Korelasi dengan lalu lintas jaringan — menilai apakah data yang dienkripsi dengan mode bermasalah juga teramati dikirim keluar perangkat |

### 2.3 Prasyarat Lingkungan

- Device rooted/emulator dengan `frida-server`.
- Aplikasi target harus **di-exercise secara ekstensif** mencakup sebanyak mungkin alur (sesuai langkah resmi) — pemanggilan `Cipher.getInstance()` yang hanya terjadi pada fitur tertentu (mis. backup/restore) tidak akan tertangkap bila fitur tersebut tidak dipicu selama sesi pengujian.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0005** untuk instalasi aplikasi.
2. Gunakan **MASTG-TECH-0043** untuk hook API yang relevan.
3. Exercise aplikasi secara ekstensif untuk memicu sebanyak mungkin alur, masukkan data sensitif di mana pun memungkinkan.

### 3.2 Metode A — Frida: Hook Cipher.getInstance() dengan Backtrace Lengkap

```javascript
Java.perform(function () {
    var Cipher = Java.use("javax.crypto.Cipher");
    Cipher.getInstance.overload('java.lang.String').implementation = function (transformation) {
        if (transformation.indexOf("ECB") !== -1 || transformation === "AES" || transformation === "DES") {
            console.log("[Cipher.getInstance] transformation: " + transformation);
            console.log("Backtrace:\n" +
                Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
        }
        return this.getInstance(transformation);
    };
});
```

```bash
frida -U -f com.example.targetapp -l hook_ecb.js --no-pause
```

### 3.3 Metode B — Objection untuk Eksplorasi Cepat

```bash
objection -g com.example.targetapp explore
# di dalam REPL:
android hooking watch class_method javax.crypto.Cipher.getInstance --dump-args --dump-backtrace
```

### 3.4 Metode C — Review Manual Backtrace (Wajib, Sesuai MASTG-TECH-0023)

Untuk setiap hasil tangkapan dari Metode A/B:

1. Lacak lokasi kode dari backtrace.
2. Identifikasi jenis data yang diteruskan ke operasi `encrypt`/`decrypt` berikutnya pada `Cipher` instance tersebut.
3. Nilai apakah data tersebut termasuk kategori sensitif (§1.4).

### 3.5 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Kapan dipakai |
|---|---|---|
| **A** | Frida | Baseline wajib — menangkap transformation string dan backtrace |
| **B** | Objection | Eksplorasi cepat tanpa menulis script |
| **C** | Review manual (wajib) | Inti pengujian — menilai relevansi data sensitif |

**Kombinasi minimum yang aku rekomendasikan:** **A → C (wajib)**, konsisten dengan sifat manual test ini (§1.5).

---

### 3.6 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Evaluation:** *"The test case fails if broken encryption modes are used in security-relevant cryptographic operations."*

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Hook menangkap transformation string yang menunjukkan mode ECB (atau `"AES"` murni tanpa mode eksplisit, sesuai daftar TEST-0232 §1.3) **dan** backtrace mengarah ke operasi yang menangani data sensitif |

**Contoh bukti (merefleksikan pola nyata MEGA App, §1.6):**

```
[Cipher.getInstance] transformation: AES
Backtrace:
  at com.example.app.crypto.LegacyEncryptor.encryptUserToken(LegacyEncryptor.java:27)
  at com.example.app.auth.SessionManager.persistToken(SessionManager.java:55)
```

Interpretasi: `Cipher.getInstance("AES")` (jatuh ke ECB secara default) dipanggil pada alur yang mengenkripsi token sesi pengguna — data yang jelas sensitif. **FAIL**.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Tidak ada pemanggilan `Cipher.getInstance()` dengan mode ECB/tanpa mode eksplisit yang teramati selama exercise menyeluruh, **atau** |
| P2 | Pemanggilan dengan mode bermasalah ditemukan, namun **terverifikasi** (via review manual) hanya menangani data non-sensitif |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Hasil hook mentah hanya kandidat, bukan temuan final** — sesuai sifat manual test ini (§1.5), selalu lakukan review backtrace sebelum menyimpulkan FAIL.

2. **Coverage exercise menentukan validitas PASS** — bila alur yang memakai enkripsi bermasalah tidak sempat terpicu selama sesi pengujian, hasil PASS bisa jadi false negative; dokumentasikan secara jujur alur mana yang berhasil/tidak berhasil dipicu.

3. **Manfaatkan kemampuan unik test dinamis ini untuk kasus tersembunyi** — sesuai §1.2, prioritaskan pengujian ini khususnya bila analisis statis (TEST-0232) tidak menemukan apa pun namun aplikasi memiliki indikasi obfuskasi/pengambilan konfigurasi dari remote, karena kasus semacam itu hanya bisa terkonfirmasi lewat observasi runtime.

4. **Korelasikan dengan hasil MASTG-TEST-0232** — bila statis menemukan kandidat namun dinamis tidak pernah mengamatinya terpanggil, kemungkinan kode tersebut dead code atau berada di jalur yang belum teruji; sebaliknya, temuan dinamis yang tidak ditemukan statis mengindikasikan transformation string dinamis/tersembunyi yang layak diinvestigasi lebih jauh.

5. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | ECB terkonfirmasi aktif pada data sangat sensitif (token, kredensial, data personal) | **Tinggi** |
   | ECB terkonfirmasi aktif namun pada data non-sensitif | **Rendah/Informational** |
   | Tidak ditemukan setelah exercise menyeluruh | **Bukan temuan** (dengan catatan keterbatasan coverage) |

6. **Dokumentasikan:** transformation string yang tertangkap, backtrace lengkap, jenis data yang diproses (hasil review manual), dan cakupan alur yang berhasil dipicu selama pengujian.

---

## 4. Rekomendasi Perbaikan

Rekomendasi identik dengan MASTG-TEST-0232 (pasangan statisnya) — gunakan mode terautentikasi seperti AES-GCM sesuai MASTG-BEST-0005:

```java
// SEBELUM — jatuh ke ECB secara default
Cipher cipher = Cipher.getInstance("AES");

// SESUDAH — eksplisit memakai GCM, terautentikasi
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
```

### Checklist Remediasi

- [ ] Seluruh transformation string yang tertangkap saat runtime memakai mode terautentikasi (GCM/CCM), bukan ECB
- [ ] Tidak ada pemanggilan `Cipher.getInstance("AES")` tanpa spesifikasi mode eksplisit
- [ ] Hasil pengujian dinamis dikorelasikan dengan temuan statis MASTG-TEST-0232 untuk gambaran lengkap
- [ ] Diverifikasi ulang setelah perbaikan dengan menjalankan kembali hook untuk memastikan tidak ada lagi pemanggilan mode bermasalah

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0350 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-CRYPTO/MASTG-TEST-0350.md)
- [MASTG-TEST-0232: Broken Symmetric Encryption Modes (pasangan statis — dokumen terkait dalam seri riset ini)](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0232/)
- [MASTG-BEST-0005: Use Secure Encryption Modes](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0005.md)
- [MASTG-TECH-0023: Reviewing Decompiled Java Code](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0023/)

### 5.2 Referensi Teknis dan Kasus Nyata

- [NIST SP 800-38A — Recommendation for Block Cipher Modes of Operation](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [GitHub Issue: meganz/android#299 — Kesalahan Konfigurasi Cipher.getInstance("AES") Jatuh ke ECB](https://github.com/meganz/android/issues/299)

### 5.3 Dokumentasi Tools

- [Frida — Dynamic Instrumentation Toolkit](https://frida.re/docs/home/)
- [Objection — Runtime Mobile Exploration](https://github.com/sensepost/objection)

---

*Dokumen ini disusun berdasarkan konten resmi OWASP MASTG (`tests-beta/android/MASVS-CRYPTO/MASTG-TEST-0350.md`, `MASTG-BEST-0005`), serta cross-reference mendalam dengan dokumen MASTG-TEST-0232 (pasangan statisnya) dalam seri riset ini yang sudah membahas kasus nyata MEGA Android App dan CVE-2026-22906. Nuansa metodologis terpenting: nilai tambah unik test dinamis ini dibanding pasangan statisnya adalah kemampuan menangkap transformation string yang **tidak hardcoded** di kode (hasil concatenation, decode, atau konfigurasi remote) — kasus yang secara struktural tidak mungkin terdeteksi oleh pattern-matching statis murni manapun. Sama seperti pasangan statisnya, test ini bertipe manual — hasil hook mentah hanya kandidat, relevansi keamanan final menuntut review backtrace secara manual terhadap jenis data yang diproses.*
