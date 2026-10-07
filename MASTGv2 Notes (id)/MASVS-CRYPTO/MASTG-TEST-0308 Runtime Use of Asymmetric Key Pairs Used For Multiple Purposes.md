# MASTG-TEST-0308 Runtime Use of Asymmetric Key Pairs Used For Multiple Purposes

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0308 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-CRYPTO (MASVS-CRYPTO-1) |
| **Weakness** | MASWE-0007 — *Improper Encryption* |
| **API yang disorot** | `Cipher.init(int opmode, Key key, ...)`, `Signature.initSign(PrivateKey)`, `Signature.initVerify(PublicKey)` |
| **Tipe Pengujian** | **Dynamic, Hooks** |
| **Knowledge** | MASTG-KNOW-0012 (Key Generation) |
| **Teknik terkait** | MASTG-TECH-0005 (Install App), MASTG-TECH-0043 (Method Hooking) |
| **Test terkait** | **MASTG-TEST-0307** (References to Asymmetric Key Pairs Used For Multiple Purposes) — counterpart statis; overview resmi test ini secara eksplisit menyatakan *"This test is the dynamic counterpart to MASTG-TEST-0307, but it focuses on intercepting cryptographic operations rather than generating keys with multiple purposes"* |
| **Demo terkait** | — (tidak ada) |
| **Rule resmi** | — (tidak relevan; test dinamis berbasis hooking) |
| **CWE terkait** | CWE-326, CWE-320 |

---

## 1. Penjelasan

### 1.1 Pembeda Fundamental yang Ditegaskan Sendiri oleh Overview Resmi

Overview resmi MASTG untuk test ini secara eksplisit dan tegas menandai **apa yang membedakannya** dari MASTG-TEST-0307, dengan kalimat yang jarang ditemukan presisinya di test lain dalam seri riset ini:

> *"This test is the dynamic counterpart to MASTG-TEST-0307, **but it focuses on intercepting cryptographic operations rather than generating keys with multiple purposes**."*

Ini bukan sekadar "versi dinamis dari hal yang sama" — ini adalah **pergeseran objek pengujian** yang signifikan:

| | MASTG-TEST-0307 (Statis) | MASTG-TEST-0308 (Dinamis, dokumen ini) |
|---|---|---|
| **Yang diperiksa** | Nilai bitmask `purposes` **saat kunci DIBUAT** (`KeyGenParameterSpec.Builder`) | Operasi kriptografi **saat kunci benar-benar DIPAKAI** (`Cipher.init()`, `Signature.initSign/initVerify()`) |
| **Momen observasi** | Waktu deklarasi/konfigurasi kunci | Waktu eksekusi nyata operasi kriptografi |
| **Pertanyaan yang dijawab** | "Apakah kunci ini **dikonfigurasi** untuk lebih dari satu peran?" | "Apakah kunci ini **benar-benar dipakai** untuk lebih dari satu peran dalam praktik?" |

### 1.2 Mengapa Kedua Pertanyaan Ini Bisa Menghasilkan Jawaban Berbeda

Ini poin konseptual yang penting untuk dipahami sebelum menjalankan kedua test secara bersamaan — **hasil MASTG-TEST-0307 dan MASTG-TEST-0308 untuk kunci yang sama berpotensi tidak selalu sejalan**:

- **Skenario A — FAIL di 0307, namun tidak teramati di 0308**: kunci dikonfigurasi dengan `purposes = 15` (keempat peran sekaligus, FAIL di MASTG-TEST-0307), namun dalam praktik aplikasi **hanya pernah memanggil** `Cipher.init(ENCRYPT_MODE, key)` sepanjang sesi pengujian dinamis — operasi `Signature.initSign()`/`initVerify()` pada kunci yang sama **tidak pernah terpicu** karena jalur kode tersebut tidak dieksekusi penguji. Dalam kasus ini, **MASTG-TEST-0307 tetap menjadi sinyal FAIL yang sah** (kapabilitas berbahaya tetap ada secara struktural, bisa dieksploitasi sewaktu-waktu oleh jalur kode lain atau versi aplikasi mendatang), **meski** MASTG-TEST-0308 pada sesi pengujian tertentu tidak menangkap bukti pemakaian ganda secara nyata.
- **Skenario B — PASS di 0307 (secara tekstual), namun FAIL di 0308**: ini skenario yang lebih jarang namun tetap mungkin terjadi — mis. bila alias kunci yang sama dipakai ulang untuk mereferensikan **objek kunci yang berbeda** pada titik kode yang berbeda (pola yang membingungkan namun valid dalam API Android Keystore), sehingga analisis statis murni kesulitan mengorelasikan bahwa "kunci" yang sama secara logis dipakai lintas peran, sementara observasi dinamis langsung menangkap pemakaian nyata lintas peran tersebut lewat alias yang konsisten.

Ini menegaskan **nilai komplementer** kedua test — MASTG-TEST-0307 memberi **cakupan struktural lengkap** (termasuk kapabilitas yang belum/tidak pernah dipicu), sementara MASTG-TEST-0308 memberi **bukti perilaku nyata** yang sesungguhnya terjadi saat aplikasi dipakai — rujuk pola analogi yang sama seperti dibahas mendalam di dokumen MASTG-TEST-0264 dalam seri riset ini (`StrictMode` — hooking vs logging) tentang bagaimana pendekatan statis dan dinamis bisa saling melengkapi celah masing-masing.

### 1.3 Tiga API Kunci yang Perlu Di-hook dan Pemetaannya ke Kelompok Peran

Overview resmi memetakan dengan jelas API mana yang relevan untuk masing-masing kelompok peran (identik dengan tiga kelompok yang sudah dibahas mendalam di dokumen MASTG-TEST-0307 §1.3):

| API yang Di-hook | Parameter Penentu | Kelompok Peran |
|---|---|---|
| `Cipher.init(opmode, key, ...)` | `opmode = Cipher.ENCRYPT_MODE` atau `Cipher.DECRYPT_MODE` | Enkripsi/Dekripsi |
| `Cipher.init(opmode, key, ...)` | `opmode = Cipher.WRAP_MODE` atau `Cipher.UNWRAP_MODE` | Pembungkusan Kunci |
| `Signature.initSign(privateKey)` | — | Tanda Tangan/Verifikasi |
| `Signature.initVerify(publicKey)` | — | Tanda Tangan/Verifikasi |

Poin teknis penting: `Cipher.init()` adalah **satu method yang melayani dua kelompok peran berbeda** (Enkripsi/Dekripsi **dan** Pembungkusan Kunci), dibedakan **hanya** oleh nilai parameter `opmode` yang diteruskan. Ini berarti hook pada `Cipher.init()` **harus** memeriksa nilai `opmode` secara eksplisit untuk mengklasifikasikan operasi dengan benar — sekadar mencatat "Cipher.init() dipanggil" tanpa membedakan mode tidak cukup untuk menjawab pertanyaan evaluasi test ini.

### 1.4 Nilai Unik: Korelasi Lintas Pemanggilan Berdasarkan Identitas Kunci

Tantangan teknis utama dalam mengimplementasikan test ini secara efektif adalah **mengorelasikan** apakah objek `Key`/`PrivateKey`/`PublicKey` yang muncul di pemanggilan `Cipher.init()` pada satu titik kode **adalah kunci yang sama** dengan yang muncul di `Signature.initSign()`/`initVerify()` di titik kode lain. Di Android Keystore, identitas sebuah kunci secara praktis diwakili oleh **alias**-nya (string yang dipakai saat `KeyGenParameterSpec.Builder(alias, ...)` atau `KeyStore.getKey(alias, ...)`) — sehingga hook yang efektif perlu menangkap **alias** ini di titik mana pun yang memungkinkan (mis. dengan menelusuri balik dari objek `Key` ke `KeyStore.Entry` yang menghasilkannya), bukan hanya mencatat operasi secara terisolasi tanpa konteks identitas kunci.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **Frida** | Instrumentasi dinamis inti — hooking `Cipher.init()` dan `Signature.initSign/initVerify()` |
| **frida-tools** (`frida-trace`) | Tracing cepat tanpa skrip kustom |
| **objection** | Wrapper Frida siap pakai |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **Xposed/LSPosed** | Alternatif hooking persisten sesuai MASTG-TECH-0043 |
| **adb logcat** | Korelasi tambahan bila aplikasi mencatat log terkait operasi kriptografi (meski ini sendiri berpotensi jadi temuan MASTG-TEST-0203/0231 bila memuat detail sensitif) |

### 2.3 Prasyarat Lingkungan

- **Wajib device/emulator dengan Frida server** — test murni dinamis.
- **Interaksi menyeluruh dengan aplikasi** sesuai langkah resmi — *"exercise the app extensively to trigger as many flows as possible"* — krusial mengingat skenario A di §1.2: operasi kriptografi yang jarang terpicu (alur pemulihan akun, verifikasi tanda tangan dokumen yang jarang dipakai) berisiko tidak tertangkap bila interaksi tidak menyeluruh.
- **Idealnya jalankan berdampingan dengan hasil MASTG-TEST-0307** untuk memperoleh daftar alias kunci kandidat yang perlu diprioritaskan pemicuannya saat sesi dinamis.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0005** untuk menginstal aplikasi.
2. Gunakan **MASTG-TECH-0043** untuk melakukan hooking pada pemanggilan API yang relevan.
3. Jelajahi aplikasi secara menyeluruh, masukkan data sensitif di mana pun memungkinkan.

### 3.2 Metode A — Skrip Frida dengan Korelasi Alias Kunci *(metode utama)*

```javascript
// hook-key-purpose-runtime.js
Java.perform(function () {
    function getBacktrace() {
        return Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
    }

    // Peta global untuk mengorelasikan alias kunci dengan kelompok peran yang pernah dipakai
    var keyUsageMap = {};

    function recordUsage(alias, group) {
        if (!keyUsageMap[alias]) keyUsageMap[alias] = {};
        keyUsageMap[alias][group] = true;
        var groupsUsed = Object.keys(keyUsageMap[alias]);
        if (groupsUsed.length > 1) {
            console.log("\n[!!!] FAIL TERDETEKSI — alias '" + alias + "' dipakai untuk kelompok: " + groupsUsed.join(", "));
            console.log("    Backtrace:\n" + getBacktrace());
        }
    }

    function getAliasFromKey(key) {
        try {
            // Pendekatan heuristik: banyak implementasi AndroidKeyStore Key menyimpan alias
            // yang dapat diakses lewat refleksi atau toString()
            return key.toString();
        } catch (e) { return "UNKNOWN_ALIAS"; }
    }

    // 1. Cipher.init() — membedakan ENCRYPT/DECRYPT vs WRAP/UNWRAP
    var Cipher = Java.use("javax.crypto.Cipher");
    Cipher.init.overload("int", "java.security.Key").implementation = function (opmode, key) {
        var alias = getAliasFromKey(key);
        var ENCRYPT_MODE = 1, DECRYPT_MODE = 2, WRAP_MODE = 3, UNWRAP_MODE = 4;
        var group = (opmode === WRAP_MODE || opmode === UNWRAP_MODE) ? "WRAP_KEY" : "ENCRYPT_DECRYPT";
        console.log("[*] Cipher.init(opmode=" + opmode + ", alias=" + alias + ") -> kelompok: " + group);
        recordUsage(alias, group);
        return this.init(opmode, key);
    };

    // 2. Signature.initSign()
    var Signature = Java.use("java.security.Signature");
    Signature.initSign.overload("java.security.PrivateKey").implementation = function (privateKey) {
        var alias = getAliasFromKey(privateKey);
        console.log("[*] Signature.initSign(alias=" + alias + ") -> kelompok: SIGN_VERIFY");
        recordUsage(alias, "SIGN_VERIFY");
        return this.initSign(privateKey);
    };

    // 3. Signature.initVerify()
    Signature.initVerify.overload("java.security.PublicKey").implementation = function (publicKey) {
        var alias = getAliasFromKey(publicKey);
        console.log("[*] Signature.initVerify(alias=" + alias + ") -> kelompok: SIGN_VERIFY");
        recordUsage(alias, "SIGN_VERIFY");
        return this.initVerify(publicKey);
    };
});
```

```bash
frida -U -f com.target.app -l hook-key-purpose-runtime.js --no-pause
```

### 3.3 Metode B — objection (Tanpa Menulis Skrip Kustom)

```bash
objection -g com.target.app explore
android hooking watch class_method javax.crypto.Cipher.init --dump-args --dump-backtrace
android hooking watch class_method java.security.Signature.initSign --dump-args --dump-backtrace
android hooking watch class_method java.security.Signature.initVerify --dump-args --dump-backtrace
```

Dengan pendekatan ini, korelasi antar-pemanggilan (apakah argumen `key` yang sama muncul di kedua jenis hook) dilakukan **secara manual** oleh penguji dari hasil dump, berbeda dari Metode A yang mengotomasi korelasi tersebut lewat `keyUsageMap`.

### 3.4 Metode C — frida-trace untuk Overview Cepat

```bash
frida-trace -U -f com.target.app -m "javax.crypto.Cipher!init" -m "java.security.Signature!init*"
```

### 3.5 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Korelasi alias otomatis? | Kapan dipakai |
|---|---|---|---|
| **A** | Skrip Frida kustom | ✅ | Baseline utama, paling efisien untuk deteksi otomatis |
| **B** | objection | ❌ (manual) | Eksplorasi awal cepat tanpa scripting |
| **C** | frida-trace | ❌ | Overview cepat sebelum hooking detail |

**Kombinasi minimum yang aku rekomendasikan:** **A (korelasi otomatis) dengan interaksi menyeluruh** → korelasikan hasil dengan **MASTG-TEST-0307** untuk gambaran lengkap (struktural + perilaku nyata).

---

### 3.6 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Observation:** *"The output should contain a list of all cryptographic operations together with their corresponding keys."*
>
> **Evaluation:** *"The test case fails if you find any keys used for multiple roles."*

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Kunci/alias yang sama terkonfirmasi dipakai untuk **lebih dari satu** kelompok operasi (Enkripsi/Dekripsi, Tanda Tangan/Verifikasi, Wrap Key) selama sesi pengujian dinamis |

**Contoh bukti (ilustratif — MASTG belum menyediakan demo resmi untuk test ini):**

```
[*] Cipher.init(opmode=1, alias=master_key) -> kelompok: ENCRYPT_DECRYPT
[*] Signature.initSign(alias=master_key) -> kelompok: SIGN_VERIFY

[!!!] FAIL TERDETEKSI — alias 'master_key' dipakai untuk kelompok: ENCRYPT_DECRYPT, SIGN_VERIFY
    Backtrace:
        at com.example.target.crypto.DocumentSigner.signAndEncrypt(DocumentSigner.java:58)
```

Interpretasi: alias `master_key` terkonfirmasi **secara nyata** dipakai baik untuk operasi enkripsi **maupun** penandatanganan dalam alur `signAndEncrypt()` — bukti dinamis definitif yang melengkapi (dan menguatkan) temuan statis MASTG-TEST-0307 bila kunci yang sama juga terdeteksi dikonfigurasi dengan `purposes` lintas kelompok.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Setiap alias kunci yang teramati selama sesi pengujian menyeluruh **hanya** dipakai untuk satu kelompok operasi secara konsisten |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Hasil "tidak ditemukan pemakaian ganda" TIDAK OTOMATIS membatalkan temuan FAIL dari MASTG-TEST-0307** — sesuai §1.2 Skenario A, kapabilitas berbahaya yang terkonfigurasi secara statis tetap menjadi risiko struktural meski belum teramati dipakai ganda pada satu sesi pengujian dinamis tertentu. **Selalu laporkan kedua hasil secara terpisah dan jelas, jangan biarkan hasil PASS 0308 "menutupi" FAIL 0307.**

2. **Korelasi berbasis alias adalah kunci keberhasilan metodologi ini** — pastikan skrip hooking benar-benar dapat mengidentifikasi alias kunci secara konsisten lintas pemanggilan; bila `toString()` pada objek `Key` tidak memberi info alias yang jelas, pertimbangkan pendekatan refleksi tambahan atau korelasi berdasarkan lokasi kode (stack trace) sebagai proxy identitas.

3. **Interaksi menyeluruh adalah prasyarat mutlak** untuk hasil negatif yang meyakinkan — jalur kode yang jarang terpicu (verifikasi tanda tangan dokumen yang diunggah, alur recovery akun) berisiko luput bila sesi pengujian tidak benar-benar komprehensif.

4. **Severity dimodulasi** mengikuti pola yang sama seperti dokumen MASTG-TEST-0307 — berdasarkan sensitivitas data yang diproses dan jumlah kelompok peran yang tercampur.

5. **Dokumentasikan:** alias kunci yang teramati, kelompok operasi yang terdeteksi untuk masing-masing, stack trace lokasi pemanggilan, dan korelasi eksplisit dengan hasil MASTG-TEST-0307.

---

## 4. Rekomendasi Perbaikan

Rekomendasi identik dengan **dokumen MASTG-TEST-0307 §4** — pisahkan kunci berdasarkan peran sejak level pembuatan (`KeyGenParameterSpec`). Bila test ini (0308) menemukan pemakaian ganda yang **tidak** terdeteksi di 0307 (skenario B di §1.2), ini mengindikasikan kemungkinan alias kunci dipakai ulang secara ambigu di kode — investigasi lebih lanjut lewat MASTG-TECH-0023 untuk memahami mengapa korelasi statis tidak menangkap pola ini.

### 4.1 Checklist Remediasi

- [ ] Hooking mencakup ketiga API (`Cipher.init` dengan pembedaan opmode, `Signature.initSign`, `Signature.initVerify`)
- [ ] Korelasi alias kunci berfungsi dengan andal lintas pemanggilan
- [ ] Interaksi pengujian mencakup seluruh alur yang melibatkan operasi kriptografi
- [ ] Hasil dikorelasikan secara eksplisit dengan MASTG-TEST-0307
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0308 setelah setiap perubahan pada alur kriptografi aplikasi

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0308: Runtime Use of Asymmetric Key Pairs Used For Multiple Purposes](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0308/)
- [MASTG-TEST-0307: References to Asymmetric Key Pairs Used For Multiple Purposes](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0307/)
- [MASWE-0007: Improper Encryption](https://mas.owasp.org/MASWE/MASVS-CRYPTO/MASWE-0007/)
- [MASTG-KNOW-0012: Key Generation](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CRYPTO/MASTG-KNOW-0012/)
- [MASTG-TECH-0005: Installing Apps](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0005/)
- [MASTG-TECH-0043: Method Hooking](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/)

### 5.2 Dokumentasi Resmi Android

- [Android Developers — `Cipher#init()` API reference](https://developer.android.com/reference/javax/crypto/Cipher#init(int,%20java.security.Key,%20java.security.AlgorithmParameters))
- [Android Developers — `Signature#initSign()`](https://developer.android.com/reference/java/security/Signature#initSign(java.security.PrivateKey))
- [Android Developers — `Signature#initVerify()`](https://developer.android.com/reference/java/security/Signature#initVerify(java.security.PublicKey))

### 5.3 Dokumentasi Tools

- [Frida — Dynamic instrumentation toolkit](https://frida.re/docs/javascript-api/)
- [Objection — Runtime Mobile Exploration toolkit](https://github.com/sensepost/objection)
- [frida-trace — Documentation](https://frida.re/docs/frida-trace/)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026) dan dokumentasi resmi Android Developers. Sebagai counterpart dinamis dari MASTG-TEST-0307, test ini secara eksplisit mengalihkan fokus dari "bagaimana kunci dikonfigurasi" menjadi "bagaimana kunci benar-benar dipakai" — pergeseran yang dinyatakan langsung oleh overview resminya sendiri. Nuansa terpenting: hasil kedua test bisa saling melengkapi namun tidak selalu identik — kapabilitas berbahaya yang terdeteksi secara statis (MASTG-TEST-0307) tetap merupakan temuan sah meski belum teramati dipakai secara ganda pada sesi pengujian dinamis tertentu, sehingga kedua hasil harus dilaporkan dan dinilai secara terpisah, bukan saling menggantikan.*
