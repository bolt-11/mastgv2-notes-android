# MASTG-TEST-0309 References to Reused Initialization Vectors in Symmetric Encryption

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0309 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-CRYPTO (MASVS-CRYPTO-1) |
| **Weakness** | MASWE-0007 — *Improper Encryption* |
| **Tipe Pengujian** | Static, Code |
| **Status resmi MASTG** | **`placeholder`** — belum ada Overview/Steps/Evaluation lengkap |
| **Catatan resmi (satu-satunya konten yang tersedia)** | *"Reusing a symmetric key is acceptable when IVs or nonces follow the rules defined for the mode. NIST SP 800-38A states that CBC requires a fresh or unpredictable IV for every encryption. NIST SP 800-38D states that counter based modes require a nonce that never repeats under the same key. Repeating a key and IV or nonce pair defeats confidentiality and can also undermine integrity."* |
| **Test terkait** | Berkaitan erat dengan MASTG-TEST-0232 (Broken Symmetric Encryption Modes — ECB) dan MASTG-TEST-0221 (Broken Symmetric Encryption Algorithms) dalam seri riset ini — bersama membentuk spektrum lengkap kesalahan konfigurasi enkripsi simetris Android |
| **Demo terkait** | — (tidak ada) |
| **Rule resmi** | — (tidak ada) |
| **CWE terkait** | CWE-1204 (Generation of Weak Initialization Vector), CWE-323 (Reusing a Nonce, Key Pair in Encryption), CWE-329 (Generation of Predictable IV with CBC Mode) |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian dan Nuansa Awal yang Krusial

Catatan resmi test ini (meski singkat) sudah memuat satu kalimat pembuka yang **secara eksplisit mencegah kesalahan interpretasi yang paling umum**:

> *"Reusing a symmetric key is acceptable when IVs or nonces follow the rules defined for the mode."*

Ini penting ditegaskan di awal karena **memakai ulang kunci simetris yang sama berkali-kali adalah hal yang sepenuhnya normal dan diharapkan** dalam praktik kriptografi — mis. satu `SecretKey` yang dipakai untuk mengenkripsi banyak pesan/record data dari waktu ke waktu. **Yang menjadi masalah bukan pemakaian ulang kunci itu sendiri**, melainkan **pemakaian ulang pasangan (kunci, IV/nonce) yang identik**. Test ini secara spesifik menyasar **IV/nonce**-nya — bukan kuncinya — sebagai komponen yang harus selalu berbeda setiap operasi enkripsi, meski kuncinya tetap sama.

### 1.2 Dua Aturan yang Berbeda untuk Dua Kategori Mode Operasi

Ini adalah **nuansa teknis paling penting** dari seluruh dokumen ini — catatan resmi secara eksplisit membedakan **dua standar NIST yang berbeda** untuk dua kategori mode block cipher yang berbeda, dengan **persyaratan yang tidak identik**:

| Mode | Standar NIST | Persyaratan IV/Nonce | Istilah Kunci |
|---|---|---|---|
| **CBC** (Cipher Block Chaining) | **NIST SP 800-38A** | IV harus **fresh atau tidak dapat diprediksi** (*unpredictable*) untuk setiap operasi enkripsi | **Unpredictability** |
| **Mode berbasis counter** (CTR, **GCM**) | **NIST SP 800-38D** | Nonce harus **tidak pernah berulang** (*never repeats*) di bawah kunci yang sama | **Uniqueness** (bukan harus tidak dapat diprediksi) |

Perbedaan ini **sangat halus namun penting secara teknis**: untuk **CBC**, IV harus **unpredictable** (penyerang tidak boleh bisa menebak IV yang akan dipakai **sebelum** operasi enkripsi terjadi — ini mencegah serangan seperti **BEAST** yang memanfaatkan IV CBC yang dapat diprediksi di SSL/TLS lama). Sementara untuk **mode counter-based** seperti **GCM**, persyaratannya **lebih longgar dalam satu aspek namun lebih ketat di aspek lain** — nonce **tidak perlu** tidak dapat diprediksi (nonce berupa **counter sekuensial sederhana** seperti 0, 1, 2, 3... sepenuhnya valid dan aman untuk GCM), namun ia **mutlak tidak boleh pernah berulang** sepanjang masa pakai kunci tersebut — bahkan satu kali pengulangan saja sudah cukup untuk meruntuhkan keamanan secara **katastropik** (dibahas di §1.4).

### 1.3 Mengapa Pengulangan IV pada CBC Berbahaya: Kebocoran Pola

Untuk mode CBC, pengulangan IV (terutama bila bersifat **statis/hardcoded**, pola paling sering ditemukan di lapangan) menciptakan konsekuensi yang mirip dengan kelemahan mode ECB yang sudah dibahas mendalam di dokumen **MASTG-TEST-0232** dalam seri riset ini: **blok plaintext pertama yang identik akan selalu menghasilkan blok ciphertext pertama yang identik**, selama kunci dan IV yang dipakai sama. Ini membuka jalur **serangan pencocokan pola** tanpa perlu mendekripsi apa pun — cukup membandingkan ciphertext.

### 1.4 Mengapa Pengulangan Nonce pada GCM Jauh Lebih Fatal: "Forbidden Attack"

Ini adalah bagian yang paling krusial untuk dipahami penguji, dan menjelaskan mengapa catatan resmi menutup dengan kalimat tegas: *"Repeating a key and IV or nonce pair defeats confidentiality and **can also undermine integrity**."* Riset kriptografi akademik menunjukkan bahwa pengulangan nonce pada **AES-GCM bukan sekadar "degradasi keamanan"** — ia adalah **keruntuhan kriptografi total**, melalui dua tahap serangan:

> **Tahap 1 — Kegagalan Kerahasiaan (Keystream Recovery)**: *"If two plaintexts P1 and P2 are encrypted with the same key and the same nonce, their ciphertexts satisfy C1 XOR C2 = P1 XOR P2."* — penyerang dapat langsung memperoleh **XOR dari dua plaintext** tanpa perlu kunci sama sekali, cukup dari dua ciphertext yang memakai pasangan kunci-nonce yang sama.
>
> **Tahap 2 — Kegagalan Integritas (Pemulihan Kunci Autentikasi)**: *"Nonce reuse in AES-GCM allows an attacker... to recover P1 ⊕ P2 and, via Joux's 'forbidden attack,' solve a polynomial equation over GF(2^128) for candidate GHASH keys H — enabling tag forgery."*

Teknik ini dikenal sebagai **"forbidden attack"** (diambil dari nama peneliti kriptografi Antoine Joux yang pertama mendemonstrasikannya) — dengan dua pasang (plaintext, ciphertext) yang memakai kunci-nonce sama, penyerang dapat **memecahkan persamaan polinomial** untuk **memulihkan kunci autentikasi GHASH** sepenuhnya. Begitu kunci autentikasi ini berhasil dipulihkan, penyerang **tidak hanya bisa mendekripsi** pesan terenkripsi — ia juga dapat **memalsukan** ciphertext baru yang **tetap lolos verifikasi integritas** (*authentication tag* yang valid), sepenuhnya meruntuhkan baik kerahasiaan **maupun** jaminan integritas yang menjadi alasan utama GCM dipilih sebagai mode *authenticated encryption* sejak awal.

### 1.5 Kasus Nyata: `InsecureBankv2` dan Pola IV Statis Nol

Aplikasi training keamanan `InsecureBankv2` — yang secara eksplisit dirancang untuk mendemonstrasikan kerentanan nyata — mencontohkan pola yang **sangat umum** ditemukan pada aplikasi produksi sungguhan:

> *"`InsecureBankv2` uses an IV of sixteen zero bytes, hardcoded as a static array... `InsecureBankv2` is a training app, but every single vulnerability in it appears in real production applications. If two users share the same password, their encrypted values in SharedPreferences or on the server are byte-for-byte identical. An attacker who captures one known password can build a lookup table and match it against every other encrypted password in the database — no brute force required, just pattern matching."*

Ini menggambarkan dengan sangat konkret konsekuensi praktis IV statis bernilai nol (`byte[16]` yang tidak diinisialisasi secara eksplisit di Java/Kotlin **secara default** berisi nol semua — sebuah jebakan yang membuat developer yang lupa mengisi IV secara eksplisit **secara tidak sengaja** jatuh ke pola paling rentan ini tanpa pernah menuliskan nilai IV secara sadar).

### 1.6 Kasus CVE Nyata: CVE-2026-50210

Riset menemukan CVE kontemporer yang persis menggambarkan pola ini pada skala produk nyata:

> *"CVE-2026-50210 documents a cryptographic weakness in a device that encrypts data using AES-CBC with a static, zero-filled Initialization Vector (IV). Attackers observing ciphertext can correlate identical plaintext blocks across sessions, replay captured traffic, and mount known-plaintext decryption attacks."*

Kasus ini juga sejalan dengan preseden historis lebih tua yang relevan sebagai konteks tambahan: **CVE-2011-3389 (serangan BEAST)** pada SSL/TLS yang mengeksploitasi IV CBC yang dapat diprediksi, dan **CVE-2020-1472 (ZeroLogon)** yang mengeksploitasi IV nol statis pada AES-CFB8 dalam protokol autentikasi Netlogon Microsoft — menegaskan bahwa kelas kerentanan ini **berulang kali muncul** lintas platform dan dekade, bukan sekadar kesalahan Android yang spesifik/eksotis.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **jadx** | Dekompilasi DEX → Java untuk pencarian pola konstruksi IV/nonce |
| **grep / ripgrep** | Pencarian pola `IvParameterSpec`/`GCMParameterSpec` dan sumber byte yang dipakai |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **CodeQL** | Menelusuri apakah byte array yang diteruskan ke `IvParameterSpec`/`GCMParameterSpec` berasal dari **konstanta statis/literal** (berbahaya) vs `SecureRandom`/mekanisme counter yang terkelola (aman) |
| **Frida** | Hooking `Cipher.init()` untuk menangkap nilai IV/nonce aktual yang dipakai di setiap pemanggilan saat runtime, dan membandingkan apakah nilai yang sama muncul berulang kali |
| **MobSF** | Kadang menandai pola IV statis di laporan Code Analysis kategori kriptografi |

### 2.3 Prasyarat Lingkungan

- **Tidak butuh device/root** untuk analisis statis inti.
- **Identifikasi mode cipher yang dipakai** (CBC vs GCM/CTR) sebagai langkah pertama wajib — menentukan standar NIST mana (SP 800-38A vs SP 800-38D) yang relevan untuk dinilai (§1.2).

---

## 3. Cara Pengujian

Karena tidak ada langkah resmi rinci (status placeholder), metodologi berikut disusun dari elaborasi catatan resmi dan standar NIST yang dirujuknya.

### 3.1 Langkah Umum

1. Identifikasi seluruh pemanggilan `Cipher.getInstance()` dengan mode CBC/GCM/CTR.
2. Untuk setiap pemanggilan, telusuri **asal** byte array yang dipakai sebagai IV (`IvParameterSpec`) atau nonce (`GCMParameterSpec`).
3. Klasifikasikan sumber tersebut: literal/konstanta statis (FAIL) vs `SecureRandom`/mekanisme counter terkelola dengan benar (PASS kandidat).

### 3.2 Metode A — grep/ripgrep untuk Pola IV/Nonce Statis

```bash
D=./decompiled/sources

# Pola paling mencurigakan: byte array literal yang diteruskan sebagai IV
rg -n 'new IvParameterSpec\(new byte\[\]\s*\{' $D
rg -n 'new GCMParameterSpec\([^,]+,\s*new byte\[\]\s*\{' $D

# Pola IV nol implisit (array tidak diinisialisasi secara eksplisit)
rg -n 'new byte\[16\]\s*;' $D -A5 | grep -B5 "IvParameterSpec"

# Pola AMAN yang seharusnya ditemukan sebagai pembanding
rg -n 'SecureRandom\(\).*nextBytes' $D
```

### 3.3 Metode B — CodeQL untuk Klasifikasi Sumber IV/Nonce

```ql
import java

class IvParameterSpecCreation extends ClassInstanceExpr {
  IvParameterSpecCreation() {
    this.getConstructedType().hasQualifiedName("javax.crypto.spec", "IvParameterSpec") or
    this.getConstructedType().hasQualifiedName("javax.crypto.spec", "GCMParameterSpec")
  }
}

from IvParameterSpecCreation creation
where creation.getAnArgument() instanceof ArrayInit  // byte array literal langsung
select creation, "IV/nonce dibangun dari array literal statis — berpotensi diulang di setiap pemanggilan"
```

```ql
// Pelengkap: verifikasi SecureRandom TIDAK ditemukan di sekitar pembuatan IV (indikasi kuat statis)
import java

from IvParameterSpecCreation creation
where not exists(MethodAccess secureRandomCall |
  secureRandomCall.getMethod().getDeclaringType().hasQualifiedName("java.security", "SecureRandom") and
  secureRandomCall.getEnclosingCallable() = creation.getEnclosingCallable())
select creation, "IV/nonce dibuat TANPA SecureRandom di method yang sama — verifikasi manual sumbernya"
```

### 3.4 Metode C — Frida untuk Konfirmasi Runtime (Deteksi Pengulangan Nyata)

```javascript
// hook-iv-nonce-reuse.js
Java.perform(function () {
    var seenIVs = {};
    var GCMParameterSpec = Java.use("javax.crypto.spec.GCMParameterSpec");
    var IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");

    IvParameterSpec.$init.overload("[B").implementation = function (iv) {
        var ivHex = Array.from(Java.array('byte', iv)).map(b => (b & 0xff).toString(16).padStart(2, '0')).join('');
        if (seenIVs[ivHex]) {
            console.log("\n[!!!] IV BERULANG TERDETEKSI: " + ivHex + " (sudah dipakai sebelumnya!)");
        }
        seenIVs[ivHex] = (seenIVs[ivHex] || 0) + 1;
        console.log("[*] IvParameterSpec dibuat dengan IV: " + ivHex + " (kemunculan ke-" + seenIVs[ivHex] + ")");
        return this.$init(iv);
    };
});
```

```bash
frida -U -f com.target.app -l hook-iv-nonce-reuse.js --no-pause
# Jelajahi aplikasi menyeluruh, picu operasi enkripsi berulang kali
```

Metode ini memberi **bukti paling definitif** — bila IV/nonce yang **identik secara byte** ditemukan dipakai lebih dari sekali, ini konfirmasi langsung kondisi FAIL tanpa ambiguitas.

### 3.5 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Mendeteksi IV statis literal? | Mendeteksi pengulangan nyata? | Kapan dipakai |
|---|---|---|---|---|
| **A** | grep | ✅ | ❌ | Baseline cepat |
| **B** | CodeQL | ✅ (sistematis) | ❌ | Codebase besar |
| **C** | Frida | Tidak langsung | ✅ (bukti definitif) | Konfirmasi akhir, terutama untuk IV yang dibangun dinamis tapi tetap berpola berulang |

**Kombinasi minimum yang aku rekomendasikan:** **A/B (identifikasi kandidat IV statis) → C (konfirmasi dinamis pengulangan nyata)**.

---

### 3.6 Kriteria Evaluasi: Positive Case & Negative Case

Karena tidak ada klausul Evaluation resmi (status placeholder), kriteria berikut disusun berdasarkan catatan resmi dan standar NIST SP 800-38A/800-38D yang dirujuknya.

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Mode **CBC** memakai IV yang **statis/hardcoded** (termasuk IV nol implisit dari array tidak diinisialisasi) — melanggar persyaratan *unpredictability* NIST SP 800-38A |
| F2 | Mode **GCM/CTR** memakai nonce yang **terkonfirmasi berulang** (via Metode C) di bawah kunci yang sama — melanggar persyaratan *uniqueness* NIST SP 800-38D, kondisi paling kritis mengingat dampak "forbidden attack" (§1.4) |
| F3 | IV/nonce dibangun dari sumber yang **dapat diprediksi** (mis. timestamp dengan presisi rendah, counter yang reset setiap sesi aplikasi dimulai ulang tanpa persistensi yang benar) |

**Contoh bukti (ilustratif — MASTG belum menyediakan demo resmi untuk test ini):**

```java
// Ditemukan di com/example/target/crypto/LegacyEncryptor.java
public class LegacyEncryptor {
    private static final byte[] STATIC_IV = new byte[16]; // SELALU nol — tidak pernah diisi

    public byte[] encrypt(byte[] data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(STATIC_IV));
        return cipher.doFinal(data);
    }
}
```

Interpretasi: `STATIC_IV` adalah array 16-byte yang **tidak pernah diisi nilai**, sehingga selalu berisi nol — setiap pemanggilan `encrypt()` memakai IV yang **identik**. **FAIL**, persis pola yang ditemukan pada `InsecureBankv2` dan CVE-2026-50210.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Mode CBC memakai IV yang dibangkitkan via `SecureRandom` secara segar untuk **setiap** operasi enkripsi |
| P2 | Mode GCM/CTR memakai nonce yang terjamin **unik** (baik via `SecureRandom` dengan ruang nilai cukup besar, atau counter yang dikelola dengan benar dan dipersist antar-sesi aplikasi) |
| P3 | Verifikasi dinamis (Metode C) mengonfirmasi tidak ada pengulangan nilai IV/nonce yang identik selama sesi pengujian menyeluruh |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Pahami perbedaan persyaratan CBC vs GCM/CTR** (§1.2) — jangan menerapkan kriteria "harus unpredictable" secara seragam ke semua mode; nonce counter sekuensial yang **unik** sudah cukup aman untuk GCM meski "dapat diprediksi" secara teknis.

2. **Prioritaskan temuan pada mode GCM lebih tinggi dibanding CBC** bila keduanya ditemukan — konsekuensi pengulangan nonce pada GCM jauh lebih katastropik (pemulihan kunci autentikasi penuh) dibanding pengulangan IV pada CBC (kebocoran pola plaintext).

3. **Array byte yang tidak diinisialisasi secara eksplisit di Java/Kotlin selalu bernilai nol** — ini jebakan umum yang membuat developer "secara tidak sengaja" menciptakan kondisi FAIL tanpa pernah menuliskan nilai IV secara sadar; waspadai deklarasi `new byte[N]` yang langsung dipakai tanpa `SecureRandom.nextBytes()` berikutnya.

4. **Konfirmasi dinamis (Metode C) adalah pembuktian paling meyakinkan** — analisis statis hanya bisa mengidentifikasi **kandidat** sumber IV yang berbahaya; pengulangan nyata hanya dapat dibuktikan definitif lewat observasi runtime.

5. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | Nonce GCM terbukti berulang pada kunci yang menangani data sensitif | **Kritis** (risiko pemulihan kunci autentikasi penuh) |
   | IV CBC statis/hardcoded pada data sensitif | **Tinggi** |
   | IV/nonce dibangkitkan benar tapi tidak dipersist dengan baik antar-restart aplikasi (potensi pengulangan di masa depan) | **Menengah** |

6. **Dokumentasikan:** mode cipher yang dipakai, sumber IV/nonce (literal/SecureRandom/counter), hasil verifikasi dinamis pengulangan, dan standar NIST yang relevan dilanggar.

---

## 4. Rekomendasi Perbaikan

### 4.1 Untuk CBC: Bangkitkan IV Segar via SecureRandom

```java
byte[] iv = new byte[16];
new SecureRandom().nextBytes(iv);  // IV baru untuk SETIAP operasi enkripsi
Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
// Simpan IV bersama ciphertext — IV tidak perlu rahasia
```

### 4.2 Untuk GCM: Pastikan Nonce Unik, Pertimbangkan Migrasi dari CBC

```java
byte[] nonce = new byte[12];  // 96-bit, ukuran standar GCM
new SecureRandom().nextBytes(nonce);
GCMParameterSpec gcmSpec = new GCMParameterSpec(128, nonce);
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
```

Rujuk dokumen MASTG-TEST-0232 §4 untuk pembahasan lengkap tentang mengapa migrasi dari CBC ke GCM direkomendasikan sebagai solusi arsitektural yang lebih kuat secara keseluruhan.

### 4.3 Checklist Remediasi

- [ ] Seluruh pembuatan `IvParameterSpec`/`GCMParameterSpec` diinventarisasi dan diverifikasi sumbernya
- [ ] Tidak ada IV/nonce yang dibangun dari literal/konstanta statis
- [ ] IV/nonce dibangkitkan via `SecureRandom` untuk setiap operasi enkripsi
- [ ] Verifikasi dinamis mengonfirmasi tidak ada pengulangan nilai yang identik
- [ ] Pertimbangkan migrasi CBC ke GCM untuk implementasi baru
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0309 setelah setiap perubahan pada alur enkripsi

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0309: References to Reused Initialization Vectors in Symmetric Encryption](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0309/)
- [MASTG-TEST-0232: Broken Symmetric Encryption Modes](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0232/)
- [MASWE-0007: Improper Encryption](https://mas.owasp.org/MASWE/MASVS-CRYPTO/MASWE-0007/)

### 5.2 Standar Resmi

- [NIST SP 800-38A: Recommendation for Block Cipher Modes of Operation](https://csrc.nist.gov/pubs/sp/800/38/a/final)
- [NIST SP 800-38D: Recommendation for Block Cipher Modes of Operation — GCM and GMAC](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [CWE-1204: Generation of Weak Initialization Vector (IV)](https://cwe.mitre.org/data/definitions/1204.html)
- [CWE-323: Reusing a Nonce, Key Pair in Encryption](https://cwe.mitre.org/data/definitions/323.html)
- [CWE-329: Generation of Predictable IV with CBC Mode](https://cwe.mitre.org/data/definitions/329.html)

### 5.3 Riset dan Kasus Nyata

- [SentinelOne — CVE-2026-50210: AES-CBC Encryption Weakness Vulnerability](https://www.sentinelone.com/vulnerability-database/cve-2026-50210/)
- [Medium — Tearing Apart InsecureBankv2](https://medium.com/@mohamed0salah213/breaking-insecurebankv2-a-deep-dive-into-android-security-failures-10b18b88e9be)
- [Medium — AES-GCM Nonce Reuse Attack From Scratch](https://medium.com/@patrickl.publique/aes-gcm-nonce-reuse-attack-515f7acec3f7)
- [frereit.de — AES-GCM and Breaking It on Nonce Reuse](https://frereit.de/aes_gcm/)
- [USENIX WOOT16 — Nonce-Disrespecting Adversaries: Practical Forgery Attacks on GCM in TLS](https://www.usenix.org/sites/default/files/conference/protected-files/woot16_slides_bock.pdf)

### 5.4 Dokumentasi Tools

- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [Frida — Dynamic instrumentation toolkit](https://frida.re/docs/javascript-api/)

---

*Dokumen ini disusun sepenuhnya dari riset independen (standar NIST SP 800-38A/800-38D, riset kriptografi akademik, dan kasus nyata termasuk CVE-2026-50210) karena MASTG-TEST-0309 berstatus **placeholder**. Nuansa terpenting: CBC dan GCM/CTR memiliki persyaratan IV/nonce yang berbeda (unpredictability vs uniqueness) dan konsekuensi pelanggaran yang sangat berbeda tingkat keparahannya — pengulangan nonce pada GCM bukan sekadar degradasi keamanan, melainkan keruntuhan kriptografi total via "forbidden attack" Joux yang memulihkan kunci autentikasi GHASH sepenuhnya, memungkinkan baik dekripsi maupun pemalsuan ciphertext yang lolos verifikasi integritas.*
