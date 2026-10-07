# MASTG-TEST-0307 References to Asymmetric Key Pairs Used For Multiple Purposes

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0307 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-CRYPTO (MASVS-CRYPTO-1) |
| **Weakness** | MASWE-0007 — *Improper Encryption* |
| **API yang disorot** | `java.security.KeyPairGenerator`, `android.security.keystore.KeyGenParameterSpec.Builder`, `android.security.keystore.KeyProperties` |
| **Tipe Pengujian** | Static, Code |
| **Knowledge** | MASTG-KNOW-0012 (Key Generation) |
| **Teknik terkait** | MASTG-TECH-0013, MASTG-TECH-0014 |
| **Demo terkait** | — (tidak ada) |
| **Rule resmi** | `mastg-android-asymmetric-key-pair-used-for-multiple-purposes.yml` — rule yang **secara jujur** hanya mengumpulkan lokasi untuk ditinjau manual, **tidak** mengevaluasi nilai bitmask `purposes` itu sendiri (lihat §3.2) |
| **CWE terkait** | CWE-326 (Inadequate Encryption Strength), CWE-320 (Key Management Errors) |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian dan Landasan Standarnya

Kutipan overview resmi MASTG, yang secara eksplisit merujuk standar internasional:

> *"According to section '5.2 Key Usage' of NIST SP 800-57 part 1 revision 5, cryptographic keys should be assigned a specific purpose and used only for that purpose (e.g., encryption, integrity authentication, key wrapping, random bit generation, or digital signatures). For example, a key intended for encryption should not be used for signing."*

Ini adalah salah satu test dalam seri riset ini yang **landasan teoretisnya** paling langsung dirujuk ke standar kriptografi formal (**NIST SP 800-57 Part 1 Rev. 5**, dokumen rekomendasi manajemen kunci kriptografi yang menjadi rujukan industri luas) — bukan sekadar praktik baik yang bersifat konvensi. Prinsip **pemisahan kunci berdasarkan tujuan** (*key separation by purpose*) adalah fondasi dasar dalam desain sistem kriptografi yang aman: setiap kunci harus dibatasi **hanya** untuk satu peran spesifik (enkripsi, tanda tangan, pembungkusan kunci lain, dsb.), dan tidak boleh "dipakai ulang" lintas peran yang berbeda.

### 1.2 Mekanisme Teknis: Bitmask `purposes` pada `KeyGenParameterSpec`

Di Android, pembuatan key pair asimetris lewat `KeyPairGenerator` dikonfigurasi lewat `KeyGenParameterSpec.Builder`, yang menerima **bitmask integer** `purposes` — kombinasi dari konstanta `KeyProperties`:

```java
KeyProperties.PURPOSE_SIGN      // = 4   — menandatangani data
KeyProperties.PURPOSE_VERIFY    // = 8   — memverifikasi tanda tangan
KeyProperties.PURPOSE_ENCRYPT   // = 1   — mengenkripsi data
KeyProperties.PURPOSE_DECRYPT   // = 2   — mendekripsi data
KeyProperties.PURPOSE_WRAP_KEY  // = 32  — membungkus kunci lain
```

Karena `purposes` adalah **bitmask** (nilai-nilai tersebut di-OR-kan secara bitwise), satu kunci secara teknis **bisa** dikonfigurasi untuk mendukung kombinasi peran apa pun — inilah tepatnya yang membuat test ini relevan: **kemampuan teknis untuk mencampur peran tidak berarti itu aman untuk dilakukan**, sesuai prinsip NIST SP 800-57 di atas.

### 1.3 Tabel Nilai yang Dapat Diterima vs Tidak Dapat Diterima — Detail Krusial dari Overview Resmi

Ini bagian paling presisi dan actionable dari seluruh overview test ini — ia memberi **contoh numerik konkret** yang menjadi dasar evaluasi:

> *"For example, a purpose value of `15` combines all four purposes, which is not acceptable: (`PURPOSE_ENCRYPT`=1) | (`PURPOSE_DECRYPT`=2) | (`PURPOSE_SIGN`=4) | (`PURPOSE_VERIFY`=8) = 15"*

Kombinasi nilai yang **DAPAT DITERIMA** (sesuai overview resmi) — masing-masing mewakili **satu peran** (atau pasangan operasi yang secara inheren termasuk **peran yang sama**, bukan dua peran berbeda):

| Nilai Bitmask | Komposisi | Peran |
|---|---|---|
| `1` | `PURPOSE_ENCRYPT` saja | Enkripsi/Dekripsi |
| `2` | `PURPOSE_DECRYPT` saja | Enkripsi/Dekripsi |
| `3` | `PURPOSE_ENCRYPT`\|`PURPOSE_DECRYPT` | Enkripsi/Dekripsi (satu peran utuh) |
| `4` | `PURPOSE_SIGN` saja | Tanda Tangan/Verifikasi |
| `8` | `PURPOSE_VERIFY` saja | Tanda Tangan/Verifikasi |
| `12` | `PURPOSE_SIGN`\|`PURPOSE_VERIFY` | Tanda Tangan/Verifikasi (satu peran utuh) |
| `32` | `PURPOSE_WRAP_KEY` saja | Pembungkusan Kunci |

Kombinasi yang **TIDAK DAPAT DITERIMA** — nilai apa pun yang **mencampur** bit dari lebih dari satu kelompok peran, contoh paling ekstrem adalah `15` (menggabungkan **seluruh** kelompok Enkripsi/Dekripsi **dan** Tanda Tangan/Verifikasi dalam satu kunci yang sama) — namun juga nilai seperti `5` (`ENCRYPT`|`SIGN` = 1+4), `9` (`ENCRYPT`|`VERIFY` = 1+8), `33` (`ENCRYPT`|`WRAP_KEY` = 1+32), dan seterusnya — **setiap** kombinasi yang melintasi batas tiga kelompok peran (Enkripsi/Dekripsi, Tanda Tangan/Verifikasi, Pembungkusan Kunci) dianggap melanggar prinsip pemisahan.

### 1.4 Mengapa Pencampuran Peran Berbahaya: Fondasi Teoretis dan Bukti Empiris

Risiko mencampur peran kunci bukan sekadar formalitas kepatuhan standar — ia memiliki **dasar matematis dan bukti serangan nyata** dalam literatur kriptografi. Riset akademik keamanan protokol (*"The Dangers of Key Reuse: Practical Attacks on IPsec IKE"*, dipresentasikan di USENIX Security Symposium) mendemonstrasikan bagaimana **penggunaan ulang satu key pair lintas protokol/mode operasi yang berbeda** memungkinkan **serangan cross-protocol** — penyerang dapat memanfaatkan **oracle** yang terbentuk dari satu konteks operasi (mis. proses dekripsi pada protokol/mode A) untuk **membobol** keamanan konteks operasi lain (mis. proses verifikasi tanda tangan pada protokol/mode B) yang memakai **kunci kriptografi yang sama**. Prinsip matematis di baliknya: skema kriptografi yang aman untuk satu jenis operasi (mis. enkripsi RSA dengan padding OAEP) **tidak secara otomatis** terbukti aman ketika kunci yang sama dipakai untuk operasi kriptografi yang berbeda (mis. tanda tangan RSA dengan padding PKCS#1) — **asumsi keamanan** yang mendasari pembuktian formal suatu skema kriptografi seringkali **secara eksplisit mengasumsikan** bahwa kunci tersebut **hanya** dipakai untuk satu jenis operasi yang dianalisis.

Ini menjelaskan mengapa NIST SP 800-57 — sebagai standar manajemen kunci paling otoritatif di industri — **secara eksplisit** mewajibkan pemisahan peran kunci sebagai salah satu prinsip fundamentalnya, bukan sekadar rekomendasi kosmetik.

### 1.5 Konteks Tambahan dari MASTG-KNOW-0012: Praktik Terkait yang Perlu Diperhatikan Bersamaan

MASTG-KNOW-0012 memberi beberapa konteks tambahan yang relevan saat mengevaluasi test ini secara menyeluruh:

- **GCM lebih disukai dibanding CBC** untuk mode enkripsi simetris karena menyediakan *authenticated encryption* bawaan — relevan sebagai konteks kualitas implementasi kriptografi secara umum, meski bukan topik utama test ini.
- **Keterbatasan EC Keys sejak Android 11 (API 30)**: *"AndroidKeyStore does not support encryption or decryption with EC keys. They can only be used for signatures."* — ini batasan platform yang justru **membantu** menegakkan pemisahan peran secara struktural untuk kunci Elliptic Curve (EC tidak bisa dipakai untuk enkripsi sama sekali di Keystore modern, sehingga risiko pencampuran peran untuk EC secara otomatis berkurang pada platform terbaru).
- **Peringatan eksplisit soal NDK sebagai "penyembunyi" kunci**: *"There is a widespread false belief that the NDK should be used to hide cryptographic operations and hardcoded keys. However, this mechanism is ineffective."* — relevan sebagai pengingat umum bahwa pemisahan peran yang benar **tidak bisa digantikan** oleh upaya obfuscation/penyembunyian lewat kode native, sebuah miskonsepsi yang berulang kali muncul dalam audit keamanan kriptografi mobile.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **jadx** | Dekompilasi DEX → Java untuk pencarian pola `KeyGenParameterSpec.Builder` |
| **grep / ripgrep** | Pencarian pola konstruktor dan ekstraksi nilai `purposes` |
| **semgrep** | Menjalankan rule resmi sebagai baseline inventarisasi lokasi |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **CodeQL** | Menelusuri nilai literal/konstanta yang diteruskan sebagai argumen `purposes`, menghitung kombinasi bit secara terprogram, dan secara otomatis mengklasifikasikan apakah kombinasi tersebut melintasi batas kelompok peran (§1.3) |
| **Frida** | Hooking konstruktor `KeyGenParameterSpec.Builder` untuk menangkap nilai `purposes` aktual saat runtime, termasuk kasus di mana nilai dibangun secara dinamis/kondisional yang sulit dianalisis statis murni |
| **MobSF** | Kadang menampilkan penggunaan `KeyGenParameterSpec` di laporan Code Analysis kategori kriptografi |

### 2.3 Prasyarat Lingkungan

- **Tidak butuh device/root** untuk analisis statis inti.
- **Pemahaman aritmatika bitwise sederhana** diperlukan untuk menafsirkan nilai `purposes` yang ditemukan, terutama bila dikombinasikan secara tidak langsung (mis. melalui variabel perantara, bukan literal langsung).

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0013** untuk reverse engineer aplikasi.
2. Gunakan **MASTG-TECH-0014** untuk mencari API yang relevan.

### 3.2 Metode A — Rule Semgrep Resmi *(ada, dan secara jujur hanya berfungsi sebagai pengumpul lokasi)*

```yaml
rules:
  - id: mastg-android-asymmetric-key-pair-used-for-multiple-purposes
    severity: WARNING
    languages: [java]
    metadata:
      summary: Detects usage of KeyGenParameterSpec.Builder to collect observations for key-purposes evaluation.
    message: |
      [MASVS-CRYPTO-1] Detected usage of KeyGenParameterSpec.Builder. Review the configured purposes to ensure key separation (avoid mixing encryption/decryption with signing/verification or wrapping).
    pattern: |
      new KeyGenParameterSpec.Builder($ALIAS, $PURPOSES)
```

```bash
semgrep --config https://raw.githubusercontent.com/OWASP/mastg/master/rules/mastg-android-asymmetric-key-pair-used-for-multiple-purposes.yml ./decompiled/sources/
```

**Catatan penting yang membedakan rule ini dari beberapa rule lain yang sudah dianalisis dalam seri riset ini**: `summary` rule ini **secara jujur** menyatakan dirinya hanya *"to collect observations for key-purposes evaluation"* — **tidak mengklaim** mampu mengevaluasi sendiri apakah kombinasi bitmask yang ditemukan melanggar prinsip pemisahan atau tidak. Ini konsisten dengan sifat pattern-nya yang murni mencocokkan **konstruktor** `KeyGenParameterSpec.Builder($ALIAS, $PURPOSES)` tanpa logika evaluasi nilai `$PURPOSES` apa pun. Rule ini **berfungsi sebagaimana diklaim** — berbeda dari pola klaim-vs-implementasi yang menyesatkan yang ditemukan pada beberapa rule lain dalam seri riset ini (`checkServerTrusted`, `onReceivedSslError`, `HostnameVerifier`).

### 3.3 Metode B — grep/ripgrep dengan Ekstraksi dan Kalkulasi Manual Nilai Bitmask

```bash
D=./decompiled/sources

# Temukan seluruh konstruktor KeyGenParameterSpec.Builder beserta argumen purposes
rg -n 'new KeyGenParameterSpec\.Builder\([^,]+,\s*([^)]+)\)' $D

# Cari kombinasi yang menggunakan operator OR (|) — kandidat pencampuran peran
rg -n 'new KeyGenParameterSpec\.Builder\([^,]+,\s*KeyProperties\.\w+\s*\|\s*KeyProperties\.\w+' $D
```

Untuk setiap hasil, hitung manual nilai bitmask berdasarkan konstanta yang ditemukan, dan bandingkan dengan tabel nilai yang dapat diterima (§1.3).

### 3.4 Metode C — CodeQL untuk Klasifikasi Otomatis

```ql
import java

class KeyGenParameterSpecBuilderCall extends ClassInstanceExpr {
  KeyGenParameterSpecBuilderCall() {
    this.getConstructedType().hasQualifiedName("android.security.keystore", "KeyGenParameterSpec$Builder")
  }
}

from KeyGenParameterSpecBuilderCall call
select call, call.getArgument(1).toString(), "Verifikasi manual: apakah nilai purposes ini melintasi batas kelompok peran (Enkripsi/Dekripsi vs Tanda Tangan/Verifikasi vs Wrap Key)?"
```

Untuk klasifikasi otomatis penuh, lengkapi dengan skrip Python yang mem-parsing nilai literal yang diekstrak:

```python
PURPOSE_ENCRYPT, PURPOSE_DECRYPT, PURPOSE_SIGN, PURPOSE_VERIFY, PURPOSE_WRAP_KEY = 1, 2, 4, 8, 32

def classify_purpose(value: int) -> str:
    enc_dec = value & (PURPOSE_ENCRYPT | PURPOSE_DECRYPT)
    sign_verify = value & (PURPOSE_SIGN | PURPOSE_VERIFY)
    wrap = value & PURPOSE_WRAP_KEY

    groups_used = sum([1 for g in [enc_dec, sign_verify, wrap] if g != 0])
    if groups_used > 1:
        return f"FAIL — nilai {value} melintasi {groups_used} kelompok peran sekaligus"
    return f"PASS — nilai {value} hanya dalam satu kelompok peran"

# Contoh dari overview resmi
print(classify_purpose(15))  # FAIL — melintasi 2 kelompok (enc/dec DAN sign/verify)
print(classify_purpose(3))   # PASS — hanya enc/dec
print(classify_purpose(12))  # PASS — hanya sign/verify
```

### 3.5 Metode D — Frida untuk Konfirmasi Runtime

```javascript
// hook-keygenparameterspec-purposes.js
Java.perform(function () {
    var Builder = Java.use("android.security.keystore.KeyGenParameterSpec$Builder");
    Builder.$init.overload("java.lang.String", "int").implementation = function (alias, purposes) {
        console.log("[*] KeyGenParameterSpec.Builder(alias=" + alias + ", purposes=" + purposes + ")");
        var ENC = 1, DEC = 2, SIGN = 4, VERIFY = 8, WRAP = 32;
        var groupsUsed = 0;
        if ((purposes & (ENC | DEC)) !== 0) groupsUsed++;
        if ((purposes & (SIGN | VERIFY)) !== 0) groupsUsed++;
        if ((purposes & WRAP) !== 0) groupsUsed++;
        if (groupsUsed > 1) {
            console.log("    [!] FAIL — purposes melintasi " + groupsUsed + " kelompok peran!");
        }
        return this.$init(alias, purposes);
    };
});
```

### 3.6 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Mendeteksi keberadaan? | Mengevaluasi nilai bitmask? | Kapan dipakai |
|---|---|---|---|---|
| **A** | Rule semgrep resmi | ✅ | ❌ (secara jujur, sesuai klaimnya) | Inventarisasi lokasi awal |
| **B** | grep + kalkulasi manual | ✅ | Manual | Baseline untuk codebase kecil |
| **C** | CodeQL + skrip Python | ✅ | ✅ (otomatis) | **Paling efisien** untuk codebase besar/banyak kunci |
| **D** | Frida | ✅ (runtime) | ✅ (otomatis) | Nilai yang dibangun dinamis, sulit dianalisis statis |

**Kombinasi minimum yang aku rekomendasikan:** **A (inventarisasi lokasi) → C (klasifikasi otomatis nilai bitmask)**, dilengkapi **D** bila dicurigai ada nilai `purposes` yang dibangun secara kondisional/dinamis di runtime.

---

### 3.7 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Evaluation:** *"The test case fails if you find any keys used for multiple roles (groups of purposes)."*

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Nilai `purposes` suatu kunci melintasi **lebih dari satu** kelompok peran (Enkripsi/Dekripsi, Tanda Tangan/Verifikasi, Wrap Key) — contoh: `15`, `5`, `9`, `33`, atau kombinasi lintas-kelompok apa pun |

**Contoh bukti (ilustratif — MASTG belum menyediakan demo resmi untuk test ini):**

```java
// Ditemukan di com/example/target/crypto/MultiPurposeKeyManager.java
KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
    "master_key",
    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT |
    KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY
).build();
// Nilai purposes = 1 | 2 | 4 | 8 = 15
```

Interpretasi: kunci `master_key` dikonfigurasi untuk **keempat** peran sekaligus — melanggar prinsip pemisahan NIST SP 800-57 secara maksimal. **FAIL kritis**.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Setiap kunci asimetris yang ditemukan dikonfigurasi dengan nilai `purposes` yang hanya berada dalam **satu** kelompok peran (sesuai tabel §1.3) |
| P2 | Aplikasi yang membutuhkan kunci untuk peran berbeda (mis. satu untuk enkripsi, satu untuk tanda tangan) memakai **key pair terpisah** untuk masing-masing peran, bukan satu kunci yang dikonfigurasi lintas peran |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Rule resmi bekerja sesuai klaimnya — jangan mengharapkan lebih** — ia murni alat inventarisasi lokasi; evaluasi nilai bitmask tetap sepenuhnya menjadi tanggung jawab penguji (manual atau via Metode C/D).

2. **Pahami bahwa nilai bitmask bisa dikombinasikan secara tidak langsung** — selain operator `|` literal, developer bisa membangun nilai `purposes` lewat variabel yang dirakit di tempat berbeda dalam kode; verifikasi alur data (Metode C CodeQL) lebih andal untuk kasus ini dibanding grep sederhana.

3. **Jika aplikasi membutuhkan banyak peran kriptografi, solusi yang benar adalah banyak kunci, bukan satu kunci multi-peran** — ini poin remediasi paling penting yang harus dikomunikasikan ke tim developer.

4. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | Kunci yang menangani data sensitif dikonfigurasi lintas 3 kelompok peran (encrypt+sign+wrap) | **Tinggi** |
   | Kunci lintas 2 kelompok peran | **Menengah-Tinggi** |
   | Seluruh kunci sudah dipisah sesuai peran masing-masing | **Bukan temuan** |

5. **Dokumentasikan:** alias kunci, nilai bitmask `purposes` persis yang ditemukan, kelompok peran yang terlibat, dan jumlah kelompok yang dilanggar (bila FAIL).

---

## 4. Rekomendasi Perbaikan

### 4.1 Pisahkan Kunci Berdasarkan Peran

```java
// SEBELUM — satu kunci untuk semua peran
KeyGenParameterSpec badSpec = new KeyGenParameterSpec.Builder(
    "master_key",
    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT |
    KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY
).build();

// SESUDAH — kunci terpisah per peran
KeyGenParameterSpec encryptionKeySpec = new KeyGenParameterSpec.Builder(
    "encryption_key",
    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT
).build();

KeyGenParameterSpec signingKeySpec = new KeyGenParameterSpec.Builder(
    "signing_key",
    KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY
).build();
```

### 4.2 Integrasikan Verifikasi ke CI/CD

```bash
#!/bin/bash
# ci-check-key-purpose-separation.sh
jadx -d /tmp/decompiled_check "$1" 2>/dev/null
rg -n 'new KeyGenParameterSpec\.Builder' /tmp/decompiled_check/sources/ | while read -r line; do
    echo "[PERIKSA MANUAL] $line"
done
```

### 4.3 Checklist Remediasi

- [ ] Seluruh pembuatan `KeyGenParameterSpec.Builder` diinventarisasi beserta nilai `purposes`-nya
- [ ] Setiap nilai `purposes` diverifikasi hanya berada dalam satu kelompok peran
- [ ] Kunci yang melanggar pemisahan dipisah menjadi kunci-kunci terpisah sesuai peran masing-masing
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0307 setelah setiap penambahan kunci kriptografi baru

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0307: References to Asymmetric Key Pairs Used For Multiple Purposes](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0307/)
- [MASWE-0007: Improper Encryption](https://mas.owasp.org/MASWE/MASVS-CRYPTO/MASWE-0007/)
- [MASTG-KNOW-0012: Key Generation](https://mas.owasp.org/MASTG/knowledge/android/MASVS-CRYPTO/MASTG-KNOW-0012/)
- [Rule resmi: mastg-android-asymmetric-key-pair-used-for-multiple-purposes.yml (GitHub)](https://github.com/OWASP/mastg/blob/master/rules/mastg-android-asymmetric-key-pair-used-for-multiple-purposes.yml)

### 5.2 Standar dan Dokumentasi Resmi

- [NIST SP 800-57 Part 1 Revision 5 — Recommendation for Key Management](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf)
- [Android Developers — `KeyGenParameterSpec.Builder`](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder)
- [Android Developers — `KeyProperties`](https://developer.android.com/reference/android/security/keystore/KeyProperties)
- [Android Developers — Cryptography (Supported Ciphers)](https://developer.android.com/guide/topics/security/cryptography#SupportedCipher)

### 5.3 Riset Akademik

- [USENIX Security 2018 — The Dangers of Key Reuse: Practical Attacks on IPsec IKE (Felsch et al.)](https://www.usenix.org/conference/usenixsecurity18/presentation/felsch)
- [CWE-326: Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)
- [CWE-320: Key Management Errors](https://cwe.mitre.org/data/definitions/320.html)

### 5.4 Dokumentasi Tools

- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [Frida — Dynamic instrumentation toolkit](https://frida.re/docs/javascript-api/)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026), standar NIST SP 800-57 Part 1 Revision 5, dan riset akademik USENIX Security tentang bahaya penggunaan ulang kunci kriptografi lintas konteks. Berbeda dari beberapa rule lain yang dianalisis dalam seri riset ini, rule semgrep resmi untuk test ini **secara jujur** mengakui keterbatasannya (murni mengumpulkan lokasi untuk ditinjau manual) — evaluasi nilai bitmask `purposes` tetap menuntut kalkulasi aritmatika bitwise eksplisit, baik manual maupun terotomasi lewat CodeQL/skrip, untuk menentukan apakah suatu kunci melanggar prinsip pemisahan peran yang ditetapkan NIST SP 800-57.*
