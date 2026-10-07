# MASTG-TEST-0225 Usage of Insecure APK Signature Key Size

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0225 |
| **Platform** | Android |
| **Kategori MASVS** | **MASVS-RESILIENCE** (Resilience Against Reverse Engineering and Tampering) |
| **Weakness** | **MASWE-0056** — *Usage of Insecure APK Signature Version* (weakness yang sama dengan TEST-0224, mencakup dua aspek berbeda dari APK signing) |
| **Tipe Pengujian** | **Static**, Code |
| **Profile** | **R** (Resilience) |
| **Knowledge** | MASTG-KNOW-0003 (App Signing) |
| **Teknik terkait** | MASTG-TECH-0116 (Obtaining Information about the APK Signature) |
| **Demo terkait** | — (MASTG belum menyediakan demo untuk test ini) |
| **Test bersaudara** | **MASTG-TEST-0224** (Usage of Insecure APK Signature Version) — MASWE-0056 dan teknik yang sama, satu perintah `apksigner` menjawab keduanya sekaligus |
| **Test konseptual serupa** | MASTG-TEST-0208 (Insufficient Key Sizes) — tetapi objeknya **kunci kriptografi data**, bukan kunci penandatangan APK (lihat §1.2) |
| **CWE terkait** | CWE-326 (Inadequate Encryption Strength), CWE-345 (Insufficient Verification of Data Authenticity), CWE-310 (Cryptographic Issues) |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Kutipan langsung dari overview MASTG:

> *"For Android apps, the cryptographic strength of the APK signature is essential for maintaining the app's integrity and authenticity. Using a signature key with **insufficient length**, such as an **RSA key shorter than 2048 bits**, weakens security, making it easier for attackers to compromise the signature. This vulnerability could allow malicious actors to **forge signatures, tamper with the app's code, or distribute unauthorized, modified versions**."*

Test ini menilai **panjang kunci kriptografi yang dipakai untuk menandatangani APK** — bukan panjang kunci konten (isi kode aplikasi mendekripsi/mengenkripsi data pengguna). Ini kunci sertifikat (`.jks`/`.keystore`) milik **developer**, yang dipakai sekali per rilis untuk membubuhkan tanda tangan digital pada seluruh paket APK.

### 1.2 Bedakan dari MASTG-TEST-0208: Dua Jenis Kunci yang Berbeda Total

Ini kebingungan yang sering muncul karena topiknya sama-sama "ukuran kunci tidak memadai". Perbedaannya fundamental:

| | MASTG-TEST-0208 (Insufficient Key Sizes) | MASTG-TEST-0225 *(dokumen ini)* |
|---|---|---|
| **Kunci yang diuji** | Kunci kriptografi **di dalam kode aplikasi** (`KeyGenerator`, `KeyPairGenerator` di Java/Kotlin) | Kunci **penandatanganan APK** (keystore developer, di luar kode aplikasi) |
| **Fungsi kunci** | Mengenkripsi/mendekripsi **data** saat aplikasi berjalan (data user, token, dsb.) | Membubuhkan **tanda tangan digital** pada seluruh paket APK saat proses build/rilis |
| **Siapa yang memakainya** | Kode aplikasi, saat runtime, berulang kali | Developer/pipeline CI-CD, saat build rilis, sekali per versi |
| **Metode deteksi** | Analisis statis kode (semgrep/CodeQL) | Membaca metadata sertifikat dari file APK (`apksigner`) |
| **Dampak bila lemah** | Data pengguna dapat didekripsi paksa | **Seluruh identitas developer dapat dipalsukan** — penyerang dapat membuat APK "resmi" palsu |

Karena objeknya adalah **sertifikat penandatanganan**, bukan kode, **tabel ekuivalensi kekuatan kunci dari MASTG-TEST-0208** (RSA vs bits of security) tetap berlaku secara matematis — tetapi konteks risikonya sangat berbeda: kunci penandatanganan yang lemah tidak membocorkan data pengguna secara langsung, melainkan **membuka jalan bagi pemalsuan identitas aplikasi itu sendiri** (lihat §1.3).

### 1.3 Mengapa Panjang Kunci Signing Sangat Kritis

Tanda tangan digital pada APK berfungsi sebagai **jaminan identitas dan integritas** — ia membuktikan kepada sistem Android dan penggunanya bahwa: (1) APK ini benar-benar berasal dari developer yang mengklaim membuatnya, dan (2) APK ini tidak dimodifikasi sejak ditandatangani.

Kunci privat yang lemah (mis. RSA < 2048-bit) merusak **kedua** jaminan ini sekaligus:

- **Pemalsuan tanda tangan (signature forgery).** Bila kunci privat dapat difaktorkan/dipecahkan, penyerang dapat menghasilkan tanda tangan yang **identik secara kriptografis sah** untuk APK apa pun yang mereka buat — termasuk versi yang sudah disisipi malware. Perangkat pengguna dan Android akan menerimanya sebagai APK "asli" dari developer tersebut.
- **Pembajakan update mechanism.** Karena Android mensyaratkan update aplikasi ditandatangani dengan kunci yang **sama** dengan versi sebelumnya, kunci privat yang bocor/dipecahkan memungkinkan penyerang mendorong "update" berbahaya yang diterima sistem sebagai kelanjutan sah dari aplikasi asli — berpotensi menggantikan aplikasi resmi di perangkat pengguna tanpa peringatan.
- **Kerusakan reputasi dan rantai kepercayaan.** Berbeda dari kebocoran data pengguna yang berdampak pada individu, kompromi kunci signing mengancam **kepercayaan terhadap identitas developer itu sendiri** — dampaknya menyebar ke seluruh basis pengguna dan seluruh riwayat rilis aplikasi.

**RSA-1024 secara spesifik** hanya memberi sekitar **80-bit security** (lihat tabel ekuivalensi NIST SP 800-57 di MASTG-TEST-0208 §1.2) — sudah lama berada di bawah ambang yang dianggap memadai oleh badan standar mana pun, dan telah **dilarang** (`disallowed`) oleh NIST untuk keperluan pembuatan tanda tangan baru sejak 2013 (SP 800-131A). Ini bukan sekadar "kurang optimal" — ini **eksplisit tidak disetujui** untuk kasus penggunaan macam ini.

Kasus dunia nyata yang relevan sebagai konteks (bukan spesifik Android, tetapi mengilustrasikan kelas risiko yang sama): serangan pemalsuan tanda tangan RSA seperti **Bleichenbacher e=3** telah berhasil mem-bypass validasi sertifikat TLS di Firefox pada masa lalu, dan kerentanan serupa terus ditemukan pada berbagai implementasi verifikasi RSA yang tidak menegakkan struktur kriptografis secara ketat. Ini menegaskan bahwa risiko pemalsuan tanda tangan berbasis RSA lemah bukan ancaman teoretis semata.

### 1.4 Algoritma dan Ukuran Kunci yang Didukung untuk APK Signing

Berbeda dari kripto data aplikasi yang leluasa memilih algoritma, penandatanganan APK terikat pada algoritma yang didukung skema signing (v1/v2/v3 — lihat MASTG-TEST-0224 untuk detail skema):

| Algoritma | Ukuran kunci yang didukung APK Signature Scheme v2/v3 | Rekomendasi |
|---|---|---|
| **RSA** | 1024, 2048, 4096, 8192, 16384 bit | **≥ 2048**; kriteria evaluasi MASTG menetapkan batas persis di sini |
| **DSA** | 1024, 2048, 3072 bit | ≥ 2048 (meski 3072 lebih kuat, `keytool` tidak mendukung generasi DSA 3072-bit secara native) |
| **EC (ECDSA)** | Kurva P-256, P-384, P-521 | Kurva P-256 ke atas dianggap memadai (setara RSA-3072+) |

Kriteria evaluasi resmi MASTG **secara spesifik hanya menyebut RSA < 2048** — perlu diperhatikan implikasinya untuk algoritma lain (lihat §3.6 catatan penilaian).

**Persyaratan Google Play** yang relevan sebagai konteks tambahan: Google merekomendasikan ukuran kunci **≥ 2048 bit**, dan mensyaratkan masa berlaku sertifikat **tidak berakhir sebelum 22 Oktober 2033**. Kombinasi persyaratan panjang kunci dan masa berlaku ini bukan kebetulan — keduanya sama-sama merespons proyeksi kemajuan kemampuan komputasi kriptanalisis dalam jangka panjang (§1.3 di MASTG-TEST-0208 membahas hal serupa untuk konteks post-quantum).

---

## 2. Tools yang Dipakai untuk Pengujian

Karena test ini adalah pasangan langsung MASTG-TEST-0224 dengan teknik yang identik (MASTG-TECH-0116), seluruh tooling-nya sama — perbedaannya hanya pada baris output yang diperiksa (`key size` alih-alih `Verified using vX scheme`).

### 2.1 Tools Wajib (Core)

| Tool | MASTG ID | Fungsi |
|---|---|---|
| **apksigner** | MASTG-TOOL-0123 | **Tool resmi MASTG.** Satu-satunya sumber kebenaran definitif untuk metadata sertifikat penandatanganan |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **keytool** (bagian JDK) | Alternatif untuk memeriksa keystore developer secara langsung (bila kamu punya akses ke file `.jks`/`.keystore` itu sendiri, bukan hanya APK jadi) |
| **openssl** | Ekstraksi dan analisis sertifikat X.509 secara manual dari blok signing APK |
| **apkanalyzer** | Alternatif GUI/CLI dari Android SDK untuk melihat info sertifikat |
| **Python `androguard`** | Scripting untuk audit massal ukuran kunci pada banyak APK sekaligus |
| **MobSF** | Analisis otomatis, melaporkan ukuran kunci sertifikat dalam laporan APK |

### 2.3 Prasyarat Lingkungan

- **Tidak butuh device dan tidak butuh root** — cukup file APK. Sepenuhnya dapat diotomatisasi di CI/CD.
- **Sama seperti TEST-0224**: uji APK final yang didistribusikan (hasil `bundletool`/Play Store), bukan hanya build lokal — konfigurasi kunci pada Google Play App Signing dikelola terpisah dari kunci upload developer.
- **Bila kamu memiliki akses langsung ke file keystore** (`.jks`/`.keystore`) untuk keperluan audit internal (bukan hanya APK hasil rilis pihak lain), `keytool` dapat memeriksa kunci secara langsung tanpa perlu APK sama sekali — berguna untuk audit proaktif sebelum rilis pertama.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0116** (*Obtaining Information about the APK Signature*) untuk mendaftar informasi tanda tangan tambahan.

Ini satu-satunya langkah resmi — test ini sangat ringkas karena seluruh informasi yang dibutuhkan sudah tercakup dalam satu perintah yang sama dengan MASTG-TEST-0224.

### 3.2 Metode A — apksigner *(resmi MASTG, satu perintah untuk kedua test bersaudara)*

```bash
apksigner verify --print-certs --verbose YourApp.apk
```

Contoh output resmi MASTG-TECH-0116 (baris yang relevan untuk test ini digarisbawahi secara konseptual):

```
Verifies
Verified using v1 scheme (JAR signing): false
Verified using v2 scheme (APK Signature Scheme v2): true
Verified using v3 scheme (APK Signature Scheme v3): true
Number of signers: 1
Signer #1 certificate DN: CN=Example Developers, OU=Android, O=Example
Signer #1 certificate SHA-256 digest: 1fc4de52d0daa33a9c0e3d67217a77c895b46266ef020fad0d48216a6ad6cb70
Signer #1 certificate SHA-1 digest: 1df329fda8317da4f17f99be83aa64da62af406b
Signer #1 certificate MD5 digest: 3dbdca9c1b56f6c85415b67957d15310
Signer #1 key algorithm: RSA
Signer #1 key size (bits): 2048
Signer #1 public key SHA-256 digest: 296b4e40a31de2dcfa2ed277ccf787db0a524db6fc5eacdcda5e50447b3b1a26
```

> **Perhatikan baris `Signer #1 key algorithm: RSA` dan `Signer #1 key size (bits): 2048`** — kedua baris inilah objek utama penilaian test ini.

**Bila terdapat lebih dari satu signer** (mis. karena rotasi kunci v3, atau aplikasi ditandatangani lebih dari satu pihak), periksa **setiap** signer:

```bash
apksigner verify --print-certs --verbose YourApp.apk | grep -E "Signer #[0-9]+ key"
```

```
Signer #1 key algorithm: RSA
Signer #1 key size (bits): 2048
Signer #2 key algorithm: RSA
Signer #2 key size (bits): 1024
```

### 3.3 Metode B — keytool *(bila kamu memiliki akses langsung ke file keystore)*

Berguna untuk audit **proaktif** sebelum rilis (mis. saat menyiapkan keystore baru), atau saat mengaudit keystore internal organisasi secara langsung.

```bash
keytool -list -v -keystore release.keystore -alias release
```

Contoh output relevan:

```
Alias name: release
Certificate chain length: 1
Certificate[1]:
Owner: CN=Example Developers, OU=Android, O=Example
...
Signature algorithm name: SHA256withRSA
Subject Public Key Algorithm: 2048-bit RSA key
Version: 3
```

### 3.4 Metode C — openssl *(analisis sertifikat X.509 langsung dari blok signing APK)*

Berguna sebagai verifikasi silang independen, terutama bila kamu perlu mengekstraksi sertifikat untuk keperluan analisis lebih lanjut (mis. memeriksa parameter kurva EC secara detail).

```bash
# Ekstrak sertifikat dari v1 signing block (bila ada) via META-INF
unzip -p YourApp.apk "META-INF/*.RSA" > cert.der 2>/dev/null || \
unzip -p YourApp.apk "META-INF/*.DSA" > cert.der 2>/dev/null

openssl pkcs7 -inform DER -in cert.der -print_certs -out cert.pem
openssl x509 -in cert.pem -noout -text | grep -A3 "Public-Key"
```

```
Public-Key: (2048 bit)
```

> Catat: metode ini hanya mengekstrak sertifikat dari skema **v1**. Untuk memeriksa sertifikat pada blok v2/v3 secara langsung dibutuhkan parser khusus format APK Signing Block — **`apksigner` tetap jauh lebih andal** dan sebaiknya menjadi sumber kebenaran utama, bukan metode ini.

### 3.5 Metode D — androguard *(scripting untuk audit massal)*

```python
# check_key_size.py
import subprocess
import glob
import re

def get_signer_info(apk_path):
    result = subprocess.run(
        ["apksigner", "verify", "--print-certs", "--verbose", apk_path],
        capture_output=True, text=True
    )
    return result.stdout

for apk_path in glob.glob("./apks/*.apk"):
    output = get_signer_info(apk_path)
    algos = re.findall(r"Signer #\d+ key algorithm:\s*(\S+)", output)
    sizes = re.findall(r"Signer #\d+ key size \(bits\):\s*(\d+)", output)

    findings = []
    for algo, size in zip(algos, sizes):
        size = int(size)
        if algo.upper() == "RSA" and size < 2048:
            findings.append(f"RSA {size}-bit (INSECURE)")
        elif algo.upper() == "DSA" and size < 2048:
            findings.append(f"DSA {size}-bit (perlu review)")

    verdict = "FAIL" if findings else "PASS"
    print(f"{apk_path}: {list(zip(algos, sizes))} -> {verdict} {findings}")
```

```bash
python3 check_key_size.py
```

### 3.6 Metode E — MobSF

```bash
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
```

Upload APK → bagian **Certificate Analysis** biasanya menampilkan algoritma dan ukuran kunci sekaligus flag peringatan otomatis bila kunci di bawah 2048-bit terdeteksi.

### 3.7 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Sumber data | Butuh akses ke keystore asli? | Cocok untuk audit massal? | Kapan dipakai |
|---|---|---|---|---|---|
| **A** | apksigner (MASTG) | File APK jadi | Tidak | Sedang (perlu scripting) | **Baseline resmi — selalu dipakai** |
| **B** | keytool | File keystore (`.jks`) | **Ya** | Rendah | Audit proaktif sebelum rilis; akses internal ke keystore |
| **C** | openssl | File APK jadi (ekstraksi manual) | Tidak | Rendah | Verifikasi silang independen; hanya menjangkau v1 |
| **D** | androguard | File APK jadi | Tidak | ✅ **(terbaik untuk skala besar)** | Audit portofolio banyak APK, integrasi CI |
| **E** | MobSF | File APK jadi | Tidak | Sebagian | Laporan menyeluruh siap kutip |

**Kombinasi minimum yang aku rekomendasikan:** **A (apksigner) selalu**, ditambah **B (keytool)** khusus untuk audit internal proaktif saat keystore baru dibuat — sebelum aplikasi apa pun ditandatangani dengannya. Sama seperti TEST-0224, `apksigner` sudah memberi jawaban definitif dalam satu perintah, sehingga jalur multi-tool di sini lebih untuk kenyamanan skala/akses daripada menutup celah metodologis.

---

### 3.8 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Observation:** *"The output should contain the information about the key size in a line like: `Signer #1 key size (bits):`."*
>
> **Evaluation:** *"The test case **fails** if any of the key sizes (in bits) is **less than 2048 (RSA)**. For example, `Signer #1 key size (bits): 1024`."*

Kriterianya lugas dan **secara literal spesifik untuk RSA**: ukuran kunci < 2048 bit → FAIL.

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi | Contoh bukti |
|---|---|---|
| F1 | `Signer #N key algorithm: RSA` dengan `key size (bits)` < 2048 | `Signer #1 key algorithm: RSA` + `Signer #1 key size (bits): 1024` |
| F2 | Terdapat **lebih dari satu signer**, dan **salah satu** memakai RSA < 2048 | `Signer #1: RSA 2048` (aman) tetapi `Signer #2: RSA 1024` (lemah) — kriteria "**any** of the key sizes" berarti satu kegagalan sudah cukup untuk FAIL keseluruhan |
| F3 | Kunci upload (upload key) untuk Google Play App Signing memakai RSA < 2048, meski kunci signing final dikelola Google | Rantai kepercayaan tetap melemah di titik upload |
| F4 | Sertifikat sah secara ukuran kunci, tetapi **algoritma tanda tangan** (bukan algoritma kunci) memakai hash lemah seperti SHA-1/MD5 | Di luar cakupan literal kriteria evaluasi ini, tetapi layak dicatat sebagai temuan terkait — lihat catatan penilaian §3.8 |

**Contoh bukti (ilustratif — MASTG belum menyediakan demo resmi untuk test ini):**

```bash
$ apksigner verify --print-certs --verbose LegacyApp.apk
Verifies
Verified using v1 scheme (JAR signing): true
Verified using v2 scheme (APK Signature Scheme v2): false
Number of signers: 1
Signer #1 certificate DN: CN=Old Developer, OU=Mobile, O=LegacyCorp
Signer #1 key algorithm: RSA
Signer #1 key size (bits): 1024
```

Interpretasi: `Signer #1 key size (bits): 1024` — **< 2048** → **FAIL**. Kunci sertifikat ini setara ~80-bit security, sudah lama dianggap tidak memadai dan `disallowed` NIST untuk pembuatan tanda tangan sejak 2013. Bila kunci privat ini dikompromikan (mis. melalui faktorisasi dengan sumber daya komputasi yang cukup, atau kebocoran file keystore), penyerang dapat menandatangani APK jahat yang akan diterima sebagai "asli" oleh perangkat yang sudah menginstal aplikasi ini.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi | Contoh bukti |
|---|---|---|
| P1 | Semua signer memakai RSA ≥ 2048 bit | `Signer #1 key size (bits): 2048` atau lebih besar |
| P2 | Signer memakai algoritma EC (ECDSA) dengan kurva standar (P-256 ke atas) | Secara matematis setara atau lebih kuat dari RSA-2048; **tidak secara eksplisit disebutkan** kriteria evaluasi tetapi konsisten dengan tujuannya |
| P3 | Signer memakai DSA ≥ 2048 bit | `Signer #1 key algorithm: DSA`, `Signer #1 key size (bits): 2048` |
| P4 | Terdapat beberapa signer (rotasi kunci v3), dan **seluruhnya** memenuhi ambang minimum | Konsisten di semua entri, tidak ada satu pun yang lemah |

**Contoh output yang menandakan PASS:**

```bash
$ apksigner verify --print-certs --verbose ModernApp.apk
Verifies
Verified using v1 scheme (JAR signing): true
Verified using v2 scheme (APK Signature Scheme v2): true
Verified using v3 scheme (APK Signature Scheme v3): true
Number of signers: 1
Signer #1 certificate DN: CN=Example Developers, OU=Android, O=Example
Signer #1 key algorithm: RSA
Signer #1 key size (bits): 2048
```

Interpretasi: RSA 2048-bit → **PASS**. Setara ~112-bit security menurut NIST SP 800-57 — masih dapat diterima meski akan menghadapi tekanan deprecation menuju 2030 (lihat pembahasan lebih dalam di MASTG-TEST-0208 §1.2 untuk konteks jangka panjang, meski tidak menjadi kriteria FAIL/PASS test ini saat ini).

Contoh PASS dengan rotasi kunci v3 (dua signer, keduanya memadai):

```bash
$ apksigner verify --print-certs --verbose RotatedKeyApp.apk
Number of signers: 2
Signer #1 key algorithm: RSA
Signer #1 key size (bits): 2048
Signer #2 key algorithm: RSA
Signer #2 key size (bits): 4096
```

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Kriteria resmi MASTG secara literal hanya menyebut RSA.** Bila `key algorithm` menunjukkan **DSA** atau **EC**, kriteria FAIL yang eksplisit ("< 2048 bit RSA") **tidak secara langsung berlaku** secara harfiah. Terapkan penilaian dengan akal sehat menggunakan tabel ekuivalensi (§1.4): DSA < 2048 tetap harus diperlakukan sebagai temuan yang setara seriusnya (bertaut MASTG-TEST-0208 untuk landasan tabel ekuivalensi kekuatan kunci), dan EC dengan kurva di bawah P-256 (jarang ditemukan dalam praktik APK signing, tetapi tetap perlu diperiksa) juga layak dicatat.

2. **"Any of the key sizes" berarti periksa SEMUA signer, bukan hanya yang pertama.** Pada aplikasi dengan rotasi kunci v3 (multiple signers), satu kunci lemah di antara beberapa yang kuat **tetap membuat keseluruhan hasil FAIL**. Jangan berhenti memeriksa setelah menemukan signer pertama yang aman.

3. **Uji APK final yang didistribusikan, bukan hanya build lokal** — identik dengan catatan di MASTG-TEST-0224. Konfigurasi Google Play App Signing dapat melibatkan kunci upload yang berbeda dari kunci signing final; keduanya perlu diperiksa dalam konteks yang sesuai (kunci upload untuk keamanan proses submit, kunci final untuk keamanan APK yang diterima pengguna).

4. **Algoritma hash pada tanda tangan (bukan ukuran kunci) adalah dimensi terpisah yang tidak tercakup kriteria literal test ini, tetapi layak dicatat.** `keytool`/`openssl` dapat menunjukkan `Signature algorithm name: SHA1withRSA` — ini masalah berbeda (hash lemah, bukan ukuran kunci) yang secara konseptual dekat dengan area MASTG-TEST-0221 (broken algorithms) meski test tersebut berfokus pada enkripsi data, bukan signing certificate. Dokumentasikan sebagai catatan tambahan bila ditemukan.

5. **Panjang kunci yang memadai tidak menyelamatkan kunci yang bocor.** Test ini murni menilai **panjang** kunci sebagaimana tercatat dalam sertifikat — ia tidak dan tidak bisa menilai apakah file keystore itu sendiri disimpan dengan aman (mis. tersimpan plaintext di repository kode, dibagikan lewat saluran tidak aman, dsb.). Itu adalah risiko operasional terpisah yang jauh lebih umum terjadi dalam praktik dibanding kunci yang secara matematis dipecahkan — lihat rekomendasi §4 untuk pengelolaan keystore yang aman.

6. **Perbedaan penting dengan MASTG-TEST-0208 soal ambang "cukup".** MASTG-TEST-0208 memperdebatkan apakah AES-128 memadai mengingat ancaman kuantum jangka panjang. Untuk kunci **signing** seperti di sini, ambang 2048-bit RSA **belum** menjadi bahan perdebatan serupa dalam kriteria evaluasi MASTG saat ini — tetapi tim keamanan yang ingin proaktif dapat mempertimbangkan RSA-3072/4096 atau EC P-256+ sebagai target hardening melebihi baseline minimum, khususnya untuk aplikasi dengan masa hidup sangat panjang (§1.4, mengingat validitas sertifikat yang direkomendasikan ≥ 25 tahun).

7. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | RSA < 1024 bit (sangat lemah, hampir tidak pernah ditemukan di alam nyata untuk APK modern) | **Kritis** |
   | RSA 1024 bit | **Tinggi** — sesuai contoh eksplisit kriteria evaluasi MASTG |
   | RSA antara 1024–2048 (bila memungkinkan secara teknis, jarang) | **Tinggi** |
   | Salah satu dari beberapa signer (rotasi kunci) lemah, sisanya kuat | **Tinggi** — tetap FAIL keseluruhan |
   | RSA ≥ 2048, DSA ≥ 2048, atau EC P-256+ | **Bukan temuan** |

8. **Dokumentasikan:** output lengkap `apksigner verify --print-certs --verbose`, algoritma dan ukuran kunci untuk **setiap** signer, apakah APK yang diuji adalah build lokal atau hasil distribusi final, serta — bila kunci ditemukan lemah — rekomendasi rotasi kunci dan dampaknya terhadap mekanisme update aplikasi yang sudah terpasang di perangkat pengguna (lihat §4).

---

## 4. Rekomendasi Perbaikan

### 4.1 Prinsip Utama

**Prioritas 1 — Gunakan RSA ≥ 2048 bit (idealnya 4096) atau EC P-256+ saat membuat keystore baru.**

```bash
# ✅ RSA 4096-bit — melebihi baseline minimum untuk margin keamanan jangka panjang
keytool -genkeypair -v \
  -keystore release.keystore \
  -alias release \
  -keyalg RSA \
  -keysize 4096 \
  -validity 10000 \
  -storetype PKCS12

# ✅ Alternatif: EC dengan kurva P-256 (setara/lebih kuat dari RSA-3072, ukuran file lebih kecil)
keytool -genkeypair -v \
  -keystore release.keystore \
  -alias release \
  -keyalg EC \
  -groupname secp256r1 \
  -validity 10000 \
  -storetype PKCS12
```

**Prioritas 2 — Bila kunci existing terdeteksi lemah (RSA < 2048), lakukan rotasi kunci via APK Signature Scheme v3.** Ini skenario yang jauh lebih kompleks daripada sekadar membuat kunci baru, karena Android mensyaratkan kesinambungan tanda tangan untuk mekanisme update:

- **v3 signing scheme secara khusus dirancang untuk kasus ini** — memungkinkan APK ditandatangani dengan kunci **baru** sambil tetap menyertakan bukti bahwa kunci baru tersebut merupakan penerus sah dari kunci **lama**, sehingga perangkat yang sudah menginstal versi lama tetap dapat menerima update tanpa perlu uninstall-reinstall.
- Proses ini disebut **key rotation**, dan didokumentasikan resmi oleh Android sebagai mekanisme untuk kasus persis seperti ini (kunci lama dianggap lemah/berisiko, tetapi kontinuitas dengan basis pengguna existing harus dipertahankan).
- **Google Play App Signing** menyederhanakan skenario ini secara signifikan — karena Google mengelola kunci signing final, developer hanya perlu memperbarui kunci **upload**, dan Google menangani transisi tanda tangan final tanpa mengganggu basis pengguna existing.

**Prioritas 3 — Pastikan validitas sertifikat memadai bersamaan dengan penguatan ukuran kunci.** Saat membuat ulang keystore, sekaligus terapkan masa berlaku yang sesuai rekomendasi (≥ 25 tahun, berakhir setelah 22 Oktober 2033 untuk syarat Google Play) — lihat `-validity 10000` (≈ 27,4 tahun) pada contoh perintah di atas.

**Prioritas 4 — Migrasi ke Google Play App Signing bila belum dilakukan.** Ini memindahkan tanggung jawab pengelolaan kunci signing final ke infrastruktur Google yang menerapkan standar keamanan kunci secara konsisten, sekaligus memberi jaring pengaman berupa kemampuan reset kunci upload bila terjadi insiden, tanpa kehilangan identitas signing final aplikasi.

**Prioritas 5 — Amankan penyimpanan file keystore terlepas dari kekuatan kuncinya.** Sesuai catatan penilaian §3.8 poin 5 — kekuatan matematis kunci tidak relevan bila file `.jks`/`.keystore` itu sendiri bocor:
- Jangan pernah menyimpan file keystore atau password-nya di repository kode sumber (Git, dsb.).
- Gunakan secret management (mis. GitHub Actions Secrets, HashiCorp Vault, atau setara) untuk pipeline CI/CD.
- Batasi akses ke file keystore hanya untuk personel/sistem yang benar-benar memerlukannya.
- Simpan cadangan (backup) keystore secara aman dan terenkripsi — kehilangan keystore sama parahnya dengan kompromi keamanannya, karena developer kehilangan kemampuan menerbitkan update sah selamanya untuk aplikasi tersebut.

**Prioritas 6 — Integrasikan pemeriksaan ukuran kunci ke pipeline rilis**, sejalan dengan MASTG-TEST-0224:

```bash
#!/bin/bash
# ci-verify-key-size.sh
APK=$1
apksigner verify --print-certs --verbose "$APK" | \
  awk '/key algorithm: RSA/{getline; if ($0 ~ /key size \(bits\): (10[0-9][0-9]|[1-9][0-9][0-9])$/) exit 1}'

if [ $? -eq 1 ]; then
    echo "[GAGAL] Ditemukan signer dengan kunci RSA < 2048 bit"
    exit 1
fi
echo "[OK] Ukuran kunci signing memadai"
```

### 4.2 Checklist Remediasi

- [ ] Ukuran kunci signing diverifikasi untuk **setiap** signer (bukan hanya yang pertama) dengan `apksigner verify --print-certs --verbose`
- [ ] Semua signer memakai RSA ≥ 2048 bit (idealnya 4096), atau DSA ≥ 2048, atau EC P-256+
- [ ] Bila kunci existing terdeteksi lemah: rencana rotasi kunci via APK Signature Scheme v3 disusun dan dieksekusi
- [ ] Migrasi ke Google Play App Signing dipertimbangkan/sudah dilakukan
- [ ] Validitas sertifikat memadai (≥ 25 tahun, berakhir setelah 22 Oktober 2033)
- [ ] File keystore dan password-nya **tidak** tersimpan di repository kode
- [ ] Secret management dipakai untuk kredensial signing di pipeline CI/CD
- [ ] Backup keystore tersimpan aman dan terenkripsi
- [ ] APK final hasil distribusi (Play Store/bundletool) diverifikasi terpisah dari build lokal
- [ ] Algoritma hash pada signature (bukan hanya ukuran kunci) turut diperiksa untuk kelemahan tambahan (SHA-1/MD5)
- [ ] Pemeriksaan ukuran kunci diintegrasikan sebagai gate otomatis di pipeline CI/CD rilis
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0225 setelah setiap perubahan/rotasi kunci signing
- [ ] **Verifikasi silang:** jalankan MASTG-TEST-0224 (skema signing) — satu perintah `apksigner` yang sama menjawab keduanya

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0225: Usage of Insecure APK Signature Key Size](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0225/)
- [MASTG-TEST-0224: Usage of Insecure APK Signature Version](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0224/)
- [MASTG-TEST-0208: Insufficient Key Sizes](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0208/)
- [MASWE-0056: Usage of Insecure APK Signature Version](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0056/)
- [MASTG-KNOW-0003: App Signing](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0003/)
- [MASTG-BEST-0006: Use Up-to-Date APK Signing Schemes](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0006/)
- [MASTG-TECH-0116: Obtaining Information about the APK Signature](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0116/)
- [MASTG-TOOL-0123: apksigner](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0123/)
- [MASVS-RESILIENCE: Resilience Against Reverse Engineering and Tampering](https://mas.owasp.org/MASVS/11-MASVS-RESILIENCE/)
- [OWASP Mobile Top 10 2024 — M7: Insufficient Binary Protections](https://owasp.org/www-project-mobile-top-10/2023-risks/m7-insufficient-binary-protections.html)

### 5.2 Dokumentasi Resmi Android / Google

- [Android — Application Signing](https://developer.android.com/studio/publish/app-signing.html)
- [Android — Sign your app (key generation, keytool)](https://developer.android.com/studio/publish/app-signing)
- [Android — APK Signature Scheme v3 (key rotation)](https://source.android.com/docs/security/features/apksigning/v3)
- [Android — apksigner tool reference](https://developer.android.com/tools/apksigner)
- [Android — Google Play App Signing](https://support.google.com/googleplay/android-developer/answer/9842756)
- [Android — Signing Considerations (key size, validity period)](https://developer.android.com/studio/publish/app-signing#considerations)
- [Google Play Console Help — Play App Signing](https://support.google.com/googleplay/android-developer/answer/9842756?hl=en)
- [Guardian Project — How to Migrate Your Android App's Signing Key](https://guardianproject.info/2015/12/29/how-to-migrate-your-android-apps-signing-key/)

### 5.3 Standar Kriptografi & Riset

- [NIST SP 800-57 Part 1 Rev. 5 — Recommendation for Key Management](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
- [NIST SP 800-131A Rev. 2 — Transitioning the Use of Cryptographic Algorithms and Key Lengths](https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final)
- [CWE-326: Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)
- [CWE-345: Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)
- [CWE-310: Cryptographic Issues](https://cwe.mitre.org/data/definitions/310.html)
- [CERT/CC VU#725167 — node-forge Signature Forgery Vulnerabilities in RSA-PKCS](https://kb.cert.org/vuls/id/725167)
- [Cryptopals — Bleichenbacher's e=3 RSA Attack](https://cryptopals.com/sets/6/challenges/42)
- [NIST SP 800-163 Rev.1 — Vetting the Security of Mobile Applications](https://csrc.nist.gov/publications/detail/sp/800-163/rev-1/final)

### 5.4 Dokumentasi Tools

- [apksigner — Android Developers tool reference](https://developer.android.com/tools/apksigner)
- [keytool — Java key and certificate management tool](https://docs.oracle.com/en/java/javase/17/docs/specs/man/keytool.html)
- [OpenSSL — command-line tools](https://www.openssl.org/docs/man3.0/man1/)
- [Androguard — Android APK/DEX analysis library](https://github.com/androguard/androguard)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026), dokumentasi resmi Android Open Source Project mengenai APK Signature Scheme dan App Signing, serta standar NIST SP 800-57/800-131A. Test ini belum memiliki demo (MASTG-DEMO) resmi dari MASTG, dan merupakan pasangan langsung MASTG-TEST-0224 yang berbagi teknik pengujian (MASTG-TECH-0116) dan weakness (MASWE-0056).*
