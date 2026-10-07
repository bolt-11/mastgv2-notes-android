# MASTG-TEST-0207 Runtime Storage of Unencrypted Data in the App Sandbox

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0207 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-STORAGE (MASVS-STORAGE-1: Aplikasi menyimpan data sensitif secara aman) |
| **Weakness** | **MASWE-0001** — *Sensitive Data Stored Unencrypted in Private Storage* |
| **Tipe Pengujian** | Dynamic, Filesystem |
| **Profile** | **L2 saja** (bukan L1) |
| **Prerequisites** | `identify-sensitive-data` |
| **Knowledge** | MASTG-KNOW-0041 (Internal Storage) |
| **Best Practice** | MASTG-BEST-0050 (Store Data Encrypted in App Sandbox Directory) |
| **Teknik terkait** | MASTG-TECH-0005 (Installing Apps), MASTG-TECH-0008 (Accessing App Data Directories) |
| **Demo terkait** | MASTG-DEMO-0010 (File System Snapshots from Internal Storage) |
| **Test bersaudara** | MASTG-TEST-0287 (SharedPreferences — dinamis/hooks), MASTG-TEST-0304 (SQLite), MASTG-TEST-0305 (DataStore), MASTG-TEST-0306 (Room) — semuanya MASWE-0001 |
| **Pasangan konseptual** | MASTG-TEST-0200 (*Files Written to External Storage* — MASWE-0002) |
| **CWE terkait** | CWE-312 (Cleartext Storage of Sensitive Information), CWE-311 (Missing Encryption of Sensitive Data), CWE-922 (Insecure Storage of Sensitive Information), CWE-200 (Exposure of Sensitive Information) |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Tujuan test ini adalah **mengambil file yang ditulis ke internal storage (app sandbox) lalu menginspeksi isinya**, terlepas dari API apa pun yang dipakai untuk menulisnya.

Kutipan langsung dari overview MASTG:

> *"The goal of this test is to retrieve the files written to the **internal storage** and inspect them **regardless of the APIs used to write them**. It uses a simple approach based on file retrieval from the device storage before and after the app is exercised to identify the files created during the app's execution and to check if they contain sensitive data."*

Metodologinya **identik dengan MASTG-TEST-0200**, hanya berbeda target direktorinya:

| | MASTG-TEST-0200 | MASTG-TEST-0207 *(dokumen ini)* |
|---|---|---|
| **Target** | External storage (`/sdcard/...`) | **Internal storage / app sandbox** (`/data/data/<pkg>/`) |
| **Weakness** | MASWE-0002 (*outside* private storage) | **MASWE-0001** (*in* private storage) |
| **Profile** | L1, L2 | **L2 saja** |
| **Butuh root?** | Tidak | **Ya** (atau app debuggable) |
| Metodologi | Snapshot before/after + diff | Snapshot before/after + diff |

Keduanya bersama-sama mencakup **seluruh permukaan penyimpanan lokal** aplikasi.

### 1.2 Pertanyaan Utama: Kalau Sandbox Sudah Melindungi, Kenapa Ini FAIL?

Ini pertanyaan paling wajar dan paling penting untuk dijawab sebelum menguji, karena MASTG-KNOW-0041 sendiri menyatakan:

> *"Files saved to internal storage are **containerized by default and cannot be accessed by other apps** on the device. When the user uninstalls your app, these files are removed."*

Jadi mengapa menyimpan data plaintext di sana tetap dinyatakan gagal? Karena sandbox melindungi terhadap **satu** kelas penyerang saja: aplikasi lain pada perangkat yang tidak dikompromikan. Ada banyak jalur lain:

| Jalur akses | Kondisi | Catatan |
|---|---|---|
| **Perangkat di-root** | Root/exploit/custom ROM | Sandbox UID Linux tidak lagi berarti. Root user selalu dapat membaca `/data/data/*` |
| **Malware dengan privilege escalation** | Exploit kernel/vendor | Sama seperti di atas |
| **Aplikasi debuggable** | `android:debuggable="true"` | `adb shell run-as <pkg>` memberi akses penuh ke sandbox **tanpa root** |
| **`adb backup`** | `allowBackup="true"` | Ekstraksi data sandbox tanpa root. Dibatasi pada Android modern, tetapi masih relevan untuk device/target SDK lama. Bertaut dengan MASTG-TEST-0216 |
| **Cloud/vendor backup** | Auto Backup, backup vendor (Samsung/Xiaomi) | Data sandbox tersinkronisasi ke luar perangkat |
| **Kerentanan berantai (chained)** | Path traversal, exported ContentProvider, arbitrary file read, `WebView` `file://`, deep link | Kerentanan "ringan" berubah menjadi pencurian kredensial karena datanya plaintext |
| **Forensik fisik / perangkat dicuri** | Akses fisik | FBE melindungi saat *Before First Unlock*. Setelah perangkat pernah di-unlock (AFU), kunci ada di memori dan data dapat diekstraksi dengan tooling forensik komersial |
| **Perangkat bersama / profil kerja** | MDM, profil ganda | Admin perangkat dapat memiliki akses lebih luas |
| **Bug di aplikasi itu sendiri** | Logika salah | Mis. file sandbox dicopy ke external storage atau dilampirkan ke laporan bug |

Prinsipnya: **sandbox adalah kontrol akses, bukan kerahasiaan (confidentiality) data at-rest.** Enkripsi adalah lapisan pertahanan berikutnya (*defense in depth*) yang membuat data tetap aman ketika lapisan pertama jatuh.

**Inilah juga alasan profile-nya `L2`, bukan L1.** MASVS-L2 ditujukan untuk aplikasi dengan kebutuhan keamanan lebih tinggi (finansial, kesehatan, pemerintahan) yang model ancamannya **mencakup** penyerang dengan akses fisik atau perangkat yang di-root. Untuk aplikasi L1, data plaintext di sandbox dapat dianggap risiko yang diterima; untuk L2, tidak.

> Perhatikan kontrasnya: MASTG-TEST-0287 (SharedPreferences) berprofil **L1 dan L2**, sedangkan TEST-0207 hanya **L2**. Artinya MASTG menilai `SharedPreferences` plaintext sebagai masalah bahkan pada tingkat dasar (karena sangat sering dipakai untuk token dan mudah ditemukan), sementara pemeriksaan menyeluruh seluruh sandbox adalah aktivitas tingkat lanjut.

### 1.3 Anatomi App Sandbox — Apa yang Harus Diperiksa

Berdasarkan MASTG-TECH-0008, direktori data internal berada di `/data/data/<package-name>` atau `/data/user/0/<package-name>` (keduanya ekuivalen; `/data/user/0/` adalah bentuk yang sadar-multi-user).

**Struktur standar dan artinya untuk pengujian:**

| Direktori | Fungsi | Yang perlu dicari |
|---|---|---|
| **`shared_prefs/`** | File XML dari `SharedPreferences` API | **Target prioritas tertinggi.** Sering memuat token, flag login, ID user, setting. Plaintext XML — sangat mudah dibaca |
| **`databases/`** | File SQLite yang dibuat aplikasi saat runtime | Data user, cache respons API, riwayat chat. **Jangan lupa file `-wal`, `-shm`, `-journal`** (lihat §1.4) |
| **`files/`** | File reguler yang dibuat aplikasi | Apa pun — token, dokumen, kunci, cache terenkode |
| **`cache/`** | Cache data; **cache WebView ada di sini** | Respons HTTP ter-cache (bisa memuat body API berisi PII), gambar, thumbnail |
| **`code_cache/`** | Cache kode; dihapus sistem saat app/platform di-upgrade | Kode ter-optimasi |
| **`lib/`** | Native library (`.so`) per arsitektur (`armeabi-v7a`, `arm64-v8a`, `x86`, `x86_64`, dst.) | Biasanya bukan target, tetapi bisa memuat string sensitif |
| **`no_backup/`** | File yang dikecualikan dari backup | Tetap perlu diperiksa isinya |
| **`app_webview/`** | Data WebView: `Cookies`, `Local Storage`, `Session Storage`, `IndexedDB` | **Sering terlewat.** Cookie sesi dan token dari SPA di dalam WebView |
| **`app_textures/`, `app_flutter/`, `app_*`** | Direktori spesifik framework | Flutter (`app_flutter/`), React Native, dsb. |

MASTG-TECH-0008 memberi peringatan yang penting:

> *"However, the app might store more data not only inside these folders but also in the **parent folder** (`/data/data/[package-name]`)."*

Jadi jangan hanya memeriksa subdirektori yang dikenal — **sapu seluruh direktori secara rekursif**. Inilah kekuatan pendekatan diffing: ia API-agnostic **dan** direktori-agnostic.

### 1.4 Titik Buta Khas Internal Storage: WAL, Journal, dan Sisa Data

Ini aspek yang membuat test ini sering menemukan hal yang tidak ditemukan analisis statis maupun hooking:

**SQLite Write-Ahead Log (WAL) dan journal.** Bila aplikasi memakai SQLite (langsung, via Room, atau via library pihak ketiga), operasi tulis melewati file tambahan:

| File | Isi |
|---|---|
| `<db>.db-wal` | Write-ahead log — memuat **halaman data yang belum di-checkpoint**, termasuk baris yang sudah "dihapus" dari perspektif aplikasi |
| `<db>.db-shm` | Shared memory index untuk WAL |
| `<db>.db-journal` | Rollback journal (mode journal lama) |

Konsekuensinya: **data sensitif bisa tetap ada di `-wal` meski sudah dihapus dari tabel utama**, dan bahkan ketika aplikasi mengklaim "menghapus data saat logout". Selalu tarik dan periksa file-file ini, bukan hanya `.db`-nya.

**Sisa data lain yang perlu diperiksa:**
- **File temporer** yang ditulis lalu dihapus — mungkin tidak muncul di diff, tetapi terkadang tertinggal karena crash
- **Backup file** buatan aplikasi sendiri (`*.bak`, `*.old`, `*.tmp`)
- **Cache WebView** yang memuat body respons API
- **Crash dump / ANR trace** yang aplikasi tulis ke sandbox

### 1.5 Elemen Baru dalam Evaluasi: Encoding Bukan Enkripsi

Kriteria evaluasi test ini memuat instruksi yang **tidak ada di MASTG-TEST-0200** dan merupakan nilai tambah pentingnya:

> *"When evaluating the data, attempt to identify and decode data that has been encoded using methods such as **base64 encoding, hexadecimal representation, URL encoding, escape sequences, wide characters** and common data obfuscation methods such as **xoring**. Also consider identifying and decompressing compressed files such as **tar or zip**. **These methods obscure but do not protect sensitive data.**"*

Kalimat terakhirnya adalah inti penilaian test ini. Pola yang sering ditemui di aplikasi nyata:

| Yang ditemukan | Apakah ini enkripsi? | Verdict |
|---|---|---|
| `c2VjcjN0UGEkJFcwcmQK` (Base64) | ❌ Encoding | **FAIL** |
| `7365637233745061242457307264` (hex) | ❌ Representasi | **FAIL** |
| `secr3tPa%24%24W0rd` (URL-encoded) | ❌ Encoding | **FAIL** |
| `sec...` (escape sequence) | ❌ Encoding | **FAIL** |
| UTF-16LE / wide char (`s\0e\0c\0...`) | ❌ Representasi | **FAIL** |
| XOR dengan kunci statis/hardcoded | ❌ Obfuscation | **FAIL** |
| ROT13 / substitusi sederhana | ❌ Obfuscation | **FAIL** |
| ZIP/GZIP/TAR (bahkan dengan password ZIP lemah) | ❌ Kompresi | **FAIL** |
| AES-256-GCM dengan kunci dari Android KeyStore | ✅ Enkripsi authenticated | PASS |

Karena itu, alur inspeksi wajib mencakup **normalisasi berlapis** — bukan sekadar `grep` polos. Implementasinya di §3.4.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | MASTG ID | Fungsi dalam test ini |
|---|---|---|
| **adb** | MASTG-TOOL-0004 | Instalasi APK, enumerasi file (`find`), penarikan file (`pull`), `run-as`. Tool utama |
| **Android device / emulator (rooted)** | MASTG-TOOL-0003 | **Root diperlukan** untuk membaca `/data/data/<pkg>/` — kecuali aplikasi debuggable. Emulator AVD dengan image *Google APIs* (bukan Google Play) mudah di-root via `adb root` |
| **Objection** | MASTG-TOOL-0038 | MASTG-TECH-0008 memakainya: `env` untuk menampilkan seluruh path direktori aplikasi, `ls`/`cd` untuk eksplorasi, `filesystem download <file>` / `--folder` untuk menarik data. **Bekerja tanpa app harus debuggable** |
| **`sqlite3` / DB Browser for SQLite** | — | Membuka database yang ditemukan, termasuk memeriksa WAL |
| **`file`, `strings`, `xxd`, `hexdump`** | — | Identifikasi tipe file dan ekstraksi string |

### 2.2 Tools Pendukung

| Tool | Fungsi |
|---|---|
| **`ent` / analisis entropi** | Membedakan file benar-benar ter-enkripsi (≈7.9+ bit/byte) dari yang hanya di-encode/obfuscate. **Krusial** untuk test ini |
| **`base64`, `xxd -r -p`, `python3`** | Dekode berlapis sesuai instruksi evaluasi MASTG |
| **`binwalk`** | Deteksi & ekstraksi file terkompresi/tertanam di dalam blob |
| **`xortool`** | Memulihkan kunci XOR — membuktikan bahwa "enkripsi" yang ditemukan hanyalah XOR |
| **`jq`, `protoc --decode_raw`** | Membaca payload JSON dan Protobuf (Proto DataStore memakai Protobuf) |
| **`grep` / `ripgrep`, TruffleHog, gitleaks** | Pemindaian pola secret pada hasil tarikan |
| **jadx** | MASTG-TOOL-0018 — konfirmasi lokasi kode dan memverifikasi klaim enkripsi (mode cipher, asal kunci) |
| **Frida** | MASTG-TOOL-0001 — untuk MASTG-TEST-0287 (hooking `SharedPreferences`) dan untuk menangkap file temporer yang ditulis-lalu-dihapus |
| **Android Studio Device File Explorer** | Browsing visual (View → Tool Windows → Device File Explorer). Pada device non-rooted hanya bekerja bila app debuggable, dan "terkurung" di dalam sandbox app |
| **`adb backup` / `abe` (Android Backup Extractor)** | Jalur ekstraksi alternatif tanpa root. Dibatasi pada Android modern — lihat §2.3 |

### 2.3 Prasyarat Lingkungan

**Ini pembeda praktis terbesar dari MASTG-TEST-0200: kamu butuh akses ke dalam sandbox.** Ada tiga jalur:

```bash
# Jalur A — ROOT (paling andal, direkomendasikan)
adb root
adb shell "find /data/data/com.example.target -type f"
adb pull /data/data/com.example.target ./sandbox_dump

# Pada emulator, `adb root` biasanya langsung berhasil.
# Pada device rooted dengan Magisk:
adb shell "su -c 'find /data/data/com.example.target -type f'"
# Untuk pull, copy dulu ke lokasi yang dapat dibaca adb:
adb shell "su -c 'tar czf /data/local/tmp/sandbox.tgz -C /data/data com.example.target'"
adb pull /data/local/tmp/sandbox.tgz

# Jalur B — run-as (tanpa root, TAPI app harus debuggable)
adb shell run-as com.example.target ls -laR /data/data/com.example.target
adb shell run-as com.example.target tar czf - . > sandbox.tgz   # dari dalam sandbox
# Jika app tidak debuggable -> "run-as: package not debuggable"
# Solusi: repackaging APK dengan android:debuggable="true" (apktool + apksigner)

# Jalur C — Objection (tanpa root, TANPA perlu app debuggable)
objection -g com.example.target explore
#   env                                  -> tampilkan semua path direktori
#   cd /data/user/0/com.example.target
#   ls
#   filesystem download shared_prefs ./sp --folder
```

> **Catatan tentang `adb backup`:** ini jalur ekstraksi tanpa root yang dulu populer, tetapi pada Android modern sudah sangat dibatasi — data aplikasi tidak lagi disertakan secara default kecuali aplikasi menandai dirinya debuggable. Jangan jadikan ini jalur utama; pakai sebagai pelengkap, dan perlakukan keberhasilannya sebagai **temuan tersendiri** (bertaut dengan MASTG-TEST-0216 tentang eksklusi data dari backup).

**Prasyarat lainnya:**

- **Penuhi prerequisite `identify-sensitive-data` lebih dulu.** Kamu perlu tahu data apa yang dianggap sensitif untuk aplikasi ini sebelum bisa menilai isi file.
- **Device/emulator bersih** (fresh wipe atau snapshot) agar diff tidak tercemar sisa sesi sebelumnya.
- **Canary value yang unik** untuk setiap input — teknik kunci yang sama seperti pada TEST-0200/0203. Contoh: `MASTG_CANARY_PWD_7f3a`, `mastg.canary.7f3a@example.com`, `MASTG_TOKEN_A1B2C3`.
- **Uji build yang relevan.** Sebisa mungkin uji build **release**; catat bila hanya debug build yang tersedia (dan ingat bahwa debug build umumnya debuggable, sehingga Jalur B tersedia).
- **Waktu exercise yang cukup.** Beberapa data hanya ditulis saat logout, saat cache di-flush, atau saat aplikasi masuk background.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0005** (*Installing Apps*) untuk menginstall aplikasi.
2. Gunakan **MASTG-TECH-0008** (*Accessing App Data Directories*) untuk mengambil **salinan pertama** direktori data privat aplikasi sebagai referensi untuk analisis offline.
3. **Jalankan dan gunakan aplikasi**, melalui berbagai alur kerja sambil memasukkan data sensitif di setiap tempat yang memungkinkan. **Mencatat data yang kamu masukkan akan membantu mengidentifikasinya nanti** menggunakan tool pencarian.
4. Gunakan MASTG-TECH-0008 untuk mengambil **salinan kedua** direktori data privat aplikasi, lalu **diff dengan salinan pertama** untuk mengidentifikasi semua file yang dibuat atau dimodifikasi selama sesi pengujian.

> Perhatikan perbedaan penekanan dari TEST-0200: di sini MASTG secara eksplisit menyarankan mengambil **salinan penuh** (bukan hanya daftar file) untuk **analisis offline**, dan menyebut diff mencakup file yang **dibuat ATAU DIMODIFIKASI**. Ini penting karena file seperti `shared_prefs/*.xml` dan `databases/*.db` biasanya sudah ada sejak awal dan hanya **berubah isinya** — sehingga pendekatan "hanya file baru" akan melewatkannya.

### 3.2 Implementasi Praktis — Metode Timestamp Marker (MASTG-DEMO-0010)

**Langkah 0 — Persiapan**

```bash
adb devices
adb install -g ./target-app.apk
PKG=com.example.target

# Verifikasi akses ke sandbox & petakan direktorinya (MASTG-TECH-0008)
adb root
adb shell "ls -la /data/user/0/$PKG/"
# atau via objection:
#   objection -g $PKG explore  -> env
```

**Langkah 1 — Buat penanda waktu (`run_before.sh`)**

```bash
#!/bin/bash

# SUMMARY: This script creates a dummy file to mark a timestamp that we can use later
# on to identify files created while the app was being exercised

adb shell "touch /data/local/tmp/test_start"
```

**Langkah 2 — Exercise aplikasi**

Jalankan alur sebanyak mungkin dengan canary value di setiap input:

- Registrasi, login, "remember me", logout, **login ulang** (logout sering memicu penulisan/penghapusan)
- Gagal login, akun terkunci, reset password, OTP, setup 2FA/biometrik
- Lengkapi profil: nama, NIK, alamat, telepon, tanggal lahir, upload dokumen/foto
- Tambah metode pembayaran, transaksi, unduh invoice/e-statement
- Chat/pesan, draft, riwayat pencarian
- **Mode offline** (matikan jaringan) → memicu caching lokal; lalu online kembali
- Buka fitur berbasis **WebView** (login SSO, syarat & ketentuan, halaman bantuan) → mengisi `app_webview/`
- Background/foreground berulang, rotasi layar, force-stop, buka ulang
- Biarkan idle beberapa menit (cache flush periodik)
- Aktifkan semua toggle di Settings, termasuk opsi debug bila ada
- Picu error/crash bila mungkin

**Langkah 3 — Ambil selisih dan tarik file (`run_after.sh`)**

```bash
#!/bin/bash

# SUMMARY: List all files created after the creation date of a file created in run_before

adb shell "find /data/user/0/org.owasp.mastestapp/ -type f -newer /data/local/tmp/test_start" > output.txt
adb shell "rm /data/local/tmp/test_start"
mkdir -p new_files
while read -r line; do
  adb pull "$line" ./new_files/
done < output.txt
```

> Skrip demo ini menarik semua file ke satu direktori datar (`./new_files/`). Untuk aplikasi nyata dengan banyak file bernama sama (mis. beberapa `index`), ini akan saling menimpa. Versi yang mempertahankan struktur direktori ada di §3.4.

**Langkah 4 — Inspeksi isi file**

```bash
file ./new_files/*
grep -riE "MASTG_CANARY_PWD_7f3a|password|token|api[_-]?key" ./new_files/
```

### 3.3 Metode Snapshot Penuh (Lebih Sesuai Langkah Resmi MASTG)

Langkah resmi MASTG meminta **salinan penuh** direktori, dua kali, lalu di-diff. Metode ini lebih sesuai dan menangkap **file yang dimodifikasi**, bukan hanya yang baru — sesuatu yang penting untuk `shared_prefs` dan `databases`.

```bash
PKG=com.example.target
D=/data/user/0/$PKG

# ---- SNAPSHOT 1 (sebelum exercise) ----
adb shell "su -c 'tar czf /data/local/tmp/before.tgz -C /data/user/0 $PKG'"
adb pull /data/local/tmp/before.tgz ./
mkdir -p before && tar xzf before.tgz -C before

# (alternatif tanpa root, app debuggable)
# adb shell "run-as $PKG tar czf - -C $D ." > before.tgz

# ---- EXERCISE APLIKASI ----

# ---- SNAPSHOT 2 (sesudah exercise) ----
adb shell "su -c 'tar czf /data/local/tmp/after.tgz -C /data/user/0 $PKG'"
adb pull /data/local/tmp/after.tgz ./
mkdir -p after && tar xzf after.tgz -C after

# ---- DIFF: file baru MAUPUN yang berubah isinya ----
diff -rq before after
# Only in after/...            -> file baru
# Files ... and ... differ     -> file DIMODIFIKASI (sering terlewat metode -newer)

# Diff isi untuk file teks (shared_prefs, json, xml)
diff -ru before/$PKG/shared_prefs after/$PKG/shared_prefs
```

Bandingkan berbasis hash untuk daftar yang rapi:

```bash
( cd before && find . -type f -exec sha256sum {} \; | sort ) > before.sha
( cd after  && find . -type f -exec sha256sum {} \; | sort ) > after.sha
comm -13 before.sha after.sha        # baru atau berubah
```

### 3.4 Inspeksi Mendalam — Normalisasi Encoding (Wajib per Kriteria Evaluasi)

Ini implementasi dari instruksi evaluasi MASTG di §1.5.

```bash
# ============ 1. Petakan tipe setiap file ============
find ./after -type f -exec file {} \;

# ============ 2. Pencarian canary & pola secret (case-insensitive, termasuk biner) ============
grep -raiE "MASTG_CANARY_PWD_7f3a|mastg\.canary|MASTG_TOKEN_A1B2C3" ./after/
grep -raiE "password|passwd|pwd|token|bearer|authorization|api[_-]?key|secret|credential|session|jwt|eyJ[A-Za-z0-9_-]{10,}|BEGIN (RSA|EC|OPENSSH)? ?PRIVATE KEY" ./after/

# ============ 3. shared_prefs — target prioritas tertinggi ============
for f in ./after/*/shared_prefs/*.xml; do echo "--- $f"; cat "$f"; done

# ============ 4. Database SQLite — JANGAN LUPA WAL/journal ============
for db in $(find ./after -name "*.db" -o -name "*.sqlite" -o -name "*.db3"); do
  echo "=== $db"
  sqlite3 "$db" ".tables"
  sqlite3 "$db" ".dump" | grep -iE "MASTG_CANARY|password|token|email"
done
# WAL & journal: bisa memuat data yang sudah "dihapus" dari tabel
for w in $(find ./after -name "*-wal" -o -name "*-journal" -o -name "*-shm"); do
  echo "=== $w"; strings -n 4 "$w" | grep -iE "MASTG_CANARY|password|token"
done

# ============ 5. WebView — sering terlewat ============
find ./after -path "*app_webview*" -type f
sqlite3 ./after/*/app_webview/Default/Cookies ".dump" 2>/dev/null | head -40
find ./after -path "*Local Storage*" -o -path "*Session Storage*" | head

# ============ 6. NORMALISASI ENCODING (instruksi eksplisit MASTG) ============
cat > decode_scan.py <<'PY'
import base64, binascii, codecs, gzip, io, os, re, sys, urllib.parse, zlib, zipfile, tarfile

CANARIES = [b"MASTG_CANARY_PWD_7f3a", b"MASTG_TOKEN_A1B2C3", b"mastg.canary"]
PATTERNS = [rb"password", rb"passwd", rb"token", rb"api[_-]?key", rb"secret",
            rb"BEGIN (RSA |EC )?PRIVATE KEY", rb"eyJ[A-Za-z0-9_-]{10,}"]

def hits(data: bytes):
    out = []
    low = data.lower()
    for c in CANARIES:
        if c.lower() in low: out.append(("canary", c.decode()))
    for p in PATTERNS:
        if re.search(p, low): out.append(("pattern", p.decode(errors="ignore")))
    return out

def layers(data: bytes, depth=0):
    """Hasilkan varian data yang sudah dinormalisasi (rekursif, dibatasi kedalaman)."""
    if depth > 3 or not data:
        return
    yield ("raw", data)

    # Base64
    for m in re.findall(rb"[A-Za-z0-9+/=]{16,}", data):
        try:
            d = base64.b64decode(m + b"==", validate=False)
            if d and d != data:
                yield ("base64", d)
                yield from layers(d, depth + 1)
        except Exception: pass

    # Hexadecimal
    for m in re.findall(rb"(?:[0-9a-fA-F]{2}){8,}", data):
        try:
            d = binascii.unhexlify(m)
            if d: yield ("hex", d); yield from layers(d, depth + 1)
        except Exception: pass

    # URL encoding
    try:
        d = urllib.parse.unquote_to_bytes(data.decode("latin-1"))
        if d != data: yield ("urldecode", d)
    except Exception: pass

    # Escape sequences (\uXXXX, \xXX)
    try:
        d = codecs.decode(data.decode("latin-1"), "unicode_escape").encode("latin-1")
        if d != data: yield ("unicode_escape", d)
    except Exception: pass

    # Wide characters (UTF-16LE / BE)
    for enc in ("utf-16-le", "utf-16-be"):
        try:
            d = data.decode(enc).encode("utf-8")
            if d != data: yield (f"widechar:{enc}", d)
        except Exception: pass

    # Kompresi
    for name, fn in (("gzip", gzip.decompress), ("zlib", zlib.decompress)):
        try:
            d = fn(data)
            if d: yield (name, d); yield from layers(d, depth + 1)
        except Exception: pass

    # ZIP / TAR
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
        for n in z.namelist()[:50]:
            d = z.read(n)
            yield (f"zip:{n}", d); yield from layers(d, depth + 1)
    except Exception: pass
    try:
        t = tarfile.open(fileobj=io.BytesIO(data))
        for m in t.getmembers()[:50]:
            if m.isfile():
                d = t.extractfile(m).read()
                yield (f"tar:{m.name}", d); yield from layers(d, depth + 1)
    except Exception: pass

    # XOR satu byte (obfuscation paling umum)
    for key in range(1, 256):
        d = bytes(b ^ key for b in data[:4096])
        if hits(d):
            yield (f"xor:0x{key:02x}", d)

for root, _, files in os.walk(sys.argv[1] if len(sys.argv) > 1 else "."):
    for fn in files:
        path = os.path.join(root, fn)
        try:
            raw = open(path, "rb").read()
        except Exception:
            continue
        for how, variant in layers(raw):
            h = hits(variant)
            if h and how != "raw":
                print(f"[!] {path}  via {how}  -> {h}")
            elif h:
                print(f"[!] {path}  PLAINTEXT      -> {h}")
PY
python3 decode_scan.py ./after

# ============ 7. Uji apakah file benar-benar TER-ENKRIPSI (bukan hanya di-encode) ============
for f in $(find ./after -type f -size +64c); do
  E=$(ent "$f" 2>/dev/null | awk '/Entropy/ {print $3}')
  echo "$E  $f"
done | sort -rn | head -20
# Entropi ~7.9+ bit/byte  => konsisten dengan enkripsi
# Entropi < 6.0           => plaintext / encoding / obfuscation lemah

# ============ 8. Bila ada file "terenkripsi", verifikasi di kode (jadx) ============
jadx -d ./decompiled ./target-app.apk
grep -rnE "EncryptedFile|EncryptedSharedPreferences|MasterKey|CipherOutputStream|AndroidKeyStore|SQLCipher|Tink|AeadSerializer" ./decompiled/sources/
# Tolak temuan bila: AES/ECB, DES/RC4, atau kunci hardcoded
grep -rnE "AES/ECB|\"DES\"|RC4|SecretKeySpec\(\"" ./decompiled/sources/
```

**Skrip `run_after.sh` yang mempertahankan struktur direktori** (perbaikan atas skrip demo):

```bash
#!/bin/bash
PKG=${1:-org.owasp.mastestapp}
adb shell "find /data/user/0/$PKG/ -type f -newer /data/local/tmp/test_start" > output.txt
adb shell "rm /data/local/tmp/test_start"
mkdir -p new_files
while read -r remote; do
  [ -z "$remote" ] && continue
  rel="${remote#/data/user/0/$PKG/}"          # path relatif
  mkdir -p "./new_files/$(dirname "$rel")"     # pertahankan struktur
  adb pull "$remote" "./new_files/$rel" >/dev/null 2>&1 \
    || adb shell "su -c 'cat $remote'" > "./new_files/$rel"
done < output.txt
find ./new_files -type f | sed 's|^|  |'
```

### 3.5 Metode Pengujian Alternatif (Multi-Tool)

Hambatan utama test ini adalah **akses ke dalam sandbox** (§2.3). Metode alternatif di bawah menawarkan jalur berbeda untuk masuk, plus cara menangkap data yang tidak pernah muncul di snapshot.

#### Metode B — Objection *(tanpa root, tanpa app debuggable)*

Ini jalur terbaik ketika root tidak tersedia — Objection bekerja lewat Frida sehingga tidak butuh `run-as` maupun `adb root`.

```bash
objection -g com.example.target explore

# Di dalam shell objection:
env                                                        # petakan seluruh path sandbox
cd /data/user/0/com.example.target
ls

# Tarik direktori-direktori kunci
filesystem download shared_prefs ./sp --folder             # target prioritas #1
filesystem download databases    ./db --folder
filesystem download files        ./files --folder
filesystem download app_webview  ./webview --folder        # sering terlewat

# Shortcut khusus: baca semua SharedPreferences langsung
android hooking list classes | grep -i preference
android heap search instances android.app.SharedPreferencesImpl
```

Objection juga punya perintah siap pakai untuk SQLite:

```bash
sqlite connect /data/user/0/com.example.target/databases/app.db
.tables
SELECT * FROM users LIMIT 5;
```

#### Metode C — Frida: hooking API penyimpanan *(menangkap data SEBELUM ditulis)*

Keunggulan menentukan: ia melihat **nilai plaintext** yang masuk ke API penyimpanan, bahkan ketika file hasilnya ter-enkripsi atau segera dihapus.

```javascript
// sandbox_writes.js
function bt(max = 10) {
    const E = Java.use("java.lang.Exception");
    const st = E.$new().getStackTrace();
    return Array.from({length: Math.min(max, st.length)}, (_, i) => "    " + st[i]).join("\n");
}

Java.perform(() => {
    // --- SharedPreferences: target prioritas tertinggi (lihat juga MASTG-TEST-0287) ---
    const Ed = Java.use("android.content.SharedPreferences$Editor");
    ['putString', 'putInt', 'putLong', 'putBoolean', 'putFloat'].forEach(m => {
        try {
            Ed[m].overloads.forEach(ov => {
                ov.implementation = function (k, v) {
                    console.log(`\n[SP] ${m}("${k}", "${v}")`);
                    console.log(bt());
                    return ov.call(this, k, v);
                };
            });
        } catch (e) {}
    });

    // --- SQLite: nilai yang dimasukkan ke database ---
    const DB = Java.use("android.database.sqlite.SQLiteDatabase");
    DB.insert.overload('java.lang.String', 'java.lang.String', 'android.content.ContentValues')
      .implementation = function (t, n, v) {
        console.log(`\n[SQL] insert into ${t}: ${v}`);
        console.log(bt());
        return this.insert(t, n, v);
    };
    DB.execSQL.overloads.forEach(ov => {
        ov.implementation = function (...a) {
            console.log(`\n[SQL] execSQL: ${a[0]}`);
            return ov.apply(this, a);
        };
    });

    // --- File I/O internal storage ---
    const INT = ['/data/data/', '/data/user/'];
    const addr = Process.getModuleByName('libc.so').findExportByName('openat');
    if (addr) Interceptor.attach(addr, {
        onEnter(args) {
            const p = args[1].readCString();
            if (p && INT.some(e => p.indexOf(e) === 0)) {
                console.log(`\n[open] ${p}`);
                Java.perform(() => console.log(bt()));
            }
        }
    });

    // --- Intip isi yang ditulis ---
    const FOS = Java.use("java.io.FileOutputStream");
    FOS.write.overload('[B', 'int', 'int').implementation = function (b, off, len) {
        try {
            const prev = Java.use("java.lang.String").$new(b, off, Math.min(len, 200));
            console.log(`[write] ${len}B  preview: ${prev}`);
        } catch (e) {}
        return this.write(b, off, len);
    };
});
```

```bash
frida -U -f com.example.target -l sandbox_writes.js -o sandbox.log
grep -i "MASTG_CANARY" sandbox.log        # canary ditemukan meski file ter-enkripsi
```

> **Ini juga yang membedakan temuan "data plaintext di disk" dari "data ter-enkripsi di disk".** Bila canary muncul di hook `putString` tetapi **tidak** muncul di file hasil tarikan, itu bukti enkripsi bekerja. Bila muncul di keduanya, plaintext.

#### Metode D — `adb backup` / `bmgr` *(ekstraksi sandbox tanpa root)*

Jalur alternatif masuk ke sandbox yang tidak memerlukan root maupun Frida.

```bash
# Opsi 1: bmgr local transport (bekerja pada app non-debuggable)
adb shell bmgr enable true
adb shell bmgr transport com.android.localtransport/.LocalTransport
adb shell bmgr backupnow com.example.target
adb root && adb pull /data/data/com.android.localtransport/files/1/_full/com.example.target app.ab
tar xvf app.ab       # -> apps/<pkg>/{f,db,sp,r}/

# Opsi 2: adb backup (butuh android:debuggable="true")
adb backup -apk -nosystem com.example.target
java -jar abe.jar unpack backup.ab backup.tar && tar xvf backup.tar
```

Struktur hasilnya memetakan langsung ke direktori sandbox: `f/` = `filesDir`, `db/` = `databases`, `sp/` = `shared_prefs`, `r/` = akar. Lihat MASTG-TEST-0216 untuk detail.

> Catat: file yang **dikecualikan dari backup** tidak akan muncul di sini — jadi metode ini bisa **melewatkan** data sensitif. Gunakan sebagai pelengkap, bukan pengganti.

#### Metode E — fsmon / strace *(monitoring tanpa menyentuh aplikasi)*

```bash
# fsmon — memantau seluruh aktivitas filesystem di sandbox
adb push fsmon-arm64 /data/local/tmp/fsmon && adb shell "chmod 755 /data/local/tmp/fsmon"
adb shell "su -c '/data/local/tmp/fsmon /data/data/com.example.target'" | tee fsmon.log

# strace — level syscall, tahan anti-Frida
PID=$(adb shell pidof -s com.example.target)
adb shell "su -c 'strace -f -e trace=openat,write,unlink,rename -p $PID'" 2>&1 \
  | grep "/data/data/com.example.target" | tee strace.log
```

Keunggulan: menangkap penulisan dari **kode native** dan **proses terpisah** (`:remote` service) yang luput dari hook Java.

#### Metode F — MobSF Dynamic Analyzer *(otomatis + SQLite dump)*

```bash
docker run -it --rm -p 8000:8000 -p 1337:1337 \
  opensecurity/mobile-security-framework-mobsf:latest
```

Upload APK → **Start Dynamic Analysis**. Bagian yang relevan di laporan:

| Bagian | Isinya |
|---|---|
| **Dumped Files / Files Analysis** | Seluruh isi sandbox beserta file-nya, siap diunduh |
| **SQLite Database** | Dump tabel otomatis dari semua `.db` yang ditemukan |
| **Shared Preferences** | Isi XML `shared_prefs` yang di-parse |
| **Logcat** | Bertaut MASTG-TEST-0203 |

Keunggulan: satu sesi menghasilkan inventaris sandbox lengkap tanpa menulis script. Keterbatasan: exercise otomatisnya dangkal (tidak bisa login), jadi **pelengkap** untuk pass awal.

#### Metode G — Pemeriksaan khusus SQLite: WAL, journal, dan free page

Ini titik buta yang dijelaskan di §1.4 dan tidak tertangkap metode mana pun kecuali diperiksa eksplisit.

```bash
D=./after/com.example.target/databases

# 1. Pastikan WAL/journal ikut ditarik — data "terhapus" bisa bertahan di sini
ls -la $D/*.db $D/*-wal $D/*-shm $D/*-journal 2>/dev/null

# 2. String mentah pada WAL — mengungkap baris yang sudah dihapus dari tabel
for w in $D/*-wal $D/*-journal; do
  [ -f "$w" ] && { echo "--- $w"; strings -n 4 "$w" | grep -iE "MASTG_CANARY|password|token|@.*\."; }
done

# 3. Free page pada .db itu sendiri (sisa data yang belum di-VACUUM)
sqlite3 $D/app.db "PRAGMA freelist_count;"
strings -n 6 $D/app.db | grep -iE "MASTG_CANARY|password|token"

# 4. Dump lengkap termasuk WAL yang belum di-checkpoint
sqlite3 $D/app.db ".recover" > recovered.sql
grep -iE "MASTG_CANARY|password|token" recovered.sql

# 5. Alat khusus untuk carving record SQLite yang terhapus
#    undark / sqlite-deleted-records-parser
undark --file $D/app.db --freespace | grep -i "MASTG_CANARY"
```

> `.recover` (SQLite 3.29+) jauh lebih kuat dari `.dump` karena ia merekonstruksi data dari halaman yang rusak/terhapus. Ini yang sering mengungkap data pasca-logout yang dikira sudah hilang.

#### Metode H — Pemeriksaan WebView storage *(direktori yang paling sering terlewat)*

```bash
W=./after/com.example.target/app_webview

# Cookie sesi — sering memuat token
sqlite3 "$W/Default/Cookies" "SELECT host_key, name, value, is_secure, is_httponly FROM cookies;"

# Local Storage & Session Storage (LevelDB)
find "$W" -path "*Local Storage*" -o -path "*Session Storage*"
strings -n 6 "$W/Default/Local Storage/leveldb/"*.log 2>/dev/null | grep -iE "token|MASTG_CANARY"

# IndexedDB
find "$W" -path "*IndexedDB*" -type f | head
```

#### Metode I — Tooling forensik *(timeline & sisa data)*

```bash
# ALEAPP — parsing artefak Android terstruktur + timeline
python3 aleapp.py -t fs -i ./sandbox_dump -o ./aleapp_out

# Timeline dengan Sleuth Kit
fls -r -m / ./image.dd > bodyfile && mactime -b bodyfile -d > timeline.csv

# Bulk extractor — carving PII/kredensial dari blob biner
bulk_extractor -o ./bulk_out -R ./sandbox_dump
grep -iE "MASTG_CANARY|password" ./bulk_out/*.txt
```

Berguna untuk menjawab pertanyaan "**kapan** file ini ditulis relatif terhadap logout?" dan untuk carving data dari file biner yang tidak terbaca `strings`.

---

### 3.6 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Butuh root? | Butuh app debuggable? | Melihat data sebelum enkripsi? | Menangkap file temporer? | Kapan dipakai |
|---|---|---|---|---|---|---|
| **A** | `adb root` + `find`/`tar` (MASTG) | **Ya** | Tidak | ❌ | ❌ | Baseline resmi — paling lengkap bila root tersedia |
| **A'** | `run-as` | Tidak | **Ya** | ❌ | ❌ | Alternatif tanpa root untuk build debug |
| **B** | Objection | Tidak | Tidak | Sebagian | Sebagian | **Terbaik tanpa root** — juga punya `sqlite connect` |
| **C** | Frida hook API storage | Ya/gadget | Tidak | ✅ **(keunggulan utama)** | ✅ | **Membedakan plaintext vs ter-enkripsi**; menangkap temp file |
| **D** | `bmgr` / `adb backup` + `abe` | Sebagian | Sebagian | ❌ | ❌ | Tanpa root; **tapi melewatkan file yang di-exclude dari backup** |
| **E** | fsmon / strace | Ya | Tidak | ❌ | ✅ | Kode native & proses `:remote`; tahan anti-Frida |
| **F** | MobSF Dynamic | Tidak | Tidak | ❌ | ❌ | Pass awal luas + SQLite/SharedPrefs dump otomatis |
| **G** | sqlite3 `.recover` / undark | — | — | — | — | **WAL/journal & data terhapus** — titik buta §1.4 |
| **H** | sqlite3 pada `app_webview` | — | — | — | — | **Cookie & Local Storage WebView** — paling sering terlewat |
| **I** | ALEAPP / Sleuth Kit / bulk_extractor | Ya | — | ❌ | ❌ | Timeline, carving, analisis pasca-logout |

**Kombinasi minimum yang aku rekomendasikan:** **A (snapshot penuh) → G (WAL/journal) → H (WebView)**.
A memberi inventaris dasar, G dan H menutup dua titik buta yang paling sering melewatkan temuan nyata. Tambahkan **C (Frida)** untuk membedakan data plaintext dari yang benar-benar ter-enkripsi — ini yang mengubah dugaan menjadi bukti. Gunakan **B (Objection)** bila root tidak tersedia.

---

### 3.7 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Observation:** *"The output should contain a list of files that were created in the app's private storage during execution."*
>
> **Evaluation:** *"The test case **fails** if you find **any sensitive data (keys, passwords, or any data inputted into the app)** in the extracted files."*
>
> *"When evaluating the data, attempt to identify and decode data that has been encoded using methods such as base64 encoding, hexadecimal representation, URL encoding, escape sequences, wide characters and common data obfuscation methods such as xoring. Also consider identifying and decompressing compressed files such as tar or zip. **These methods obscure but do not protect sensitive data.**"*

Perhatikan bahwa kriterianya **lebih tegas daripada MASTG-TEST-0200**. TEST-0200 mensyaratkan file *"not encrypted **and** leak sensitive data"*. Di sini: **"any sensitive data ... in the extracted files"** → FAIL. Frasa *"or any data inputted into the app"* juga memperluas cakupannya ke seluruh input user, bukan hanya kredensial.

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi | Contoh bukti |
|---|---|---|
| F1 | Ditemukan file di sandbox berisi **kredensial plaintext** | `/data/user/0/<pkg>/files/secret.txt` berisi `secr3tPa$$W0rd` |
| F2 | **`shared_prefs/*.xml`** memuat token, password, atau flag autentikasi plaintext | `<string name="auth_token">eyJhbGciOi...</string>` — target paling umum |
| F3 | **Database SQLite tak ter-enkripsi** memuat data user | `sqlite3 app.db ".dump"` menampilkan tabel `users` dengan kolom `password`/`email` |
| F4 | Data sensitif ditemukan di **`-wal` / `-journal`** meski sudah "dihapus" dari tabel | `strings app.db-wal \| grep MASTG_CANARY` → ada hasil |
| F5 | **Canary value** yang kamu masukkan ditemukan di file mana pun di sandbox | `grep -r MASTG_CANARY_PWD_7f3a ./after/` → ada hasil |
| F6 | Data sensitif hanya di-**Base64** | `echo 'c2VjcjN0...' \| base64 -d` → plaintext. **Encoding bukan enkripsi** |
| F7 | Data sensitif di-**hex / URL-encode / escape sequence / wide char** | Terdeteksi oleh `decode_scan.py` |
| F8 | Data sensitif di-**XOR** dengan kunci statis | `xortool` memulihkan kunci; atau `decode_scan.py` menemukan hit pada varian `xor:` |
| F9 | Data sensitif di dalam **arsip terkompresi** (zip/tar/gzip) tanpa enkripsi nyata | Terdeteksi setelah dekompresi |
| F10 | Ada enkripsi, tetapi **kunci hardcoded** di APK atau ikut disimpan di sandbox | jadx: `SecretKeySpec("hardcodedkey".getBytes(), "AES")`; atau `key.bin` di direktori yang sama |
| F11 | Ada enkripsi, tetapi **algoritma/mode lemah** | `AES/ECB`, DES/3DES/RC4, CBC tanpa MAC |
| F12 | **Cache WebView** memuat body respons API berisi PII, atau `Cookies` memuat token sesi | `app_webview/Default/Cookies` |
| F13 | **Log / crash dump** berisi data sensitif ditulis ke sandbox | `files/logs/debug.log` berisi `Authorization: Bearer ...` |
| F14 | Data sensitif **masih ada setelah logout** | Ulangi snapshot setelah logout — token masih di `shared_prefs` |
| F15 | Data sensitif dapat diekstraksi via **`adb backup`** (tanpa root) | Menaikkan severity; bertaut dengan MASTG-TEST-0216 |
| F16 | Aplikasi **debuggable** di build release, sehingga `run-as` memberi akses sandbox tanpa root | Temuan gabungan: eksposur sandbox + data plaintext |
| F17 | Penggunaan `MODE_WORLD_READABLE` / `MODE_WORLD_WRITEABLE` | Deprecated & berisiko; membatalkan proteksi sandbox |

**Contoh output yang menandakan FAIL** (hasil resmi MASTG-DEMO-0010):

Kode sampel (`MastgTest.kt`):

```kotlin
private fun mastgTestWriteIntFile() {
    val internalStorageDir = context.filesDir
    val fileName = File(internalStorageDir, "secret.txt")
    val fileContent = "secr3tPa\$\$W0rd\n"

    try {
        FileOutputStream(fileName).use { output ->
            output.write(fileContent.toByteArray())
            Log.d("WriteInternalStorage", "File written to internal storage successfully.")
        }
    } catch (e: IOException) {
        Log.e("WriteInternalStorage", "Error writing file to internal storage", e)
    }
}
```

`output.txt`:

```
/data/user/0/org.owasp.mastestapp/files/secret.txt
```

`./new_files/secret.txt`:

```
secr3tPa$$W0rd
```

MASTG menambahkan catatan lokasi:

> *"The file was created in `/data/user/0/org.owasp.mastestapp/files/` which is equivalent to `/data/data/org.owasp.mastestapp/files/`."*

Evaluasi MASTG: *"This test **fails** because the file is not encrypted and contains sensitive data (a password). You can further confirm this by reverse engineering the app and inspecting the code."*

**Tiga observasi dari demo ini:**

1. **Kodenya identik dengan MASTG-DEMO-0001** kecuali satu baris: `context.filesDir` (internal) alih-alih `context.getExternalFilesDir(null)` (external). Ini menegaskan bahwa memindahkan data ke internal storage **saja** tidak menyelesaikan MASWE-0001 — data tetap plaintext, hanya berpindah dari MASWE-0002 ke MASWE-0001.
2. **`run_after.sh` memakai `find /data/user/0/<pkg>/`**, yang pada device non-rooted akan gagal dengan *permission denied*. Demo ini berjalan pada emulator (dan MASTestApp bersifat debuggable). Untuk aplikasi nyata, kamu perlu root, `run-as`, atau Objection — lihat §2.3.
3. **Hanya satu file yang terdeteksi** di demo. Pada aplikasi nyata, diff akan menghasilkan puluhan hingga ratusan file (cache WebView, database, shared_prefs), sehingga triase dan normalisasi encoding (§3.4) menjadi penting.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi | Contoh bukti |
|---|---|---|
| P1 | **Tidak ada data sensitif** ditemukan di seluruh file sandbox, bahkan setelah normalisasi encoding berlapis | `decode_scan.py` tidak menghasilkan hit; canary tidak ditemukan |
| P2 | Ada file baru/termodifikasi, tetapi **isinya tidak sensitif** | Cache aset publik, konfigurasi UI, flag feature, log non-sensitif |
| P3 | Data sensitif ada, tetapi **ter-enkripsi dengan benar** — AEAD (AES-256-GCM / ChaCha20-Poly1305) dengan kunci dari **Android KeyStore** | `file` → `data`; entropi ≈7.99; canary tidak ditemukan pada varian encoding apa pun; jadx menunjukkan `EncryptedFile`/`EncryptedSharedPreferences`/Tink dengan `MasterKey` |
| P4 | `SharedPreferences` sensitif memakai **`EncryptedSharedPreferences`** atau mekanisme ekuivalen | XML memuat key dan value ter-enkripsi, bukan plaintext |
| P5 | Database memakai **SQLCipher** atau enkripsi ekuivalen; `.db`, `-wal`, dan `-journal` semuanya tidak terbaca | `sqlite3 app.db ".tables"` → *file is not a database* |
| P6 | Token sesi **hanya disimpan di memori**, tidak pernah menyentuh disk | Diff sandbox tidak memuat token sama sekali |
| P7 | Data sensitif **dihapus dengan benar saat logout** | Snapshot pasca-logout bersih |
| P8 | Kunci tidak pernah keluar dari secure hardware | jadx: `KeyGenParameterSpec` + `"AndroidKeyStore"`, idealnya dengan `setUserAuthenticationRequired` / StrongBox |

**Contoh output yang menandakan PASS:**

```bash
$ diff -rq before after
Files before/com.example.app/shared_prefs/secure_prefs.xml and after/com.example.app/shared_prefs/secure_prefs.xml differ

$ cat after/com.example.app/shared_prefs/secure_prefs.xml
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="AY6FZ9k1pQ...">AaX2m9QvT7...==</string>
</map>
# -> key DAN value ter-enkripsi (pola EncryptedSharedPreferences)

$ python3 decode_scan.py ./after
# (tidak ada hit)

$ grep -rai "MASTG_CANARY_PWD_7f3a" ./after/
# (tidak ada hasil)

$ ent after/com.example.app/files/vault.bin | grep Entropy
Entropy = 7.998211 bits per byte.

$ sqlite3 after/com.example.app/databases/app.db ".tables"
Error: file is not a database        # -> SQLCipher
```

Dikonfirmasi via jadx:

```kotlin
val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build()

val prefs = EncryptedSharedPreferences.create(
    context,
    "secure_prefs",
    masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
)
```

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Kriteria test ini lebih tegas daripada TEST-0200.** Di sini cukup *"any sensitive data ... in the extracted files"* → FAIL. Tidak ada klausa "dan tidak terenkripsi" seperti pada TEST-0200 (meski secara praktis enkripsi yang benar membuat data tidak lagi "ditemukan"). Frasa *"or any data inputted into the app"* juga memperluas cakupan ke seluruh input user.

2. **Wajib melakukan normalisasi encoding — ini instruksi eksplisit MASTG.** Pencarian `grep` polos akan melewatkan Base64, hex, URL-encoding, escape sequence, wide char, XOR, dan arsip terkompresi. Ingat kalimat kunci MASTG: *"These methods obscure but do not protect sensitive data."* Gunakan `decode_scan.py` (§3.4) atau yang setara.

3. **Metode `find -newer` melewatkan file yang DIMODIFIKASI dengan mtime tidak berubah, dan lebih penting: melewatkan konteks.** Langkah resmi MASTG meminta **salinan penuh dua kali lalu diff** justru karena `shared_prefs/*.xml` dan `databases/*.db` biasanya sudah ada sebelum sesi dimulai dan hanya berubah isinya. Gunakan metode §3.3 untuk hasil yang lengkap; metode timestamp (§3.2) sebagai versi cepat.

4. **Jangan lupa file WAL/journal.** Data sensitif dapat bertahan di `<db>-wal` meski sudah dihapus dari tabel utama. Ini titik buta yang tidak akan ditemukan oleh analisis statis maupun hooking.

5. **Jangan lupa `app_webview/`.** Cookie sesi dan Local Storage dari WebView sering memuat token, dan direktori ini rutin terlewat karena tidak termasuk struktur "standar" yang dihafal.

6. **Periksa juga direktori induk.** MASTG-TECH-0008 memperingatkan aplikasi dapat menyimpan data langsung di `/data/data/<pkg>/`, bukan hanya di subdirektori yang dikenal.

7. **Waspadai false pass akibat enkripsi palsu.** Selalu uji dengan `strings`, dekode berlapis, dan **analisis entropi**. Entropi < 6.0 bit/byte pada file yang diklaim terenkripsi adalah tanda bahaya. Lalu verifikasi di kode: mode cipher (tolak ECB) dan **asal kunci** (tolak hardcoded).

8. **Output kosong ≠ otomatis PASS.** Penyebab false pass:
   - Alur pemicu belum di-*exercise* (data sering ditulis saat logout, background, atau cache flush)
   - **Akses sandbox gagal** (tidak root, app tidak debuggable) sehingga snapshot tidak lengkap — ini **Inconclusive, bukan PASS**
   - File temporer ditulis lalu segera dihapus → tidak muncul di diff. Lengkapi dengan **MASTG-TEST-0287** (hooking `SharedPreferences`) dan hooking file I/O
   - Data ditulis oleh **proses terpisah** (`:remote` service) di direktori berbeda
   - Snapshot diambil sebelum aplikasi mem-*flush* data ke disk → force-stop aplikasi sebelum snapshot kedua agar buffer tertulis

9. **Uji ulang setelah logout.** Ini pemeriksaan bernilai tinggi yang tidak disebut eksplisit di langkah MASTG: ambil snapshot ketiga setelah logout. Token yang masih tersisa berarti sesi tidak benar-benar diakhiri (bertaut dengan MASWE-0024, *Sensitive Data Accessible After Session Termination*).

10. **Severity dimodulasi oleh beberapa faktor:**

    | Faktor | Severity |
    |---|---|
    | Private key / kunci kriptografi plaintext di sandbox | **Kritis** |
    | Password, token sesi jangka panjang, refresh token plaintext | **Tinggi** |
    | Data finansial/kesehatan plaintext | **Tinggi** |
    | PII plaintext (NIK, alamat, telepon) | **Menengah–Tinggi** (+ dimensi privasi) |
    | Data dapat diekstraksi **tanpa root** (`adb backup` berhasil, atau app debuggable di release) | **Naik signifikan** — model penyerang jauh lebih luas |
    | "Enkripsi" ternyata hanya encoding/XOR | **Naik** — memberi rasa aman yang salah |
    | Kunci hardcoded di APK | **Naik** |
    | Data sensitif bertahan setelah logout | Naik |
    | Data hanya di `-wal` (sisa dari data yang sudah dihapus) | Menengah — tetap temuan |
    | Aplikasi berprofil **L1** dengan model ancaman yang tidak mencakup root/akses fisik | Turun — dapat dilaporkan sebagai *informational*; ingat test ini memang berprofil L2 |
    | Data non-sensitif | **Bukan temuan** |

11. **Dokumentasikan bukti lengkap per temuan:** path absolut file, tipe file (`file`), isi (redaksi sebagian tetapi cukup membuktikan), **metode dekode yang dipakai untuk mengungkapnya** (mis. "Base64 → gzip → plaintext"), nilai entropi, jalur akses yang dipakai (root / `run-as` / Objection), apakah dapat diekstraksi tanpa root, status pasca-logout, langkah reproduksi dengan canary value, dan konfirmasi kode dari jadx. Cantumkan juga batasan (mis. tidak dapat mengakses sandbox pada host tertentu, proses `:remote` belum diperiksa).

---

## 4. Rekomendasi Perbaikan

### 4.1 Prinsip Utama (urutan prioritas)

**Prioritas 1 — Jangan simpan apa yang tidak perlu disimpan.** Remediasi terkuat adalah menghilangkan datanya.

- **Token sesi sebaiknya hanya di memori.** Gunakan access token berumur pendek yang disimpan di variabel (bukan disk), dengan refresh token yang dilindungi KeyStore.
- Jangan cache respons API yang memuat PII; bila perlu cache, simpan hanya field non-sensitif.
- **Hapus data sensitif saat logout** — termasuk `shared_prefs`, database, cache WebView, dan jalankan `VACUUM` pada SQLite agar sisa data di WAL hilang.
- Jangan tulis log verbose atau crash dump berisi PII ke sandbox (lihat MASTG-TEST-0203).

**Prioritas 2 — Gunakan Android KeyStore untuk semua material kriptografi.** Kunci tidak pernah keluar dari secure hardware, sehingga tidak mungkin diekstraksi dari filesystem.

```kotlin
val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
keyGen.init(
    KeyGenParameterSpec.Builder(
        "vault_key",
        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
    )
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setRandomizedEncryptionRequired(true)
        .setUserAuthenticationRequired(true)        // untuk data paling sensitif
        .setIsStrongBoxBacked(true)                 // bila hardware mendukung
        .build()
)
keyGen.generateKey()
```

**Prioritas 3 — Enkripsi data sensitif yang memang harus persisten (MASTG-BEST-0050).**

MASTG-BEST-0050 menyatakan: *"Store sensitive data in `SharedPreferences` only after encrypting it. Standard `SharedPreferences` stores values in XML files inside the app's private data directory, so values such as credentials, authentication tokens, private keys, or personally identifiable information (PII) should not be stored in cleartext."*

Syarat mekanisme yang dapat diterima menurut BEST-0050: *"use authenticated encryption, protect encryption keys with the Android Keystore or another appropriate key management system, and avoid custom cryptography."*

| Jenis data | Mekanisme |
|---|---|
| Key-value preferences | `EncryptedSharedPreferences` — **atau** enkripsi manual AES-GCM dengan kunci KeyStore (lihat catatan deprecation di bawah) |
| File | `EncryptedFile` (Jetpack Security) atau `CipherOutputStream` dengan AES-256-GCM + kunci KeyStore |
| Database SQLite / Room | **SQLCipher** (`net.zetetic:sqlcipher-android`), dengan passphrase dari KeyStore |
| DataStore | **`androidx.datastore:datastore-tink`** + `AeadSerializer` |
| Kunci & secret | **Android KeyStore** (jangan ditulis ke file sama sekali) |

> **⚠️ Catatan deprecation penting dari MASTG-BEST-0050:**
>
> *"`EncryptedSharedPreferences` is part of the Jetpack Security Crypto library. All APIs in that library were **deprecated** in version `1.1.0`, and Android states that there will be **no subsequent releases**. It may still be a practical mitigation for existing apps that must keep using `SharedPreferences`, but it should not be treated as a long term storage strategy. Monitor Android's cryptography and DataStore guidance, and plan a migration to a supported encryption approach when available."*
>
> Jadi: `EncryptedSharedPreferences` **masih valid sebagai mitigasi** dan tetap membuat test ini PASS, tetapi bukan strategi jangka panjang. Untuk aplikasi baru, rencanakan langsung ke pendekatan yang didukung.

**Untuk DataStore** — BEST-0050 memberi arah yang jelas: Android merekomendasikan `DataStore` sebagai pengganti modern `SharedPreferences`, **tetapi `DataStore` tidak mengenkripsi data secara default**. Bila memigrasikan data sensitif ke `DataStore`, gunakan lapisan enkripsi. AndroidX memperkenalkan artifact **`androidx.datastore:datastore-tink`** pada versi `1.3.0-alpha07`, yang menyediakan enkripsi via library **Tink** dan **`AeadSerializer`** — sebuah wrapper atas serializer DataStore yang melakukan authenticated encryption/decryption.

```kotlin
// Contoh pendekatan modern: DataStore + Tink AeadSerializer
// (lihat DataStore release notes 1.3.0-alpha07 untuk contoh lengkap)
val dataStore = DataStoreFactory.create(
    serializer = AeadSerializer(
        delegate = MySettingsSerializer,
        aead = aeadFromAndroidKeystore      // kunci dikelola Android KeyStore
    ),
    produceFile = { context.dataStoreFile("settings.pb") }
)
```

```kotlin
// Contoh SQLCipher untuk Room
val passphrase: ByteArray = getPassphraseFromKeyStore()   // BUKAN hardcoded
val factory = SupportOpenHelperFactory(passphrase)
val db = Room.databaseBuilder(context, AppDatabase::class.java, "app.db")
    .openHelperFactory(factory)
    .build()
```

**Syarat kripto yang dianggap memadai:**
- **AES-256-GCM** atau ChaCha20-Poly1305 (authenticated encryption). Tolak ECB, DES/3DES/RC4, CBC tanpa MAC.
- IV/nonce acak per operasi, tidak pernah berulang.
- Kunci **dihasilkan dan disimpan di Android KeyStore** — bukan hardcoded, bukan diturunkan dari nilai statis (IMEI, package name, timestamp — lihat MASTG-TEST-0205), bukan ditulis ke sandbox.
- Bila kunci diturunkan dari password user: KDF kuat (Argon2id / scrypt / PBKDF2 iterasi tinggi) dengan salt acak dari `SecureRandom`.
- **Jangan gunakan kriptografi buatan sendiri** (BEST-0050: *"avoid custom cryptography"*).

**Prioritas 4 — Jangan pernah memakai encoding/obfuscation sebagai pengganti enkripsi.** Ini konsekuensi langsung dari kriteria evaluasi MASTG. Base64, hex, URL-encoding, XOR, dan ROT13 **tidak memberikan perlindungan apa pun** — hanya menambah satu langkah trivial bagi penyerang, sementara memberi rasa aman yang salah bagi tim pengembang.

**Prioritas 5 — Batasi jalur ekstraksi data sandbox.**

```xml
<application
    android:allowBackup="false"
    android:debuggable="false"            <!-- pastikan TIDAK true di release -->
    android:dataExtractionRules="@xml/data_extraction_rules"
    android:fullBackupContent="@xml/backup_rules">
```

- **`android:debuggable="false"`** pada build release — bila `true`, `run-as` memberi akses penuh ke sandbox **tanpa root**. Verifikasi pada APK release, bukan hanya di `build.gradle`.
- **Kecualikan data sensitif dari backup** via `dataExtractionRules` (Android 12+) / `fullBackupContent`, atau `allowBackup="false"` (lihat MASTG-TEST-0216).
- Gunakan direktori **`no_backup/`** (`context.noBackupFilesDir`) untuk file yang tidak boleh ikut backup.
- Jangan gunakan `MODE_WORLD_READABLE` / `MODE_WORLD_WRITEABLE` (deprecated sejak API 17, melempar `SecurityException` sejak API 24). Untuk berbagi data ke aplikasi lain, gunakan **ContentProvider** atau **FileProvider** — sesuai rekomendasi Android Security Guidelines yang dikutip MASTG-KNOW-0041.

**Prioritas 6 — Bersihkan sisa data secara benar.**

```kotlin
// Saat logout: hapus semua penyimpanan sensitif
context.getSharedPreferences("auth", MODE_PRIVATE).edit().clear().commit()
context.deleteDatabase("app.db")
File(context.filesDir, "cache_token.bin").delete()
WebStorage.getInstance().deleteAllData()
CookieManager.getInstance().removeAllCookies(null)
context.cacheDir.deleteRecursively()

// SQLite: VACUUM agar sisa data di WAL/free page benar-benar hilang
db.query("PRAGMA wal_checkpoint(TRUNCATE)")
db.query("VACUUM")
```

Pertimbangkan juga `PRAGMA secure_delete = ON` untuk database yang memuat data sensitif.

**Prioritas 7 — Pertahanan berlapis tambahan.**
- **Biometric/credential gating** untuk kunci paling sensitif (`setUserAuthenticationRequired(true)`), sehingga data tidak dapat didekripsi meski file diekstraksi.
- **StrongBox** bila hardware mendukung.
- Pertimbangkan kontrol MASVS-RESILIENCE (deteksi root, integrity check) sebagai lapisan tambahan — **bukan pengganti enkripsi**.
- Audit **library pihak ketiga**: SDK analytics, crash reporter, image loader, dan WebView sering menulis cache ke sandbox tanpa sepengetahuan developer. Test ini sering menemukan file dari SDK, bukan dari kode aplikasi sendiri.
- **Integrasikan ke CI/CD**: jalankan skrip snapshot+diff+decode pada emulator di pipeline bersama UI test, dan gagalkan build bila canary value muncul di sandbox.

### 4.2 Checklist Remediasi

- [ ] Seluruh file dari diff sandbox sudah ditinjau, termasuk setelah **normalisasi encoding berlapis** (Base64/hex/URL/escape/wide char/XOR/kompresi)
- [ ] Tidak ada kredensial, token, kunci, atau PII plaintext di `files/`, `cache/`, `code_cache/`, `no_backup/`, atau direktori induk
- [ ] `shared_prefs/*.xml` tidak memuat data sensitif plaintext
- [ ] Database SQLite/Room ter-enkripsi (SQLCipher atau ekuivalen); **`.db`, `-wal`, `-shm`, `-journal` semuanya tidak terbaca**
- [ ] `DataStore` yang memuat data sensitif memakai lapisan enkripsi (`datastore-tink` + `AeadSerializer`)
- [ ] `app_webview/` (Cookies, Local Storage, Session Storage) tidak memuat token/PII persisten
- [ ] Tidak ada encoding/obfuscation (Base64/hex/XOR/ROT13) dipakai sebagai pengganti enkripsi
- [ ] Enkripsi memakai AEAD (AES-256-GCM / ChaCha20-Poly1305); tidak ada ECB/DES/RC4/CBC-tanpa-MAC
- [ ] Kunci dihasilkan & disimpan di **Android KeyStore**; tidak hardcoded, tidak diturunkan dari nilai statis, tidak ditulis ke sandbox
- [ ] Tidak ada kriptografi buatan sendiri
- [ ] Token sesi hanya di memori bila memungkinkan; refresh token dilindungi KeyStore
- [ ] Data sensitif **dihapus saat logout**, termasuk WebView storage & cookie; `VACUUM`/`wal_checkpoint` dijalankan pada SQLite
- [ ] Log verbose & crash dump berisi PII tidak ditulis ke sandbox
- [ ] `android:debuggable="false"` diverifikasi pada **APK release**
- [ ] Data sensitif dikecualikan dari backup (`dataExtractionRules`/`fullBackupContent`/`allowBackup="false"`); `no_backup/` dipakai bila relevan
- [ ] Tidak ada `MODE_WORLD_READABLE` / `MODE_WORLD_WRITEABLE`; berbagi data memakai ContentProvider/FileProvider
- [ ] `setUserAuthenticationRequired(true)` dan StrongBox dipertimbangkan untuk data paling sensitif
- [ ] Library pihak ketiga diaudit atas penulisan ke sandbox
- [ ] Proses terpisah (`:remote` service) dan direktori spesifik framework (`app_flutter/`, dsb.) ikut diperiksa
- [ ] Test ini terintegrasi di CI/CD dengan pemeriksaan canary value
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0207 (snapshot penuh + decode scan) → tidak ada data sensitif
- [ ] **Verifikasi pasca-logout:** snapshot ketiga setelah logout → bersih
- [ ] **Verifikasi silang:** jalankan MASTG-TEST-0287 (`SharedPreferences` hooking), MASTG-TEST-0200 (external storage), dan MASTG-TEST-0216 (backup)

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0207: Runtime Storage of Unencrypted Data in the App Sandbox](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0207/)
- [MASTG-TEST-0287: Runtime Storage of Unencrypted Data via the SharedPreferences API](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0287/)
- [MASTG-TEST-0200: Files Written to External Storage](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0200/)
- [MASTG-TEST-0216: Data Exclusion from Backups](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0216/)
- [MASTG-TEST-0001: Testing Local Storage for Sensitive Data](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0001/)
- [MASWE-0001: Sensitive Data Stored Unencrypted in Private Storage](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0001/)
- [MASWE-0024: Sensitive Data Accessible After Session Termination](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0024/)
- [MASTG-DEMO-0010: File System Snapshots from Internal Storage](https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0010/MASTG-DEMO-0010/)
- [MASTG-DEMO-0059: Using SharedPreferences to Write Sensitive Data Unencrypted to the App Sandbox](https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0059/MASTG-DEMO-0059/)
- [MASTG-DEMO-0060: App Writing Sensitive Data to Sandbox using EncryptedSharedPreferences](https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0060/MASTG-DEMO-0060/)
- [MASTG-KNOW-0041: Internal Storage](https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0041/)
- [MASTG-BEST-0050: Store Data Encrypted in App Sandbox Directory](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0050/)
- [MASTG-TECH-0008: Accessing App Data Directories](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0008/)
- [MASTG-TECH-0005: Installing Apps](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0005/)
- [MASTG-TECH-0002: Host-Device Data Transfer](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0002/)
- [MASTG-TOOL-0004: adb](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0004/)
- [MASTG-TOOL-0038: Objection](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0038/)
- [MASTG — Testing Data Storage chapter](https://mas.owasp.org/MASTG/0x05d-Testing-Data-Storage/)
- [MASVS-STORAGE: Storage](https://mas.owasp.org/MASVS/05-MASVS-STORAGE/)
- [OWASP Mobile Top 10 2024 — M9: Insecure Data Storage](https://owasp.org/www-project-mobile-top-10/2023-risks/m9-insecure-data-storage)

### 5.2 Dokumentasi Resmi Android / Google

- [Data and file storage overview](https://developer.android.com/training/data-storage)
- [Access app-specific files (internal storage)](https://developer.android.com/training/data-storage/app-specific)
- [Security tips — Internal storage](https://developer.android.com/privacy-and-security/security-tips#internal-storage)
- [Security tips — Content providers](https://developer.android.com/privacy-and-security/security-tips#content-providers)
- [App security best practices — Store data in internal storage based on use case](https://developer.android.com/privacy-and-security/security-best-practices#internal-storage)
- [Cryptography best practices](https://developer.android.com/privacy-and-security/cryptography)
- [Jetpack Security Crypto deprecation notice](https://developer.android.com/privacy-and-security/cryptography#security-crypto-jetpack-deprecated)
- [`EncryptedSharedPreferences` — API reference](https://developer.android.com/reference/androidx/security/crypto/EncryptedSharedPreferences)
- [`EncryptedFile` — API reference](https://developer.android.com/reference/androidx/security/crypto/EncryptedFile)
- [`MasterKey` — API reference](https://developer.android.com/reference/androidx/security/crypto/MasterKey)
- [DataStore — Jetpack library](https://developer.android.com/topic/libraries/architecture/datastore)
- [DataStore release notes — `datastore-tink` 1.3.0-alpha07](https://developer.android.com/jetpack/androidx/releases/datastore#1.3.0-alpha07)
- [`AeadSerializer` — API reference](https://developer.android.com/reference/kotlin/androidx/datastore/tink/AeadSerializer)
- [Android Keystore system](https://developer.android.com/privacy-and-security/keystore)
- [`KeyGenParameterSpec` — API reference](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec)
- [`Context.getFilesDir()` / `getNoBackupFilesDir()`](https://developer.android.com/reference/android/content/Context#getNoBackupFilesDir())
- [SharedPreferences APIs](https://developer.android.com/training/data-storage/shared-preferences)
- [Room persistence library](https://developer.android.com/training/data-storage/room)
- [Back up user data with Auto Backup](https://developer.android.com/identity/data/autobackup)
- [File-Based Encryption (AOSP)](https://source.android.com/docs/security/features/encryption/file-based)
- [Application sandbox (AOSP)](https://source.android.com/docs/security/app-sandbox)
- [FileProvider](https://developer.android.com/reference/androidx/core/content/FileProvider)
- [Google Tink — cryptographic library](https://developers.google.com/tink)
- [SQLCipher for Android (Zetetic)](https://www.zetetic.net/sqlcipher/sqlcipher-for-android/)
- [SQLite — Write-Ahead Logging](https://www.sqlite.org/wal.html)
- [SQLite — `PRAGMA secure_delete`](https://www.sqlite.org/pragma.html#pragma_secure_delete)

### 5.3 Standar, Taksonomi, dan Guideline Lain

- [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
- [CWE-311: Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html)
- [CWE-922: Insecure Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/922.html)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [CWE-732: Incorrect Permission Assignment for Critical Resource](https://cwe.mitre.org/data/definitions/732.html)
- [SEI CERT Android — DRD10: Do not release apps that are debuggable](https://wiki.sei.cmu.edu/confluence/display/android/DRD10-J.+Do+not+release+apps+that+are+debuggable)
- [NIST SP 800-163 Rev.1 — Vetting the Security of Mobile Applications](https://csrc.nist.gov/publications/detail/sp/800-163/rev-1/final)
- [NIST SP 800-124 Rev.2 — Guidelines for Managing the Security of Mobile Devices](https://csrc.nist.gov/publications/detail/sp/800-124/rev-2/final)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [CodeQL — Cleartext storage of sensitive information in the Android filesystem](https://codeql.github.com/codeql-query-help/java/java-android-cleartext-storage-filesystem/)
- [MITRE ATT&CK Mobile — T1409: Stored Application Data](https://attack.mitre.org/techniques/T1409/)
- [MITRE ATT&CK Mobile — T1533: Data from Local System](https://attack.mitre.org/techniques/T1533/)

### 5.4 Riset Keamanan & Artikel Teknis

- [Security Café — Mobile Pentesting 101: The Death of ADB Backup: Modern Data Extraction](https://securitycafe.ro/2026/02/02/mobile-pentesting-101-the-death-of-adb-backup-modern-data-extraction-in-2026/)
- [Pen Test Partners — How to subvert Android backups to export sandboxed app files](https://www.pentestpartners.com/security-blog/how-to-subvert-android-backups-to-export-sandboxed-app-files/)
- [ProAndroidDev — How to Extract Sandbox data of an Android App?](https://proandroiddev.com/how-to-extract-sandbox-data-of-an-android-app-d9d80c535a19)
- [Oxygen Forensics — Sandboxing in Android: implications for extraction of data via ADB](https://www.oxygenforensics.com/resources/android-sandboxing/)
- [Hack The Dome — Data Storage Security & Local Forensics in Android](https://hackthedome.com/module-15-data-storage-security-local-forensics-in-android/)
- [Check Point Research — Man-in-the-Disk (untuk kontras dengan external storage)](https://research.checkpoint.com/2018/androids-man-in-the-disk/)
- [HackTricks — Android Applications Pentesting](https://book.hacktricks.wiki/en/mobile-pentesting/android-app-pentesting/index.html)

### 5.5 Dokumentasi Tools

- [adb — Android Debug Bridge](https://developer.android.com/tools/adb)
- [Objection — runtime mobile exploration](https://github.com/sensepost/objection)
- [Frida — Documentation Home](https://frida.re/docs/home/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [apktool — Reverse engineering Android APK files](https://apktool.org/)
- [Android Backup Extractor (abe)](https://github.com/nelenkov/android-backup-extractor)
- [sqlite3 CLI](https://www.sqlite.org/cli.html)
- [DB Browser for SQLite](https://sqlitebrowser.org/)
- [ent — Pseudorandom number sequence test (entropi)](https://www.fourmilab.ch/random/)
- [binwalk — firmware analysis tool](https://github.com/ReFirmLabs/binwalk)
- [xortool — XOR cipher analysis](https://github.com/hellman/xortool)
- [TruffleHog — secret scanning](https://github.com/trufflesecurity/trufflehog)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026), dokumentasi resmi Android Developers, standar CWE/NIST/SEI CERT, serta riset keamanan dan forensik pihak ketiga.*
