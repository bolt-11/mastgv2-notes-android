# MASTG-TEST-0235 Android App Configurations Allowing Cleartext Traffic

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0235 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-NETWORK (MASVS-NETWORK-1: Seluruh lalu lintas jaringan dienkripsi memakai TLS) |
| **Weakness** | MASWE-0026 — *Network Traffic Not Encrypted* |
| **Tipe Pengujian** | Static, Code |
| **Profile** | L1, L2 |
| **Knowledge** | MASTG-KNOW-0014 (Android Network Security Configuration) |
| **Teknik terkait** | MASTG-TECH-0013 (Reverse Engineering), MASTG-TECH-0117 (Obtaining Info from AndroidManifest), MASTG-TECH-0150 (Analyzing the AndroidManifest), MASTG-TECH-0151 (Analyzing the Network Security Configuration) |
| **Test terkait** | **MASTG-TEST-0233** (Hardcoded HTTP URLs — menemukan **lokasi** URL; test ini menentukan apakah URL tersebut **bisa jalan**), **MASTG-TEST-0236** (Cleartext Traffic dalam Network Traffic Capture — bukti dinamis) |
| **Demo terkait** | — (MASTG belum menyediakan demo resmi untuk test ini) |
| **Rule resmi** | — (tidak ada rule semgrep — objeknya adalah XML manifest/NSC, bukan kode Java/Kotlin, sehingga di luar cakupan rule semgrep MASTG yang ada) |
| **CWE terkait** | CWE-319 (Cleartext Transmission of Sensitive Information) |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Kutipan overview resmi MASTG:

> *"Since Android 9 (API level 28) cleartext HTTP traffic is blocked by default (thanks to the default Network Security Configuration) but there are multiple ways in which an application can still send it."*

Test ini adalah **penentu konfigurasi** dalam trio pengujian cleartext traffic (lihat §1.4 MASTG-TEST-0233): ia menjawab pertanyaan "**apakah sistem operasi mengizinkan** aplikasi ini mengirim HTTP plaintext?" — terlepas dari apakah kode aplikasi benar-benar mencoba melakukannya. Ada dua mekanisme konfigurasi yang bisa mengizinkan cleartext, dan MASTG menuntut **keduanya** diperiksa:

1. **`AndroidManifest.xml`**: atribut `android:usesCleartextTraffic` pada tag `<application>`.
2. **Network Security Configuration (NSC)**: atribut `cleartextTrafficPermitted` pada elemen `<base-config>` atau `<domain-config>`.

### 1.2 Poin Krusial: Interaksi Antara Manifest dan NSC

Ini bagian paling sering disalahpahami dari test ini. **`usesCleartextTraffic` di manifest diabaikan sepenuhnya jika NSC dikonfigurasi** — bukan digabung, bukan salah satu menang berdasarkan prioritas nilai, melainkan **NSC yang sepenuhnya mengambil alih keputusan** begitu ia ada:

> *"Note that this flag is ignored in case the Network Security Configuration is configured."*

Konsekuensi dari aturan ini menghasilkan sebuah **catatan resmi yang berlawanan dengan intuisi** dan wajib dipahami penguji sebelum menyimpulkan hasil:

> *"The test doesn't fail if the AndroidManifest sets `usesCleartextTraffic` to `true` and there's a NSC, even if it only has an empty `<network-security-config>` element."*

Contoh konkret dari overview resmi:

```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
</network-security-config>
```

Meski `AndroidManifest.xml` menyatakan `android:usesCleartextTraffic="true"`, kombinasi ini **TIDAK FAIL** karena NSC (walau kosong) tetap **mengambil alih keputusan** dari sistem, dan NSC kosong secara efektif mewarisi default aman (`cleartextTrafficPermitted="false"` untuk API 28+ sesuai MASTG-KNOW-0014). Ini artinya **urutan pemeriksaan tidak boleh berhenti di manifest saja** — kehadiran elemen `<network-security-config>` apa pun, bahkan yang kosong, mengubah total kesimpulan evaluasi.

### 1.3 Efek Merisasi (Inheritance) `base-config` vs `domain-config`

Sesuai MASTG-KNOW-0014, struktur NSC memiliki dua level cakupan:

- **`base-config`**: berlaku untuk **seluruh** koneksi yang dibuat aplikasi, kecuali di-override.
- **`domain-config`**: **mengganti** (override) `base-config` untuk domain spesifik yang didaftarkan.

Contoh dari MASTG-KNOW-0014 yang menunjukkan pola umum (dan sekaligus jebakan potensial):

```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false" />
    <domain-config cleartextTrafficPermitted="true">
        <domain>localhost</domain>
    </domain-config>
</network-security-config>
```

Konfigurasi ini **aman secara keseluruhan** (base-config menolak cleartext untuk semua domain), tetapi memiliki **pengecualian eksplisit** untuk `localhost` — pola yang sering dipakai untuk keperluan debugging lokal (proxy development, emulator loopback). Bahaya nyata muncul ketika pengecualian semacam ini **tertinggal untuk domain produksi** yang bukan `localhost`, sesuatu yang harus ditelusuri satu per satu di setiap `<domain-config>`, bukan hanya memeriksa `<base-config>` saja.

### 1.4 Default Konfigurasi Berdasarkan `targetSdkVersion` — Bukan `minSdkVersion`

Poin teknis penting yang sering keliru diasumsikan: default NSC ditentukan oleh **`targetSdkVersion`** aplikasi, bukan versi Android yang menjalankannya atau `minSdkVersion`-nya:

| `targetSdkVersion` | Default `cleartextTrafficPermitted` |
|---|---|
| ≥ 28 (Android 9+) | `false` — cleartext **diblokir** secara default |
| 24–27 (Android 7.0–8.1) | `true` — cleartext **diizinkan** secara default |
| ≤ 23 (Android 6.0 ke bawah) | `true`, **dan** trust anchor turut menyertakan sertifikat yang di-install pengguna (`certificates src="user"`) selain sistem |

Implikasi pentingnya: **aplikasi yang sengaja menahan `targetSdkVersion` di angka rendah** (mis. untuk kompatibilitas library lama) akan **otomatis mengizinkan cleartext** tanpa developer perlu menuliskan `usesCleartextTraffic="true"` secara eksplisit sama sekali — ini kondisi FAIL yang **tidak akan terlihat** hanya dengan mencari literal string `usesCleartextTraffic` atau `cleartextTrafficPermitted` di manifest/NSC, karena tidak ada satu pun atribut eksplisit yang perlu dicari. Penguji **wajib memeriksa nilai `targetSdkVersion`** sebagai bagian tak terpisahkan dari test ini.

### 1.5 Risiko Manifest Merging dari Library/Modul Pihak Ketiga

Ini nuansa yang tidak dibahas eksplisit oleh overview resmi MASTG namun sangat relevan secara praktis. Sistem build Android **menggabungkan (merge)** `AndroidManifest.xml` dari seluruh modul dan dependency library ke dalam satu manifest final APK. Ini artinya:

- Sebuah **library SDK pihak ketiga** (iklan, analitik, SDK pembayaran) dapat membawa `AndroidManifest.xml` sendiri yang mendeklarasikan `android:usesCleartextTraffic="true"` — dan bila tidak ditangani secara eksplisit (`tools:replace` di manifest aplikasi), nilai ini bisa **ikut termerger** ke manifest final, bertentangan dengan niat asli developer aplikasi.
- Konfigurasi NSC yang dianggap "aman" oleh tim developer aplikasi utama tidak menjamin apa-apa bila **modul terpisah dalam proyek multi-modul** (mis. modul `:debug-tools` atau `:wear-companion`) membawa NSC berbeda yang ikut ter-bundle ke APK final untuk flavor build tertentu.

Sesuai standar dokumen ini (rujuk pada konfirmasi user sebelumnya bahwa pengujian tidak boleh hanya berpatokan pada metode resmi), penguji **wajib memeriksa manifest final hasil merge** (yang ada di dalam APK terpasang), bukan hanya `AndroidManifest.xml` sumber di repositori — karena keduanya bisa berbeda.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | MASTG ID | Fungsi |
|---|---|---|
| **jadx** (`--no-src`) | MASTG-TOOL-0018 | Ekstraksi `AndroidManifest.xml` dan resource NSC dari APK (MASTG-TECH-0117), termasuk elemen `<uses-sdk>` yang penting untuk §1.4 |
| **apktool** | MASTG-TOOL-0011 | Alternatif ekstraksi manifest dan NSC |
| **aapt2** | — | Query manifest tanpa ekstraksi penuh, format decoded custom |
| **grep / xmlstarlet / yq** | — | Pencarian atribut spesifik di XML hasil ekstraksi (MASTG-TECH-0150, MASTG-TECH-0151) |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **MobSF** | Analisis otomatis manifest, biasanya langsung menandai `usesCleartextTraffic="true"` dan konfigurasi NSC bermasalah sebagai temuan siap kutip |
| **androguard** (`androguard axml`) | Parsing AndroidManifest.xml biner secara terprogram — cocok untuk automasi/CI tanpa perlu dekompilasi penuh |
| **apkanalyzer** (Android SDK bawaan) | `apkanalyzer manifest print app.apk` — cara cepat resmi dari Android SDK tanpa tool pihak ketiga |
| **ostorlab / MASTG-adjacent scanner (APK_USES_CLEAR_TEXT_TRAFFIC check)** | Beberapa platform analisis APK komersial/open-source memiliki rule siap pakai spesifik untuk atribut ini, berguna sebagai cross-check kedua |
| **Frida** (hooking `NetworkSecurityConfig`) | Konfirmasi runtime — melihat konfigurasi NSC yang **benar-benar dimuat sistem** saat aplikasi berjalan, termasuk hasil akhir manifest merging (§1.5) yang mungkin berbeda dari sumber |
| **adb logcat** | Sistem mencetak log `D/NetworkSecurityConfig: Using Network Security Config from resource ...` saat NSC dimuat — bukti langsung konfigurasi mana yang aktif (MASTG-TECH-0009) |

### 2.3 Prasyarat Lingkungan

- **Tidak butuh device/root** untuk analisis statis inti — cukup file APK.
- **Butuh device/emulator** untuk verifikasi runtime via logcat atau Frida (mengonfirmasi hasil manifest merging yang sesungguhnya, §1.5).
- **Selalu periksa manifest hasil ekstraksi dari APK final** (bukan hanya source repository) untuk menangkap efek manifest merging dari dependency.
- **Catat `targetSdkVersion`** di awal analisis — ini menentukan default behavior yang harus dijadikan baseline sebelum mencari override eksplisit.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0013** untuk reverse engineer aplikasi.
2. Gunakan **MASTG-TECH-0117** untuk memperoleh `AndroidManifest.xml`.
3. Gunakan **MASTG-TECH-0150** untuk membaca nilai `android:usesCleartextTraffic` dan memeriksa apakah `android:networkSecurityConfig` ada.
4. Gunakan **MASTG-TECH-0151** untuk membaca nilai `cleartextTrafficPermitted` di `<base-config>` dan `<domain-config>` dari file NSC.

### 3.2 Metode A — jadx + grep/xmlstarlet *(metode resmi utama)*

```bash
# Ekstraksi manifest (MASTG-TECH-0117)
jadx --no-src -d ./out_dir target-app.apk
MANIFEST=./out_dir/resources/AndroidManifest.xml

# 1. Cek targetSdkVersion (§1.4 — WAJIB sebagai baseline)
grep -o 'targetSdkVersion="[0-9]*"' "$MANIFEST"

# 2. Cek usesCleartextTraffic dan networkSecurityConfig (MASTG-TECH-0150)
grep -i "usesCleartextTraffic" "$MANIFEST"
grep -i "networkSecurityConfig" "$MANIFEST"

# 3. Bila NSC ditemukan, ekstrak dan periksa isinya (MASTG-TECH-0151)
NSC_FILE=$(grep -oP 'networkSecurityConfig="@xml/\K[^"]+' "$MANIFEST")
if [ -n "$NSC_FILE" ]; then
    cat "./out_dir/resources/res/xml/${NSC_FILE}.xml"
    grep -i "cleartextTrafficPermitted" "./out_dir/resources/res/xml/${NSC_FILE}.xml"
fi
```

Query terstruktur dengan `xmlstarlet`/`yq` untuk hasil yang lebih presisi dan siap diparse otomatis:

```bash
# Manifest
xmlstarlet sel -N android="http://schemas.android.com/apk/res/android" \
  -t -v "//application/@android:usesCleartextTraffic" -n "$MANIFEST"

# NSC — base-config
yq -p=xml -o=json -r '."network-security-config"."base-config"."+@cleartextTrafficPermitted" // "not-set"' "$NSC_FILE"

# NSC — seluruh domain-config beserta domain yang dicakup (WAJIB diperiksa satu per satu, §1.3)
yq -p=xml -o=json '."network-security-config"."domain-config"' "$NSC_FILE"
```

### 3.3 Metode B — aapt2 (tanpa ekstraksi penuh)

```bash
aapt2 dump badging target-app.apk | grep -i "targetSdkVersion\|cleartext"
aapt2 dump xmltree target-app.apk --file AndroidManifest.xml | grep -A2 "usesCleartextTraffic"
```

### 3.4 Metode C — androguard (otomasi/CI, tanpa tool eksternal Java)

```python
from androguard.core.bytecodes.axml import AXMLPrinter
from androguard.core.apk import APK

apk = APK("target-app.apk")
print("targetSdkVersion:", apk.get_target_sdk_version())
manifest_xml = apk.get_android_manifest_xml()
app_element = manifest_xml.find("application")
uses_cleartext = app_element.get("{http://schemas.android.com/apk/res/android}usesCleartextTraffic")
nsc_ref = app_element.get("{http://schemas.android.com/apk/res/android}networkSecurityConfig")
print("usesCleartextTraffic:", uses_cleartext)
print("networkSecurityConfig ref:", nsc_ref)
```

```bash
pip install androguard
python3 check_cleartext_config.py
```

Pendekatan ini ideal untuk **integrasi CI/CD** karena tidak bergantung pada parsing teks XML yang rapuh terhadap variasi format output tool (lihat catatan MASTG-TECH-0150 tentang perbedaan format jadx/apktool vs aapt2).

### 3.5 Metode D — apkanalyzer (Android SDK resmi, tanpa tool tambahan)

```bash
apkanalyzer manifest print target-app.apk | grep -i "cleartext\|networkSecurityConfig\|targetSdkVersion"
```

### 3.6 Metode E — MobSF

```bash
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
```

Bagian **Manifest Analysis** MobSF secara otomatis menandai `usesCleartextTraffic="true"` sebagai temuan dengan severity yang sudah dipetakan, sekaligus menampilkan isi NSC bila ada — mempercepat triase awal sebelum verifikasi manual mendalam.

### 3.7 Metode F — Verifikasi Runtime (menjawab risiko manifest merging §1.5)

```bash
# 1. Install APK dan pantau logcat saat aplikasi start
adb install target-app.apk
adb logcat -c
adb shell am start -n com.target.app/.MainActivity
adb logcat | grep -i "NetworkSecurityConfig"
```

Output yang diharapkan bila NSC kustom dimuat:

```
D/NetworkSecurityConfig: Using Network Security Config from resource network_security_config
```

Bila log ini **tidak muncul** padahal manifest sumber menyatakan ada `networkSecurityConfig`, ini indikasi konfigurasi tersebut **tidak benar-benar termuat** di APK final (bisa jadi karena manifest merging override dari flavor build tertentu, atau kesalahan resource linking) — sinyal untuk menyelidiki lebih lanjut manifest **hasil merge final**, bukan hanya sumber repositori.

Hooking Frida untuk kasus lebih dalam:

```javascript
// hook-nsc-loaded.js
Java.perform(function () {
    var NetworkSecurityConfig = Java.use("android.security.net.config.NetworkSecurityConfig");
    // Verifikasi objek konfigurasi yang benar-benar dipakai sistem saat runtime
    console.log("[*] Hooking NetworkSecurityConfig...");
});
```

### 3.8 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Cakupan | Cocok CI/CD? | Kapan dipakai |
|---|---|---|---|---|
| **A** | jadx/apktool + grep/xmlstarlet | Manifest + NSC lengkap | Sedang | **Baseline resmi wajib** |
| **B** | aapt2 | Cepat, tanpa ekstraksi penuh | ✅ | Verifikasi cepat/spot-check |
| **C** | androguard (Python) | Terprogram, robust terhadap variasi format | ✅ | **Terbaik untuk CI/CD** |
| **D** | apkanalyzer | Resmi dari Android SDK, tanpa tool tambahan | ✅ | Lingkungan yang sudah punya Android SDK terpasang |
| **E** | MobSF | Laporan siap kutip, triase cepat | Sebagian | Audit awal/dokumentasi temuan |
| **F** | adb logcat / Frida | **Bukti runtime** — konfigurasi yang benar-benar dimuat | ❌ (butuh device) | Menyelidiki dugaan manifest merging (§1.5) |

**Kombinasi minimum yang aku rekomendasikan:** **A (baseline resmi) → C (androguard untuk automasi/gate CI) → F (verifikasi runtime)** bila dicurigai ada perbedaan antara manifest sumber dan manifest final APK akibat merging dependency. Selalu sertakan pemeriksaan `targetSdkVersion` (§1.4) sebagai langkah pertama sebelum mencari atribut eksplisit apa pun.

---

### 3.9 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Observation:** *"The output should contain a list of configurations potentially allowing for cleartext traffic."*
>
> **Evaluation:** *"The test case fails if cleartext traffic is permitted."*

Dengan tiga kondisi FAIL yang didefinisikan **secara eksplisit dan lengkap** oleh MASTG sendiri:

1. AndroidManifest menyetel `usesCleartextTraffic` ke `true` **dan tidak ada NSC**.
2. NSC menyetel `cleartextTrafficPermitted` ke `true` di `<base-config>`.
3. NSC menyetel `cleartextTrafficPermitted` ke `true` di **domain-config manapun**.

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi | Sesuai klausul resmi |
|---|---|---|
| F1 | `usesCleartextTraffic="true"` di manifest, **tanpa** `networkSecurityConfig` sama sekali | Klausul #1 |
| F2 | NSC ada, `<base-config cleartextTrafficPermitted="true">` | Klausul #2 |
| F3 | NSC ada, base-config aman, tapi **ada satu atau lebih** `<domain-config cleartextTrafficPermitted="true">` untuk domain produksi (bukan `localhost`/dev-only) | Klausul #3 |
| F4 | `targetSdkVersion` bernilai 24–27 (default `true`) **tanpa** override eksplisit `cleartextTrafficPermitted="false"` di base-config — cleartext diizinkan "secara diam-diam" oleh default sistem | §1.4 — tidak eksplisit disebut MASTG tapi konsekuensi logis dari default behavior yang didokumentasikan |
| F5 | Manifest hasil merge final (di dalam APK terinstal) berbeda dari manifest sumber akibat library pihak ketiga yang membawa `usesCleartextTraffic="true"` sendiri, dan tidak di-override dengan `tools:replace` | §1.5 — dikonfirmasi via Metode F |

**Contoh bukti (ilustratif — MASTG belum menyediakan demo resmi untuk test ini):**

```xml
<!-- AndroidManifest.xml hasil ekstraksi jadx --no-src -->
<manifest ...>
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="26" />  <!-- targetSdk 26 -->
    <application
        android:networkSecurityConfig="@xml/network_security_config"
        ... >
```

```xml
<!-- res/xml/network_security_config.xml -->
<network-security-config>
    <base-config cleartextTrafficPermitted="false" />
    <domain-config cleartextTrafficPermitted="true">
        <domain>internal-staging-api.example.com</domain>   <!-- BUKAN localhost! -->
    </domain-config>
</network-security-config>
```

Interpretasi: meski `base-config` aman, `<domain-config>` mengizinkan cleartext untuk `internal-staging-api.example.com` — domain yang bunyinya seperti endpoint staging tapi berpotensi masih dipakai di build produksi bila belum dibersihkan sebelum rilis. **FAIL** sesuai klausul #3, terlepas dari `base-config` yang aman.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi | Contoh bukti |
|---|---|---|
| P1 | `targetSdkVersion` ≥ 28, **tidak ada** `usesCleartextTraffic` eksplisit, **tidak ada** NSC kustom — mengandalkan default aman sistem | Manifest bersih tanpa atribut cleartext apa pun |
| P2 | NSC ada dengan `<base-config cleartextTrafficPermitted="false">` dan **tidak ada** `<domain-config>` yang mengizinkan cleartext untuk domain produksi | Seluruh domain-config (bila ada) hanya untuk `localhost`/domain testing yang terbukti bukan bagian dari build rilis |
| P3 | `usesCleartextTraffic="true"` ada di manifest, **tapi** ada NSC (bahkan yang kosong) — sesuai catatan resmi §1.2, kombinasi ini **tidak FAIL** | `<network-security-config></network-security-config>` kosong menimpa flag manifest |
| P4 | `targetSdkVersion` 24-27 (default cleartext `true`) **namun** developer secara eksplisit menambahkan `<base-config cleartextTrafficPermitted="false">` untuk menimpa default tersebut | Override eksplisit ditemukan dan terkonfirmasi |
| P5 | Manifest hasil merge final (dikonfirmasi Metode F) identik dengan manifest sumber yang sudah aman — tidak ada kontaminasi dari library pihak ketiga | Log `NetworkSecurityConfig` runtime sesuai ekspektasi sumber |

**Contoh output yang menandakan PASS:**

```bash
$ grep -i "usesCleartextTraffic" AndroidManifest.xml
# (tidak ditemukan)
$ grep -o 'targetSdkVersion="[0-9]*"' AndroidManifest.xml
targetSdkVersion="34"
$ cat res/xml/network_security_config.xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false" />
</network-security-config>
```

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Jangan berhenti setelah menemukan `usesCleartextTraffic="true"` di manifest — periksa dulu apakah ada NSC.** Ini kesalahan paling umum yang menghasilkan **false positive**: sesuai §1.2, keberadaan NSC (bahkan kosong) membuat flag manifest tersebut sepenuhnya diabaikan sistem.

2. **`<domain-config>` harus diperiksa satu per satu, bukan hanya `<base-config>`.** File NSC yang tampak aman di sekilas pandang (`base-config` bernilai `false`) bisa saja menyembunyikan pengecualian berbahaya di salah satu `<domain-config>` yang jumlahnya bisa banyak pada aplikasi kompleks.

3. **`targetSdkVersion` adalah pemeriksaan wajib, bukan opsional** — sesuai §1.4, aplikasi bisa FAIL tanpa satu pun atribut eksplisit dituliskan, murni karena mengandalkan default sistem untuk `targetSdkVersion` rendah.

4. **Uji manifest APK final, bukan hanya source code repositori.** Sesuai §1.5, manifest merging dari dependency dapat mengubah hasil akhir — laporan yang hanya membaca `AndroidManifest.xml` di repositori Git tanpa mem-build dan mengekstrak APK final berisiko melewatkan kontaminasi dari library pihak ketiga.

5. **Bedakan domain pengecualian yang legitimate (localhost/dev-only) dari yang berbahaya (domain produksi).** Pengecualian `cleartextTrafficPermitted="true"` untuk `localhost` semata untuk kebutuhan debugging proxy lokal adalah pola umum dan **rendah risiko** — tapi hal yang sama untuk domain yang menyerupai endpoint produksi/staging nyata harus ditandai prioritas tinggi.

6. **Test ini murni tentang KEBOLEHAN sistem, bukan APAKAH aplikasi benar-benar mengirim HTTP.** Hasil FAIL di sini berarti "sistem operasi tidak akan menghalangi" — untuk bukti bahwa data benar-benar terkirim plaintext, korelasikan dengan MASTG-TEST-0233 (lokasi kode HTTP) dan MASTG-TEST-0236 (capture jaringan nyata).

7. **Severity dimodulasi oleh cakupan domain yang terpengaruh:**

   | Faktor | Severity |
   |---|---|
   | `cleartextTrafficPermitted="true"` di `base-config` (berlaku untuk SEMUA domain) | **Kritis** |
   | `cleartextTrafficPermitted="true"` hanya untuk domain produksi tertentu di `domain-config` | **Tinggi** |
   | `cleartextTrafficPermitted="true"` hanya untuk `localhost`/domain testing yang terbukti tidak dipakai di rilis | **Informational** — catat sebagai code hygiene, bukan kerentanan aktif |
   | Cleartext diizinkan hanya karena default `targetSdkVersion` rendah tanpa override eksplisit (F4) | **Tinggi** — sering merupakan kelalaian, bukan keputusan sadar |

8. **Dokumentasikan:** nilai `targetSdkVersion`, isi lengkap `usesCleartextTraffic` di manifest, keberadaan dan isi lengkap NSC (`base-config` + seluruh `domain-config`), hasil verifikasi manifest APK final vs sumber (bila dilakukan), dan korelasi dengan MASTG-TEST-0233/0236 bila tersedia.

---

## 4. Rekomendasi Perbaikan

### 4.1 Terapkan NSC Eksplisit yang Ketat

```xml
<!-- res/xml/network_security_config.xml -->
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
    <!-- Hanya tambahkan domain-config untuk kebutuhan development, PASTIKAN
         terpisah dari build variant production -->
</network-security-config>
```

```xml
<!-- AndroidManifest.xml -->
<application
    android:networkSecurityConfig="@xml/network_security_config"
    android:usesCleartextTraffic="false"
    ... >
```

### 4.2 Naikkan `targetSdkVersion` ke Nilai Terkini

Menaikkan `targetSdkVersion` ke ≥28 (idealnya versi API terkini yang didukung Google Play) secara otomatis mengaktifkan default aman tanpa perlu konfigurasi tambahan, sekaligus memenuhi kebijakan Google Play Console yang mewajibkan target SDK terkini untuk publikasi aplikasi baru.

### 4.3 Pisahkan Konfigurasi Development dari Production via Build Variant

```gradle
android {
    buildTypes {
        debug {
            manifestPlaceholders = [nscConfig: "@xml/network_security_config_debug"]
        }
        release {
            manifestPlaceholders = [nscConfig: "@xml/network_security_config_release"]
        }
    }
}
```

```xml
<!-- network_security_config_debug.xml — HANYA untuk build debug -->
<network-security-config>
    <base-config cleartextTrafficPermitted="false" />
    <domain-config cleartextTrafficPermitted="true">
        <domain>localhost</domain>
        <domain>10.0.2.2</domain>  <!-- alias localhost host machine dari emulator -->
    </domain-config>
</network-security-config>
```

```xml
<!-- network_security_config_release.xml — TANPA pengecualian apa pun -->
<network-security-config>
    <base-config cleartextTrafficPermitted="false" />
</network-security-config>
```

### 4.4 Kendalikan Manifest Merging dari Dependency

Bila sebuah library dependency diketahui membawa `usesCleartextTraffic="true"` di manifest-nya sendiri, override secara eksplisit di manifest aplikasi:

```xml
<application
    android:usesCleartextTraffic="false"
    tools:replace="android:usesCleartextTraffic"
    ... >
```

Verifikasi hasil merging dengan memeriksa manifest final:

```bash
./gradlew :app:processReleaseManifest
cat app/build/intermediates/merged_manifest/release/AndroidManifest.xml | grep -i cleartext
```

### 4.5 Integrasikan ke CI/CD

```bash
#!/bin/bash
# ci-check-cleartext-config.sh — jalankan pada APK RELEASE hasil build final
APK=$1
python3 -c "
from androguard.core.apk import APK
apk = APK('$APK')
target_sdk = apk.get_target_sdk_version()
print(f'targetSdkVersion: {target_sdk}')
manifest = apk.get_android_manifest_xml()
app = manifest.find('application')
ns = '{http://schemas.android.com/apk/res/android}'
uct = app.get(f'{ns}usesCleartextTraffic')
nsc = app.get(f'{ns}networkSecurityConfig')
print(f'usesCleartextTraffic: {uct}')
print(f'networkSecurityConfig: {nsc}')
if uct == 'true' and not nsc:
    print('[GAGAL] Cleartext traffic diizinkan tanpa NSC!')
    exit(1)
if int(target_sdk) < 28 and not nsc:
    print('[PERINGATAN] targetSdkVersion < 28 tanpa NSC eksplisit — cleartext default true')
"
```

### 4.6 Checklist Remediasi

- [ ] `targetSdkVersion` sudah diperiksa dan dinaikkan ke nilai terkini bila memungkinkan
- [ ] `usesCleartextTraffic="false"` sudah diset eksplisit di manifest
- [ ] NSC eksplisit dengan `<base-config cleartextTrafficPermitted="false">` sudah diterapkan
- [ ] Seluruh `<domain-config>` (bila ada) sudah ditinjau satu per satu — tidak ada pengecualian untuk domain produksi
- [ ] Pengecualian cleartext untuk keperluan development dipisahkan lewat build variant, tidak pernah masuk ke build release
- [ ] Manifest hasil merge final (APK release) sudah diverifikasi tidak terkontaminasi `usesCleartextTraffic="true"` dari dependency pihak ketiga
- [ ] Verifikasi runtime (logcat/`NetworkSecurityConfig`) sudah dilakukan untuk memastikan konfigurasi yang dimaksud benar-benar termuat
- [ ] Korelasi dengan MASTG-TEST-0233 (lokasi HTTP) dan MASTG-TEST-0236 (capture jaringan) sudah dilakukan
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0235 pada APK release final setelah remediasi

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0235: Android App Configurations Allowing Cleartext Traffic](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0235/)
- [MASTG-TEST-0233: Hardcoded HTTP URLs](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0233/)
- [MASTG-TEST-0236: Cleartext Traffic in Network Traffic Capture](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0236/)
- [MASWE-0026: Network Traffic Not Encrypted](https://mas.owasp.org/MASWE/MASVS-NETWORK/MASWE-0026/)
- [MASTG-KNOW-0014: Android Network Security Configuration](https://mas.owasp.org/MASTG/knowledge/android/MASVS-NETWORK/MASTG-KNOW-0014/)
- [MASTG-TECH-0013: Reverse Engineering Android Apps](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0013/)
- [MASTG-TECH-0117: Obtaining Information from the AndroidManifest](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0117/)
- [MASTG-TECH-0150: Analyzing the AndroidManifest](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0150/)
- [MASTG-TECH-0151: Analyzing the Network Security Configuration](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0151/)
- [MASTG Document 0x05g — Testing Network Communication](https://mas.owasp.org/MASTG/0x05g-Testing-Network-Communication/)
- [OWASP Mobile Top 10 2024 — M5: Insecure Communication](https://owasp.org/www-project-mobile-top-10/2023-risks/m5-insecure-communication)

### 5.2 Dokumentasi Resmi Android

- [Android Developers — Network Security Configuration](https://developer.android.com/training/articles/security-config)
- [Android Developers — `usesCleartextTraffic` attribute reference](https://developer.android.com/guide/topics/manifest/application-element#usesCleartextTraffic)
- [Android Developers — `cleartextTrafficPermitted` reference](https://developer.android.com/privacy-and-security/security-config#CleartextTrafficPermitted)
- [Android Codelab — Network Security Configuration](https://developer.android.com/codelabs/android-network-security-config)
- [Android Developers Blog — Protecting against unintentional regressions to cleartext traffic in your Android apps](https://android-developers.googleblog.com/2016/04/protecting-against-unintentional.html)
- [Android Developers — Manifest merging documentation](https://developer.android.com/build/manage-manifests)

### 5.3 Riset dan Kasus Nyata

- [NCC Group — Bypassing Android's Network Security Configuration](https://www.nccgroup.com/research-blog/bypassing-android-s-network-security-configuration/)
- [NowSecure — A Security Analyst's Guide to Network Security Configuration in Android P](https://www.nowsecure.com/blog/2018/08/15/a-security-analysts-guide-to-network-security-configuration-in-android-p/)
- [GitHub Issue — corona-warn-app/cwa-app-android#2: usesCleartextTraffic/cleartextTrafficPermitted set to true](https://github.com/corona-warn-app/cwa-app-android/issues/2)
- [Haxoris — Cleartext Traffic: Mobile Risk and Fix (M5 Insecure Communication)](https://haxoris.com/haxoris-wiki/mobile-owasp-top-10/m5-insecure-communication/cleartext-traffic)
- [Ostorlab Knowledge Base — Attribute usesCleartextTraffic set](https://docs.ostorlab.co/kb/APK_USES_CLEAR_TEXT_TRAFFIC/index.html)
- [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)

### 5.4 Dokumentasi Tools

- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [apktool](https://apktool.org/)
- [aapt2 — Android Asset Packaging Tool](https://developer.android.com/tools/aapt2)
- [androguard](https://github.com/androguard/androguard)
- [apkanalyzer — Android SDK command-line tool](https://developer.android.com/tools/apkanalyzer)
- [xmlstarlet](http://xmlstar.sourceforge.net/)
- [yq — YAML/XML/JSON processor](https://github.com/mikefarah/yq)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026), dokumentasi resmi Android Developers, riset NCC Group dan NowSecure, serta kasus nyata dari proyek open-source (Corona Warn App). Test ini belum memiliki demo (MASTG-DEMO) maupun rule semgrep resmi karena objek pengujiannya adalah manifest/XML konfigurasi, bukan kode Java/Kotlin — dokumen ini menekankan pemeriksaan `targetSdkVersion` dan manifest hasil merge final sebagai langkah yang sering terlewat dari pembacaan literal atribut semata.*
