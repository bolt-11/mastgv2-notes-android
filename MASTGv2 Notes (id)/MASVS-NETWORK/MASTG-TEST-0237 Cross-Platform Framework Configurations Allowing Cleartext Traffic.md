# MASTG-TEST-0237 Cross-Platform Framework Configurations Allowing Cleartext Traffic

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0237 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-NETWORK (MASVS-NETWORK-1: Seluruh lalu lintas jaringan dienkripsi memakai TLS) |
| **Weakness** | MASWE-0026 — *Network Traffic Not Encrypted* |
| **Tipe Pengujian** | Static, Code |
| **Profile** | L1, L2 |
| **Status resmi MASTG** | **`placeholder`** — MASTG belum menuliskan Overview/Steps/Observation/Evaluation lengkap untuk test ini |
| **Catatan resmi (satu-satunya konten yang tersedia)** | *"Cross-platform frameworks (e.g. Flutter, React Native, ...), typically have their own implementations for HTTP libraries, where cleartext traffic can be allowed."* |
| **Test terkait** | **MASTG-TEST-0235** (Android App Configurations Allowing Cleartext Traffic — konfigurasi native manifest/NSC; test ini adalah **counterpart lintas-framework**-nya) |
| **Demo terkait** | — (tidak ada) |
| **Rule resmi** | — (tidak ada; test berstatus placeholder) |
| **CWE terkait** | CWE-319 (Cleartext Transmission of Sensitive Information) |

---

## 1. Penjelasan

### 1.1 Status Test Ini: Placeholder Resmi

Ini penting untuk ditegaskan sejak awal: MASTG-TEST-0237 saat ini berstatus **`status: placeholder`** di source resminya. Artinya, **tidak ada** bagian Overview, Steps, Observation, atau Evaluation formal yang dipublikasikan MASTG untuk test ini — satu-satunya isi yang tersedia hanyalah metadata `note` singkat:

> *"Cross-platform frameworks (e.g. Flutter, React Native, ...), typically have their own implementations for HTTP libraries, where cleartext traffic can be allowed."*

Karena struktur resminya belum lengkap, dokumen ini disusun terutama dari **riset independen dan dokumentasi resmi masing-masing framework** (Flutter, React Native, Cordova), sesuai standar riset yang berlaku untuk seri dokumen ini — bukan dari kutipan langsung "Steps/Observation/Evaluation" MASTG seperti pada test-test lain, karena bagian tersebut memang belum ditulis MASTG.

### 1.2 Mengapa Test Ini Perlu Berdiri Sendiri, Terpisah dari MASTG-TEST-0235

MASTG-TEST-0235 menguji `android:usesCleartextTraffic` dan Network Security Configuration (NSC) — mekanisme yang bekerja pada **lapisan networking native Android** (`HttpsURLConnection`, `OkHttp`, `WebView` bawaan, dan sebagian besar library HTTP yang membangun koneksinya lewat socket API sistem Android).

Masalahnya: **banyak cross-platform framework tidak sepenuhnya memakai lapisan networking native tersebut** — mereka membawa runtime dan/atau implementasi HTTP client sendiri yang berjalan **di atas** Android, bukan terintegrasi penuh dengannya. Ini artinya konfigurasi NSC yang tampak sempurna di `AndroidManifest.xml`/`network_security_config.xml` **bisa saja tidak berlaku sama sekali** untuk lalu lintas yang dihasilkan lapisan cross-platform tersebut — sebuah kesenjangan (*gap*) yang tidak akan pernah terungkap hanya dengan menjalankan MASTG-TEST-0235.

### 1.3 Kasus Flutter: Temuan Paling Signifikan — NSC Tidak Berlaku untuk Traffic Dart

Ini adalah temuan riset terpenting untuk test ini, dan contoh paling ekstrem dari kesenjangan yang dijelaskan di §1.2.

**Flutter tidak memakai stack networking Java/Kotlin Android sama sekali** untuk HTTP client bawaannya (`dart:io HttpClient`, dan library populer di atasnya seperti `package:http` dan `dio`). Sebagai gantinya, Flutter engine membangun koneksi socket **langsung dari Dart VM**, dengan implementasi TLS memakai **BoringSSL yang di-bundle langsung ke dalam `libflutter.so`** — sepenuhnya terpisah dari trust store dan kebijakan jaringan sistem operasi Android.

Konsekuensinya, sesuai riset komunitas Flutter sendiri (GitHub issue `flutter/flutter#106678`, *"Flutter doesn't respect Android's `android:usesCleartextTraffic="false"` settings"*):

- Flutter **sebelumnya** memiliki dukungan parsial untuk membaca Network Security Configuration Android lewat `ApplicationInfoLoader.java` di level engine.
- Dukungan ini **dihapus** lewat pull request bertajuk *"Turn off insecure socket policy configuration in the engine"*, yang menghardcode `may_insecurely_connect_to_all_domains = true` dan mengosongkan seluruh kebijakan domain jaringan.
- Issue yang melaporkan masalah ini **ditutup dengan status "not planned"** oleh tim Flutter — mengindikasikan tim Flutter **tidak berencana** mengembalikan dukungan penuh terhadap enforcement NSC pada level engine untuk semua kasus.

**Implikasi krusial bagi penguji:** aplikasi Flutter dapat memiliki `network_security_config.xml` yang tampak sempurna (lulus MASTG-TEST-0235 dengan bersih) — namun kode Dart aplikasi (business logic, bukan `WebView`) tetap dapat mengirim HTTP plaintext tanpa terhalang apa pun, karena **socket yang dipakai adalah milik Dart VM, bukan socket yang tunduk pada policy Android**. Ini mengapa MASTG-TEST-0235 **tidak cukup** untuk aplikasi berbasis Flutter, dan test ini (0237) harus dijalankan sebagai pemeriksaan terpisah yang menyasar konfigurasi framework itu sendiri, bukan konfigurasi Android murni.

> **Catatan penting soal sumber yang saling bertentangan:** Sejumlah artikel pihak ketiga (termasuk panduan keamanan Flutter populer) tetap merekomendasikan NSC sebagai mitigasi utama untuk memblokir cleartext di aplikasi Flutter, tanpa menyebutkan keterbatasan di atas. Berdasarkan riset primer langsung ke laporan bug resmi `flutter/flutter`, **klaim itu tidak sepenuhnya dapat diandalkan** untuk lalu lintas yang dibuat langsung dari kode Dart (`dart:io`, `package:http`, `dio`) — NSC kemungkinan besar **hanya efektif** untuk komponen yang benar-benar berjalan di atas WebView Android native (mis. `flutter_webview_plugin`/`webview_flutter` yang secara internal memakai `android.webkit.WebView`), bukan untuk panggilan HTTP langsung dari Dart. Penguji **wajib memverifikasi secara empiris** (§3.4) untuk versi Flutter engine yang dipakai aplikasi target, bukan berasumsi dari dokumentasi mana pun — termasuk dokumen ini.

### 1.4 Kasus React Native: Umumnya Lebih Aman, Tapi Tidak Selalu

Berbeda dari Flutter, **modul networking bawaan React Native (`fetch`, `XMLHttpRequest`) pada Android umumnya diimplementasikan di atas OkHttp** — library HTTP client Java/Kotlin yang **memang tunduk** pada Network Security Configuration Android. Ini artinya untuk kasus paling umum, MASTG-TEST-0235 **cukup relevan** untuk menutup jalur networking utama React Native.

Namun, ada pengecualian penting yang perlu diperiksa:

- **`react-native-webview`**: Komponen WebView di React Native memiliki riwayat masalah serupa (`react-native-webview#3142` — *"Enable Cleartext traffic inside React Native Webview in Android"*) di mana perilaku cleartext untuk konten yang dimuat WebView tidak selalu konsisten dengan konfigurasi NSC aplikasi induk, tergantung versi library dan cara WebView diinisialisasi.
- **Native module kustom**: Bila aplikasi memiliki native module Java/Kotlin kustom yang membangun koneksi jaringannya sendiri (di luar `fetch`/`XMLHttpRequest` standar RN) memakai library selain OkHttp (mis. `SSLSocket` mentah — lihat MASTG-TEST-0234), NSC tetap berlaku selama library tersebut memang memakai socket Android — tapi ini harus diverifikasi per-modul, bukan diasumsikan.
- **Metro bundler / dev server**: Selama development, RN secara default membutuhkan akses cleartext ke bundler lewat `localhost` (`facebook/react-native#22375`) — ini legitimate untuk debug build tapi **wajib dipastikan tidak tertinggal** di konfigurasi release (pola risiko yang sama seperti dibahas di MASTG-TEST-0235 §1.3 tentang domain-config `localhost`).

### 1.5 Kasus Cordova/Ionic (WebView-based Hybrid Apps)

Aplikasi Cordova (dan turunannya seperti Ionic dengan Capacitor) pada dasarnya adalah **WebView** yang menjalankan HTML/JS/CSS — sehingga lalu lintas jaringan utamanya (fetch/XHR dari JavaScript di dalam WebView) **umumnya tunduk** pada perilaku `android.webkit.WebView`, yang pada gilirannya **memang mematuhi** Network Security Configuration Android sejak API 24+.

Meski begitu, ekosistem Cordova memiliki riwayat masalah cleartext yang cukup dikenal luas di komunitasnya sendiri:

- Error **`net::ERR_CLEARTEXT_NOT_PERMITTED`** adalah keluhan umum yang dicari developer Cordova sejak Android 9 dirilis — cukup umum sampai muncul plugin komunitas khusus seperti `cordova-plugin-enable-cleartext-traffic` yang secara otomatis menyuntikkan `usesCleartextTraffic="true"` ke manifest hasil build.
- Plugin semacam ini, bila **tertinggal terpasang di build produksi** (bukan hanya untuk kebutuhan development), secara efektif menciptakan kondisi FAIL yang identik dengan MASTG-TEST-0235, tetapi sumber masalahnya berasal dari **konfigurasi plugin cross-platform**, bukan edit manual developer pada `AndroidManifest.xml` — sehingga mudah luput dari code review yang hanya memeriksa manifest yang ditulis tangan.
- `cordova-plugin-whitelist` mengatur domain mana yang boleh diakses/dinavigasi WebView (`<allow-navigation>`, `<access origin>` di `config.xml`) — ini kontrol terpisah dari cleartext, tapi sering dikonfigurasi bersamaan dan perlu diperiksa keduanya.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **jadx / apktool** | Ekstraksi manifest, NSC, dan resource untuk pemeriksaan dasar (sama seperti MASTG-TEST-0235) |
| **grep / ripgrep** | Pencarian konfigurasi spesifik framework di dalam `assets/flutter_assets/`, bundle JS React Native, atau `config.xml` Cordova |
| **Deteksi framework** (`apkid`, pemeriksaan manual struktur APK) | Langkah pertama wajib: identifikasi framework yang dipakai (`libflutter.so` menandakan Flutter, `libreactnativejni.so`/`index.android.bundle` menandakan React Native, `cordova.js`/`config.xml` menandakan Cordova) sebelum menentukan metode pengujian yang relevan |

### 2.2 Tools Spesifik per Framework

| Framework | Tool/Teknik | Fungsi |
|---|---|---|
| **Flutter** | **Reflutter** / **Fridantic** | Instrumentasi Flutter engine untuk hooking pada level Dart VM — dibutuhkan karena Frida hook standar untuk API Java (`javax.net.ssl.*`) **tidak akan pernah terpicu** oleh traffic Dart |
| **Flutter** | `strings`/`rabin2` pada `libflutter.so` dan `libapp.so` | Mencari string endpoint hardcoded, karena analisis dekompilasi Java/Kotlin standar (jadx) **tidak dapat membaca kode Dart** yang sudah dikompilasi AOT ke dalam `libapp.so` |
| **Flutter** | **Blutter** / **doldrums** (dekompiler khusus Dart snapshot) | Mengekstrak dan menganalisis kode Dart terkompilasi dari `libapp.so` untuk menemukan konfigurasi HTTP client secara statis |
| **React Native** | `react-native-decompiler` / ekstraksi `index.android.bundle` | Bundle JS RN (biasanya di `assets/index.android.bundle`) dapat diekstrak dan dianalisis sebagai teks JavaScript untuk mencari konfigurasi `fetch`/`XMLHttpRequest` dan endpoint hardcoded |
| **Cordova** | Ekstraksi `assets/www/` | Kode HTML/JS/CSS aplikasi Cordova disimpan sebagai file mentah di `assets/www/` — dapat langsung dibaca/di-grep tanpa dekompilasi apa pun |
| **Cordova** | Pemeriksaan `res/xml/config.xml` | Mencari `<allow-navigation>`, `<access>`, dan keberadaan plugin cleartext seperti `cordova-plugin-enable-cleartext-traffic` di `plugins/` |

### 2.3 Tools Pendukung Dinamis

| Tool | Fungsi |
|---|---|
| **mitmproxy / Burp Suite / PCAPdroid** | Bukti definitif lintas-framework — menangkap paket mentah tanpa peduli lapisan mana yang menghasilkannya (Dart, JS bridge, atau Java native) |
| **Frida + Reflutter (khusus Flutter)** | Hooking pada level Dart runtime untuk menangkap pemanggilan `dart:io HttpClient` secara langsung |
| **adb logcat** | Baseline — memeriksa apakah pesan `NetworkSecurityConfig` sistem muncul sama sekali saat traffic framework tersebut terjadi (bila tidak muncul, indikasi kuat traffic tidak melalui jalur yang tunduk NSC) |

### 2.4 Prasyarat Lingkungan

- **Identifikasi framework terlebih dahulu** adalah langkah wajib pertama — metodologi pengujian sama sekali berbeda antara Flutter, React Native, dan Cordova.
- **Analisis statis kode Dart membutuhkan tooling khusus** (Blutter/doldrums) yang berbeda total dari toolchain Java/Kotlin standar (jadx) yang dipakai di hampir seluruh dokumen lain dalam seri riset ini.
- **Pengujian dinamis dengan capture jaringan mentah (mitmproxy/PCAPdroid) adalah metode yang paling dapat diandalkan** untuk semua jenis framework cross-platform, karena tidak bergantung pada asumsi tentang lapisan mana yang menangani request — ini konsisten dengan prinsip "percayakan pada bukti runtime" yang berulang kali ditekankan di seluruh seri dokumen MASVS-NETWORK ini.

---

## 3. Cara Pengujian

Karena tidak ada langkah resmi MASTG untuk test placeholder ini, bagian ini disusun murni dari riset independen per framework.

### 3.1 Langkah 0 — Identifikasi Framework Cross-Platform yang Dipakai

```bash
unzip -l target-app.apk | grep -E "libflutter\.so|libapp\.so|libreactnativejni\.so|index\.android\.bundle|cordova\.js|config\.xml"
```

| Bukti ditemukan | Framework terindikasi |
|---|---|
| `lib/*/libflutter.so`, `lib/*/libapp.so`, `assets/flutter_assets/` | **Flutter** |
| `lib/*/libreactnativejni.so`, `assets/index.android.bundle` | **React Native** |
| `assets/www/cordova.js`, `res/xml/config.xml` dengan skema Cordova | **Cordova/Ionic (Capacitor)** |

### 3.2 Metode A — Flutter: Analisis Konfigurasi NSC + Verifikasi Empiris Keberlakuannya

```bash
# 1. Tetap periksa NSC seperti MASTG-TEST-0235 (baseline, meski keberlakuannya harus diverifikasi §3.4)
jadx --no-src -d ./out target-app.apk
grep -i "networkSecurityConfig\|usesCleartextTraffic" ./out/resources/AndroidManifest.xml

# 2. Cari string endpoint HTTP di dalam binary Dart (libapp.so) — dekompilasi Java TIDAK bisa membaca ini
find . -name "libapp.so" -exec rabin2 -zz {} \; | grep -oE 'http://[a-zA-Z0-9./?=&_-]+'

# 3. Cari referensi package HTTP populer yang dipakai (untuk konteks risiko)
grep -r "dart:io\|package:http\|package:dio" ./pubspec.lock 2>/dev/null   # bila source tersedia (whitebox)
```

Untuk analisis lebih dalam pada bytecode Dart terkompilasi (blackbox, hanya dari APK):

```bash
# Blutter — dekompiler snapshot Dart AOT
python3 blutter.py ./out/lib/arm64-v8a/ ./blutter_output/
grep -r "http://" ./blutter_output/
```

### 3.3 Metode B — React Native: Ekstraksi dan Analisis Bundle JS

```bash
unzip -o target-app.apk assets/index.android.bundle -d ./rn_extracted

# Bundle biasanya di-minify; unpack/format dulu untuk analisis yang layak
npx js-beautify ./rn_extracted/assets/index.android.bundle > ./rn_extracted/bundle_formatted.js

# Cari pola fetch/XMLHttpRequest dengan URL http://
rg -n 'http://[a-zA-Z0-9./_-]+' ./rn_extracted/bundle_formatted.js
rg -n 'fetch\(["\x27]http://' ./rn_extracted/bundle_formatted.js

# Verifikasi NSC (relevan untuk RN, berbeda dari Flutter — lihat §1.4)
grep -i "networkSecurityConfig\|usesCleartextTraffic" ./out/resources/AndroidManifest.xml
```

Untuk hasil yang lebih terstruktur (mengembalikan sebagian nama variabel/fungsi bila source map tersedia):

```bash
react-native-decompiler -i ./rn_extracted/assets/index.android.bundle -o ./rn_decompiled/
```

### 3.4 Metode C — Verifikasi Empiris "Apakah NSC Benar-Benar Berlaku?" *(WAJIB untuk Flutter, sesuai §1.3)*

Ini metode terpenting di seluruh dokumen ini — sesuai peringatan §1.3, klaim dari dokumentasi (termasuk dokumen ini) **tidak boleh dipercaya tanpa verifikasi** untuk versi Flutter engine spesifik yang dipakai aplikasi target:

```bash
# 1. Terapkan NSC paling ketat yang mungkin: blokir SEMUA cleartext
cat > network_security_config_test.xml << 'EOF'
<network-security-config>
    <base-config cleartextTrafficPermitted="false" />
</network-security-config>
EOF
# (build ulang APK uji dengan konfigurasi ini bila melakukan whitebox testing,
#  atau gunakan APK asli bila sudah memiliki NSC ketat serupa)

# 2. Jalankan aplikasi dengan proxy yang HANYA menerima cleartext HTTP (bukan HTTPS)
#    pada endpoint yang diketahui dipanggil aplikasi
mitmproxy --mode transparent --set http2=false

# 3. Amati: apakah request HTTP dari kode Dart/JS tetap BERHASIL terkirim
#    meski NSC seharusnya memblokirnya?
```

Bila request **tetap berhasil** meski NSC secara eksplisit melarang cleartext — ini bukti definitif bahwa lalu lintas framework tersebut **tidak tunduk** pada NSC Android, mengonfirmasi kondisi yang dijelaskan di §1.3 untuk Flutter.

### 3.5 Metode D — Cordova: Pemeriksaan `config.xml` dan Plugin Cleartext

```bash
unzip -o target-app.apk res/xml/config.xml -d ./cordova_check
cat ./cordova_check/res/xml/config.xml | grep -i "allow-navigation\|access origin\|cleartext"

# Cari jejak plugin cleartext pihak ketiga yang mungkin tertinggal dari development
unzip -l target-app.apk | grep -i "cleartext"
jadx --no-src -d ./out2 target-app.apk
grep -i "usesCleartextTraffic" ./out2/resources/AndroidManifest.xml

# Periksa kode aplikasi WebView (assets/www) untuk endpoint HTTP
unzip -o target-app.apk -d ./cordova_full 'assets/www/*'
rg -n 'http://[a-zA-Z0-9./_-]+' ./cordova_full/assets/www/
```

### 3.6 Metode E — Capture Jaringan Universal (Lintas Framework, Paling Andal)

```bash
# PCAPdroid (tidak butuh root, cocok untuk semua framework)
adb shell am start -n com.emanuelef.remote_capture/.activities.CaptureCtrl \
  --es action start --es pcap_dump_mode tcp --es collector_ip 127.0.0.1

# Atau mitmproxy dengan sertifikat CA sistem (root) untuk MITM penuh
mitmweb --mode transparent
```

Capture mentah **tidak peduli** apakah traffic berasal dari Dart, JS bridge, atau kode Java native — ini alasan mengapa metode ini menjadi **pembanding definitif** terlepas dari framework apa pun yang dipakai aplikasi target.

### 3.7 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Framework target | Menjawab pertanyaan | Kapan dipakai |
|---|---|---|---|
| **A** | Flutter | Konfigurasi statis + verifikasi keberlakuan NSC | Wajib untuk semua aplikasi Flutter |
| **B** | React Native | Endpoint hardcoded di bundle JS | Wajib untuk semua aplikasi RN |
| **C** | Flutter (utamanya) | **Apakah NSC benar-benar berlaku?** | **Wajib** — jangan simpulkan PASS dari analisis statis NSC saja pada Flutter |
| **D** | Cordova/Ionic | Konfigurasi WebView + plugin tertinggal | Wajib untuk semua aplikasi Cordova/Capacitor |
| **E** | Semua framework | Bukti definitif lapangan | **Wajib** sebagai konfirmasi akhir, apa pun frameworknya |

**Kombinasi minimum yang aku rekomendasikan:** **0 (identifikasi framework) → metode statis sesuai framework (A/B/D) → E (capture jaringan) sebagai pembuktian akhir**. Untuk Flutter secara khusus, **C tidak boleh dilewati** — ini satu-satunya cara memastikan konfigurasi NSC yang terlihat aman benar-benar memberikan proteksi nyata.

---

### 3.8 Kriteria Evaluasi: Positive Case & Negative Case

Karena tidak ada klausul Evaluation resmi dari MASTG (status placeholder), kriteria berikut disusun dari prinsip dasar MASWE-0026 (Network Traffic Not Encrypted) yang mendasari test ini, diadaptasi untuk konteks cross-platform.

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Aplikasi Flutter memiliki referensi `http://` yang dikonfirmasi dipanggil dari kode Dart (`dart:io`, `package:http`, `dio`), **terlepas dari** status NSC — karena §1.3 menunjukkan NSC berpotensi tidak relevan sama sekali untuk traffic ini |
| F2 | Verifikasi empiris (Metode C) menunjukkan request HTTP dari kode framework **tetap berhasil terkirim** meski NSC secara eksplisit melarang cleartext |
| F3 | Bundle JS React Native mengandung endpoint `http://` yang dikonfirmasi aktif dipanggil lewat `fetch`/`XMLHttpRequest`, **dan** NSC tidak memblokirnya (§1.4 — kasus RN yang NSC-nya memang relevan) |
| F4 | Aplikasi Cordova/Ionic memiliki plugin cleartext pihak ketiga (mis. `cordova-plugin-enable-cleartext-traffic`) yang **masih aktif di build produksi**, menghasilkan `usesCleartextTraffic="true"` yang tidak disengaja untuk rilis |
| F5 | Capture jaringan nyata (Metode E) menunjukkan paket HTTP plaintext benar-benar terkirim, apa pun sumber lapisan kodenya |

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Tidak ditemukan endpoint `http://` yang aktif dipakai di kode Dart/JS framework manapun |
| P2 | Untuk Flutter: verifikasi empiris (Metode C) mengonfirmasi bahwa **seluruh** endpoint yang dipanggil memang `https://`, sehingga ketidakberlakuan NSC terhadap Dart socket menjadi tidak relevan (karena tidak ada percobaan cleartext untuk diblokir) |
| P3 | Untuk React Native: NSC terkonfirmasi (Metode C style verification) benar-benar memblokir upaya cleartext dari `fetch`/`XMLHttpRequest` |
| P4 | Untuk Cordova: `config.xml` dan manifest bersih dari pengecualian cleartext, dan tidak ada jejak plugin cleartext development yang tertinggal |
| P5 | Capture jaringan menyeluruh (Metode E) selama sesi pengujian penuh hanya menunjukkan koneksi TLS |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Ini test yang paling menuntut verifikasi empiris di antara seluruh rangkaian test MASVS-NETWORK yang sudah dibahas.** Karena statusnya placeholder dan lanskap cross-platform framework berubah cepat (perilaku Flutter soal NSC bahkan berubah antar versi engine, sesuai riwayat di GitHub issue #106678), **jangan pernah menyimpulkan hasil hanya dari membaca dokumentasi framework** — verifikasi selalu dengan Metode C/E pada versi framework yang benar-benar dipakai aplikasi target.

2. **Untuk Flutter, MASTG-TEST-0235 (PASS) tidak memberi jaminan apa pun untuk test ini.** Ulangi: aplikasi bisa lulus sempurna di MASTG-TEST-0235 dan tetap FAIL total di sini karena traffic Dart tidak tunduk pada mekanisme yang diperiksa MASTG-TEST-0235.

3. **Analisis statis kode Dart terkompilasi jauh lebih sulit dibanding Java/Kotlin.** Tooling seperti Blutter masih tergolong riset aktif dan tidak seandal jadx untuk kode Java — bila analisis statis tidak memungkinkan/tidak lengkap, **naikkan bobot pada pengujian dinamis (Metode C/E)** sebagai sumber kebenaran utama.

4. **Perhatikan versi framework secara spesifik saat melaporkan temuan.** Karena perilaku ini adalah keputusan desain/engine yang bisa berubah antar rilis (seperti riwayat Flutter di §1.3), laporan pengujian **wajib mencantumkan versi Flutter/React Native/Cordova** yang diuji agar temuan dapat direproduksi dan tidak menyesatkan bila dibaca setelah framework tersebut merilis versi baru.

5. **Severity dimodulasi oleh framework dan jenis data:**

   | Faktor | Severity |
   |---|---|
   | Flutter mengirim data sensitif lewat `http://` — NSC tidak relevan sama sekali | **Kritis** — kesalahpahaman umum bahwa NSC sudah menutup celah ini membuat risiko sering tidak disadari tim developer |
   | React Native mengirim data sensitif lewat `http://` tanpa NSC yang memblokir | **Kritis** |
   | Plugin cleartext Cordova development tertinggal di rilis produksi | **Tinggi** |
   | Endpoint HTTP hanya dipakai untuk komunikasi non-sensitif (health check, cek versi) | **Menengah/Rendah** |

6. **Dokumentasikan:** framework dan versi persisnya, hasil identifikasi (§3.1), status NSC di manifest, hasil verifikasi empiris (§3.4) yang membuktikan/menyangkal keberlakuan NSC untuk framework tersebut, dan bukti capture jaringan.

---

## 4. Rekomendasi Perbaikan

### 4.1 Flutter: Jangan Andalkan NSC — Kendalikan di Level Kode Dart

Karena NSC berpotensi tidak berlaku (§1.3), kendalikan skema URL secara eksplisit di level kode Dart, jangan mengandalkan konfigurasi platform semata:

```dart
// Validasi eksplisit di level aplikasi — jangan andalkan Android/NSC untuk memblokir HTTP
Uri buildSecureUri(String url) {
  final uri = Uri.parse(url);
  if (uri.scheme != 'https') {
    throw ArgumentError('Hanya HTTPS yang diizinkan, ditemukan: ${uri.scheme}');
  }
  return uri;
}
```

Untuk `dio`, gunakan interceptor untuk menegakkan kebijakan ini secara terpusat:

```dart
dio.interceptors.add(InterceptorsWrapper(
  onRequest: (options, handler) {
    if (!options.uri.toString().startsWith('https://')) {
      return handler.reject(DioException(
        requestOptions: options,
        error: 'Cleartext HTTP tidak diizinkan',
      ));
    }
    return handler.next(options);
  },
));
```

### 4.2 React Native: Pertahankan NSC, Tambahkan Audit Bundle JS ke CI/CD

```bash
#!/bin/bash
# ci-check-rn-cleartext.sh
unzip -o "$1" assets/index.android.bundle -d /tmp/rn_check
if grep -q 'http://' /tmp/rn_check/assets/index.android.bundle; then
    echo "[PERINGATAN] Ditemukan referensi http:// di bundle JS React Native"
fi
```

### 4.3 Cordova: Hapus Plugin Cleartext Development Sebelum Rilis

```bash
cordova plugin remove cordova-plugin-enable-cleartext-traffic --save
```

Pisahkan konfigurasi lewat build variant/environment sesuai rekomendasi yang sama seperti MASTG-TEST-0235 §4.3 — jangan biarkan plugin/konfigurasi debug ikut ke pipeline rilis produksi.

### 4.4 Verifikasi Ulang Setiap Upgrade Versi Framework

Karena perilaku ini terbukti berubah antar versi engine (§1.3), jadikan verifikasi empiris (§3.4) sebagai **bagian rutin dari proses upgrade** Flutter/React Native/Cordova — bukan hanya dilakukan sekali di awal proyek.

### 4.5 Checklist Remediasi

- [ ] Framework cross-platform yang dipakai sudah diidentifikasi beserta versinya
- [ ] Untuk Flutter: validasi skema HTTPS ditegakkan eksplisit di level kode Dart (interceptor/wrapper), tidak mengandalkan NSC semata
- [ ] Untuk React Native: NSC diterapkan dan diverifikasi benar-benar memblokir upaya cleartext dari `fetch`/`XMLHttpRequest`
- [ ] Untuk Cordova: plugin cleartext development sudah dihapus dari build produksi
- [ ] Verifikasi empiris (§3.4) sudah dilakukan pada versi framework spesifik yang dipakai, bukan berasumsi dari dokumentasi
- [ ] Audit bundle JS/binary Dart terintegrasi ke CI/CD untuk mendeteksi endpoint HTTP baru
- [ ] Proses upgrade versi framework menyertakan re-verifikasi perilaku cleartext
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0237 pada APK release final setelah remediasi dan setiap upgrade framework

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0237: Cross-Platform Framework Configurations Allowing Cleartext Traffic](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0237/)
- [MASTG-TEST-0235: Android App Configurations Allowing Cleartext Traffic](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0235/)
- [MASWE-0026: Network Traffic Not Encrypted](https://mas.owasp.org/MASWE/MASVS-NETWORK/MASWE-0026/)
- [OWASP Mobile Top 10 2024 — M5: Insecure Communication](https://owasp.org/www-project-mobile-top-10/2023-risks/m5-insecure-communication)

### 5.2 Flutter — Riset Utama

- [GitHub flutter/flutter#106678 — Flutter doesn't respect Android's `android:usesCleartextTraffic="false"` settings](https://github.com/flutter/flutter/issues/106678)
- [GitHub flutter/flutter#45956 — Android 9: Cleartext HTTP traffic not permitted in webview_flutter](https://github.com/flutter/flutter/issues/45956)
- [GitHub dart-lang/sdk#40548 — Ban HTTP by default in HttpClient](https://github.com/dart-lang/sdk/issues/40548)
- [Flutter Documentation — Insecure HTTP connections are disabled by default on iOS and Android](https://docs.flutter.dev/release/breaking-changes/network-policy-ios-android)
- [Talsec — OWASP Top 10 For Flutter: M5 Insecure Communication for Flutter and Dart](https://docs.talsec.app/appsec-articles/articles/owasp-top-10-for-flutter-m5-insecure-communication-for-flutter-and-dart)
- [Blutter — Dart snapshot decompiler (GitHub)](https://github.com/worawit/blutter)

### 5.3 React Native — Riset Utama

- [React Native Documentation — Networking](https://reactnative.dev/docs/next/network)
- [GitHub facebook/react-native#22375 — Android 9 can not access bundler via cleartext request](https://github.com/facebook/react-native/issues/22375)
- [GitHub react-native-webview/react-native-webview#3142 — Enable Cleartext traffic inside React Native Webview in Android](https://github.com/react-native-webview/react-native-webview/issues/3142)
- [Apryse Documentation — Does my app need cleartext network traffic support?](https://docs.apryse.com/documentation/android/faq/uses-clear-text-traffic/)
- [react-native-decompiler (GitHub)](https://github.com/numandev1/react-native-decompiler)

### 5.4 Cordova/Ionic — Riset Utama

- [RahulCV/cordova-plugin-enable-cleartext-traffic (GitHub)](https://github.com/RahulCV/cordova-plugin-enable-cleartext-traffic)
- [cordova-plugin-whitelist Documentation](https://cordova.apache.org/docs/en/latest/reference/cordova-plugin-whitelist/)
- [meumobi Dev Blog — Allow cleartext, unencrypted HTTP, with Cordova](https://meumobi.github.io/fix/2020/10/21/android-cleartext-http-traffic-permission.html)
- [Our Code World — How to solve net::ERR_CLEARTEXT_NOT_PERMITTED](https://ourcodeworld.com/articles/read/1651/how-to-solve-cordova-in-app-browser-plugin-error-net-err-cleartext-not-permitted)

### 5.5 Standar dan Dokumentasi Umum

- [Android Developers — Network Security Configuration](https://developer.android.com/training/articles/security-config)
- [Ostorlab Knowledge Base — Attribute usesCleartextTraffic set](https://docs.ostorlab.co/kb/APK_USES_CLEAR_TEXT_TRAFFIC/index.html)
- [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)

### 5.6 Dokumentasi Tools

- [PCAPdroid — Network capture tanpa root](https://github.com/emanuele-f/PCAPdroid)
- [mitmproxy](https://mitmproxy.org/)
- [Frida — Dynamic instrumentation toolkit](https://frida.re/)
- [apkid — APK identifier untuk deteksi framework/compiler](https://github.com/rednaga/APKiD)
- [rabin2 / radare2](https://github.com/radareorg/radare2)

---

*Dokumen ini disusun terutama dari riset independen (dokumentasi resmi Flutter/React Native/Cordova, laporan bug komunitas, dan artikel keamanan pihak ketiga) karena MASTG-TEST-0237 saat ini berstatus **placeholder** dan belum memiliki Overview/Steps/Evaluation resmi. Temuan paling signifikan dalam riset ini adalah bahwa Flutter secara sengaja menghapus dukungan enforcement Network Security Configuration pada level engine (`flutter/flutter#106678`, ditutup sebagai "not planned") — sebuah kesenjangan kritis yang membuat MASTG-TEST-0235 tidak cukup untuk menjamin keamanan jaringan aplikasi berbasis Flutter. Karena sifat placeholder dan lanskap framework yang terus berubah, dokumen ini akan memerlukan pembaruan berkala seiring perkembangan versi Flutter/React Native/Cordova dan publikasi konten resmi MASTG di masa depan.*
