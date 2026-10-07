# MASTG-TEST-0320 WebViews Not Cleaning Up Sensitive Data

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0320 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-PLATFORM |
| **Weakness** | MASWE-0001 |
| **Tipe Pengujian** | Dynamic, Hooks |
| **Teknik terkait** | MASTG-TECH-0005 (Installing Apps), MASTG-TECH-0043 (Method Hooking), MASTG-TECH-0002 (Host-Device Data Transfer), MASTG-TECH-0143 (Monitor File System Operations in WebViews) |
| **Best Practice terkait** | MASTG-BEST-0028 (WebViews Cache Cleanup) |
| **Knowledge terkait** | MASTG-KNOW-0018 (WebViews) |
| **Prasyarat** | `identify-sensitive-data` |
| **Rule resmi** | — (tidak ada; empat rule WebView yang ada — `mastg-android-webview-allow-local-access.yml`, `mastg-android-webview-bridges.yml`, `mastg-android-webview-safebrowsing.yml`, `mastg-android-webview-url-handlers.yml` — menyasar topik WebView lain, bukan cleanup storage, konsisten dengan sifat dinamis test ini) |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Kutipan overview resmi MASTG:

> *"This test verifies whether the app cleans up sensitive data used by WebViews. Apps can enable several specific storage areas in their WebViews and not clean them up properly, leading to sensitive data being stored on the device longer than necessary."*

Test ini menyasar risiko **retensi data berlebih** (data retention) — bukan soal apakah WebView *menyimpan* data (itu perilaku normal dan diperlukan untuk performa), melainkan apakah aplikasi **membersihkan** data tersebut setelah tidak lagi diperlukan (mis. setelah logout, atau setelah WebView ditutup). Berbeda dari banyak test lain dalam seri riset ini yang bersifat statis-dulu-dinamis-kedua, test ini **murni dinamis sejak awal** — tidak ada rule semgrep resmi untuk test ini, dan secara logis memang sulit dibuat secara statis karena menuntut observasi **isi filesystem sesungguhnya** setelah serangkaian interaksi aplikasi.

### 1.2 Empat API Enablement dan Cleanup yang Harus Dipasangkan

Overview resmi memberikan daftar pasangan API "enable" vs "cleanup" yang eksplisit — ini kerangka inti evaluasi test:

| Storage Area | API yang Mengaktifkan | API Cleanup yang Diharapkan |
|---|---|---|
| **HTTP Cache** | `WebSettings.setAppCacheEnabled()` *(deprecated/removed API 33)* atau `setCacheMode()` ≠ `LOAD_NO_CACHE` | `WebView.clearCache(includeDiskFiles = true)` |
| **DOM Storage** (localStorage/sessionStorage) | `WebSettings.setDomStorageEnabled(true)` | `WebStorage.deleteAllData()` |
| **WebSQL Database** *(deprecated API 35)* | `WebSettings.setDatabaseEnabled(true)` | `WebStorage.deleteAllData()` |
| **Cookies** | `CookieManager.setAcceptCookie()` — **default `true`**, harus diset `false` secara eksplisit untuk dinonaktifkan | `CookieManager.removeAllCookies(callback)` |

Catatan penting: untuk Cookies, **default aplikasi adalah menerima cookie** — artinya bila developer tidak menyentuh setting ini sama sekali, perilaku default tetap mengaktifkan penyimpanan cookie, menjadikan cleanup eksplisit sebuah kewajiban tersembunyi, bukan opsional.

### 1.3 Nuansa Kritis: WebView Bisa Membuat File Meski Developer Tidak Memanggil API Secara Langsung

Ini poin metodologis paling penting dari seluruh test ini:

> *"Regardless of whether the app uses these APIs directly, WebViews may use them internally when rendering content (e.g., JavaScript code using localStorage). So tracing calls to APIs such as open, openat, opendir, unlinkat, etc., can help identify file operations in the WebView storage directory."*

Artinya **developer aplikasi bisa jadi sama sekali tidak pernah memanggil `setDomStorageEnabled()` secara eksplisit**, namun bila halaman web yang dimuat di WebView memiliki JavaScript yang memanggil `localStorage.setItem(...)`, data tetap tersimpan di disk — karena DOM storage **aktif secara default** di semua versi WebView yang didukung (dikonfirmasi MASTG-KNOW-0018: *"DOM storage is enabled by default on all supported WebView versions"*). Ini berarti audit kode semata (grep untuk pemanggilan API tertentu) **tidak cukup** — penguji harus melacak operasi filesystem level rendah (`open`, `openat`, `unlinkat`) untuk menangkap aktivitas yang dipicu JavaScript pihak ketiga di dalam halaman yang dimuat, bukan hanya kode Kotlin/Java aplikasi.

### 1.4 Mengapa Tidak Ada API Resmi untuk "Hapus Semuanya Sekaligus"

MASTG-KNOW-0018 menegaskan fakta arsitektural yang sangat relevan untuk ekspektasi evaluasi:

> *"Android does not provide a dedicated API to delete the Chromium profile under app_webview. Apps must not attempt to delete this directory directly."*

Developer **tidak bisa** sekadar memanggil satu API "bersihkan semua WebView storage" — mereka harus memanggil **kombinasi beberapa API berbeda** (`clearCache`, `deleteAllData`, `removeAllCookies`) secara manual, dan beberapa jenis storage modern **sama sekali tidak bisa dibersihkan** lewat API publik:

> *"IndexedDB and OPFS are managed internally by Chromium and are not covered by the WebStorage API. They cannot be deleted with Java file APIs... Clearing requires deleting the entire WebView profile."*
>
> *"SQLite Wasm databases live inside OPFS... Clearing requires deleting the entire WebView profile."*

Ini adalah **celah arsitektural permanen** — bila aplikasi memuat halaman web yang menggunakan IndexedDB atau SQLite Wasm (OPFS) untuk menyimpan data sensitif, **tidak ada cara granular** untuk membersihkannya tanpa menghapus *seluruh* profil WebView (`ActivityManager.clearApplicationUserData()`), yang juga akan menghapus data non-sensitif aplikasi lain yang mungkin ingin dipertahankan. Developer dihadapkan pada trade-off nyata antara privasi (hapus semua) dan pengalaman pengguna (pertahankan data).

### 1.5 Risiko Nyata: Tidak Ada Garansi Cleanup Method Selalu Terpanggil

Catatan resmi MASTG-BEST-0028 mengungkap kelemahan fundamental dari pendekatan "panggil clear saat onDestroy":

> *"The lack of a guarantee that the clear method will always be called, particularly if the app process is killed abruptly. In this case, evaluation of prior cache clearing and active clearing would be required, such as at the next app start."*

Pada Android, proses aplikasi bisa di-kill paksa oleh sistem (low memory killer) tanpa memanggil lifecycle callback (`onDestroy`) secara penuh — bila logika cleanup hanya ditempatkan di `onDestroy()`, skenario ini akan **selalu meninggalkan data residual**. Ini menjelaskan mengapa rekomendasi yang baik (§4) selalu menyertakan **cleanup proaktif saat app start berikutnya** sebagai lapisan pertahanan kedua, bukan hanya mengandalkan cleanup reaktif saat keluar.

### 1.6 Kasus Nyata: Session Cookie Tersimpan Mentah di SQLite WebView (Apache Cordova)

Kasus nyata yang terdokumentasi di tracker resmi **Apache Cordova** (CB-9641) menunjukkan persisnya risiko yang disasar test ini:

> *"A Cordova application using a Java web service with session cookie authentication discovered through security audit that the cookie's value was stored within the SQLite database at `/data/data/com.my.app/app_webview/Cookies`, which was easily viewable via SQLiteManager on a rooted phone."*

Kasus ini membuktikan dua hal sekaligus: (1) cookie sesi otentikasi memang **benar-benar tersimpan dalam bentuk plaintext** yang dapat dibaca langsung lewat SQLite manager biasa pada device rooted — tidak perlu exploit canggih; (2) riset independen (Securing.pl) menegaskan bahwa bahkan saat `setAllowFileAccess(false)` diaktifkan — yang developer mungkin salah kira cukup untuk mengamankan WebView — **direktori `app_webview` tetap bisa diakses WebView itu sendiri** untuk menyimpan LocalStorage, karena setting tersebut hanya mengontrol akses WebView ke `file://` URL eksternal, bukan storage internalnya sendiri.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core, Sesuai MASTG-TECH)

| Tool | Fungsi |
|---|---|
| **Frida** | Hooking API enable/cleanup WebView (MASTG-TECH-0043) |
| **ADB** | Instalasi app, pull direktori `app_webview` (MASTG-TECH-0002/0005) |

### 2.2 Tools Alternatif & Pendukung untuk Tracing Filesystem

| Tool | Fungsi |
|---|---|
| **strace** | Memantau system call (`open`, `openat`, `unlinkat`) level kernel langsung terhadap proses (MASTG-TECH-0032) |
| **lsof** | Menampilkan file yang sedang dibuka proses (`lsof -p <pid> | grep app_webview`, MASTG-TECH-0027) |
| **fsmon** (NowSecure) | Tool filesystem monitor cross-platform (Linux/Android/iOS/macOS) — alternatif strace yang lebih ringan untuk tracing event I/O spesifik direktori |
| **Android `FileObserver` / inotify** | Mekanisme kernel-level untuk memantau event filesystem (read/write/move/delete) — basis dari banyak tool monitoring di atas |
| **Objection** | Eksplorasi dan download direktori `app_webview` tanpa perlu root penuh / app debuggable |
| **SQLiteManager / DB Browser for SQLite** | Membuka langsung file `Cookies`/WebSQL yang ditemukan di `app_webview` untuk verifikasi isi data sensitif (sesuai kasus nyata Cordova CB-9641) |

### 2.3 Prasyarat Lingkungan

- **Device rooted / emulator** untuk akses penuh ke `/data/data/<app_package>/app_webview/`.
- **Definisi data sensitif disepakati** di awal (prasyarat `identify-sensitive-data`), dan **daftar data yang dimasukkan selama pengujian dicatat** agar bisa dicocokkan di akhir.
- Memahami bahwa beberapa jenis storage (IndexedDB, OPFS, SQLite Wasm) tidak muncul sebagai file biasa yang mudah dibaca — perlu penanganan khusus saat pull dan inspeksi.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0005** untuk instalasi aplikasi.
2. Gunakan **MASTG-TECH-0043** untuk hook API yang relevan.
3. Exercise aplikasi secara ekstensif, masukkan data sensitif di mana pun memungkinkan.
4. Tutup aplikasi.
5. Gunakan **MASTG-TECH-0002** untuk pull direktori `/data/data/<app_package>/app_webview/`, atau cari langsung data sensitif di dalamnya.

### 3.2 Metode A — Frida: Hook API Enable & Cleanup Sekaligus

```javascript
Java.perform(function () {
    var WebSettings = Java.use("android.webkit.WebSettings");
    WebSettings.setDomStorageEnabled.implementation = function (flag) {
        console.log("[setDomStorageEnabled] " + flag);
        return this.setDomStorageEnabled(flag);
    };
    WebSettings.setCacheMode.implementation = function (mode) {
        console.log("[setCacheMode] " + mode);
        return this.setCacheMode(mode);
    };

    var WebView = Java.use("android.webkit.WebView");
    WebView.clearCache.implementation = function (includeDiskFiles) {
        console.log("[clearCache] includeDiskFiles=" + includeDiskFiles);
        return this.clearCache(includeDiskFiles);
    };

    var WebStorage = Java.use("android.webkit.WebStorage");
    WebStorage.deleteAllData.implementation = function () {
        console.log("[WebStorage.deleteAllData] called");
        return this.deleteAllData();
    };

    var CookieManager = Java.use("android.webkit.CookieManager");
    CookieManager.removeAllCookies.implementation = function (callback) {
        console.log("[CookieManager.removeAllCookies] called");
        return this.removeAllCookies(callback);
    };
});
```

### 3.3 Metode B — strace: Tracing Operasi Filesystem Langsung (Sesuai MASTG-TECH-0143)

```bash
# Dapatkan PID proses aplikasi target
adb shell pidof com.example.targetapp

# Trace system call terkait file operations khusus direktori app_webview
adb shell strace -f -e trace=open,openat,opendir,unlinkat -p <PID> 2>&1 | grep app_webview
```

Pendekatan ini menangkap operasi file **yang dipicu WebView secara internal** (termasuk oleh JavaScript `localStorage`), bukan hanya pemanggilan API Java eksplisit — menutup celah yang dijelaskan di §1.3.

### 3.4 Metode C — fsmon sebagai Alternatif strace yang Lebih Ringan

```bash
adb push fsmon /data/local/tmp/
adb shell /data/local/tmp/fsmon -p <PID> /data/data/com.example.targetapp/app_webview
```

`fsmon` (dikembangkan NowSecure) memberikan output event filesystem yang lebih mudah dibaca dibanding raw `strace`, berguna untuk sesi monitoring jangka panjang selama exercise aplikasi berlangsung.

### 3.5 Metode D — lsof untuk Snapshot File Terbuka

```bash
adb shell "lsof -p $(adb shell pidof com.example.targetapp) | grep app_webview"
```

Berguna sebagai pemeriksaan cepat di titik waktu tertentu (mis. tepat sebelum app ditutup) untuk melihat file mana yang masih terbuka aktif oleh proses WebView.

### 3.6 Metode E — Pull dan Inspeksi Manual dengan Objection/SQLite Browser

```bash
objection -g com.example.targetapp explore
# di dalam REPL:
filesystem download app_webview webview_dump --folder
```

```bash
sqlite3 webview_dump/Default/Cookies "SELECT host_key, name, value FROM cookies;"
sqlite3 webview_dump/Default/Local\ Storage/leveldb "..." # periksa isi LevelDB localStorage
```

Mencocokkan temuan ini langsung dengan kasus nyata CB-9641 (§1.6) — cookie sesi yang tersimpan plaintext dapat langsung dibaca lewat query SQL biasa.

### 3.7 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Kapan dipakai |
|---|---|---|
| **A** | Frida hooking | Memastikan API mana yang benar-benar dipanggil (atau tidak dipanggil) oleh kode aplikasi |
| **B** | strace | Menangkap operasi file yang dipicu WebView secara internal/JavaScript, termasuk yang tidak terlihat dari hooking Java |
| **C** | fsmon | Monitoring jangka panjang yang lebih mudah dibaca dibanding strace mentah |
| **D** | lsof | Snapshot cepat file yang sedang terbuka |
| **E** | Objection + SQLite browser | Verifikasi isi data sensitif sesungguhnya di file yang ditemukan |

**Kombinasi minimum yang aku rekomendasikan:** **A (hooking API) + B/C (tracing filesystem, menutup celah §1.3) → E (verifikasi isi data)**, sesuai urutan langkah resmi (install → hook → exercise → close → pull & cari).

---

### 3.8 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Evaluation:** *"The test case fails if the app still has sensitive data on the `/data/data/<app_package>/app_webview/` directory after the app is closed. This could be due to the app not calling the relevant cleanup APIs after using the WebView."*

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | Data sensitif yang dimasukkan selama exercise (§1.3, sesuai definisi dari prasyarat `identify-sensitive-data`) **masih ditemukan** di dalam `/data/data/<app_package>/app_webview/` setelah aplikasi ditutup |
| F2 | API enable storage dipanggil/aktif secara default, namun **tidak ada** pemanggilan API cleanup yang berpasangan terdeteksi dari hooking (Metode A) |

**Contoh bukti (ilustratif, berdasarkan pola kasus nyata CB-9641):**

```
$ sqlite3 webview_dump/Default/Cookies "SELECT host_key, name, value FROM cookies;"
api.example.com|session_token|eyJhbGciOiJIUzI1NiJ9.eyJ1c2VySWQiOiI0MjIxIn0...
```

Interpretasi: token sesi otentikasi pengguna (yang sudah logout sebelum app ditutup) **masih tersimpan plaintext** di database cookie WebView. **FAIL**.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Setelah exercise ekstensif dan app ditutup, **tidak ditemukan** data sensitif apa pun di direktori `app_webview` |
| P2 | API cleanup yang berpasangan (`clearCache`, `deleteAllData`, `removeAllCookies`) terbukti dipanggil (via hooking) pada titik yang tepat (logout, `onDestroy`, atau sebelum app start berikutnya sebagai pertahanan kedua sesuai §1.5) |
| P3 | Untuk storage yang tidak bisa dibersihkan granular (IndexedDB/OPFS/SQLite Wasm), aplikasi **tidak menyimpan data sensitif** di storage tersebut sama sekali (mitigasi arsitektural, bukan cleanup) |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Ini test yang eksplisit diakui MASTG sendiri sebagai sulit dievaluasi dengan pasti** — catatan resmi menyatakan: *"It can be challenging to determine whether the right cleanup APIs were called for the enabled storage areas."* Penguji harus transparan tentang tingkat keyakinan temuan, bukan mengklaim kepastian absolut.

2. **"Tidak ditemukan data sensitif" bisa jadi false negative bila exercise tidak menyeluruh** — bila tidak semua alur berhasil dipicu selama sesi pengujian (mis. tidak sempat menguji skenario logout), kesimpulan PASS harus diberi catatan terbatas pada alur yang teruji.

3. **IndexedDB/OPFS/SQLite Wasm adalah celah arsitektural, bukan kesalahan developer** — tidak adanya API cleanup granular untuk storage ini (§1.4) berarti **satu-satunya mitigasi nyata** adalah tidak menaruh data sensitif di sana sejak awal; temuan data sensitif di storage jenis ini harus dicatat sebagai **risiko desain**, bukan sekadar "lupa panggil API cleanup".

4. **Proses yang di-kill paksa adalah skenario uji yang sering terlewat** — pertimbangkan menambahkan skenario uji **force-stop** (`adb shell am force-stop <package>`) selain exit normal, untuk memverifikasi apakah cleanup tetap terjadi pada kondisi abnormal (§1.5).

5. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | Kredensial/token otentikasi tersimpan plaintext dan dapat diekstrak lewat akses filesystem biasa (device rooted) | **Tinggi** |
   | Data sensitif non-kredensial (mis. histori pencarian) tersimpan tanpa cleanup | **Sedang** |
   | Data residual hanya muncul pada skenario force-kill abnormal, tidak pada flow normal | **Sedang-Rendah**, tapi tetap dicatat karena kondisi tersebut umum terjadi di perangkat nyata (low memory killer) |

6. **Dokumentasikan:** API enable yang aktif, API cleanup yang terpanggil (atau tidak), hasil pencarian data sensitif di `app_webview` dengan path file spesifik, dan skenario exercise yang berhasil/tidak berhasil dipicu.

---

## 4. Rekomendasi Perbaikan

### 4.1 Pasangkan Setiap API Enable dengan Cleanup yang Sesuai

```kotlin
override fun onDestroy() {
    webView.clearCache(true)
    WebStorage.getInstance().deleteAllData()
    CookieManager.getInstance().removeAllCookies(null)
    CookieManager.getInstance().flush()
    super.onDestroy()
}
```

### 4.2 Lapisan Pertahanan Kedua: Cleanup Proaktif Saat Startup

Mengingat `onDestroy()` tidak terjamin selalu terpanggil (§1.5), tambahkan pengecekan/cleanup di titik app start berikutnya sebagai jaring pengaman untuk kasus proses yang di-kill paksa.

### 4.3 Preferensi Server-Side Cache Prevention (Sesuai MASTG-BEST-0028)

```http
Cache-Control: no-store, no-cache
```

Mengirim header ini dari API/endpoint yang memuat data sensitif ke WebView mencegah caching sejak awal, menghindari keharusan membersihkan cache secara manual nanti.

### 4.4 Hindari Menaruh Data Sensitif di IndexedDB/OPFS Bila Tidak Bisa Dibersihkan Granular

Untuk storage tanpa API cleanup granular, evaluasi apakah data sensitif benar-benar perlu disimpan di sana — bila harus, pertimbangkan `ActivityManager.clearApplicationUserData()` saat logout meski menghapus profil WebView secara keseluruhan.

### 4.5 Pertimbangkan Alternatif WebView

Sesuai MASTG-KNOW-0018, **Trusted Web Activities** dan **Custom Tabs** memindahkan eksekusi JavaScript dan penyimpanan storage ke konteks browser pengguna (mengikuti model keamanan dan siklus update browser), melepaskan aplikasi dari kewajiban cleanup storage WebView sepenuhnya — relevan dipertimbangkan bila aplikasi tidak butuh WebView tertanam secara ketat.

### 4.6 Checklist Remediasi

- [ ] Setiap storage area yang diaktifkan (cache, DOM storage, WebSQL, cookies) memiliki cleanup yang berpasangan
- [ ] Cleanup dipanggil di titik logout DAN sebagai pertahanan kedua saat app start
- [ ] Header `Cache-Control` server-side digunakan untuk konten sensitif, bukan hanya mengandalkan cleanup klien
- [ ] Tidak ada data sensitif disimpan di IndexedDB/OPFS/SQLite Wasm tanpa mitigasi
- [ ] Diuji ulang dengan skenario force-stop, tidak hanya exit normal

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0320 (source, tests-beta)](https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0320.md)
- [MASTG-KNOW-0018: WebViews](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0018/)
- [MASTG-BEST-0028: WebViews Cache Cleanup](https://github.com/OWASP/mastg/blob/master/best-practices/MASTG-BEST-0028.md)
- [MASTG-TECH-0143: Monitor File System Operations in WebViews](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0143/)
- [MASTG-TECH-0002: Host-Device Data Transfer](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0002/)

### 5.2 Kasus Nyata dan Riset

- [Apache Cordova JIRA CB-9641: Android WebView Writing Session Cookies to SQLite Database](https://issues.apache.org/jira/browse/CB-9641)
- [Securing.pl: WebView Security Issues in Android Applications](https://www.securing.pl/en/webview-security-issues-in-android-applications/)
- [SecureLayer7: Android WebView Vulnerabilities: Risks and Hardening](https://blog.securelayer7.net/android-webview-vulnerabilities/)
- [NIST Mobile Threat Catalogue — APP-8](https://pages.nist.gov/mobile-threat-catalogue/application-threats/APP-8.html)
- [CMU SEI — DRD22: Do Not Cache Sensitive Information](https://wiki.sei.cmu.edu/confluence/spaces/android/pages/87150623/DRD22.+Do+not+cache+sensitive+information)

### 5.3 Dokumentasi Tools

- [fsmon — Filesystem Monitor Tool (NowSecure)](https://github.com/nowsecure/fsmon)
- [Android FileObserver Documentation](https://developer.android.com/reference/android/os/FileObserver)
- [Objection — Runtime Mobile Exploration](https://github.com/sensepost/objection)
- [strace man page](https://man7.org/linux/man-pages/man1/strace.1.html)

---

*Dokumen ini disusun berdasarkan konten resmi OWASP MASTG (`tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0320.md`, `MASTG-KNOW-0018`, `MASTG-BEST-0028`), kasus nyata kebocoran session cookie pada tracker resmi Apache Cordova (CB-9641), serta riset industri (Securing.pl, SecureLayer7) tentang kesalahpahaman umum developer bahwa `setAllowFileAccess(false)` cukup untuk mengamankan direktori `app_webview` — padahal setting tersebut tidak mencegah WebView menyimpan LocalStorage/cookie-nya sendiri. Nuansa metodologis terpenting: celah arsitektural pada IndexedDB/OPFS/SQLite Wasm (tidak ada API cleanup granular) menjadikan sebagian temuan FAIL dari test ini sebagai risiko desain yang hanya bisa dimitigasi di tingkat keputusan arsitektur, bukan sekadar "developer lupa panggil API".*
