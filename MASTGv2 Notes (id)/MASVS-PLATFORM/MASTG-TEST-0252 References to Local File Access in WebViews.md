# MASTG-TEST-0252 References to Local File Access in WebViews

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0252 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-PLATFORM (MASVS-PLATFORM-2) |
| **Weakness** | MASWE-0034 — *WebViews Allow Access to Local Resources with Untrusted Content* |
| **API yang disorot** | `WebView`, `WebSettings`, `getSettings`, `setAllowFileAccess`, `setAllowFileAccessFromFileURLs`, `setAllowUniversalAccessFromFileURLs` |
| **Tipe Pengujian** | Static, Code |
| **Profile** | L1, L2 |
| **Knowledge** | MASTG-KNOW-0018 (WebViews) |
| **Best Practice** | MASTG-BEST-0010 (Use Up-to-Date minSdkVersion), MASTG-BEST-0011 (Securely Load File Content in WebView), MASTG-BEST-0012 (Disable JavaScript in WebViews) |
| **Teknik terkait** | MASTG-TECH-0013, MASTG-TECH-0014, MASTG-TECH-0117, MASTG-TECH-0150 |
| **Test terkait** | **MASTG-TEST-0250** (sibling — content provider access, bukan local file access; berbagi API `setAllowUniversalAccessFromFileURLs`) |
| **Demo terkait** | — (tidak ada) |
| **Rule resmi** | `mastg-android-webview-allow-local-access.yml` — rule yang sama seperti dipakai MASTG-TEST-0250, mencakup keenam API sekaligus (lihat dokumen MASTG-TEST-0250 §3.2 untuk analisis lengkap celah rule ini) |
| **CWE terkait** | CWE-200, CWE-668 |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian dan Perbedaan dengan MASTG-TEST-0250

Test ini adalah **sibling konseptual** dari MASTG-TEST-0250 — keduanya menyasar kombinasi pengaturan `WebSettings` yang berbahaya dan berbagi API `setAllowUniversalAccessFromFileURLs`, namun **objek yang diekspos berbeda**:

| | MASTG-TEST-0250 | MASTG-TEST-0252 *(dokumen ini)* |
|---|---|---|
| **Objek yang terekspos** | **Content provider** (skema `content://`) | **File sistem lokal** (skema `file://`) — internal storage, external storage |
| **API kunci pembeda** | `setAllowContentAccess` | `setAllowFileAccess`, `setAllowFileAccessFromFileURLs` |
| **Ketergantungan `minSdkVersion`** | Tidak ada — `setAllowContentAccess` selalu default `true` di semua versi | **Sangat bergantung** — default berubah berdasarkan API level (lihat §1.2) |

### 1.2 Perbedaan Krusial: Default yang Bergantung pada `minSdkVersion` (Berbeda dari MASTG-TEST-0250)

Berbeda dari `setAllowContentAccess` yang dibahas di dokumen MASTG-TEST-0250 (selalu default `true` tanpa pengecualian), ketiga API pada test ini memiliki default yang **berubah seiring evolusi platform Android**, sesuai tabel resmi di MASTG-KNOW-0018:

| API | Default `True` | Default `False` |
|---|---|---|
| `setAllowFileAccess` | ≤ API 29 (Android 10 ke bawah) | ≥ API 30 (Android 11+) |
| `setAllowFileAccessFromFileURLs` | ≤ API 15 (Android 4.0.3 ke bawah) | ≥ API 16 (Android 4.1+) |
| `setAllowUniversalAccessFromFileURLs` | ≤ API 15 | ≥ API 16 |

Ketiganya juga berstatus **deprecated sejak Android 10/11**, namun overview resmi menegaskan mengapa ini tetap relevan diuji:

> *"Even though these methods have secure defaults and are deprecated in Android 10 (API level 29) and later, they can still be explicitly set to `true` or their insecure defaults may be used in apps that run on older versions of Android (due to their `minSdkVersion`)."*

Ini konsekuensi langsung dari nuansa **`minSdkVersion` vs OS aktual perangkat** yang sudah dibahas mendalam di dokumen **MASTG-TEST-0245** — sebuah aplikasi dengan `targetSdkVersion` modern tetap dapat berjalan pada device Android lawas (di bawah API 30/16) bila `minSdkVersion`-nya diset rendah, dan pada device tersebut, nilai default insecure API ini **tetap berlaku** apa pun `targetSdkVersion` yang dideklarasikan. Inilah mengapa **MASTG-TECH-0150 dipakai secara eksplisit untuk mengekstrak `minSdkVersion`** sebagai langkah resmi wajib (§3.1 langkah 4) — evaluasi kondisi FAIL test ini **tidak bisa dilakukan tanpa mengetahui nilai ini terlebih dahulu**.

### 1.3 Mengapa "Ketiadaan Referensi" Justru Menarik — Kebalikan dari Intuisi Umum

Ini poin metodologis paling penting dan unik dari test ini dibanding kebanyakan test statis lain dalam seri riset ini. Observation resmi menyatakan secara eksplisit:

> *"Note that in this case, **the lack of references to the `setAllow*` methods is especially interesting** and must be captured, because it could mean that the app is using the default values, which in some scenarios are insecure."*

Pada kebanyakan test lain di seri ini, "tidak ditemukan pemanggilan API" biasanya diinterpretasikan sebagai indikasi **tidak ada masalah** (tidak ada fitur berisiko yang dipakai). Namun untuk test ini, ketiadaan referensi **justru bisa menjadi kondisi FAIL** — karena, dikombinasikan dengan `minSdkVersion` rendah (§1.2), WebView akan **diam-diam mewarisi default insecure** tanpa jejak kode apa pun yang bisa langsung "ditunjuk" sebagai penyebab. Inilah mengapa MASTG secara eksplisit merekomendasikan: *"it's highly recommended to try to identify **every** WebView instance in the app"* — pendekatan pasif "cari pemanggilan API yang mencurigakan" tidak cukup; penguji harus **menginventarisasi seluruh instance WebView** terlebih dahulu, baru kemudian memeriksa (untuk setiap instance) apakah pengaturan terkait dipanggil eksplisit ATAU dibiarkan default.

### 1.4 Tiga Kondisi FAIL yang Bergantung pada `minSdkVersion` (Lebih Kompleks dari MASTG-TEST-0250)

Klausul Evaluation resmi test ini secara struktural lebih rumit dibanding MASTG-TEST-0250 karena setiap kondisi punya **cabang bersyarat** berdasarkan `minSdkVersion`:

> *"The test case fails if all of the following applies: `setJavaScriptEnabled` is explicitly set to `true`. `setAllowFileAccess` is explicitly set to `true` (**or not used at all when `minSdkVersion` < 30**, inheriting the default value, `true`). Either `setAllowFileAccessFromFileURLs` or `setAllowUniversalAccessFromFileURLs` is explicitly set to `true` (**or not used at all when `minSdkVersion` < 16**, inheriting the default value, `true`)."*

Ini berarti **hasil evaluasi yang identik secara kode** (mis. tidak ada pemanggilan `setAllowFileAccess` sama sekali) dapat menghasilkan kesimpulan **PASS atau FAIL yang berbeda**, murni tergantung nilai `minSdkVersion` aplikasi:

| `minSdkVersion` | `setAllowFileAccess` tidak dipanggil sama sekali → |
|---|---|
| < 30 (di bawah Android 11) | Default `true` berlaku → **berkontribusi pada kondisi FAIL** |
| ≥ 30 (Android 11+) | Default `false` berlaku → **kondisi ini terpenuhi untuk PASS** |

### 1.5 Nuansa Ketiga (Terpenting): Kebocoran Data Bisa Terjadi Meski Pembacaan Diblokir CORS ("Blind Exfiltration")

Ini bagian paling teknis dan paling sering disalahpahami. Overview resmi memberi peringatan eksplisit soal `setAllowUniversalAccessFromFileURLs`:

> *"The JavaScript **can always send data to any origin** (e.g., via `POST`), regardless of this setting; this setting only affects **reading** data (e.g., the code wouldn't get a response to a `POST` request, but the data would still be sent)."*

Ini nuansa kritis: kebijakan same-origin (yang dilonggarkan setting ini) pada dasarnya membatasi kemampuan JavaScript **membaca respons** dari origin lain — tapi **tidak pernah membatasi kemampuan mengirim data**. Konsekuensinya, penyerang **tidak butuh** kemampuan membaca respons untuk berhasil mengeksfiltrasi data — cukup membaca file lokal (lewat `XMLHttpRequest`/`fetch` ke `file://`) dan mengirim isinya (lewat `POST` biasa) ke server yang dikendalikan penyerang, **tanpa peduli apakah response dari server tersebut bisa dibaca kembali atau tidak**.

Overview resmi memberi bukti diagnostik konkret yang mengonfirmasi fenomena ini — skenario di mana **kedua** setting (`setAllowFileAccessFromFileURLs` dan `setAllowUniversalAccessFromFileURLs`) diset `false` (idealnya seharusnya sepenuhnya aman):

```bash
[INFO:CONSOLE(0)] "Access to XMLHttpRequest at 'file:///data/data/org.owasp.mastestapp/files/api-key.txt' from origin 'null' has been blocked by CORS policy..."
[INFO:CONSOLE(31)] "File content sent successfully.", source: file:/// (31)
```

Perhatikan **kedua baris log muncul bersamaan** — baris pertama menunjukkan CORS **memblokir pembacaan** file (`XMLHttpRequest` gagal), namun baris kedua (dicetak oleh kode JavaScript penyerang) menunjukkan **"berhasil terkirim"**. Namun overview resmi juga mengonfirmasi bahwa pada skenario khusus ini (kedua flag `false`), payload sesungguhnya **tidak berhasil dibaca** untuk dikirim (karena `XMLHttpRequest` untuk membaca file gagal lebih dulu):

```bash
[*] Received POST data from 127.0.0.1:
Error reading file: 0
```

Ini justru mengonfirmasi bahwa **kedua flag `false` sudah cukup untuk mencegah pembacaan file yang gagal diteruskan** — tapi baris "File content sent successfully" pada log JS tetap menjadi **pengingat penting**: skema serangan yang **berhasil** membaca file (dengan minimal salah satu dari kedua flag `true`) akan menghasilkan pola log yang serupa **tanpa** baris CORS block, dan **data akan benar-benar terkirim** meski aplikasi tidak pernah bisa mengonfirmasi keberhasilan lewat pembacaan respons. Penguji harus memahami bahwa **"gagal membaca respons" bukan indikator keamanan** — satu-satunya indikator andal adalah **apakah pembacaan file sumber berhasil dilakukan sejak awal**.

### 1.6 Interaksi antara `setAllowFileAccessFromFileURLs` dan `setAllowUniversalAccessFromFileURLs`

Overview resmi memberi catatan penting tentang hierarki kedua flag ini:

> **Note 2:** *"As indicated in the Android docs, the value of `setAllowFileAccessFromFileURLs` is ignored if `allowUniversalAccessFromFileURLs=true`."*

`setAllowUniversalAccessFromFileURLs` **mencakup sepenuhnya** cakupan `setAllowFileAccessFromFileURLs` (mengizinkan akses lintas origin ke *manapun*, bukan hanya sesama `file://`) — sehingga bila yang pertama `true`, nilai yang kedua menjadi tidak relevan untuk diperiksa lebih lanjut. Ini konsisten dengan mengapa klausul Evaluation resmi menggabungkan keduanya dengan kata **"Either... or"** (§1.4) — cukup **salah satu** dari keduanya bernilai `true` untuk memenuhi kondisi ketiga.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **jadx** | Dekompilasi DEX → Java untuk pencarian pola `WebSettings` |
| **grep / ripgrep** | Pencarian pola API dan verifikasi nilai argumen |
| **semgrep** | Menjalankan rule resmi (sama seperti MASTG-TEST-0250) sebagai baseline |
| **aapt2 / jadx --no-src** | Ekstraksi `minSdkVersion` — **wajib** karena evaluasi bergantung penuh padanya (§1.4) |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **CodeQL** | Menelusuri kombinasi kondisi FAIL pada instance WebView yang sama, sekaligus mengorelasikan dengan nilai `minSdkVersion` proyek |
| **jadx-gui "Find Usage"** | Menginventarisasi **seluruh** instance WebView di aplikasi (§1.3) — termasuk yang tidak memanggil `setAllow*` sama sekali, sesuai rekomendasi eksplisit MASTG untuk mengidentifikasi setiap instance |
| **MobSF** | Kadang menandai kombinasi pengaturan WebView berisiko |
| **Frida** | Hooking untuk konfirmasi nilai efektif runtime (termasuk yang berasal dari default, lihat dokumen MASTG-TEST-0251 §1.3 untuk penjelasan mengapa ambiguitas eksplisit-vs-default melebur di runtime) |

### 2.3 Prasyarat Lingkungan

- **Tidak butuh device/root** untuk analisis statis inti.
- **Ekstraksi `minSdkVersion` adalah langkah wajib pertama**, bukan opsional — tanpa nilai ini, kondisi FAIL/PASS untuk API kedua dan ketiga tidak dapat dievaluasi sama sekali.
- **Inventarisasi menyeluruh setiap instance WebView** sesuai rekomendasi eksplisit resmi (§1.3) — jangan hanya mencari pemanggilan `setAllow*` secara pasif.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0013** untuk reverse engineer aplikasi.
2. Gunakan **MASTG-TECH-0014** untuk mencari API yang relevan.
3. Gunakan **MASTG-TECH-0117** untuk memperoleh `AndroidManifest.xml`.
4. Gunakan **MASTG-TECH-0150** untuk memperoleh `minSdkVersion` dari manifest.

### 3.2 Metode A — Inventarisasi Menyeluruh Instance WebView + Ekstraksi `minSdkVersion` *(metode utama)*

```bash
jadx -d ./decompiled ./target-app.apk
jadx --no-src -d ./out ./target-app.apk

# 1. WAJIB pertama: ekstrak minSdkVersion
MINSDK=$(grep -oP 'minSdkVersion="\K[0-9]+' ./out/resources/AndroidManifest.xml)
echo "minSdkVersion: $MINSDK"

# 2. Inventarisasi SELURUH instance WebView (bukan hanya yang memanggil setAllow*)
rg -l 'new WebView\(|findViewById.*WebView\)|extends WebView' ./decompiled/sources/ > webview_instances.txt
cat webview_instances.txt

# 3. Untuk SETIAP file yang berisi instance WebView, periksa ketiga pengaturan
for f in $(cat webview_instances.txt); do
    echo "=== $f ==="
    grep -n "setJavaScriptEnabled\|setAllowFileAccess\b\|setAllowFileAccessFromFileURLs\|setAllowUniversalAccessFromFileURLs" "$f" || echo "  [!] TIDAK ADA referensi setAllow* ditemukan -> periksa default berdasarkan minSdkVersion=$MINSDK"
done
```

### 3.3 Metode B — Skrip Evaluasi Otomatis yang Memperhitungkan `minSdkVersion`

```python
def evaluate_test_0252(min_sdk, js_enabled, file_access, file_access_from_file_urls, universal_access):
    """
    Mengimplementasikan klausul Evaluation resmi MASTG-TEST-0252 secara terprogram.
    Setiap parameter: True / False / None (None = tidak dipanggil sama sekali di kode)
    """
    # Kondisi 1: JavaScript
    cond1 = (js_enabled is True)

    # Kondisi 2: setAllowFileAccess
    if file_access is True:
        cond2 = True
    elif file_access is None and min_sdk < 30:
        cond2 = True  # mewarisi default true
    else:
        cond2 = False

    # Kondisi 3: salah satu dari setAllowFileAccessFromFileURLs / setAllowUniversalAccessFromFileURLs
    def resolve(value, threshold):
        if value is True:
            return True
        if value is None and min_sdk < threshold:
            return True
        return False

    cond3 = resolve(file_access_from_file_urls, 16) or resolve(universal_access, 16)

    fail = cond1 and cond2 and cond3
    return {"FAIL": fail, "cond1_js": cond1, "cond2_file_access": cond2, "cond3_from_file_urls": cond3}

# Contoh pemakaian setelah ekstraksi manual dari kode:
result = evaluate_test_0252(
    min_sdk=24,
    js_enabled=True,
    file_access=None,               # tidak dipanggil -> default true karena minSdk < 30
    file_access_from_file_urls=None,# tidak dipanggil -> default true karena minSdk < 16? PERIKSA
    universal_access=None
)
print(result)
```

Skrip ini membantu menghindari kesalahan manual dalam menerapkan logika bersyarat yang cukup rumit pada §1.4 — terutama untuk audit berskala besar dengan banyak instance WebView.

### 3.4 Metode C — Semgrep (Rule Resmi, Sama seperti MASTG-TEST-0250)

```bash
semgrep --config https://raw.githubusercontent.com/OWASP/mastg/master/rules/mastg-android-webview-allow-local-access.yml ./decompiled/sources/
```

Berlaku catatan celah yang sama seperti dibahas mendalam di dokumen MASTG-TEST-0250 §3.2 — rule ini murni inventarisasi lokasi tanpa mengevaluasi kombinasi kondisi FAIL maupun ketergantungan `minSdkVersion`.

### 3.5 Metode D — CodeQL (Korelasi dengan `minSdkVersion`)

```ql
import java

class WebSettingsFileAccessCall extends MethodAccess {
  WebSettingsFileAccessCall() {
    this.getMethod().hasName(["setAllowFileAccess", "setAllowFileAccessFromFileURLs", "setAllowUniversalAccessFromFileURLs", "setJavaScriptEnabled"]) and
    this.getMethod().getDeclaringType().hasQualifiedName("android.webkit", "WebSettings")
  }
}

from MethodAccess call
select call, call.getMethod().getName(), call.getArgument(0)
```

Hasil query ini kemudian disandingkan manual/skrip dengan nilai `minSdkVersion` proyek untuk menerapkan logika Metode B secara terprogram pada skala codebase penuh.

### 3.6 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Menangani logika `minSdkVersion`? | Kapan dipakai |
|---|---|---|---|
| **A** | Inventarisasi manual + grep | Manual | Baseline wajib, terutama untuk menangkap "ketiadaan referensi" (§1.3) |
| **B** | Skrip evaluasi Python | ✅ Otomatis | Menghindari kesalahan logika bersyarat manual, skala besar |
| **C** | Rule semgrep resmi | ❌ | Baseline lokasi cepat |
| **D** | CodeQL | Perlu korelasi manual tambahan | Codebase besar, ekstraksi data terstruktur |

**Kombinasi minimum yang aku rekomendasikan:** **A (inventarisasi menyeluruh, termasuk yang TIDAK memanggil setAllow*) → B (evaluasi otomatis dengan logika minSdkVersion yang benar)**. Rule resmi (C) dapat dipakai sebagai pelengkap cepat, tapi tidak boleh jadi metode utama karena tidak menangani ketergantungan `minSdkVersion` yang menjadi inti evaluasi test ini.

---

### 3.7 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Evaluation:** *"The test case fails if all of the following applies: `setJavaScriptEnabled` is explicitly set to `true`. `setAllowFileAccess` is explicitly set to `true` (or not used at all when `minSdkVersion` < 30). Either `setAllowFileAccessFromFileURLs` or `setAllowUniversalAccessFromFileURLs` is explicitly set to `true` (or not used at all when `minSdkVersion` < 16)."*

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | `setJavaScriptEnabled(true)` **dan** kondisi `setAllowFileAccess` terpenuhi (eksplisit `true` atau default `true` karena `minSdkVersion` < 30) **dan** kondisi salah satu dari `setAllowFileAccessFromFileURLs`/`setAllowUniversalAccessFromFileURLs` terpenuhi (eksplisit `true` atau default `true` karena `minSdkVersion` < 16) |
| F2 | Ditemukan instance WebView **tanpa satu pun** pemanggilan `setAllow*`, dan `minSdkVersion` aplikasi < 30 — kombinasi "senyap" yang secara eksplisit diperingatkan MASTG sebagai kondisi yang harus ditangkap (§1.3) |
| F3 | Verifikasi dinamis mengonfirmasi pembacaan file `file://` **berhasil** (bukan sekadar "terkirim" — lihat nuansa §1.5 tentang blind exfiltration) |

**Contoh bukti (ilustratif — MASTG belum menyediakan demo resmi untuk test ini):**

```bash
$ grep -oP 'minSdkVersion="\K[0-9]+' AndroidManifest.xml
21    # Android 5.0 — di bawah ambang batas 30 DAN 16

$ rg -n "setJavaScriptEnabled|setAllowFileAccess" ./decompiled/sources/com/example/target/ui/HelpViewerActivity.java
42:    settings.setJavaScriptEnabled(true);
# Tidak ada pemanggilan setAllowFileAccess/setAllowFileAccessFromFileURLs/setAllowUniversalAccessFromFileURLs SAMA SEKALI
```

Interpretasi: `minSdkVersion=21` berarti ketiga API mewarisi default `true` untuk seluruh device yang menjalankan aplikasi ini (karena 21 < 30 dan 21 < 16... perhatikan: 21 tidak lebih kecil dari 16, jadi periksa tabel dengan tepat — device dengan API 21 sudah di atas ambang 16, sehingga default untuk `setAllowFileAccessFromFileURLs`/`setAllowUniversalAccessFromFileURLs` sudah `false`. Namun `setAllowFileAccess` tetap default `true` karena 21 < 30). Kombinasikan dengan JavaScript aktif — **FAIL** karena kondisi 1 dan 2 terpenuhi, sementara kondisi 3 bergantung pada apakah salah satu dari dua API terakhir eksplisit diset `true` di kode (perlu diverifikasi lebih lanjut, tidak otomatis FAIL hanya dari `minSdkVersion=21` semata).

*(Catatan: contoh ini sengaja menunjukkan kompleksitas perhitungan ambang batas ganda yang berbeda per API — inilah mengapa Metode B/skrip otomatis sangat direkomendasikan untuk menghindari kesalahan manual.)*

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | `minSdkVersion` ≥ 30 **dan** tidak ada pemanggilan eksplisit `true` pada ketiga API — seluruhnya mewarisi default aman modern |
| P2 | `setJavaScriptEnabled` diset `false`/tidak dipakai pada WebView yang memuat `file://` |
| P3 | Ketiga API diset eksplisit `false` terlepas dari `minSdkVersion` |
| P4 | Aplikasi memakai `WebViewAssetLoader` (MASTG-BEST-0011), menghindari `file://` sepenuhnya |

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Ekstraksi `minSdkVersion` bukan langkah pelengkap — ini prasyarat mutlak.** Tanpa nilai ini, mustahil menentukan apakah ketiadaan pemanggilan API berarti PASS (default aman modern) atau FAIL (default insecure lawas).

2. **Jangan abaikan instance WebView yang "bersih" dari pemanggilan `setAllow*`** — sesuai §1.3, inilah justru yang paling perlu diperiksa hati-hati, kebalikan dari intuisi umum bahwa "tidak ada pemanggilan API berisiko = aman".

3. **Pahami perbedaan antara "gagal membaca" dan "gagal terkirim"** (§1.5) — log yang menunjukkan CORS block pada pembacaan tidak serta-merta berarti data tidak bocor; periksa selalu apakah **pembacaan file sumber** berhasil terjadi lebih dulu, karena itulah faktor penentu sesungguhnya, bukan status pengiriman.

4. **Perhatikan bahwa ambang batas API berbeda untuk setiap kondisi** (30 untuk `setAllowFileAccess`, 16 untuk dua API lainnya) — jangan menyamaratakan perhitungan, gunakan skrip otomatis (Metode B) untuk menghindari kesalahan manual pada audit berskala besar.

5. **`setAllowFileAccessFromFileURLs` diabaikan bila `setAllowUniversalAccessFromFileURLs=true`** (§1.6) — periksa yang kedua terlebih dahulu sebagai penentu utama.

6. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | Kombinasi FAIL lengkap, `minSdkVersion` sangat rendah, WebView memuat konten dari sumber yang bisa disusupi (download eksternal, deep link) | **Kritis** |
   | Kombinasi FAIL lengkap tapi WebView hanya memuat aset internal tepercaya (tidak ada jalur untuk menyuntik HTML jahat) | **Menengah** — risiko lebih rendah karena kurang jalur eksploitasi praktis |
   | `minSdkVersion` sudah tinggi (30+), tanpa override eksplisit ke nilai insecure | **Bukan temuan** |

7. **Dokumentasikan:** `minSdkVersion` aplikasi, daftar lengkap instance WebView (termasuk yang tidak memanggil `setAllow*`), nilai efektif ketiga API per instance (hasil perhitungan default vs eksplisit), dan hasil verifikasi dinamis bila dilakukan.

---

## 4. Rekomendasi Perbaikan

### 4.1 Naikkan `minSdkVersion` (Rujuk MASTG-BEST-0010 dan Dokumen MASTG-TEST-0245)

Menaikkan `minSdkVersion` ke ≥30 secara struktural mengubah default `setAllowFileAccess` menjadi aman tanpa perlu kode tambahan — konsisten dengan rekomendasi lintas-dokumen dalam seri riset ini soal pentingnya `minSdkVersion` yang mutakhir.

### 4.2 Nonaktifkan Eksplisit Terlepas dari `minSdkVersion`

```kotlin
webView.settings.apply {
    allowFileAccess = false
    allowFileAccessFromFileURLs = false          // tetap set eksplisit meski deprecated, untuk kejelasan intent
    allowUniversalAccessFromFileURLs = false
}
```

Sesuai MASTG-BEST-0011: *"For apps with a `minSdkVersion` that has secure defaults... ensure that these methods are not used and the default values are preserved. Alternatively, explicitly set them to `false`"* — pengaturan eksplisit lebih aman untuk diaudit di masa depan dibanding mengandalkan default yang bergantung `minSdkVersion`.

### 4.3 Migrasi ke `WebViewAssetLoader`

Rujuk implementasi lengkap di dokumen MASTG-TEST-0250 §4.3 — solusi yang sama berlaku di sini, menghindari `file://` sepenuhnya.

### 4.4 Checklist Remediasi

- [ ] `minSdkVersion` dievaluasi dan dinaikkan bila memungkinkan
- [ ] Seluruh instance WebView diinventarisasi, termasuk yang tidak memanggil `setAllow*` sama sekali
- [ ] Ketiga API diset eksplisit `false` pada seluruh instance yang memuat konten `file://`
- [ ] Migrasi ke `WebViewAssetLoader` dipertimbangkan
- [ ] Verifikasi dinamis dilakukan untuk membedakan "gagal membaca" vs "gagal terkirim" (§1.5)
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0252 setelah setiap perubahan `minSdkVersion` atau implementasi WebView

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0252: References to Local File Access in WebViews](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0252/)
- [MASTG-TEST-0250: References to Content Provider Access in WebViews](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0250/)
- [MASTG-TEST-0245: References to Platform Version APIs](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0245/)
- [MASWE-0034: WebViews Allow Access to Local Resources with Untrusted Content](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0034/)
- [MASTG-KNOW-0018: WebViews](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0018/)
- [MASTG-BEST-0010: Use Up-to-Date minSdkVersion](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0010/)
- [MASTG-BEST-0011: Securely Load File Content in a WebView](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0011/)
- [MASTG-BEST-0012: Disable JavaScript in WebViews](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0012/)
- [MASTG Document 0x05h — Testing Platform Interaction (WebView Local File Access Settings)](https://mas.owasp.org/MASTG/0x05h-Testing-Platform-Interaction/)

### 5.2 Dokumentasi Resmi Android

- [Android Developers — `WebSettings#setAllowFileAccess`](https://developer.android.com/reference/android/webkit/WebSettings#setAllowFileAccess(boolean))
- [Android Developers — `WebSettings#setAllowFileAccessFromFileURLs`](https://developer.android.com/reference/android/webkit/WebSettings#setAllowFileAccessFromFileURLs(boolean))
- [Android Developers — `WebSettings#setAllowUniversalAccessFromFileURLs`](https://developer.android.com/reference/android/webkit/WebSettings#setAllowUniversalAccessFromFileURLs(boolean))
- [Chromium — CORS and WebView API Documentation](https://chromium.googlesource.com/chromium/src/+/HEAD/android_webview/docs/cors-and-webview-api.md)

### 5.3 Riset dan Kasus Nyata

- [Medium — Exploiting Insecure Android WebView with setAllowUniversalAccessFromFileURLs](https://medium.com/@youssefhussein212103168/exploiting-insecure-android-webview-with-setallowuniversalaccessfromfileurls-c7f4f7a8db9c)
- [INTEGRITY Labs — Reviewing Android WebViews fileAccess Attack Vectors](https://labs.integrity.pt/articles/review-android-webviews-fileaccess-attack-vectors/index.html)
- [arXiv — Cross Site Request Forgery on Android WebView](https://arxiv.org/pdf/1411.3124)
- [Google Issue Tracker — WebView doesn't allow to read the body of a POST request](https://issuetracker.google.com/issues/119844519)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [CWE-668: Exposure of Resource to Wrong Sphere](https://cwe.mitre.org/data/definitions/668.html)

### 5.4 Dokumentasi Tools

- [Semgrep — Documentation](https://semgrep.dev/docs/)
- [CodeQL — Documentation](https://codeql.github.com/docs/)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [Frida — Dynamic instrumentation toolkit](https://frida.re/docs/javascript-api/)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026), dokumentasi resmi Android/Chromium, serta riset komunitas keamanan mengenai eksploitasi WebView. Tiga nuansa terpenting test ini: (1) evaluasi bergantung sepenuhnya pada `minSdkVersion` dengan ambang batas berbeda per API (30 vs 16), (2) ketiadaan referensi `setAllow*` justru menjadi sinyal yang harus ditangkap serius — bukan diabaikan, dan (3) kegagalan membaca respons (CORS block) tidak berarti data tidak bocor, karena JavaScript selalu bisa mengirim data terlepas dari kemampuan membaca balasannya ("blind exfiltration").*
