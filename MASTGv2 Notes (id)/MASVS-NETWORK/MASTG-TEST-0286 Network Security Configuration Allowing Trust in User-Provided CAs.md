# MASTG-TEST-0286 Network Security Configuration Allowing Trust in User-Provided CAs

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0286 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-NETWORK (MASVS-NETWORK-2) |
| **Weakness** | MASWE-0027 — *Insecure Certificate Validation* |
| **Tipe Pengujian** | Static, Code |
| **Knowledge** | MASTG-KNOW-0014 (Android Network Security Configuration) |
| **Teknik terkait** | MASTG-TECH-0013, MASTG-TECH-0117, MASTG-TECH-0150, MASTG-TECH-0151 (Analyzing NSC) |
| **Test terkait** | **MASTG-TEST-0285** (Outdated Android Version Allowing Trust in User-Provided CAs) — counterpart **implisit**; test ini menyasar trust user CA yang **eksplisit** dikonfigurasi developer, bukan diwarisi dari platform lawas |
| **Demo terkait** | — (tidak ada) |
| **Rule resmi** | — (tidak relevan; objek pengujian adalah XML konfigurasi, bukan kode Java/Kotlin) |
| **CWE terkait** | CWE-295, CWE-926 (Improper Export of Android Application Components — analog struktural: konfigurasi yang melonggarkan batas kepercayaan) |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian dan Hubungannya dengan MASTG-TEST-0285

Kutipan overview resmi MASTG:

> *"This test evaluates whether an Android app **explicitly** trusts user-added CA certificates by including `<certificates src="user"/>` in its Network Security Configuration... Even though starting with Android 7.0 (API level 24) apps no longer trust user-added CAs by default, this configuration overrides that behavior."*

Test ini adalah **pasangan cermin** dari MASTG-TEST-0285 yang sudah dibahas di seri riset ini — keduanya menghasilkan konsekuensi akhir yang identik (aplikasi mempercayai CA yang ditambahkan pengguna, rentan MITM), namun lewat **jalur penyebab yang sepenuhnya berbeda**:

| | MASTG-TEST-0285 | MASTG-TEST-0286 *(dokumen ini)* |
|---|---|---|
| **Penyebab** | **Implisit** — `minSdkVersion` rendah mewarisi default platform lawas | **Eksplisit** — developer **secara sadar menuliskan** `<certificates src="user"/>` di NSC |
| **Berlaku pada** | Device dengan API ≤23 saja | **Seluruh device**, termasuk Android modern terbaru, karena ini **override eksplisit**, bukan warisan default |
| **Sifat kesalahan** | Kelalaian tidak menaikkan `minSdkVersion` | Keputusan konfigurasi (sengaja atau tidak sengaja tertinggal) |

Poin krusial yang membedakan tingkat urgensi kedua test: MASTG-TEST-0286 **berpotensi lebih berbahaya** dalam praktiknya karena ia **secara aktif melonggarkan** perlindungan yang justru sudah menjadi default aman sejak API 24 — developer **harus melakukan langkah tambahan yang disengaja** untuk memicu kondisi FAIL ini, sesuatu yang biasanya menunjukkan adanya **alasan spesifik** di balik keputusan tersebut (paling umum: kebutuhan debugging yang tertinggal, dibahas mendalam di §1.3).

### 1.2 Mekanisme dan Sintaks

Konfigurasi ini muncul di dalam elemen `<trust-anchors>` pada file NSC (`data_extraction_rules.xml`/`network_security_config.xml`, dirujuk lewat `android:networkSecurityConfig` di manifest):

```xml
<network-security-config>
    <base-config>
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />  <!-- INI yang diperiksa test ini -->
        </trust-anchors>
    </base-config>
</network-security-config>
```

`src="user"` menginstruksikan sistem untuk turut mempercayai **seluruh sertifikat CA yang diinstal manual oleh pengguna** device (lewat Settings > Security > Install Certificate) — sumber kepercayaan yang **sepenuhnya berada di luar kendali developer aplikasi**, dan secara historis menjadi vektor utama serangan MITM sebelum perubahan default API 24 (dibahas di dokumen MASTG-TEST-0285).

### 1.3 Nuansa Paling Kritis: Lokasi Penempatan Menentukan Segalanya — `<debug-overrides>` vs `<base-config>`/`<domain-config>`

Ini adalah **temuan paling penting** dalam dokumen ini, dan merupakan celah evaluasi yang **sangat mudah menghasilkan false positive** bila penguji hanya melakukan pencarian teks sederhana (`grep 'src="user"'`) tanpa memperhatikan **konteks elemen induk** tempat baris tersebut berada.

Android Network Security Configuration menyediakan elemen khusus **`<debug-overrides>`** yang dirancang **khusus** untuk kasus penggunaan legitimate ini — mempercayai CA pengguna **hanya selama development**, secara otomatis dan aman dinonaktifkan di build produksi:

```xml
<!-- POLA AMAN — src="user" di dalam debug-overrides -->
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
    <debug-overrides>
        <trust-anchors>
            <certificates src="user" />
        </trust-anchors>
    </debug-overrides>
</network-security-config>
```

Perilaku elemen `<debug-overrides>` menurut dokumentasi resmi Android:

- **Aktif** hanya ketika `android:debuggable="true"` — flag yang secara otomatis diset oleh IDE/build tool untuk build **non-release** (debug/staging), dan **secara eksplisit ditolak** oleh Google Play Store serta app store lain untuk aplikasi yang dipublikasikan.
- **Sepenuhnya diabaikan** ketika `android:debuggable="false"` — kondisi yang berlaku untuk **seluruh build release** yang lolos ke Play Store, membuat blok `<debug-overrides>` **secara struktural tidak pernah aktif** di tangan pengguna akhir.

**Implikasi krusial bagi evaluasi test ini**: `<certificates src="user"/>` yang ditemukan **di dalam** elemen `<debug-overrides>` adalah **pola yang aman dan direkomendasikan** — inilah cara yang **benar** untuk memenuhi kebutuhan legitimate developer menguji koneksi lewat proxy intersepsi (Charles, Burp, mitmproxy — sesuai konteks yang dibahas di dokumen MASTG-TEST-0285 §1.4) tanpa membahayakan pengguna produksi. **Baris teks yang identik secara literal** (`<certificates src="user" />`) memiliki **makna keamanan yang sepenuhnya berlawanan** tergantung semata pada **elemen XML induk** yang membungkusnya — di dalam `<base-config>`/`<domain-config>` berarti FAIL kritis yang selalu aktif; di dalam `<debug-overrides>` berarti PASS yang aman dan sesuai praktik terbaik.

### 1.4 Mengapa Overview Resmi Tidak Secara Eksplisit Membedakan Ini — Potensi Celah Evaluasi

Perlu dicatat secara jujur: klausul Evaluation resmi MASTG untuk test ini berbunyi sederhana:

> *"The test case fails if `<certificates src="user" />` has been defined as part of the `<trust-anchors>` in the Network Security Configuration file."*

Klausul ini **tidak secara eksplisit mengecualikan** kasus `<debug-overrides>` dari kondisi FAIL — pembacaan paling literal atas kalimat ini bisa **saja** diartikan bahwa **keberadaan baris tersebut di mana pun** dalam file NSC (termasuk di dalam `<debug-overrides>`) memenuhi kondisi FAIL. Namun, berdasarkan riset mendalam pada dokumentasi resmi Android tentang tujuan dan perilaku `<debug-overrides>` (§1.3), **secara substansi keamanan**, menandai pola `<debug-overrides>` sebagai FAIL yang setara dengan pola `<base-config>` akan menghasilkan **false positive yang signifikan** terhadap praktik yang justru **direkomendasikan resmi** oleh Android Developers sendiri sebagai cara aman melakukan debugging jaringan.

**Rekomendasi metodologis dokumen ini**: penguji **wajib membedakan** kedua konteks ini secara eksplisit dalam laporan — melaporkan `<debug-overrides>` sebagai temuan **severity setara** dengan `<base-config>`/`<domain-config>` akan menyesatkan prioritas remediasi tim developer dan bisa merusak kredibilitas laporan audit di mata tim teknis yang memahami mekanisme ini dengan baik.

### 1.5 Skenario Risiko Nyata: Kesalahan Konfigurasi Build Variant

Meski `<debug-overrides>` itu sendiri aman **selama** `debuggable=false` benar-benar diberlakukan di release, ada skenario kegagalan nyata yang tetap perlu diwaspadai, konsisten dengan pola risiko "artefak debug tertinggal di produksi" yang sudah dibahas mendalam di dokumen MASTG-TEST-0226 (debuggable flag) dan MASTG-TEST-0263/0264/0265 (StrictMode) dalam seri riset ini:

- **`android:debuggable="true"` tidak sengaja tertinggal** di build release (kesalahan konfigurasi Gradle) — dalam skenario ini, blok `<debug-overrides>` yang tadinya "aman" akan **ikut aktif** di tangan pengguna produksi. Ini **bukan** kesalahan pada file NSC itu sendiri, melainkan **kegagalan pada test MASTG-TEST-0226** yang seharusnya menangkap kondisi `debuggable=true` di rilis — menegaskan pentingnya **korelasi antar-test** dalam laporan audit menyeluruh.
- **Developer salah menempatkan** `<certificates src="user"/>` langsung di `<base-config>`/`<domain-config>` karena kurang familiar dengan keberadaan mekanisme `<debug-overrides>` yang lebih tepat — inilah kondisi FAIL sesungguhnya yang ditargetkan test ini, kemungkinan besar berasal dari kebutuhan debugging yang sama namun diimplementasikan dengan cara yang salah.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **jadx --no-src / apktool** | Ekstraksi `AndroidManifest.xml` dan file NSC |
| **grep / xmlstarlet / yq** | Pencarian dan parsing terstruktur elemen `<certificates src="user"/>` **beserta elemen induknya** |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **MobSF** | Kadang menampilkan konfigurasi NSC lengkap dalam laporan Manifest Analysis, termasuk struktur elemen |
| **CodeQL/skrip Python dengan parser XML DOM** | Untuk audit skala besar, memverifikasi secara terprogram apakah setiap kemunculan `src="user"` berada dalam elemen `<debug-overrides>` atau tidak |
| **Verifikasi silang dengan MASTG-TEST-0226** | Memastikan `android:debuggable` benar-benar `false` pada build yang diuji — prasyarat untuk menyatakan `<debug-overrides>` benar-benar tidak aktif (§1.5) |

### 2.3 Prasyarat Lingkungan

- **Tidak butuh device/root** — sepenuhnya dapat dilakukan dari file APK.
- **WAJIB memakai parser XML terstruktur** (bukan grep baris tunggal murni) untuk secara akurat menentukan elemen induk dari setiap kemunculan `<certificates src="user"/>` — ini prasyarat metodologis paling penting sesuai §1.3.
- **Uji pada APK release final**, dan korelasikan dengan status `debuggable` (MASTG-TEST-0226) untuk interpretasi yang akurat.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0013** untuk reverse engineer aplikasi.
2. Gunakan **MASTG-TECH-0117** untuk memperoleh `AndroidManifest.xml`.
3. Gunakan **MASTG-TECH-0150** untuk memeriksa apakah `android:networkSecurityConfig` ada.
4. Gunakan **MASTG-TECH-0151** untuk mengekstrak seluruh penggunaan `<certificates src="user" />` dari file NSC.

### 3.2 Metode A — Parsing Terstruktur dengan Konteks Elemen Induk *(metode utama yang benar, menghindari false positive §1.3)*

```bash
jadx --no-src -d ./out target-app.apk
NSC_FILE=$(grep -oP 'networkSecurityConfig="@xml/\K[^"]+' ./out/resources/AndroidManifest.xml)
NSC_PATH="./out/resources/res/xml/${NSC_FILE}.xml"

# WAJIB: gunakan xmlstarlet untuk menentukan KONTEKS elemen induk, bukan grep baris tunggal
echo "=== Kemunculan src=user di BASE-CONFIG (FAIL jika ditemukan) ==="
xmlstarlet sel -t -c "//base-config//certificates[@src='user']" "$NSC_PATH"

echo "=== Kemunculan src=user di DOMAIN-CONFIG (FAIL jika ditemukan) ==="
xmlstarlet sel -t -c "//domain-config//certificates[@src='user']" "$NSC_PATH"

echo "=== Kemunculan src=user di DEBUG-OVERRIDES (PASS/aman, JANGAN tandai FAIL) ==="
xmlstarlet sel -t -c "//debug-overrides//certificates[@src='user']" "$NSC_PATH"
```

### 3.3 Metode B — Skrip Python dengan Parser XML DOM (Automasi/CI)

```python
import xml.etree.ElementTree as ET

def check_user_ca_trust(nsc_path):
    tree = ET.parse(nsc_path)
    root = tree.getroot()
    findings = {"fail_base_config": [], "fail_domain_config": [], "safe_debug_overrides": []}

    for base in root.findall('.//base-config'):
        for cert in base.findall('.//certificates[@src="user"]'):
            findings["fail_base_config"].append("base-config")

    for domain in root.findall('.//domain-config'):
        domains = [d.text for d in domain.findall('domain')]
        for cert in domain.findall('.//certificates[@src="user"]'):
            findings["fail_domain_config"].append(domains)

    for debug in root.findall('.//debug-overrides'):
        for cert in debug.findall('.//certificates[@src="user"]'):
            findings["safe_debug_overrides"].append("debug-overrides (aman, jika debuggable=false di release)")

    return findings

result = check_user_ca_trust("network_security_config.xml")
if result["fail_base_config"] or result["fail_domain_config"]:
    print(f"[FAIL] src=user ditemukan di base-config/domain-config: {result}")
if result["safe_debug_overrides"]:
    print(f"[INFO] src=user ditemukan di debug-overrides (verifikasi debuggable=false di release): {result['safe_debug_overrides']}")
```

### 3.4 Metode C — Korelasi dengan Status `debuggable` (MASTG-TEST-0226)

```bash
# Verifikasi debuggable flag pada APK release yang SAMA dengan NSC yang diperiksa
aapt2 dump badging target-app-release.apk | grep -i debuggable
```

Bila baris ini **muncul** (mengindikasikan `debuggable=true`), maka **seluruh** temuan `<debug-overrides>` yang tadinya diklasifikasi "aman" harus **direklasifikasi sebagai FAIL aktif** — sesuai skenario risiko §1.5.

### 3.5 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Membedakan konteks elemen induk? | Kapan dipakai |
|---|---|---|---|
| **A** | xmlstarlet/yq terstruktur | ✅ | **Wajib**, metode utama yang benar |
| **B** | Skrip Python DOM | ✅ | Automasi/CI, audit skala besar |
| **C** | Korelasi debuggable | N/A (pelengkap) | **Wajib** untuk interpretasi akurat status `<debug-overrides>` |

**Kombinasi minimum yang aku rekomendasikan:** **A atau B (parsing terstruktur, JANGAN grep baris tunggal naif) → C (korelasi status debuggable)** untuk kesimpulan yang benar-benar akurat dan tidak menghasilkan false positive terhadap praktik `<debug-overrides>` yang justru direkomendasikan.

---

### 3.6 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG** (dengan kualifikasi penting dari §1.3–1.4 yang ditambahkan dokumen ini):

> **Evaluation:** *"The test case fails if `<certificates src="user" />` has been defined as part of the `<trust-anchors>` in the Network Security Configuration file."*

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | `<certificates src="user"/>` ditemukan di dalam `<base-config>` — berlaku untuk **seluruh** koneksi aplikasi, di **semua** kondisi build |
| F2 | `<certificates src="user"/>` ditemukan di dalam `<domain-config>` untuk domain first-party/security-sensitive |
| F3 | `<certificates src="user"/>` ditemukan di dalam `<debug-overrides>`, **namun** dikonfirmasi (Metode C) bahwa `android:debuggable="true"` **tertinggal** di build release — kondisi ini mengaktifkan blok yang seharusnya tidak pernah aktif di produksi |

**Contoh bukti (ilustratif — MASTG belum menyediakan demo resmi untuk test ini):**

```xml
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />   <!-- baris 5 — LANGSUNG di base-config -->
        </trust-anchors>
    </base-config>
</network-security-config>
```

Interpretasi: `src="user"` ditempatkan langsung di `<base-config>`, berlaku untuk **seluruh** koneksi aplikasi tanpa syarat apa pun, tidak dibatasi kondisi debug. **FAIL kritis** — pola paling berbahaya yang membuka celah MITM untuk seluruh traffic aplikasi di **semua** device, terlepas dari status `debuggable` build tersebut.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | **Tidak ditemukan** `<certificates src="user"/>` di mana pun dalam file NSC |
| P2 | `<certificates src="user"/>` **hanya** ditemukan di dalam `<debug-overrides>`, **dan** dikonfirmasi `android:debuggable="false"` pada build release yang diuji (Metode C) — pola aman dan sesuai praktik terbaik resmi Android |

**Contoh output yang menandakan PASS (dengan kualifikasi):**

```xml
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors><certificates src="system" /></trust-anchors>
    </base-config>
    <debug-overrides>
        <trust-anchors><certificates src="user" /></trust-anchors>
    </debug-overrides>
</network-security-config>
```

```bash
$ aapt2 dump badging target-app-release.apk | grep -i debuggable
# (tidak ada hasil — debuggable=false terkonfirmasi)
```

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Ini catatan terpenting di seluruh dokumen ini: JANGAN gunakan grep baris tunggal naif tanpa memperhatikan elemen induk.** Sesuai §1.3, baris teks yang identik secara literal punya makna keamanan yang **sepenuhnya berlawanan** tergantung apakah ia berada di dalam `<debug-overrides>` (aman) atau `<base-config>`/`<domain-config>` (berbahaya). Laporan yang gagal membedakan ini akan menghasilkan false positive yang signifikan terhadap praktik yang justru direkomendasikan resmi Android.

2. **Klausul resmi MASTG tidak secara eksplisit membuat pengecualian untuk `<debug-overrides>`** (§1.4) — dokumen ini merekomendasikan tetap melaporkan **keberadaannya** sebagai observasi (sesuai klausul Observation resmi: *"should contain all the trust-anchors... along with any defined certificates entries"*), namun **klasifikasi severity/FAIL** harus mempertimbangkan konteks elemen induk dan status `debuggable` secara eksplisit, bukan diperlakukan setara dengan temuan di `<base-config>`.

3. **Selalu korelasikan dengan MASTG-TEST-0226** (debuggable flag) — status "aman" dari `<debug-overrides>` **sepenuhnya bergantung** pada kebenaran hasil test tersebut; jangan simpulkan PASS pada `<debug-overrides>` tanpa verifikasi eksplisit ini.

4. **Periksa SEMUA `<domain-config>`, bukan hanya `<base-config>`** — pola yang sama seperti ditekankan di dokumen MASTG-TEST-0235 dalam seri riset ini, sebuah aplikasi bisa memiliki `base-config` yang tampak aman namun menyembunyikan pengecualian di salah satu domain-config.

5. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | `src="user"` di `base-config`, berlaku untuk semua koneksi | **Kritis** |
   | `src="user"` di `domain-config` untuk domain sensitif spesifik | **Tinggi** |
   | `src="user"` di `debug-overrides`, `debuggable=true` tertinggal di release | **Kritis** (setara base-config karena efektif sama-sama aktif) |
   | `src="user"` di `debug-overrides`, `debuggable=false` terkonfirmasi di release | **Informational** — bukan temuan keamanan aktif, praktik yang benar |

6. **Dokumentasikan:** lokasi elemen induk persis dari setiap kemunculan `src="user"` (base-config/domain-config/debug-overrides), status `debuggable` build yang diuji, dan domain yang terpengaruh bila berada dalam domain-config.

---

## 4. Rekomendasi Perbaikan

### 4.1 Hapus `src="user"` dari `<base-config>`/`<domain-config>`

```xml
<!-- SEBELUM -->
<base-config>
    <trust-anchors>
        <certificates src="system" />
        <certificates src="user" />
    </trust-anchors>
</base-config>

<!-- SESUDAH -->
<base-config cleartextTrafficPermitted="false">
    <trust-anchors>
        <certificates src="system" />
    </trust-anchors>
</base-config>
```

### 4.2 Pindahkan Kebutuhan Debugging ke `<debug-overrides>`

```xml
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors><certificates src="system" /></trust-anchors>
    </base-config>
    <debug-overrides>
        <trust-anchors><certificates src="user" /></trust-anchors>
    </debug-overrides>
</network-security-config>
```

### 4.3 Pastikan `debuggable=false` Terjaga di Release (Rujuk MASTG-TEST-0226)

```gradle
android {
    buildTypes {
        release {
            debuggable false  // eksplisit, jangan andalkan default Gradle semata
        }
    }
}
```

### 4.4 Terapkan Konfigurasi Terkunci sebagai Basis, Override Hanya di Non-Release

Sesuai rekomendasi praktik terbaik komunitas: gunakan konfigurasi aman terkunci sebagai basis yang diwarisi build release, dan override hanya di source set debug/staging — sehingga build release **otomatis** mewarisi default aman tanpa perlu tindakan tambahan apa pun.

### 4.5 Checklist Remediasi

- [ ] Seluruh kemunculan `<certificates src="user"/>` diinventarisasi beserta elemen induknya (base-config/domain-config/debug-overrides)
- [ ] Kemunculan di `<base-config>`/`<domain-config>` dihapus atau dipindahkan ke `<debug-overrides>`
- [ ] `android:debuggable="false"` dikonfirmasi eksplisit untuk build type release
- [ ] Konfigurasi NSC dipisahkan per source set (debug vs release) untuk mencegah kontaminasi silang
- [ ] Hasil dikorelasikan dengan MASTG-TEST-0226 (status debuggable) dan MASTG-TEST-0285 (minSdkVersion)
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0286 pada APK release final setelah remediasi

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0286: Network Security Configuration Allowing Trust in User-Provided CAs](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0286/)
- [MASTG-TEST-0285: Outdated Android Version Allowing Trust in User-Provided CAs](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0285/)
- [MASTG-TEST-0226: Debuggable Flag Enabled in the AndroidManifest](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0226/)
- [MASWE-0027: Insecure Certificate Validation](https://mas.owasp.org/MASWE/MASVS-NETWORK/MASWE-0027/)
- [MASTG-KNOW-0014: Android Network Security Configuration](https://mas.owasp.org/MASTG/knowledge/android/MASVS-NETWORK/MASTG-KNOW-0014/)
- [MASTG-TECH-0151: Analyzing the Network Security Configuration](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0151/)

### 5.2 Dokumentasi Resmi Android

- [Android Developers — Network Security Configuration: Custom Trust (debug-overrides)](https://developer.android.com/privacy-and-security/security-config#CustomTrust)
- [Android Developers — `<certificates>` element reference](https://developer.android.com/privacy-and-security/security-config#certificates)
- [Android Developers — `android:networkSecurityConfig` attribute](https://developer.android.com/guide/topics/manifest/application-element#networkSecurityConfig)

### 5.3 Riset dan Artikel Komunitas

- [Medium — Android: Different Network Configuration per Build Variant](https://medium.com/@kostadin.georgiev90/android-different-network-configuration-per-build-variant-ade8b299dce7)
- [NowSecure — A Security Analyst's Guide to Network Security Configuration in Android P](https://www.nowsecure.com/blog/2018/08/15/a-security-analysts-guide-to-network-security-configuration-in-android-p/)
- [CWE-295: Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)

### 5.4 Dokumentasi Tools

- [xmlstarlet](http://xmlstar.sourceforge.net/)
- [yq — YAML/XML/JSON processor](https://github.com/mikefarah/yq)
- [aapt2 — Android Asset Packaging Tool](https://developer.android.com/tools/aapt2)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026) dan dokumentasi resmi Android Developers seputar Network Security Configuration. Sebagai pasangan cermin dari MASTG-TEST-0285 (implisit vs eksplisit), temuan paling penting dokumen ini: baris konfigurasi `<certificates src="user"/>` yang identik secara literal memiliki makna keamanan yang sepenuhnya berlawanan tergantung elemen XML induknya — di dalam `<debug-overrides>` (dengan `debuggable=false` di release) adalah praktik aman yang direkomendasikan resmi Android, sementara di dalam `<base-config>`/`<domain-config>` adalah kondisi FAIL kritis yang aktif di semua kondisi build. Evaluasi yang valid menuntut parsing XML terstruktur untuk membedakan konteks ini, bukan sekadar pencarian teks naif, serta korelasi wajib dengan status `android:debuggable` (MASTG-TEST-0226) pada build yang diuji.*
