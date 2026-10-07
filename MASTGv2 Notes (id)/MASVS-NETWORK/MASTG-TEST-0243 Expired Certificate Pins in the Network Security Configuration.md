# MASTG-TEST-0243 Expired Certificate Pins in the Network Security Configuration

| Atribut | Nilai |
|---|---|
| **Test ID** | MASTG-TEST-0243 |
| **Platform** | Android |
| **Kategori MASVS** | MASVS-NETWORK (MASVS-NETWORK-2: Aplikasi memverifikasi identitas endpoint server) |
| **Weakness** | MASWE-0028 — *Insecure Identity Pinning* |
| **Tipe Pengujian** | Static, Code |
| **Profile** | **L2 saja** |
| **Knowledge** | MASTG-KNOW-0014 (Android Network Security Configuration), MASTG-KNOW-0015 (Certificate Pinning) |
| **Prasyarat** | `identify-first-party-domains` — sama seperti MASTG-TEST-0242 |
| **Teknik terkait** | MASTG-TECH-0013, MASTG-TECH-0117, MASTG-TECH-0150, MASTG-TECH-0151, MASTG-TECH-0022, MASTG-TECH-0023 |
| **Test terkait** | **MASTG-TEST-0242** (Missing Certificate Pinning in NSC — prasyarat konseptual; test ini mengasumsikan pin **ada**, lalu memeriksa apakah pin tersebut **masih berlaku**) |
| **Demo terkait** | — (tidak ada) |
| **Rule resmi** | — (tidak ada rule semgrep MASTG; tersedia **lint rule resmi Android AOSP** `PinSetExpiry` — lihat §2.1/§3.2) |
| **CWE terkait** | CWE-295 (Improper Certificate Validation), CWE-298 (Improper Validation of Certificate Expiration) |

---

## 1. Penjelasan

### 1.1 Tujuan Pengujian

Kutipan overview resmi MASTG:

> *"Apps can configure expiration dates for pinned certificates in the Network Security Configuration (NSC) by using the `expiration` attribute. When a pin expires, the app no longer enforces certificate pinning and instead relies on its configured trust anchors."*

Test ini adalah **pelengkap langsung** dari MASTG-TEST-0242. Sementara TEST-0242 bertanya *"apakah pin ada?"*, test ini bertanya *"bila pin ada, apakah pin tersebut **masih berlaku** (belum melewati tanggal `expiration`)?"* — sebuah pin yang sudah kedaluwarsa secara efektif **sama saja tidak ada** dari sudut pandang perlindungan yang diberikannya, meski secara tekstual tetap tertulis di file XML.

### 1.2 Mekanisme "Fail-Open" — Desain yang Disengaja, Bukan Bug

Ini konsep inti yang harus dipahami sebelum menilai temuan test ini secara proporsional. Perilaku ketika pin kedaluwarsa **bukanlah cacat implementasi Android**, melainkan **keputusan desain yang disengaja**, secara eksplisit didokumentasikan Android Developers:

> *"Once a pin set expires, Android stops enforcing it (this is done to prevent connectivity issues in apps which do not get updates to their pin set). Connections are then authenticated using the applicable trust anchors."*

Perilaku ini dikenal dalam komunitas keamanan sebagai **"fail open"** (gagal terbuka) — kebalikan dari **"fail closed"** (gagal tertutup, yang akan memutus seluruh koneksi begitu pin kedaluwarsa). Rationale di baliknya bersifat praktis: banyak aplikasi memiliki basis pengguna yang **tidak selalu memperbarui aplikasi tepat waktu** (update dinonaktifkan, perangkat lawas, App Store approval delay). Bila Android memilih **fail closed**, jutaan pengguna dengan versi aplikasi lama akan **kehilangan konektivitas total** begitu tanggal `expiration` pin mereka terlewati — meski server sebenarnya masih menyajikan sertifikat yang sah dari CA tepercaya.

Riset komunitas (CommonsWare, *"Certificate Pinning and Failing Open"*) merangkum trade-off ini dengan tepat:

> *"This reduces security temporarily for older app versions but maintains functionality. Users who update get new pins for new certificates, while outdated apps continue working without breaking user experience."*

### 1.3 Mengapa Ini Tetap Layak Diuji Meski "By Design"

Justru **karena** perilaku ini adalah pengurangan keamanan yang disengaja (bukan bug), muncul pertanyaan krusial yang menjadi inti evaluasi test ini: **apakah tim developer benar-benar menyadari trade-off ini, atau mengira pinning masih aktif padahal sudah lama tidak?**

Overview resmi menyoroti risiko ini secara eksplisit lewat contoh konkret:

> *"If developers assume pinning is still in effect but don't realize it has expired, the app may start trusting CAs it was never intended to."*
>
> *Contoh: "A financial app previously pinned to its own private CA but, after the pin expires, any certificate valid under the app's configured trust anchors may be accepted, whereas previously it also had to satisfy the pinning policy."*

Skenario ini menggambarkan **regresi keamanan senyap** (*silent security regression*) — tidak ada crash, tidak ada error log yang mencolok, tidak ada perubahan perilaku yang terlihat pengguna. Aplikasi terus berfungsi normal, tapi lapisan pertahanan MITM yang tadinya diberikan pinning (khususnya untuk private CA finansial pada contoh di atas) **diam-diam menghilang** begitu tanggal tersebut lewat — dan karena sifatnya senyap, **tim developer mungkin tidak menyadarinya selama berbulan-bulan atau bertahun-tahun** kecuali ada proses pemantauan aktif.

### 1.4 Bukan Otomatis FAIL — Tergantung Threat Model Aplikasi

Ini nuansa evaluasi penting yang membedakan test ini dari kebanyakan test lain di seri ini. Overview resmi tidak menyatakan "pin kedaluwarsa = selalu buruk", melainkan:

> *"Determine whether this behavior is intentional and consistent with the application's threat model."*

Sesuai riset CommonsWare, **pin kedaluwarsa dengan fail-open yang disengaja** justru adalah **rekomendasi praktik terbaik** yang eksplisit dianjurkan penulis:

> *"Always set expiration dates on pins and fail open... prepare emergency update procedures for urgent certificate replacements."*

Artinya, keberadaan `expiration` attribute itu sendiri **bukan masalah** — bahkan dianjurkan dibanding pin yang tidak pernah kedaluwarsa sama sekali (yang berisiko mem-brick konektivitas aplikasi lawas permanen bila sertifikat berubah tak terduga). **Masalah sesungguhnya muncul ketika**:
- Tanggal `expiration` **sudah terlewati di masa lalu** dan **tidak ada rencana/proses pembaruan** pin yang berjalan — mengindikasikan pin tersebut "terlupakan", bukan hasil keputusan sadar.
- Domain yang terpengaruh adalah **first-party dan security-sensitive** (finansial, autentikasi) di mana hilangnya pinning secara diam-diam punya konsekuensi nyata terhadap threat model aplikasi.

### 1.5 Hubungan dengan MASTG-TEST-0242

| | MASTG-TEST-0242 | MASTG-TEST-0243 *(dokumen ini)* |
|---|---|---|
| **Pertanyaan** | Apakah pin **ada** untuk domain first-party? | Apakah pin yang ada **masih berlaku** (belum kedaluwarsa)? |
| **Kondisi FAIL** | Tidak ada `<pin-set>` sama sekali | `<pin-set>` ada, tapi `expiration` sudah lewat |
| **Prasyarat** | `identify-first-party-domains` (sama) | `identify-first-party-domains` (sama) |

Urutan pengujian logis: jalankan MASTG-TEST-0242 terlebih dahulu untuk memetakan domain mana yang memiliki pin, lalu MASTG-TEST-0243 untuk memeriksa validitas temporal dari pin-pin yang ditemukan tersebut.

---

## 2. Tools yang Dipakai untuk Pengujian

### 2.1 Tools Wajib (Core)

| Tool | Fungsi |
|---|---|
| **jadx / apktool** | Ekstraksi AndroidManifest.xml dan NSC |
| **grep / xmlstarlet / yq** | Parsing atribut `expiration` di elemen `<pin-set>` |
| **Android Lint (`PinSetExpiry`)** | **Lint rule resmi AOSP** (Issue ID: `PinSetExpiry`, kategori Correctness, sejak Android Studio 2.3.0/2017) yang secara spesifik memvalidasi bahwa atribut `expiration` valid dan **belum/tidak akan segera kedaluwarsa** — dijalankan langsung dari Android Studio atau `lint` CLI, jauh lebih presisi untuk kasus ini dibanding parsing manual karena sudah menghitung perbandingan tanggal secara otomatis |

### 2.2 Tools Alternatif & Pendukung

| Tool | Fungsi |
|---|---|
| **date/dateutils (bash)** | Perbandingan tanggal `expiration` terhadap tanggal saat ini untuk automasi CI/CD tanpa memerlukan Android SDK penuh |
| **Python `datetime`** | Sama seperti di atas, untuk skrip validasi yang lebih fleksibel dan mudah diintegrasikan ke pipeline non-Gradle |
| **MobSF** | Kadang menampilkan isi lengkap NSC termasuk atribut expiration dalam laporan Manifest/Network Analysis |
| **git blame / git log pada `network_security_config.xml`** | Untuk whitebox testing — menelusuri kapan pin terakhir diperbarui, memberi indikasi apakah proses pembaruan pin berjalan rutin atau sudah lama terbengkalai (mendukung penilaian §1.4 soal "disengaja vs terlupakan") |

### 2.3 Prasyarat Lingkungan

- **Tidak butuh device/root** — cukup APK atau, untuk hasil optimal, akses source code proyek untuk menjalankan Android Lint secara langsung.
- **Perlu mengetahui tanggal pengujian dilakukan** sebagai baseline perbandingan (`expiration` di masa lalu relatif terhadap kapan pengujian ini dijalankan, bukan tanggal rilis APK).
- **Sama seperti MASTG-TEST-0242**, identifikasi first-party domain adalah prasyarat wajib sebelum menyimpulkan hasil.

---

## 3. Cara Pengujian

### 3.1 Langkah Resmi MASTG

1. Gunakan **MASTG-TECH-0013** untuk reverse engineer aplikasi.
2. Gunakan **MASTG-TECH-0117** untuk memperoleh `AndroidManifest.xml`.
3. Gunakan **MASTG-TECH-0150** untuk memeriksa apakah `android:networkSecurityConfig` diset.
4. Gunakan **MASTG-TECH-0151** untuk mengekstrak tanggal `expiration` dari seluruh pin di NSC.
5. Gunakan **MASTG-TECH-0022** untuk mengidentifikasi domain first-party.

### 3.2 Metode A — Android Lint `PinSetExpiry` *(metode resmi Android, paling presisi — whitebox)*

Bila source code proyek tersedia (whitebox testing/audit internal):

```bash
cd android-project/
./gradlew lint

# Atau langsung menyasar check spesifik ini
./gradlew lint -PlintCheck=PinSetExpiry
```

Hasil akan muncul di `app/build/reports/lint-results.html`, memberi peringatan presisi untuk setiap `<pin-set>` yang atribut `expiration`-nya **sudah lewat atau akan segera lewat** (bukan hanya lewat — lint ini bahkan proaktif memperingatkan sebelum kedaluwarsa terjadi, sesuai deskripsi resminya: *"has not already expired or is expiring soon"*).

**Catatan penting**: cakupan built-in Android Lint ini menjadikannya **satu-satunya kasus dalam seri riset dokumen ini** di mana tool resmi vendor platform (bukan MASTG) sudah menyediakan deteksi presisi tanpa perlu rule kustom — jadikan ini metode utama bila source code tersedia.

### 3.3 Metode B — Ekstraksi Manual + Perbandingan Tanggal (blackbox, hanya dari APK)

```bash
jadx --no-src -d ./out target-app.apk
NSC_FILE=$(grep -oP 'networkSecurityConfig="@xml/\K[^"]+' ./out/resources/AndroidManifest.xml)
NSC_PATH="./out/resources/res/xml/${NSC_FILE}.xml"

# Ekstrak seluruh atribut expiration beserta domain yang dicakupnya
yq -p=xml -o=json "$NSC_PATH" | jq -r '
  .["network-security-config"]["domain-config"][]? |
  {domains: (.domain // [] | if type=="array" then [.[]."+content"] else [."+content"] end),
   expiration: .["pin-set"]["+@expiration"]}
'
```

```bash
# Bandingkan setiap tanggal expiration dengan tanggal hari ini
TODAY=$(date +%Y-%m-%d)
for exp_date in $(yq -p=xml '.."+@expiration"' "$NSC_PATH" 2>/dev/null); do
    if [[ "$exp_date" < "$TODAY" ]]; then
        echo "[EXPIRED] Pin kedaluwarsa: $exp_date (hari ini: $TODAY)"
    fi
done
```

### 3.4 Metode C — Skrip Python untuk Automasi CI/CD

```python
import xml.etree.ElementTree as ET
from datetime import date

def check_expired_pins(nsc_path):
    tree = ET.parse(nsc_path)
    root = tree.getroot()
    today = date.today()
    findings = []

    for domain_config in root.findall('.//domain-config'):
        domains = [d.text for d in domain_config.findall('domain')]
        pin_set = domain_config.find('pin-set')
        if pin_set is not None:
            exp_str = pin_set.get('expiration')
            if exp_str:
                exp_date = date.fromisoformat(exp_str)
                if exp_date < today:
                    findings.append({
                        'domains': domains,
                        'expiration': exp_str,
                        'days_expired': (today - exp_date).days
                    })
    return findings

results = check_expired_pins('network_security_config.xml')
for f in results:
    print(f"[EXPIRED] Domain: {f['domains']}, kedaluwarsa {f['days_expired']} hari lalu ({f['expiration']})")
```

### 3.5 Metode D — Korelasi Riwayat Perubahan (Whitebox — Menilai "Disengaja vs Terlupakan")

Sesuai pembahasan §1.4, untuk menilai apakah pin yang kedaluwarsa mencerminkan keputusan sadar atau kelalaian, tinjau riwayat perubahan file NSC:

```bash
git log --follow -p -- app/src/main/res/xml/network_security_config.xml | head -100
git log --follow --format="%ad %s" --date=short -- app/src/main/res/xml/network_security_config.xml
```

Bila riwayat menunjukkan **tidak ada commit terkait NSC** dalam jangka waktu jauh melampaui tanggal `expiration` yang tercatat, ini indikasi kuat bahwa pin tersebut **terlupakan**, bukan bagian dari strategi fail-open yang dikelola aktif.

### 3.6 Metode E — Verifikasi Dinamis (Konfirmasi Perilaku Fail-Open Benar-Benar Terjadi)

```bash
# Set tanggal sistem perangkat uji melampaui expiration (khusus lingkungan uji/emulator)
adb shell date $(date -d "+2 years" +%m%d%H%M%Y.%S)

# Jalankan aplikasi dan amati apakah MITM dengan CA sistem (bukan CA yang di-pin) sekarang BERHASIL
mitmproxy --mode transparent
```

Bila MITM dengan sertifikat CA sistem biasa (bukan CA yang sebelumnya di-pin) **berhasil** menembus koneksi setelah pin dinyatakan kedaluwarsa, ini konfirmasi definitif perilaku fail-open sesuai dokumentasi resmi Android — berguna untuk memvalidasi pemahaman tim tentang dampak nyata dari kedaluwarsanya pin tersebut.

### 3.7 Perbandingan Metode: Kapan Memakai yang Mana

| Metode | Tool | Presisi | Kapan dipakai |
|---|---|---|---|
| **A** | Android Lint `PinSetExpiry` | Tertinggi — resmi AOSP, bahkan proaktif (peringatan sebelum kedaluwarsa) | **Wajib bila source code tersedia** |
| **B** | Ekstraksi manual + bash | Baik | Blackbox, hanya dari APK |
| **C** | Skrip Python | Baik, mudah diintegrasikan CI/CD | Automasi pipeline |
| **D** | Riwayat git | Kontekstual — menilai kesengajaan | Menilai §1.4 (disengaja vs terlupakan) |
| **E** | Verifikasi dinamis | Bukti definitif perilaku runtime | Konfirmasi akhir/edukasi tim |

**Kombinasi minimum yang aku rekomendasikan:** **A (bila whitebox tersedia) atau B/C (blackbox) → D (untuk konteks kesengajaan) → korelasi dengan hasil klasifikasi first-party dari MASTG-TEST-0242**. Integrasikan Metode A ke pipeline CI/CD proyek sebagai pencegahan proaktif — jauh lebih baik mencegah pin kedaluwarsa daripada menemukannya setelah fakta.

---

### 3.8 Kriteria Evaluasi: Positive Case & Negative Case

**Aturan resmi MASTG:**

> **Observation:** *"The output should contain a list of expiration dates for pinned certificates, along with the domains they apply to... identify which of those domains are relevant first-party domains."*
>
> **Evaluation:** *"The test case fails if any certificate pin configured for a relevant first-party domain has an expiration date in the past. The test case should not fail only because pins for unrelated third-party domains have expired."*

Dengan klausul **Further Validation Required** yang identik strukturnya dengan MASTG-TEST-0242 — mengonfirmasi aplikasi benar-benar terhubung ke domain first-party yang terpengaruh sebelum melaporkan.

---

#### ❌ FAIL / ISSUE — Check dinyatakan GAGAL apabila:

| No | Kondisi |
|---|---|
| F1 | `<pin-set>` untuk domain first-party memiliki `expiration` dengan tanggal **di masa lalu** relatif terhadap tanggal pengujian dilakukan |
| F2 | Terkonfirmasi (Metode D) tidak ada proses pembaruan pin yang berjalan — indikasi kelalaian, bukan strategi fail-open yang dikelola sadar |
| F3 | Domain yang terpengaruh adalah endpoint security-sensitive (autentikasi, finansial) sesuai contoh eksplisit overview resmi, di mana kehilangan pinning berdampak signifikan pada threat model |
| F4 | Verifikasi dinamis (Metode E) mengonfirmasi MITM dengan CA sistem biasa berhasil menembus koneksi yang sebelumnya dilindungi pin tersebut |

**Contoh bukti (ilustratif — MASTG belum menyediakan demo resmi untuk test ini):**

```xml
<!-- res/xml/network_security_config.xml -->
<network-security-config>
    <domain-config>
        <domain includeSubdomains="true">api-payment.example.com</domain>
        <pin-set expiration="2023-01-15">   <!-- Diuji pada 2026-09-15 — kedaluwarsa 3+ tahun lalu -->
            <pin digest="SHA-256">...</pin>
        </pin-set>
    </domain-config>
</network-security-config>
```

```bash
$ TODAY=2026-09-15
$ echo "2023-01-15" # expiration ditemukan
[EXPIRED] Pin kedaluwarsa: 2023-01-15 (hari ini: 2026-09-15) — 1339 hari lalu

$ git log --follow --format="%ad" --date=short -- res/xml/network_security_config.xml
2022-11-03   # commit terakhir — tidak ada pembaruan sejak sebelum tanggal kedaluwarsa
```

Interpretasi: `api-payment.example.com` — endpoint pembayaran, jelas first-party dan security-sensitive — memiliki pin yang kedaluwarsa **lebih dari 3 tahun lalu**, tanpa riwayat commit pembaruan sejak itu. **FAIL** dengan indikasi kuat kelalaian (bukan strategi sadar), sesuai skenario persis yang diperingatkan overview resmi.

---

#### ✅ PASS — Check dinyatakan LULUS apabila:

| No | Kondisi |
|---|---|
| P1 | Seluruh pin untuk domain first-party memiliki `expiration` di **masa depan** relatif terhadap tanggal pengujian |
| P2 | Pin domain first-party memang sudah kedaluwarsa, **tapi** terkonfirmasi (Metode D + dokumentasi tim) sebagai bagian dari strategi fail-open yang dikelola sadar dan konsisten dengan threat model aplikasi (mis. didokumentasikan eksplisit sebagai keputusan arsitektur, dengan monitoring aktif atas periode fail-open tersebut) |
| P3 | Pin yang kedaluwarsa hanya berlaku untuk domain **third-party**, di luar cakupan evaluasi test ini |
| P4 | `<pin-set>` tidak menyertakan atribut `expiration` sama sekali (pin tidak pernah kedaluwarsa) — bukan kondisi FAIL, tapi dicatat sebagai trade-off berbeda (risiko konektivitas jangka panjang vs keamanan permanen, lihat §1.4) |

**Contoh output yang menandakan PASS:**

```bash
$ ./gradlew lint -PlintCheck=PinSetExpiry
BUILD SUCCESSFUL — tidak ada peringatan PinSetExpiry ditemukan
```

---

#### ⚠️ Catatan Penting tentang Penilaian

1. **Ini test yang paling menuntut penilaian kontekstual soal "kesengajaan", bukan sekadar deteksi mekanis tanggal.** Sesuai §1.4, pin kedaluwarsa **bukan otomatis buruk** — ini fitur yang disengaja dan bahkan direkomendasikan komunitas keamanan (fail-open lebih baik dari fail-closed untuk mencegah brick konektivitas). Fokus penilaian pada **apakah tim menyadarinya dan mengelolanya secara sadar**, bukan sekadar "apakah tanggal sudah lewat".

2. **Manfaatkan riwayat git (Metode D) sebagai bukti kontekstual utama** untuk membedakan kelalaian dari strategi sadar — ini pendekatan yang tidak eksplisit disebut MASTG namun sangat relevan secara praktis untuk memenuhi klausul "Determine whether this behavior is intentional".

3. **Sama seperti MASTG-TEST-0242, jangan tuntut domain third-party.** Fokus murni pada domain first-party dan security-sensitive.

4. **Manfaatkan Android Lint `PinSetExpiry` sebagai pencegahan, bukan hanya deteksi.** Karena tool ini resmi dari AOSP dan sudah terintegrasi ke toolchain build standar Android Studio, rekomendasikan tim developer mengaktifkannya sebagai **build-blocking check** (bukan hanya warning) untuk mencegah pin kedaluwarsa lolos ke produksi sejak awal — jauh lebih efisien dibanding menemukannya lewat audit keamanan periodik.

5. **Perhatikan proximity ke tanggal kedaluwarsa, bukan hanya status sudah/belum lewat.** Sesuai deskripsi resmi lint rule (*"has not already expired or **is expiring soon**"*), pin yang akan kedaluwarsa dalam waktu dekat (mis. 30 hari) sebaiknya dilaporkan sebagai **peringatan proaktif** meski secara teknis belum FAIL — memberi waktu bagi tim untuk memperbarui sebelum benar-benar bermasalah.

6. **Severity dimodulasi:**

   | Faktor | Severity |
   |---|---|
   | Pin domain finansial/autentikasi kedaluwarsa lama, tanpa bukti pengelolaan sadar | **Tinggi** |
   | Pin domain first-party kedaluwarsa tapi terkonfirmasi bagian dari strategi fail-open terkelola dengan dokumentasi jelas | **Informational** — bukan temuan keamanan, catat sebagai observasi |
   | Pin akan kedaluwarsa dalam waktu dekat (<30 hari) tanpa proses pembaruan terjadwal | **Rendah/Menengah** — peringatan proaktif |
   | Pin third-party kedaluwarsa | **Bukan temuan** |

7. **Dokumentasikan:** domain yang terpengaruh, tanggal expiration persis, berapa lama sudah/akan kedaluwarsa, bukti kontekstual soal kesengajaan (riwayat git/dokumentasi tim), dan hasil verifikasi dinamis bila dilakukan.

---

## 4. Rekomendasi Perbaikan

### 4.1 Terapkan Proses Pembaruan Pin Terjadwal

Tetapkan proses operasional (idealnya terintegrasi kalender rilis) untuk memperbarui `expiration` dan pin digest **sebelum** tanggal kedaluwarsa tercapai — jangan menunggu insiden atau audit untuk menyadarinya.

### 4.2 Aktifkan Android Lint `PinSetExpiry` sebagai Build-Blocking Check

```gradle
// app/build.gradle
android {
    lintOptions {
        error 'PinSetExpiry'  // jadikan error, bukan sekadar warning, agar build gagal bila terdeteksi
    }
}
```

### 4.3 Tetapkan Periode Expiration yang Proporsional dengan Siklus Rilis

Sesuai rekomendasi umum industri, tetapkan `expiration` dengan margin yang cukup (mis. 6-12 bulan ke depan) relatif terhadap siklus rilis aplikasi, dan jadwalkan pembaruan pin sebagai bagian rutin dari setiap beberapa rilis — bukan `expiration` yang ditetapkan sangat jauh (multi-tahun) yang berisiko terlupakan, atau terlalu dekat yang berisiko sering terlewat tanpa disadari.

### 4.4 Dokumentasikan Strategi Fail-Open Secara Eksplisit

Bila tim secara sadar memilih strategi fail-open dengan periode tertentu (sesuai rekomendasi CommonsWare), dokumentasikan keputusan ini secara eksplisit dalam dokumentasi arsitektur keamanan aplikasi, termasuk rencana darurat (*"emergency update procedures"*) bila diperlukan penggantian sertifikat mendesak.

### 4.5 Integrasikan Pemantauan Proaktif ke CI/CD

```bash
#!/bin/bash
# ci-check-pin-expiration.sh — jalankan sebagai bagian dari pipeline rutin, BUKAN hanya saat rilis
python3 check_expired_pins.py network_security_config.xml
# Tambahkan peringatan untuk pin yang akan kedaluwarsa dalam 60 hari ke depan
python3 -c "
from datetime import date, timedelta
import check_expired_pins as c
today = date.today()
warning_threshold = today + timedelta(days=60)
# ... logika peringatan proaktif
"
```

### 4.6 Checklist Remediasi

- [ ] Seluruh pin domain first-party memiliki `expiration` di masa depan
- [ ] Android Lint `PinSetExpiry` diaktifkan sebagai build-blocking check di pipeline CI/CD
- [ ] Proses pembaruan pin terjadwal sudah ditetapkan sebagai bagian rutin siklus rilis
- [ ] Bila strategi fail-open sengaja dipakai, didokumentasikan eksplisit beserta rencana darurat
- [ ] Pemantauan proaktif untuk pin yang akan kedaluwarsa dalam waktu dekat (60-90 hari) sudah berjalan
- [ ] **Verifikasi ulang:** jalankan kembali MASTG-TEST-0243 secara berkala (bukan hanya sekali saat audit), karena sifat temporal dari test ini membuat hasilnya berubah seiring waktu tanpa perubahan kode apa pun

---

## 5. Referensi

### 5.1 OWASP MASTG / MASVS

- [MASTG-TEST-0243: Expired Certificate Pins in the Network Security Configuration](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0243/)
- [MASTG-TEST-0242: Missing Certificate Pinning in Network Security Configuration](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0242/)
- [MASWE-0028: Insecure Identity Pinning](https://mas.owasp.org/MASWE/MASVS-NETWORK/MASWE-0028/)
- [MASTG-KNOW-0014: Android Network Security Configuration](https://mas.owasp.org/MASTG/knowledge/android/MASVS-NETWORK/MASTG-KNOW-0014/)
- [MASTG-KNOW-0015: Certificate Pinning](https://mas.owasp.org/MASTG/knowledge/android/MASVS-NETWORK/MASTG-KNOW-0015/)
- [MASTG Prerequisite: Identifying First-Party Domains](https://mas.owasp.org/MASTG/prerequisites/identify-first-party-domains/)
- [OWASP Mobile Top 10 2024 — M5: Insecure Communication](https://owasp.org/www-project-mobile-top-10/2023-risks/m5-insecure-communication)

### 5.2 Dokumentasi Resmi Android

- [Android Developers — Network Security Configuration (`pin-set` reference)](https://developer.android.com/privacy-and-security/security-config#pin-set)
- [Android Custom Lint Rules — PinSetExpiry](https://googlesamples.github.io/android-custom-lint-rules/checks/PinSetExpiry.md.html)

### 5.3 Riset dan Diskusi Komunitas

- [CommonsWare — Certificate Pinning and Failing Open](https://commonsware.com/blog/2016/11/28/certificate-pinning-failing-open.html)
- [NowSecure — A Security Analyst's Guide to Network Security Configuration in Android P](https://www.nowsecure.com/blog/2018/08/15/a-security-analysts-guide-to-network-security-configuration-in-android-p/)
- [Securevale — Deep Dive into Certificate Pinning on Android](https://securevale.blog/articles/deep-dive-into-certificate-pinning-on-android/)
- [CWE-295: Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)
- [CWE-298: Improper Validation of Certificate Expiration](https://cwe.mitre.org/data/definitions/298.html)

### 5.4 Dokumentasi Tools

- [Android Lint — Documentation](https://developer.android.com/studio/write/lint)
- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [yq — YAML/XML/JSON processor](https://github.com/mikefarah/yq)
- [mitmproxy](https://mitmproxy.org/)
- [MobSF — Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)

---

*Dokumen ini disusun berdasarkan OWASP MASTG (rilis terkini per September 2026), dokumentasi resmi Android Developers, serta diskusi komunitas keamanan (CommonsWare) mengenai trade-off desain fail-open pada certificate pinning. Nuansa terpenting test ini: kedaluwarsanya pin **bukan otomatis kerentanan** — ini fitur desain Android yang disengaja untuk mencegah gangguan konektivitas. Evaluasi yang tepat menuntut penilaian kontekstual apakah kondisi tersebut mencerminkan strategi keamanan yang dikelola sadar atau kelalaian yang tidak disadari tim developer, sesuai klausul resmi "Determine whether this behavior is intentional and consistent with the application's threat model."*
