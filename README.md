# APKLab

**Toolkit CLI untuk inspeksi APK/XAPK dan alur analisis Android berbasis salinan.**

[Lisensi MIT](LICENSE) · Python 3.9+ · Dirancang untuk pengguna dan AI agent

APKLab membantu memeriksa paket Android, menelusuri DEX dan aset, serta menyiapkan alur modifikasi tanpa mengubah file asli. Toolkit ini bersifat umum dan tidak bergantung pada satu aplikasi atau game tertentu.

> Gunakan hanya pada aplikasi yang berwenang Anda analisis. Hasil rebuild atau signing **tidak menjamin** aplikasi dapat dipasang atau dimainkan. Perlakukan APK, XAPK, dan alat pihak ketiga sebagai input tidak tepercaya.

## Fitur

| Perintah | Kegunaan |
| --- | --- |
| `doctor` | Mencari alat Android dan analisis yang tersedia. |
| `setup` | Menampilkan rencana atau mencoba pemasangan terbatas melalui APT. |
| `inspect` | Memeriksa ZIP, ABI native, metadata dan signature APK, termasuk beberapa split. |
| `xapk` | Memeriksa dan menyalin isi XAPK ke direktori baru. |
| `dex` | Mengindeks kelas, referensi metode, API, string, URL, dan kandidat model. |
| `inventory` | Mendata aset dan library native; dapat menggunakan `readelf`. |
| `work` | Membuat workspace salinan untuk decode, rebuild, alignment, dan signing. |

Beberapa pemeriksaan memerlukan alat eksternal. Hasil dikelompokkan sebagai `verified`, `inferences`, `failures`, dan `not_tested` agar pemeriksaan yang tidak dijalankan tidak dianggap berhasil.

## Instalasi

Persyaratan: Python 3.9+, Git, pip/venv, serta akses ke GitHub dan indeks paket untuk dependensi build. Contoh berikut untuk Linux/macOS:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install 'git+https://github.com/egad13744-collab/LAB-CLI.git'
.venv/bin/apklab --help
.venv/bin/apklab doctor
```

Pada Windows, executable virtual environment berada di `.venv\Scripts\`. APKLab tidak menyertakan APK atau alat Android. Instalasi langsung di atas memasang CLI, tetapi tidak membuat checkout untuk membaca panduan repo. Untuk hasil yang dapat direproduksi, gunakan commit atau tag yang telah ditinjau.

### Instalasi untuk AI agent

Agent memerlukan akses terminal dan jaringan. Jika tidak tersedia, agent harus menjelaskan hambatannya. Untuk memasang sekaligus membaca panduan, jalankan dari direktori kerja yang aman:

```sh
git clone https://github.com/egad13744-collab/LAB-CLI.git apklab-toolkit
cd apklab-toolkit
cat README.md AGENTS.md
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/apklab --help
.venv/bin/apklab doctor
```

Jika `apklab-toolkit` sudah ada, gunakan checkout yang benar atau pilih nama direktori baru—jangan hapus atau timpa file yang ada. Jika setiap perintah agent dimulai dari direktori berbeda, masuk kembali ke checkout atau gunakan path lengkap ke `.venv/bin/apklab`. Langkah clone dan instalasi dari checkout telah diuji dengan APKLab 0.2.0 pada Linux.

### Prompt siap salin untuk agent

Ganti `[LOKASI_FILE]` dengan lokasi APK/XAPK yang dapat diakses agent, atau beri tahu agent bahwa file akan disediakan kemudian.

```text
Bantu saya menganalisis APK/XAPK yang saya berwenang gunakan.
Lokasi file: [LOKASI_FILE]

Jika APKLab belum tersedia, clone https://github.com/egad13744-collab/LAB-CLI.git ke direktori baru, baca README.md dan AGENTS.md, lalu instal APKLab dalam virtual environment. Jalankan apklab --help dan apklab doctor. Jika tidak bisa mengakses terminal atau menginstal, jelaskan hambatannya.

Bekerjalah pada salinan dan jangan ubah atau hapus file asli. Untuk XAPK, periksa dan ekstrak ke direktori baru sebelum memeriksa APK di dalamnya. Jangan memasukkan file aplikasi, hasil ekstraksi, kredensial, atau data pribadi ke Git. Jika alat tambahan diperlukan, jelaskan rencana dan minta persetujuan sebelum memasangnya.

Pisahkan hasil terverifikasi, dugaan, kegagalan, dan yang belum diuji. Jangan mengklaim APK bisa dipasang atau dimainkan tanpa pengujian, dan jangan menganggap kode atau data server tersedia dalam APK.
```

## Pemeriksaan dan pemasangan alat

```sh
apklab doctor
apklab setup                 # tampilkan rencana; tidak memasang alat
apklab setup --install       # opt-in: mencoba memasang paket melalui APT
```

`doctor` mencari executable melalui PATH, `ANDROID_SDK_ROOT`, `ANDROID_HOME`, `~/Android/Sdk`, dan `GHIDRA_HOME` untuk Ghidra. Penemuan executable **belum membuktikan** bahwa alat berfungsi. Misalnya, metadata paket memerlukan `aapt` dan verifikasi signature memerlukan `apksigner`.

`setup --install` khusus sistem berbasis Debian/Ubuntu dan mengubah sistem: ia menjalankan `apt-get update`, mencoba memasang paket yang belum ditemukan, lalu memeriksa keberadaan executable. Tinjau sumber APT dan rencananya terlebih dahulu. Perintah ini memerlukan root atau sudo tanpa prompt password; kegagalan dilaporkan per paket. JADX, SDK lengkap, emulator, dan Ghidra tidak dipasang otomatis.

Jika diperlukan, instal alat dari sumber resmi dan verifikasi checksum/signature yang disediakan:

- [Android SDK command-line tools dan build tools](https://developer.android.com/studio#command-line-tools-only): `aapt`, `zipalign`, `apksigner`, emulator, dan ADB.
- [apktool](https://apktool.org/), [JADX](https://github.com/skylot/jadx), [Eclipse Temurin Java](https://adoptium.net/), dan [Ghidra](https://github.com/NationalSecurityAgency/ghidra).
- `readelf` dari toolchain sistem bersifat opsional untuk pemeriksaan header dan dependensi native. APKLab mendeteksi JADX/Ghidra, tetapi belum menjalankannya secara otomatis.

Ketersediaan alat bergantung pada sistem dan jaringan. Pemasangan SDK, penerimaan lisensi SDK, dan konfigurasi perangkat tidak dilakukan otomatis.

## Penggunaan

Aktifkan virtual environment (`. .venv/bin/activate` pada Linux/macOS), atau ganti `apklab` dengan path lengkap ke executable di virtual environment.

### Inspeksi APK dan split

```sh
apklab inspect app.apk
apklab inspect base.apk split_config.arm64_v8a.apk
apklab inspect ./split-directory --recursive --report inspection.json
apklab dex app.apk --search login --limit 50
apklab inventory app.apk --search lib --native-details
```

`inspect` memeriksa CRC ZIP, direktori ABI native, dan keberadaan manifest. Dengan `aapt` dan `apksigner`, ia juga membaca metadata dan memverifikasi signature. Untuk beberapa APK, nama paket, kode versi, dan kumpulan digest sertifikat yang tersedia dibandingkan. Hasil yang tidak tersedia ditandai `not_tested`; kesamaan digest tidak membuktikan split lengkap atau kompatibel. Pemilihan base, dependensi split, kompatibilitas perangkat, rotasi signer, dan pemasangan belum divalidasi sepenuhnya.

`dex` mengindeks kelas dan referensi metode, bukan perilaku runtime atau call graph. URL dan nama model adalah petunjuk, bukan bukti bahwa server aktif atau definisi model lengkap. Obfuscation, string terenkripsi, DEX dinamis, dan kode native dapat menyembunyikan informasi. `inventory` mendata path dan ukuran, bukan isi seluruh aset.

### Inspeksi dan ekstraksi XAPK

```sh
apklab xapk inspect game.xapk --verify
apklab xapk unpack game.xapk ./xapk-copy
apklab inspect ./xapk-copy --recursive --max-entry-mib 2048 --max-total-mib 8192
```

`xapk inspect` mendata entri; `--verify` membaca setiap file, memeriksa CRC, dan menghitung SHA-256. `unpack` hanya membaca arsip asli dan menyalin isinya ke direktori **baru**, dengan pemeriksaan CRC dan hash. Path traversal, duplikat atau tabrakan path, symlink, file khusus, entri terenkripsi, dan pelanggaran batas ukuran ditolak.

Referensi APK pada `manifest.json` root dengan daftar `split_apks` yang didukung dibandingkan dengan nama entri; format lain ditandai belum diuji. Pemeriksaan ini tidak memvalidasi kelengkapan manifest, isi APK secara menyeluruh, atau kompatibilitas OBB. Jika manifest menghasilkan kegagalan setelah ekstraksi, direktori hasil salinan dapat tetap ada. Penyusunan ulang XAPK, penempatan OBB, pemilihan split sesuai perangkat, dan pemasangan belum diimplementasikan.

Batas default APK adalah 100.000 entri, 64 MiB per entri, dan 512 MiB total tidak terkompresi. Untuk XAPK, batas ukuran default adalah 2.048 MiB per entri dan 8.192 MiB total. Sesuaikan secara sadar melalui `--max-entry-mib` dan `--max-total-mib`; batas lebih besar dapat memakai banyak memori, CPU, dan ruang disk. CRC bukan pengganti verifikasi signature. Kontainer `.apks` belum diekstrak secara otomatis.

### Alur modifikasi berbasis salinan

```sh
apklab work init app.apk ./apklab-work-example
apklab work decode ./apklab-work-example
# Edit hanya file dalam apklab-work-example/decoded.
apklab work build ./apklab-work-example
apklab work align ./apklab-work-example
apklab work sign ./apklab-work-example --keystore /secure/path/key.jks --alias mykey --pass-env APKLAB_KS_PASS
apklab inspect ./apklab-work-example/signed.apk
```

Workspace harus baru; `original.apk` adalah salinan. Tahapan menggunakan `apktool`, `zipalign`, dan `apksigner` yang dipasang terpisah. Output harus baru dan berada di dalam workspace; `--input` dan `--output` dapat mengubah path dalam workspace. Masukkan password ke variabel lingkungan melalui cara lokal yang aman, bukan ke perintah, laporan, atau Git. Dukungan key password terpisah, hardware token, dan rebuild satu set split belum tersedia.

Verifikasi signature dan alignment secara terpisah, lalu uji pemasangan/fungsi hanya pada perangkat atau emulator terisolasi dengan izin. Kunci signing yang berbeda dapat mencegah pembaruan aplikasi asli atau memengaruhi integrasi. Tidak semua APK dapat direbuild dengan apktool tanpa perubahan.

### Laporan

Semua output berupa JSON. Exit code `1` menunjukkan kegagalan yang dilaporkan; `0` berarti tidak ada kegagalan, **bukan** semua pemeriksaan telah dijalankan. `--report FILE` hanya membuat file baru dan tidak menimpa file yang ada. Untuk `work` dan `xapk`, letakkan `--report` setelah nama perintah dan sebelum subperintah.

Laporan dapat memuat string, endpoint, atau path sensitif. Tinjau dan samarkan sebelum membagikannya. Jangan memasukkan APK/XAPK, OBB, hasil ekstraksi, keystore, kredensial, atau data pribadi ke Git; `.gitignore` hanya bantuan, bukan jaminan.

## Batasan server dan pengujian

URL, referensi API, model, dan kode native dapat menunjukkan ketergantungan server, tetapi tidak menyediakan kode atau data server privat dan tidak membuktikan ketersediaan maupun kompatibilitasnya. APKLab tidak membuat server game yang kompatibel secara otomatis. Jangan menghubungi endpoint produksi tanpa izin.

Jalankan tes otomatis dengan:

```sh
python3 -m unittest discover -s tests -v
```

Tes menggunakan APK/DEX sintetis dan mock untuk metadata, signing, serta alur alat eksternal; tes native juga menggunakan `readelf` sistem jika tersedia. Smoke test terpisah pernah menggunakan [APK uji publik Androguard](https://github.com/androguard/androguard/blob/master/tests/data/APK/TestActivity.apk), yang tidak disertakan di repo ini. Decode, rebuild, alignment, signing dengan alat nyata dan uji perangkat/emulator belum diuji menyeluruh di lingkungan awal.

## Lisensi

APKLab didistribusikan di bawah **MIT License**. Lisensi ini mengizinkan penggunaan, penyalinan, modifikasi, penggabungan, publikasi, distribusi, sublicensing, dan penjualan, dengan syarat pemberitahuan hak cipta dan lisensi disertakan dalam semua salinan atau bagian substansial perangkat lunak. Perangkat lunak disediakan **“sebagaimana adanya” tanpa jaminan**; ketentuan lengkap ada di [LICENSE](LICENSE).

Lisensi APKLab tidak memberikan hak atas APK/XAPK, aset, data, atau alat pihak ketiga yang Anda analisis atau gunakan. Hak dan lisensi masing-masing tetap berlaku.
