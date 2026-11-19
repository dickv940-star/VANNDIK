# VANNDIK

**Premium Digital Experience**

Website resmi VANNDIK, dibangun dengan Astro dan identitas visual hitam, biru, putih, dan abu-abu.

## Struktur proyek
```text
VANNDIK/
├── public/                 # Aset statis: gambar, ikon, file publik
├── src/
│   ├── components/         # Komponen UI yang dapat digunakan ulang
│   ├── data/               # Data katalog, game, dan konten
│   ├── layouts/            # Kerangka halaman dan navigasi bersama
│   ├── pages/              # Route website (satu file = satu halaman)
│   └── styles/             # CSS global dan animasi
├── .github/workflows/      # Otomatisasi build
├── astro.config.mjs
├── package.json
└── README.md
```

## Lokasi penting
| Bagian | Lokasi |
|---|---|
| Beranda | `src/pages/index.astro` |
| Navigasi halaman dalam | `src/layouts/SecondaryLayout.astro` |
| Halaman Game | `src/pages/game.astro` |
| Data katalog game | `src/data/games.js` |
| Gaya dasar | `src/styles/global.css` |
| Animasi | `src/styles/animations.css` |
| Aset publik | `public/` |

## Menambah game
1. Buka `src/data/games.js`.
2. Tambahkan objek dengan `title`, `description`, `category`, `icon`, dan `status`.
3. Gunakan `status: 'available'` hanya jika game sudah dibuat dan diuji.
4. Game yang belum siap memakai `status: 'soon'`.

## Tech stack & perintah
- [Astro](https://astro.build/), HTML, CSS, JavaScript
- Cloudflare Pages untuk hosting static
- GitHub untuk source control

```bash
npm install
npm run dev
npm run build
npm run preview
```

Build output berada di folder `dist/`. Konfigurasi Cloudflare Pages: build command `npm run build`, output directory `dist`, production branch `main`.

## Prinsip pengembangan
- Pisahkan data dari tampilan agar konten mudah diperbarui.
- Gunakan komponen bersama untuk elemen yang muncul di banyak halaman.
- Hormati `prefers-reduced-motion` agar animasi ramah aksesibilitas.
- Jangan menandai fitur sebagai aktif sebelum benar-benar tersedia.
- Logo resmi dipasang setelah file logo asli diberikan.


## VANNDIK CMS

CMS admin tersedia sebagai Progressive Web App (PWA) di `/admin/` dan dapat dipasang dari browser desktop atau mobile.

### Fitur
- Manajemen artikel, berita, produk affiliate, game, dan aplikasi/tools.
- Draft, publikasi, jadwal, kategori, slug, thumbnail URL, tautan, dan konten unggulan.
- Pengaturan tema global dan override tema tiap halaman.
- Pengaturan navigasi, footer, dan daftar bahasa.
- Login password dengan PBKDF2-SHA256, sesi HttpOnly, serta passkey WebAuthn (sidik jari, Face ID, Windows Hello, PIN perangkat, atau security key).
- Konten terbit dan tema dibaca oleh website melalui Pages Functions API.

### Infrastruktur Cloudflare
- D1 database: `vanndik-cms`
- Pages D1 binding: `CMS_DB`
- Pages Functions: `functions/api/cms/` dan `functions/api/public/`
- PWA manifest dan service worker: `public/manifest.webmanifest`, `public/admin-sw.js`
- Media storage: Google Drive akun `dickv940@gmail.com`, folder `VANNDIK Media`; OAuth refresh token dienkripsi di D1.

### Aktivasi awal admin
1. Di Cloudflare Dashboard buka **Workers & Pages → vanndik → Settings → Variables and Secrets**.
2. Tambahkan secret bernama `CMS_SETUP_TOKEN` pada **Production** (dan Preview bila diperlukan). Buat token acak panjang milik sendiri; jangan masukkan ke GitHub atau source code.
3. Simpan lalu redeploy Pages.
4. Buka `https://vanndik.pages.dev/admin/`, masukkan token aktivasi, nama, email admin, dan password minimal 12 karakter.
5. Setelah masuk, buka **Keamanan Admin** lalu daftarkan passkey di perangkat. Browser/perangkat akan menawarkan sidik jari, Face ID, Windows Hello, atau metode verifikasi perangkat yang tersedia.
6. Untuk memasang aplikasi, gunakan tombol **Install App** jika tersedia, atau menu browser **Install app / Add to Home Screen**.

### Integrasi Google Drive untuk media website
Media Library CMS menggunakan Google Drive akun `dickv940@gmail.com`. File disimpan di folder `VANNDIK Media`; metadata dan refresh token terenkripsi disimpan di Cloudflare D1. R2 tidak diperlukan untuk alur ini.

1. Buka [Google Cloud Console](https://console.cloud.google.com/).
2. Pilih atau buat project Google Cloud, lalu aktifkan **Google Drive API**.
3. Konfigurasikan Google Auth Platform / OAuth consent screen. Jika aplikasi masih berstatus Testing, tambahkan `dickv940@gmail.com` sebagai test user.
4. Buat OAuth Client ID dengan tipe **Web application**.
5. Tambahkan Authorized redirect URI persis: `https://vanndik.pages.dev/api/cms/drive/callback`.
6. Di Cloudflare Dashboard → Workers & Pages → `vanndik` → Settings → Variables and Secrets → Production, tambahkan tiga secrets:
   - `GOOGLE_DRIVE_CLIENT_ID` — OAuth Client ID dari Google Cloud.
   - `GOOGLE_DRIVE_CLIENT_SECRET` — OAuth Client Secret.
   - `GOOGLE_DRIVE_TOKEN_KEY` — kunci acak rahasia minimal 32 karakter. Contoh membuat nilai acak di PowerShell: `[guid]::NewGuid().ToString("N") + [guid]::NewGuid().ToString("N")`.
7. Simpan secrets lalu deploy ulang Pages.
8. Login ke `https://vanndik.pages.dev/admin/`, buka **Media Library**, lalu pilih **Hubungkan Google Drive** dan login menggunakan `dickv940@gmail.com`.
9. Setujui akses Drive. CMS akan membuat folder `VANNDIK Media` secara otomatis.

**Batas dan privasi media**
- CMS menerima JPG, PNG, WEBP, GIF, dan AVIF hingga 8 MB per file; SVG ditolak.
- File yang diunggah diberi izin pembaca publik agar gambar dapat tampil di website. Jangan unggah dokumen pribadi atau file sensitif.
- Kapasitas mengikuti sisa kuota Google Drive akun (kuota gratis Google dibagi dengan Gmail dan Google Photos).
- Google Drive berfungsi sebagai penyimpanan, bukan CDN khusus. Kecepatan dan batas akses gambar mengikuti layanan Google.
- Hapus media yang masih dipakai konten akan ditolak sampai URL gambar pada konten diganti.

**Penting:** Jangan commit OAuth Client Secret atau kunci enkripsi ke GitHub dan jangan membagikannya di chat. CMS tetap memerlukan secret `CMS_SETUP_TOKEN` untuk membuat admin owner pertama.