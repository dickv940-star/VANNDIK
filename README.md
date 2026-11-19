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
- Media uploads: membutuhkan R2 bucket dan binding `CMS_MEDIA` (belum aktif).

### Aktivasi awal admin
1. Di Cloudflare Dashboard buka **Workers & Pages → vanndik → Settings → Variables and Secrets**.
2. Tambahkan secret bernama `CMS_SETUP_TOKEN` pada **Production** (dan Preview bila diperlukan). Buat token acak panjang milik sendiri; jangan masukkan ke GitHub atau source code.
3. Simpan lalu redeploy Pages.
4. Buka `https://vanndik.pages.dev/admin/`, masukkan token aktivasi, nama, email admin, dan password minimal 12 karakter.
5. Setelah masuk, buka **Keamanan Admin** lalu daftarkan passkey di perangkat. Browser/perangkat akan menawarkan sidik jari, Face ID, Windows Hello, atau metode verifikasi perangkat yang tersedia.
6. Untuk memasang aplikasi, gunakan tombol **Install App** jika tersedia, atau menu browser **Install app / Add to Home Screen**.

### Mengaktifkan unggah gambar
1. Aktifkan R2 Object Storage pada akun Cloudflare.
2. Buat bucket bernama `vanndik-media`.
3. Tambahkan binding R2 bernama `CMS_MEDIA` ke Pages project `vanndik`.
4. Implementasikan route upload yang memvalidasi tipe file, ukuran, dan autentikasi admin sebelum menulis ke bucket.

**Penting:** Jangan bagikan kode aktivasi atau password. CMS hanya dapat digunakan setelah secret `CMS_SETUP_TOKEN` diatur dan admin owner pertama dibuat.