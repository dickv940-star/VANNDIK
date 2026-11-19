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
