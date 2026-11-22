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
3. Konfigurasikan Google Auth Platform / OAuth consent screen. Tambahkan `dickv940@gmail.com` sebagai test user saat pengujian. **Sebelum dipakai jangka panjang, ubah Publishing status menjadi In production**: Google menyatakan refresh token untuk aplikasi External berstatus Testing (dengan scope Drive) akan kedaluwarsa setelah 7 hari. Status In production menghindari batas 7 hari tersebut, meskipun Google tetap dapat mencabut token karena alasan keamanan atau pengguna mencabut izin. [Dokumentasi masa berlaku token](https://developers.google.com/identity/protocols/oauth2#expiration).
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
## Cloud AI Orchestrator (zero-cost policy)

The AI Agent Room supports ordered provider failover. External providers are disabled unless both their secret and an explicit `*_FREE_ONLY=true` variable are configured. This is a safety gate, not a guarantee that a provider will always offer free quota; verify the provider's current terms before enabling it.

Provider order:
1. Gemini: `GEMINI_API_KEY` secret, `GEMINI_FREE_ONLY=true` variable, optional `GEMINI_MODEL`.
2. Cloudflare Workers AI: existing `AI` binding, optional `CF_AI_MODEL` (default `@cf/google/gemma-4-26b-a4b-it`).
3. Hosted Gemma endpoint: `GEMMA_API_URL`, `GEMMA_API_KEY` secrets, `GEMMA_FREE_ONLY=true` variable, optional `GEMMA_MODEL`. The endpoint must be OpenAI Chat Completions-compatible and confirmed free.
4. Groq: `GROQ_API_KEY` secret, `GROQ_FREE_ONLY=true` variable, optional `GROQ_MODEL`.
5. OpenRouter free model: `OPENROUTER_API_KEY` secret, `OPENROUTER_FREE_ONLY=true` variable, and `OPENROUTER_MODEL` ending in `:free`.

Never configure a paid-only model or enable a provider unless its account is confirmed to have a free allocation. No OpenAI API is called by this failover chain. ChatGPT subscriptions do not provide OpenAI API credits.

### Central memory and queue

- `cms_ai_memory` stores shared identity, goals, operating rules, and architecture context in D1.
- `GET /api/cms/ai-room/memory` reads central memory; authenticated `PUT` updates the four approved sections.
- `cms_ai_room_jobs` persists requests when every configured provider is unavailable.
- `POST /api/cms/ai-room/jobs/process` is a protected retry endpoint requiring `AI_JOBS_CRON_TOKEN`.
- `GET /api/cms/ai-room/jobs` lists queued/completed/paused jobs for the authenticated admin.

### Scheduled retry Worker

The scheduler source is in `workers/ai-room-scheduler/index.js`. Deploy it as a separate Cloudflare Worker with:
- Cron Trigger: `*/5 * * * *`
- Plain-text variable `VANNDIK_CMS_URL=https://vanndik.pages.dev`
- Secret `VANNDIK_CRON_TOKEN`, matching the Pages secret `AI_JOBS_CRON_TOKEN`

The scheduler only calls the protected queue processor. It does not publish content or perform destructive actions. A job is retried with exponential backoff and paused after eight failed attempts. Confirm that the Worker is deployed and the Cron Trigger is active before treating unattended retry as operational.

### Important cost boundary

Cloudflare and third-party provider free tiers have changing quotas and terms. When all configured providers are unavailable, VANNDIK stores work for later retry. Do not add billing methods or paid fallbacks. The application cannot guarantee zero cost if an administrator independently enables a paid plan or changes provider configuration.
