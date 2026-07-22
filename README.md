# Sijas Farm

Aplikasi mobile-friendly untuk mencatat produksi telur, penjualan harian, stok, pengeluaran, dan laporan Sijas Farm.

## Arsitektur

- Frontend statis: Cloudflare Pages
- API: Cloudflare Pages Functions
- Database: Cloudflare D1
- Tampilan: light mode dan dark mode
- Chart: SVG native tanpa library/CDN eksternal

## Fitur

- Produksi harian: butir dan kilogram.
- Satu record per tanggal dengan mekanisme upsert/replace.
- Penjualan harian Rumahan dan Warung.
- Harga default dapat diubah dan harga harian tetap editable.
- Pengeluaran insidental.
- Stok awal dan penyesuaian stok.
- Peringatan jika input dilakukan sebelum pukul 18.00 WIB.
- Grafik produksi dan penjualan 30 hari.
- Riwayat, laporan periode, CSV, dan backup JSON.
- Login dengan PIN dan role admin/operator dasar.
- Responsive untuk HP dan laptop.

## Deploy ke Cloudflare Pages

### 1. Buat D1 database

```bash
npm install
npx wrangler login
npx wrangler d1 create sijas-farm-db
```

Salin `database_id` dari hasil perintah ke `wrangler.jsonc`.

### 2. Jalankan migration

```bash
npm run db:migrate:remote
```

### 3. Buat project Pages dari GitHub

Push folder ini ke GitHub, lalu di Cloudflare:

1. Workers & Pages → Create → Pages → Connect to Git.
2. Pilih repository.
3. Build command: `exit 0`
4. Build output directory: `public`
5. Deploy.

Folder `functions/` harus tetap berada di root repository. Cloudflare akan membuat route API secara otomatis.

### 4. Hubungkan D1

Di project Pages:

1. Settings → Bindings.
2. Add binding → D1 database.
3. Variable name: `DB`
4. Pilih database `sijas-farm-db`.
5. Simpan lalu redeploy.

### 5. Tambahkan secret setup

Di Settings → Variables and Secrets, tambahkan secret:

```text
SETUP_KEY=buat-kunci-rahasia-yang-panjang
```

Redeploy. Saat website pertama dibuka, form setup akan meminta kunci ini untuk membuat admin pertama.

## Development lokal

Setelah `database_id` sudah benar:

```bash
npm install
npm run db:migrate:local
npm run dev
```

Buka alamat yang ditampilkan Wrangler.

## Catatan keamanan

- Jangan commit `SETUP_KEY` ke Git.
- Gunakan PIN minimal 4 digit; lebih panjang lebih baik.
- Session disimpan dalam cookie HttpOnly, Secure, SameSite=Strict.
- PIN disimpan menggunakan PBKDF2, bukan plain text.
- Untuk aplikasi publik yang lebih besar, tambahkan rate limiting dan recovery akun.
