# Sistem Nilai Zero Trust

Tugas Praktikum Individu — Keamanan Informasi (KP70065004), Informatika Universitas Siliwangi.

Sistem Nilai yang **tidak percaya pada siapa pun**, termasuk jaringan internalnya sendiri. Semua akses (user maupun antar-service) dicegat API Gateway (PEP), diputuskan Policy Engine (PE/PA) berdasarkan token **dan** data di database, lalu dicatat di audit log. Mengikuti NIST SP 800-207.

```
Client ──token + X-Device-ID──▶ ┌─ API Gateway :3000 (PEP) ─┐ ──allow + X-Gateway-Secret──▶ Service Nilai :3001
                                │  policy.js  (PE/PA)       │                                    │ finalisasi
                                │  auth.js    (login/token) │ ◀── token service + sinkron ───────┘
                                │  audit_log                │ ──allow + X-Gateway-Secret──▶ Service Transkrip :3002
                                └───────────────────────────┘                  semua service ⇄ SQLite (data/sistem.db)
```

## Cara menjalankan

Butuh **Node.js 22.13 atau lebih baru**. Database memakai SQLite bawaan Node (`node:sqlite`), jadi tidak ada paket native yang dikompilasi dan tidak perlu Visual Studio / Python.

```bash
npm install
npm run setup      # membuat keypair RS256, .env (rahasia acak), database + data awal
npm start          # gateway + 2 service dalam satu terminal; log gateway = audit log live
```

Terminal lain:

```bash
npm run redteam    # 54 skenario serangan otomatis; semua harus hijau
npm run audit -- -f --deny   # pantau penolakan secara live (hapus --deny untuk semua)
npm run reset      # kembalikan data awal (aman saat sistem berjalan)
```

## Akun & device data awal

| username | password | role | NIM | X-Device-ID |
|---|---|---|---|---|
| `admin` | `Admin#123` | admin | – | `DEV-ADMIN-01` |
| `dosen1` (Pak Budi) | `Dosen#123` | dosen — mengampu **Keamanan Informasi** (kelas 1) | – | `DEV-DOSEN1-LAPTOP` |
| `dosen2` (Bu Sari) | `Dosen#123` | dosen — mengampu **Basis Data** (kelas 2) | – | `DEV-DOSEN2-LAPTOP` |
| `mahasiswa1` | `Mhs#12345` | mahasiswa | 247006111001 | `DEV-MHS1-HP` |
| `mahasiswa2` | `Mhs#12345` | mahasiswa | 247006111002 | `DEV-MHS2-HP` |
| `mahasiswa3` | `Mhs#12345` | mahasiswa | 247006111003 | `DEV-MHS3-HP` |

Nilai `id` 1–3 = kelas 1 (mahasiswa1..3), `id` 4–6 = kelas 2. Client service: `svc-nilai` (secret ada di `.env`).

## Contoh curl

```bash
# login → simpan access_token
curl -s -X POST localhost:3000/auth/login -H 'Content-Type: application/json' \
  -H 'X-Device-ID: DEV-DOSEN1-LAPTOP' -d '{"username":"dosen1","password":"Dosen#123"}'

TOKEN=...   # isi dengan access_token
curl -s localhost:3000/nilai -H "Authorization: Bearer $TOKEN" -H 'X-Device-ID: DEV-DOSEN1-LAPTOP'
curl -s -X PUT localhost:3000/nilai/1 -H "Authorization: Bearer $TOKEN" -H 'X-Device-ID: DEV-DOSEN1-LAPTOP' \
  -H 'Content-Type: application/json' -d '{"nilai":95}'
curl -s -X POST localhost:3000/kelas/1/finalisasi -H "Authorization: Bearer $TOKEN" -H 'X-Device-ID: DEV-DOSEN1-LAPTOP'
```

## Postman

1. Jalankan `npm start`.
2. Postman → **Import** → pilih `postman/zero-trust-nilai.postman_collection.json`.
3. Jalankan folder **0. Login** dulu: token tersimpan otomatis ke variabel koleksi (`dosen1_token`, dll.).
4. Jalankan folder lain satu per satu. Nama request memuat status yang diharapkan, mis. `[harus 403]`; tab *Test Results* hijau bila pertahanan bekerja.
5. Reset data bila perlu mengulang dari awal: `npm run reset`.

Jam akses diatur di `config/policy.json` (`jamMulai`, `jamSelesai`, `zonaWaktu`), dibaca ulang **setiap request** tanpa restart. Untuk demo "di luar jam", ubah angkanya, simpan, coba lagi.

## Keputusan desain yang membedakan implementasi ini

- **JWT RS256, bukan HS256.** Hanya gateway memegang `private.pem`. Service hanya punya public key, jadi service yang diretas **tidak bisa memalsukan token**.
- **Token terikat device** (`dev` di dalam token). Token yang dicuri dan dipakai dari device lain ditolak.
- **Refresh token dirotasi + deteksi pemakaian ulang.** Refresh token lama yang dipakai lagi dianggap pencurian → semua sesi user dicabut (*assume breach*).
- **Default deny.** Rute yang tidak ada di tabel kebijakan otomatis ditolak.
- **Pertahanan berlapis.** Service tidak sekadar percaya gateway: ia cek gateway secret, tanda tangan token, lalu **memeriksa ulang kepemilikan data** (mis. `UPDATE ... WHERE kelas_id IN (kelas milik dosen) AND final=0` dalam satu query atomik).
- **Login tidak membocorkan** apakah username ada (pesan seragam; alasan sebenarnya hanya di audit log).
- **Finalisasi aman dari kegagalan sebagian:** nilai baru ditandai final **setelah** sinkron transkrip sukses; sinkron idempoten sehingga aman diulang.
- Password & client secret di-hash `scrypt`; perbandingan gateway secret waktu-konstan.

## Struktur

```
gateway/           index.js (PEP) · policy.js (PE/PA) · auth.js (token) · audit.js
service-nilai/     Service Nilai :3001
service-transkrip/ Service Transkrip :3002
shared/            config · db (skema) · crypto (scrypt) · serviceGuard
scripts/           seed · start-all · redteam · audit-tail
config/policy.json jam akses (hot reload)
```
