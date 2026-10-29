# Naskah video demo (target ±8 menit)

Siapkan dua terminal berdampingan + editor. Terminal A: `npm start`. Terminal B: perintah demo. Opsional terminal C: `npm run audit -- -f`.

| Menit | Apa yang ditunjukkan | Yang diucapkan (inti) |
|---|---|---|
| 0:00 | Diagram di README + struktur folder | "Gateway adalah satu-satunya pintu. Service tidak bisa diakses langsung. Ini PEP, PE/PA, dan resource sesuai NIST 800-207." |
| 0:45 | `gateway/auth.js` login, `issueAccess`, `issueRefresh` | "Access token 10 menit RS256. Refresh token disimpan di DB supaya bisa dicabut. Hanya gateway punya private key." |
| 1:45 | Demo login `dosen1`, lalu login dengan device dosen2 → ditolak | "Kredensial benar saja tidak cukup, device harus terdaftar." |
| 2:30 | `gateway/policy.js` → `ROUTES` dan `decide` | "Tabel 3 jadi kode. Default deny. Kepemilikan kelas dibaca dari database karena token tidak memuatnya." |
| 3:30 | Demo: dosen1 `PUT /nilai/1` ✔, `PUT /nilai/4` ✘; mahasiswa1 `?nim=` orang lain ✘ | "Least privilege: satu role, satu batas." |
| 4:30 | Ubah `config/policy.json` ke jam lain → `PUT` ditolak → kembalikan | "Jam akses hot reload, tanpa restart." |
| 5:15 | `shared/serviceGuard.js` + demo `curl localhost:3001/nilai` ✘, dengan secret saja ✘ | "Dua lapis: secret dan token. Secret bocor pun tetap ditolak." |
| 6:00 | Finalisasi kelas 1 → lihat `service-nilai/index.js` baris 73, `tokenService` → transkrip mahasiswa1 terisi; coba sinkron pakai token admin ✘ | "Service Nilai memanggil lewat gateway dengan token service. Token user mana pun ditolak." |
| 7:00 | `npm run audit` | "Setiap keputusan tercatat: waktu, subjek, endpoint, device, hasil, alasan." |
| 7:30 | `npm run redteam` sampai 54/54 hijau | "Token palsu, alg=none, token dicuri, refresh dipakai ulang: semuanya ditolak." |
| 8:15 | Penutup | "Never trust, always verify, least privilege, assume breach." |

Tips: jalankan `npm run reset` tepat sebelum merekam supaya data awal bersih.
