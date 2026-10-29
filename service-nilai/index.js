// Service Nilai (port 3001) = Resource. Tidak bisa diakses langsung: wajib X-Gateway-Secret + token valid.
// Selain itu kepemilikan data DIPERIKSA ULANG di sini (pertahanan berlapis, bukan hanya percaya gateway).
const express = require('express');
const cfg = require('../shared/config');
const { open } = require('../shared/db');
const { guard } = require('../shared/serviceGuard');

const db = open();
const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '10kb' }));
app.use(guard({ nama: 'service-nilai' }));

// Hanya token user (bukan token service) yang boleh memakai endpoint ini
const userOnly = (req, res, next) =>
  req.auth.typ === 'access' ? next() : res.status(403).json({ error: 'token service tidak boleh dipakai di sini' });
app.use(userOnly);

const me = (req) => db.prepare('SELECT id,role,nim FROM users WHERE id=? AND aktif=1').get(+req.auth.sub);

// ---- Token service untuk memanggil gateway (client credentials, di-cache sampai hampir habis) ----
let svc = { token: null, exp: 0 };
async function tokenService() {
  if (svc.token && Date.now() < svc.exp - 30_000) return svc.token;
  const r = await fetch(`${cfg.GATEWAY_URL}/auth/service`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ client_id: cfg.SERVICE_CLIENT_ID, client_secret: cfg.SERVICE_CLIENT_SECRET }),
  });
  if (!r.ok) throw new Error(`gagal minta token service (${r.status})`);
  const j = await r.json();
  svc = { token: j.access_token, exp: Date.now() + j.expires_in * 1000 };
  return svc.token;
}

// GET /nilai  -> mahasiswa: hanya miliknya; dosen: hanya kelas yang diampu
app.get('/nilai', (req, res) => {
  const u = me(req);
  if (!u) return res.status(403).json({ error: 'akun tidak valid' });
  const base = `SELECT n.id, n.kelas_id, k.nama AS kelas, n.nim, n.nilai, n.final
                FROM nilai n JOIN kelas k ON k.id = n.kelas_id`;
  let rows;
  if (u.role === 'mahasiswa') rows = db.prepare(`${base} WHERE n.nim = ? ORDER BY n.kelas_id`).all(u.nim);
  else if (u.role === 'dosen') {
    rows = db.prepare(`${base} WHERE k.dosen_id = ? AND (? IS NULL OR n.kelas_id = ?) ORDER BY n.kelas_id, n.nim`)
      .all(u.id, req.query.kelas_id ?? null, req.query.kelas_id ?? null);
  } else return res.status(403).json({ error: 'role tidak diizinkan' });
  res.json(rows);
});

// PUT /nilai/:id  -> kelas diampu, belum final
app.put('/nilai/:id', (req, res) => {
  const u = me(req);
  const v = req.body?.nilai;
  if (!Number.isFinite(v) || v < 0 || v > 100) return res.status(400).json({ error: 'nilai harus angka 0-100' });
  // Kepemilikan + status final dicek dalam satu UPDATE atomik
  const r = db.prepare(`UPDATE nilai SET nilai = ?
      WHERE id = ? AND final = 0 AND kelas_id IN (SELECT id FROM kelas WHERE dosen_id = ?)`)
    .run(v, +req.params.id, u?.role === 'dosen' ? u.id : -1);
  if (!r.changes) return res.status(403).json({ error: 'tidak boleh mengubah nilai ini' });
  res.json({ ok: true, id: +req.params.id, nilai: v });
});

// POST /kelas/:id/finalisasi -> kirim ke Service Transkrip LEWAT GATEWAY dengan token service
app.post('/kelas/:id/finalisasi', async (req, res) => {
  const u = me(req);
  const kelas = db.prepare('SELECT * FROM kelas WHERE id=? AND dosen_id=?').get(+req.params.id, u?.role === 'dosen' ? u.id : -1);
  if (!kelas) return res.status(403).json({ error: 'kelas bukan milik dosen ini' });
  const rows = db.prepare('SELECT nim, nilai, final FROM nilai WHERE kelas_id=?').all(kelas.id);
  if (rows.some(r => r.nilai === null)) return res.status(409).json({ error: 'masih ada nilai kosong' });
  if (rows.every(r => r.final)) return res.status(409).json({ error: 'kelas sudah final' });

  try {
    const r = await fetch(`${cfg.GATEWAY_URL}/transkrip/sinkron`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${await tokenService()}` },
      body: JSON.stringify({ kelas_id: kelas.id, mata_kuliah: kelas.nama, entries: rows.map(({ nim, nilai }) => ({ nim, nilai })) }),
    });
    if (!r.ok) return res.status(502).json({ error: 'sinkron transkrip gagal, kelas BELUM final', detail: await r.json().catch(() => null) });
  } catch (e) {
    return res.status(502).json({ error: `sinkron transkrip gagal: ${e.message}` });
  }
  db.prepare('UPDATE nilai SET final=1 WHERE kelas_id=?').run(kelas.id); // sinkron bersifat idempoten -> aman diulang
  res.json({ ok: true, kelas: kelas.nama, mahasiswa: rows.length, status: 'final & tersinkron ke transkrip' });
});

app.listen(cfg.ports.nilai, '127.0.0.1', () => console.log(`[service-nilai] :${cfg.ports.nilai}`));
