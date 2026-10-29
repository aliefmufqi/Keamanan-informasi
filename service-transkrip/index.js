// Service Transkrip (port 3002) = Resource. Sama seperti Service Nilai: gateway secret + token wajib.
const express = require('express');
const cfg = require('../shared/config');
const { open } = require('../shared/db');
const { guard } = require('../shared/serviceGuard');

const db = open();
const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '100kb' }));
app.use(guard({ nama: 'service-transkrip' }));

// POST /transkrip/sinkron -> HANYA token service. Token user (termasuk admin) ditolak.
app.post('/transkrip/sinkron', (req, res) => {
  if (req.auth.typ !== 'service' || req.auth.role !== 'service')
    return res.status(403).json({ error: 'hanya token service' });
  const { kelas_id, mata_kuliah, entries } = req.body || {};
  if (!Number.isInteger(kelas_id) || typeof mata_kuliah !== 'string' || !Array.isArray(entries))
    return res.status(400).json({ error: 'payload tidak valid' });
  const up = db.prepare(`INSERT INTO transkrip (nim,kelas_id,mata_kuliah,nilai) VALUES (?,?,?,?)
                         ON CONFLICT(nim,kelas_id) DO UPDATE SET nilai=excluded.nilai`);
  db.transaction(() => {
    for (const e of entries) {
      if (typeof e.nim !== 'string' || !Number.isFinite(e.nilai)) throw new Error('entry tidak valid');
      up.run(e.nim, kelas_id, mata_kuliah, e.nilai);
    }
  })();
  res.json({ ok: true, disinkron: entries.length });
});

// GET /transkrip/:nim -> mahasiswa: NIM sendiri; admin: semua NIM
app.get('/transkrip/:nim', (req, res) => {
  if (req.auth.typ !== 'access') return res.status(403).json({ error: 'token service tidak boleh dipakai di sini' });
  const u = db.prepare('SELECT role,nim FROM users WHERE id=? AND aktif=1').get(+req.auth.sub);
  if (!u || !(u.role === 'admin' || (u.role === 'mahasiswa' && u.nim === req.params.nim)))
    return res.status(403).json({ error: 'tidak boleh melihat transkrip ini' });
  const mk = db.prepare('SELECT kelas_id, mata_kuliah, nilai FROM transkrip WHERE nim=? ORDER BY kelas_id').all(req.params.nim);
  res.json({ nim: req.params.nim, mata_kuliah: mk, rata_rata: mk.length ? +(mk.reduce((a, b) => a + b.nilai, 0) / mk.length).toFixed(2) : null });
});

app.use((err, req, res, next) => res.status(400).json({ error: err.message }));
app.listen(cfg.ports.transkrip, '127.0.0.1', () => console.log(`[service-transkrip] :${cfg.ports.transkrip}`));
