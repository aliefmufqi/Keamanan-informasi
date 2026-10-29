// Policy Engine / Policy Administrator (PE/PA, NIST SP 800-207).
// decide() = fungsi murni: (request + atribut dari database) -> { allow, reason, target }.
// Prinsip: DEFAULT DENY. Rute yang tidak tercantum di tabel ROUTES otomatis ditolak.
const { loadPolicyConfig } = require('../shared/config');

// ---------- Verifikasi konteks (4.3) ----------
function jamSekarang(now = new Date()) {
  const { zonaWaktu } = loadPolicyConfig();
  const p = new Intl.DateTimeFormat('en-GB', {
    timeZone: zonaWaktu, hour: '2-digit', minute: '2-digit', hour12: false,
  }).formatToParts(now);
  const h = +p.find(x => x.type === 'hour').value % 24;
  const m = +p.find(x => x.type === 'minute').value;
  return h + m / 60;
}

function dalamJamAkses(now) {
  const { jamMulai, jamSelesai } = loadPolicyConfig(); // dibaca ulang tiap request
  const j = jamSekarang(now);
  return { ok: j >= jamMulai && j < jamSelesai, jamMulai, jamSelesai };
}

function cekJam(ctx) {
  const { ok, jamMulai, jamSelesai } = dalamJamAkses(ctx.now);
  return ok ? null : `di luar jam akses (${String(jamMulai).padStart(2, '0')}.00-${String(jamSelesai).padStart(2, '0')}.00)`;
}

// ---------- Atribut dari database (kepemilikan data) ----------
const q = {
  user: db => db.prepare('SELECT id,username,role,nim,aktif FROM users WHERE id=?'),
  device: db => db.prepare('SELECT 1 FROM devices WHERE user_id=? AND device_id=?'),
  kelas: db => db.prepare('SELECT id,dosen_id FROM kelas WHERE id=?'),
  nilai: db => db.prepare('SELECT n.id,n.final,k.dosen_id FROM nilai n JOIN kelas k ON k.id=n.kelas_id WHERE n.id=?'),
};

// ---------- Tabel kebijakan (Tabel 3 pada soal) ----------
// Setiap aturan: method, pola path, service tujuan, role yang diizinkan, dan pemeriksaan kepemilikan.
const ROUTES = [
  {
    method: 'GET', re: /^\/nilai$/, target: 'nilai', roles: ['mahasiswa', 'dosen'],
    check: (ctx, db) => {
      const { nim, kelas_id } = ctx.query;
      if (ctx.user.role === 'mahasiswa' && nim && nim !== ctx.user.nim)
        return 'mahasiswa hanya boleh melihat nilai miliknya sendiri';
      if (ctx.user.role === 'dosen' && kelas_id) {
        const k = q.kelas(db).get(+kelas_id);
        if (!k || k.dosen_id !== ctx.user.id) return 'kelas bukan yang diampu dosen ini';
      }
      return null; // sisanya difilter Service Nilai berdasarkan identitas di token
    },
  },
  {
    method: 'PUT', re: /^\/nilai\/(\d+)$/, target: 'nilai', roles: ['dosen'],
    check: (ctx, db, [id]) => {
      const n = q.nilai(db).get(+id);
      if (!n || n.dosen_id !== ctx.user.id) return 'nilai bukan dari kelas yang diampu dosen ini';
      if (n.final) return 'nilai sudah final dan tidak bisa diubah';
      return cekJam(ctx);
    },
  },
  {
    method: 'POST', re: /^\/kelas\/(\d+)\/finalisasi$/, target: 'nilai', roles: ['dosen'],
    check: (ctx, db, [id]) => {
      const k = q.kelas(db).get(+id);
      if (!k || k.dosen_id !== ctx.user.id) return 'kelas bukan yang diampu dosen ini';
      return cekJam(ctx);
    },
  },
  {
    method: 'GET', re: /^\/transkrip\/(\d{6,20})$/, target: 'transkrip', roles: ['mahasiswa', 'admin'],
    check: (ctx, db, [nim]) =>
      ctx.user.role === 'admin' || ctx.user.nim === nim ? null : 'mahasiswa hanya boleh melihat transkrip NIM sendiri',
  },
  {
    // Hanya token service. Token user mana pun (termasuk admin) ditolak oleh pengecekan role.
    method: 'POST', re: /^\/transkrip\/sinkron$/, target: 'transkrip', roles: ['service'],
    check: ctx => (ctx.auth.typ === 'service' ? null : 'wajib token service'),
  },
];

// ---------- Keputusan ----------
function decide(db, ctx) {
  const path = ctx.path;
  let rule, params;
  for (const r of ROUTES) {
    const m = r.method === ctx.method && r.re.exec(path);
    if (m) { rule = r; params = m.slice(1); break; }
  }
  if (!rule) return { allow: false, reason: 'tidak ada kebijakan untuk endpoint ini (default deny)' };

  // 1. Harus punya token valid (diverifikasi gateway sebelum masuk sini)
  if (!ctx.auth) return { allow: false, reason: ctx.authError || 'access token tidak ada' };

  // 2. Role pada token harus termasuk yang diizinkan
  if (!rule.roles.includes(ctx.auth.role))
    return { allow: false, reason: `role '${ctx.auth.role}' tidak diizinkan untuk endpoint ini` };

  if (ctx.auth.role === 'service') {
    // Service dikenali dari client_id terdaftar, bukan dari device
    const c = db.prepare('SELECT 1 FROM service_clients WHERE client_id=?').get(ctx.auth.sub);
    if (!c) return { allow: false, reason: 'client service tidak terdaftar' };
  } else {
    // 3. Atribut subjek dari database (token saja tidak cukup)
    const user = q.user(db).get(+ctx.auth.sub);
    if (!user || !user.aktif) return { allow: false, reason: 'akun tidak ditemukan atau nonaktif' };
    if (user.role !== ctx.auth.role) return { allow: false, reason: 'role di token tidak sesuai database' };
    ctx.user = user;

    // 4. Device harus terdaftar untuk user ini, dan sama dengan device saat login
    if (!ctx.device) return { allow: false, reason: 'header X-Device-ID tidak ada' };
    if (!q.device(db).get(user.id, ctx.device)) return { allow: false, reason: 'device tidak terdaftar untuk user ini' };
    if (ctx.auth.dev !== ctx.device) return { allow: false, reason: 'token diterbitkan untuk device lain' };
  }

  // 5. Pemeriksaan kepemilikan data + konteks (jam akses)
  const why = rule.check(ctx, db, params);
  if (why) return { allow: false, reason: why };

  return { allow: true, reason: 'sesuai kebijakan', target: rule.target };
}

module.exports = { decide, dalamJamAkses, ROUTES };
