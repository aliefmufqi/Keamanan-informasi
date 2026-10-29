// RED TEAM: simulasi serangan otomatis terhadap sistem yang sedang berjalan (`npm start` di terminal lain).
// Tiap skenario menyatakan hasil yang DIHARAPKAN; keluaran hijau = pertahanan bekerja.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
const jwt = require('jsonwebtoken');

execFileSync(process.execPath, [path.join(__dirname, 'seed.js')], { stdio: 'ignore' }); // data awal bersih
const cfg = require('../shared/config');
const { open } = require('../shared/db');

const GW = cfg.GATEWAY_URL, NILAI = `http://127.0.0.1:${cfg.ports.nilai}`;
const DEV = { admin: 'DEV-ADMIN-01', dosen1: 'DEV-DOSEN1-LAPTOP', dosen2: 'DEV-DOSEN2-LAPTOP',
  mahasiswa1: 'DEV-MHS1-HP', mahasiswa2: 'DEV-MHS2-HP', mahasiswa3: 'DEV-MHS3-HP' };
const PW = (u) => (u === 'admin' ? 'Admin#123' : u.startsWith('dosen') ? 'Dosen#123' : 'Mhs#12345');
const NIM = { 1: '247006111001', 2: '247006111002', 3: '247006111003' };
const privateKey = fs.readFileSync(cfg.PRIVATE_KEY_FILE);   // hanya untuk memalsukan token kedaluwarsa di lab ini
const publicKey = fs.readFileSync(cfg.PUBLIC_KEY_FILE);

const c = { g: '\x1b[32m', r: '\x1b[31m', y: '\x1b[33m', b: '\x1b[1m', d: '\x1b[2m', o: '\x1b[0m' };
let pass = 0, fail = 0;

async function call(method, url, { token, device, body, headers = {} } = {}) {
  const h = { ...headers };
  if (token) h.Authorization = `Bearer ${token}`;
  if (device) h['X-Device-ID'] = device;
  if (body) h['Content-Type'] = 'application/json';
  const r = await fetch(url.startsWith('http') ? url : GW + url, { method, headers: h, body: body ? JSON.stringify(body) : undefined });
  let json = null; try { json = await r.json(); } catch {}
  return { status: r.status, json };
}
const login = async (u) => (await call('POST', '/auth/login', { device: DEV[u], body: { username: u, password: PW(u) } })).json;

function expect(nama, got, want, extra = true) {
  const ok = got === want && extra;
  ok ? pass++ : fail++;
  console.log(`  ${ok ? c.g + '✔' : c.r + '✘'}${c.o} ${nama} ${c.d}→ ${got}${ok ? '' : ` (seharusnya ${want})`}${c.o}`);
}
const bab = (t) => console.log(`\n${c.b}${c.y}▌ ${t}${c.o}`);

(async () => {
  console.log(`${c.b}ZERO TRUST RED TEAM${c.o} ${c.d}— menyerang ${GW}${c.o}`);
  const policyFile = path.join(cfg.ROOT, 'config', 'policy.json');
  const policyAsli = fs.readFileSync(policyFile, 'utf8');
  const setJam = (a, b) => fs.writeFileSync(policyFile, JSON.stringify({ ...JSON.parse(policyAsli), jamMulai: a, jamSelesai: b }));
  setJam(0, 24); // jam akses dibuka dulu agar skenario normal tidak terpengaruh waktu menjalankan
  try {
    const T = {};
    for (const u of Object.keys(DEV)) T[u] = await login(u);

    bab('1. Autentikasi & device');
    expect('login benar (dosen1)', (await call('POST', '/auth/login', { device: DEV.dosen1, body: { username: 'dosen1', password: 'Dosen#123' } })).status, 200);
    expect('password salah', (await call('POST', '/auth/login', { device: DEV.dosen1, body: { username: 'dosen1', password: 'salah' } })).status, 401);
    expect('kredensial benar tapi device milik orang lain', (await call('POST', '/auth/login', { device: DEV.dosen2, body: { username: 'dosen1', password: 'Dosen#123' } })).status, 401);
    expect('kredensial benar tanpa X-Device-ID', (await call('POST', '/auth/login', { body: { username: 'dosen1', password: 'Dosen#123' } })).status, 401);

    bab('2. Least privilege: mahasiswa');
    let r = await call('GET', '/nilai', { token: T.mahasiswa1.access_token, device: DEV.mahasiswa1 });
    expect('mahasiswa1 lihat nilai → hanya miliknya', r.status, 200, r.json.length === 2 && r.json.every(x => x.nim === NIM[1]));
    expect('mahasiswa1 intip nilai mahasiswa2 (?nim=)', (await call('GET', `/nilai?nim=${NIM[2]}`, { token: T.mahasiswa1.access_token, device: DEV.mahasiswa1 })).status, 403);
    expect('mahasiswa1 ubah nilai sendiri (PUT /nilai/1)', (await call('PUT', '/nilai/1', { token: T.mahasiswa1.access_token, device: DEV.mahasiswa1, body: { nilai: 100 } })).status, 403);
    expect('mahasiswa1 finalisasi kelas', (await call('POST', '/kelas/1/finalisasi', { token: T.mahasiswa1.access_token, device: DEV.mahasiswa1 })).status, 403);
    expect('mahasiswa1 buka transkrip mahasiswa2', (await call('GET', `/transkrip/${NIM[2]}`, { token: T.mahasiswa1.access_token, device: DEV.mahasiswa1 })).status, 403);

    bab('3. Least privilege: dosen & admin');
    r = await call('GET', '/nilai', { token: T.dosen1.access_token, device: DEV.dosen1 });
    expect('dosen1 lihat nilai → hanya kelas 1', r.status, 200, r.json.length === 3 && r.json.every(x => x.kelas_id === 1));
    expect('dosen1 minta kelas 2 (milik dosen2)', (await call('GET', '/nilai?kelas_id=2', { token: T.dosen1.access_token, device: DEV.dosen1 })).status, 403);
    expect('dosen1 ubah nilai kelas dosen2 (PUT /nilai/4)', (await call('PUT', '/nilai/4', { token: T.dosen1.access_token, device: DEV.dosen1, body: { nilai: 100 } })).status, 403);
    expect('dosen1 finalisasi kelas dosen2', (await call('POST', '/kelas/2/finalisasi', { token: T.dosen1.access_token, device: DEV.dosen1 })).status, 403);
    expect('dosen1 buka transkrip (bukan haknya)', (await call('GET', `/transkrip/${NIM[1]}`, { token: T.dosen1.access_token, device: DEV.dosen1 })).status, 403);
    expect('admin buka transkrip mahasiswa mana pun', (await call('GET', `/transkrip/${NIM[3]}`, { token: T.admin.access_token, device: DEV.admin })).status, 200);
    expect('admin ubah nilai', (await call('PUT', '/nilai/1', { token: T.admin.access_token, device: DEV.admin, body: { nilai: 100 } })).status, 403);
    expect('endpoint tak terdaftar → default deny', (await call('GET', '/admin/dump', { token: T.admin.access_token, device: DEV.admin })).status, 403);
    expect('dosen1 ubah nilai kelasnya sendiri', (await call('PUT', '/nilai/1', { token: T.dosen1.access_token, device: DEV.dosen1, body: { nilai: 90 } })).status, 200);

    bab('4. Konteks: device & jam akses');
    expect('token dosen1 dipakai dari device dosen2 (token dicuri)', (await call('GET', '/nilai', { token: T.dosen1.access_token, device: DEV.dosen2 })).status, 403);
    expect('token dosen1 tanpa X-Device-ID', (await call('GET', '/nilai', { token: T.dosen1.access_token })).status, 403);
    setJam(3, 4); // tutup jam akses (hot reload, gateway tidak di-restart)
    expect('jam akses ditutup: ubah nilai', (await call('PUT', '/nilai/1', { token: T.dosen1.access_token, device: DEV.dosen1, body: { nilai: 91 } })).status, 403);
    expect('jam akses ditutup: finalisasi', (await call('POST', '/kelas/1/finalisasi', { token: T.dosen1.access_token, device: DEV.dosen1 })).status, 403);
    expect('jam akses ditutup: membaca tetap boleh', (await call('GET', '/nilai', { token: T.dosen1.access_token, device: DEV.dosen1 })).status, 200);
    setJam(0, 24);

    bab('5. Pemalsuan token');
    const kosong = (x) => ({ device: DEV.dosen1, token: x });
    const [h, p, s] = T.dosen1.access_token.split('.');
    const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
    const payload = JSON.parse(Buffer.from(p, 'base64url'));
    expect('tanpa token', (await call('GET', '/nilai', { device: DEV.dosen1 })).status, 403);
    expect('tanda tangan diubah 1 karakter', (await call('GET', '/nilai', kosong(`${h}.${p}.${s.slice(0, -2)}${s.endsWith('A') ? 'B' : 'A'}A`))).status, 403);
    expect('alg=none (tanpa tanda tangan)', (await call('GET', '/nilai', kosong(`${b64({ alg: 'none', typ: 'JWT' })}.${b64({ ...payload, role: 'admin' })}.`))).status, 403);
    expect('role dinaikkan jadi admin, tanda tangan lama', (await call('GET', '/nilai', kosong(`${h}.${b64({ ...payload, role: 'admin' })}.${s}`))).status, 403);
    expect('alg confusion (HS256 bertanda tangan public key)', (await call('GET', '/nilai', kosong(
      jwt.sign({ ...payload, iss: cfg.ISSUER }, publicKey, { algorithm: 'HS256' })))).status, 403);
    expect('token kedaluwarsa', (await call('GET', '/nilai', kosong(
      jwt.sign({ typ: 'access', role: 'dosen', dev: DEV.dosen1 }, privateKey, { algorithm: 'RS256', issuer: cfg.ISSUER, subject: payload.sub, expiresIn: -60 })))).status, 403);
    expect('refresh token dipakai sebagai access token', (await call('GET', '/nilai', kosong(T.dosen1.refresh_token))).status, 403);

    bab('6. Refresh & logout');
    const rt = T.mahasiswa3.refresh_token;
    r = await call('POST', '/auth/refresh', { device: DEV.mahasiswa3, body: { refresh_token: rt } });
    expect('refresh normal → token baru', r.status, 200);
    const rt2 = r.json.refresh_token;
    expect('refresh dari device lain ditolak', (await call('POST', '/auth/refresh', { device: DEV.mahasiswa1, body: { refresh_token: rt2 } })).status, 401);
    expect('refresh token lama dipakai ulang (dicuri?)', (await call('POST', '/auth/refresh', { device: DEV.mahasiswa3, body: { refresh_token: rt } })).status, 401);
    expect('...akibatnya token baru ikut dicabut (assume breach)', (await call('POST', '/auth/refresh', { device: DEV.mahasiswa3, body: { refresh_token: rt2 } })).status, 401);
    const m2 = await login('mahasiswa2');
    expect('logout', (await call('POST', '/auth/logout', { body: { refresh_token: m2.refresh_token } })).status, 200);
    expect('refresh setelah logout', (await call('POST', '/auth/refresh', { device: DEV.mahasiswa2, body: { refresh_token: m2.refresh_token } })).status, 401);

    bab('7. Token service & panggilan antar-service');
    expect('/auth/service dengan secret salah', (await call('POST', '/auth/service', { body: { client_id: cfg.SERVICE_CLIENT_ID, client_secret: 'tebakan' } })).status, 401);
    const svc = (await call('POST', '/auth/service', { body: { client_id: cfg.SERVICE_CLIENT_ID, client_secret: cfg.SERVICE_CLIENT_SECRET } })).json;
    expect('token service diterbitkan', svc.access_token ? 200 : 0, 200);
    expect('admin menyuntik transkrip via /transkrip/sinkron (token user)', (await call('POST', '/transkrip/sinkron', { token: T.admin.access_token, device: DEV.admin, body: { kelas_id: 1, mata_kuliah: 'X', entries: [{ nim: NIM[1], nilai: 100 }] } })).status, 403);
    expect('dosen1 menyuntik transkrip via /transkrip/sinkron', (await call('POST', '/transkrip/sinkron', { token: T.dosen1.access_token, device: DEV.dosen1, body: { kelas_id: 1, mata_kuliah: 'X', entries: [] } })).status, 403);
    expect('token service dipakai membaca /nilai', (await call('GET', '/nilai', { token: svc.access_token })).status, 403);
    expect('token service dipakai membaca transkrip', (await call('GET', `/transkrip/${NIM[1]}`, { token: svc.access_token })).status, 403);

    bab('8. Menembus gateway (langsung ke service)');
    const secret = cfg.GATEWAY_SECRET;
    expect('langsung ke Service Nilai tanpa apa pun', (await call('GET', `${NILAI}/nilai`)).status, 403);
    expect('token user valid tapi tanpa gateway secret', (await call('GET', `${NILAI}/nilai`, { token: T.dosen1.access_token })).status, 403);
    expect('gateway secret bocor tapi tanpa token', (await call('GET', `${NILAI}/nilai`, { headers: { 'X-Gateway-Secret': secret } })).status, 401);
    expect('gateway secret bocor + token kedaluwarsa', (await call('GET', `${NILAI}/nilai`, { headers: { 'X-Gateway-Secret': secret },
      token: jwt.sign({ typ: 'access', role: 'dosen' }, privateKey, { algorithm: 'RS256', issuer: cfg.ISSUER, subject: payload.sub, expiresIn: -60 }) })).status, 401);
    expect('gateway secret bocor + token palsu (alg=none)', (await call('GET', `${NILAI}/nilai`, { headers: { 'X-Gateway-Secret': secret },
      token: `${b64({ alg: 'none', typ: 'JWT' })}.${b64({ ...payload, role: 'dosen' })}.` })).status, 401);

    bab('9. Alur finalisasi → transkrip (jalur sah)');
    r = await call('GET', `/transkrip/${NIM[1]}`, { token: T.mahasiswa1.access_token, device: DEV.mahasiswa1 });
    expect('sebelum finalisasi: transkrip mahasiswa1 kosong', r.status, 200, r.json.mata_kuliah.length === 0);
    expect('dosen1 finalisasi kelas 1', (await call('POST', '/kelas/1/finalisasi', { token: T.dosen1.access_token, device: DEV.dosen1 })).status, 200);
    r = await call('GET', `/transkrip/${NIM[1]}`, { token: T.mahasiswa1.access_token, device: DEV.mahasiswa1 });
    expect('transkrip mahasiswa1 kini berisi Keamanan Informasi = 90', r.status, 200, r.json.mata_kuliah.length === 1 && r.json.mata_kuliah[0].nilai === 90);
    expect('nilai final tidak bisa diubah lagi', (await call('PUT', '/nilai/1', { token: T.dosen1.access_token, device: DEV.dosen1, body: { nilai: 100 } })).status, 403);
    expect('finalisasi ulang ditolak', (await call('POST', '/kelas/1/finalisasi', { token: T.dosen1.access_token, device: DEV.dosen1 })).status, 409);

    bab('10. Audit log');
    const db = open();
    const a = db.prepare("SELECT hasil, COUNT(*) n FROM audit_log GROUP BY hasil").all();
    const n = Object.fromEntries(a.map(x => [x.hasil, x.n]));
    expect(`semua keputusan tercatat (allow=${n.allow}, deny=${n.deny})`, (n.allow > 0 && n.deny > 0) ? 1 : 0, 1);
    const kosongan = db.prepare("SELECT COUNT(*) n FROM audit_log WHERE alasan IS NULL OR alasan='' OR subjek='' OR endpoint=''").get().n;
    expect('setiap baris punya subjek, endpoint, alasan', kosongan, 0);
    db.close();
  } finally {
    fs.writeFileSync(policyFile, policyAsli); // kembalikan jam akses
  }

  const total = pass + fail;
  console.log(`\n${c.b}${fail ? c.r : c.g}${pass}/${total} pertahanan bekerja${c.o}${fail ? ` — ${fail} GAGAL` : ' — tidak ada serangan yang lolos 🛡️'}`);
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(2); });
