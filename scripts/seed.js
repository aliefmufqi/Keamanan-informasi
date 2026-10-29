// Setup + seed. Aman dijalankan berulang: `npm run setup` (pertama kali) / `npm run reset` (data awal lagi).
const fs = require('fs');
const crypto = require('crypto');
const path = require('path');
const ROOT = path.join(__dirname, '..'); // jangan require config dulu: .env belum tentu ada

// 1) Kunci RS256 + rahasia -> hanya dibuat jika belum ada
const keyDir = path.join(ROOT, 'keys');
fs.mkdirSync(keyDir, { recursive: true });
fs.mkdirSync(path.join(ROOT, 'data'), { recursive: true });
if (!fs.existsSync(path.join(keyDir, 'private.pem'))) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  fs.writeFileSync(path.join(keyDir, 'private.pem'), privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  fs.writeFileSync(path.join(keyDir, 'public.pem'), publicKey.export({ type: 'spki', format: 'pem' }));
  console.log('[setup] keypair RS256 dibuat (private key hanya dipakai gateway)');
}
const envFile = path.join(ROOT, '.env');
if (!fs.existsSync(envFile)) {
  fs.writeFileSync(envFile,
    `GATEWAY_SECRET=${crypto.randomBytes(24).toString('hex')}\n` +
    `SERVICE_CLIENT_ID=svc-nilai\n` +
    `SERVICE_CLIENT_SECRET=${crypto.randomBytes(24).toString('hex')}\n`);
  console.log('[setup] .env dibuat');
}

// 2) Muat konfigurasi SETELAH .env ada, lalu isi database
const cfg = require('../shared/config');
const { open, SCHEMA } = require('../shared/db');
const { hash } = require('../shared/crypto');

const db = open();
db.exec(SCHEMA);
// Kosongkan isi tabel (bukan hapus file) -> aman dijalankan saat sistem sedang hidup
db.pragma('foreign_keys = OFF');
for (const t of ['audit_log', 'refresh_tokens', 'transkrip', 'nilai', 'kelas', 'devices', 'service_clients', 'users'])
  db.exec(`DELETE FROM ${t}`);
db.pragma('foreign_keys = ON');

const PW = { admin: 'Admin#123', dosen: 'Dosen#123', mahasiswa: 'Mhs#12345' };
const users = [
  // username, nama, role, nim, device
  ['admin',      'Bu Rina (Admin Prodi)',   'admin',     null,           'DEV-ADMIN-01'],
  ['dosen1',     'Pak Budi Santoso',        'dosen',     null,           'DEV-DOSEN1-LAPTOP'],
  ['dosen2',     'Bu Sari Wulandari',       'dosen',     null,           'DEV-DOSEN2-LAPTOP'],
  ['mahasiswa1', 'Aulia Rahma',             'mahasiswa', '247006111001', 'DEV-MHS1-HP'],
  ['mahasiswa2', 'Bagas Pratama',           'mahasiswa', '247006111002', 'DEV-MHS2-HP'],
  ['mahasiswa3', 'Citra Lestari',           'mahasiswa', '247006111003', 'DEV-MHS3-HP'],
];
const insU = db.prepare('INSERT INTO users (username,password_hash,nama,role,nim) VALUES (?,?,?,?,?)');
const insD = db.prepare('INSERT INTO devices (user_id,device_id) VALUES (?,?)');
const id = {};
for (const [u, nama, role, nim, dev] of users) {
  id[u] = insU.run(u, hash(PW[role]), nama, role, nim).lastInsertRowid;
  insD.run(id[u], dev);
}

// 2 kelas, diampu dosen berbeda
db.prepare('INSERT INTO kelas (id,nama,dosen_id) VALUES (1,?,?)').run('Keamanan Informasi', id.dosen1);
db.prepare('INSERT INTO kelas (id,nama,dosen_id) VALUES (2,?,?)').run('Basis Data', id.dosen2);
const insN = db.prepare('INSERT INTO nilai (kelas_id,nim,nilai) VALUES (?,?,?)');
for (const [k, nim, n] of [
  [1, '247006111001', 88], [1, '247006111002', 76], [1, '247006111003', 91],
  [2, '247006111001', 82], [2, '247006111002', 68], [2, '247006111003', 79],
]) insN.run(k, nim, n);

// Service Nilai terdaftar sebagai client (secret disimpan sebagai hash)
db.prepare('INSERT INTO service_clients VALUES (?,?)').run(cfg.SERVICE_CLIENT_ID, hash(cfg.SERVICE_CLIENT_SECRET));
db.close();

console.log('[seed] database siap -> data/sistem.db');
console.table(users.map(([u, nama, role, nim, dev]) => ({
  username: u, password: PW[role], role, nim: nim || '-', 'X-Device-ID': dev,
})));
