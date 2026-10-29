// SQLite bawaan Node (node:sqlite, Node >= 22.13): TANPA paket native, TANPA kompilasi (aman di Windows).
// Pembungkus tipis ini menyediakan API ala better-sqlite3 (prepare/get/all/run, exec, pragma, transaction).
const _emit = process.emitWarning;
process.emitWarning = (w, ...a) => (/SQLite/i.test(String(w?.message ?? w)) ? undefined : _emit.call(process, w, ...a));
const { DatabaseSync } = require('node:sqlite');
process.emitWarning = _emit;

const { DB_FILE } = require('./config');

function open() {
  const raw = new DatabaseSync(DB_FILE);
  const db = {
    prepare: (sql) => raw.prepare(sql),           // .get() .all() .run() bawaan
    exec: (sql) => raw.exec(sql),
    pragma: (s) => raw.exec(`PRAGMA ${s}`),
    transaction: (fn) => (...args) => {
      raw.exec('BEGIN');
      try { const r = fn(...args); raw.exec('COMMIT'); return r; }
      catch (e) { raw.exec('ROLLBACK'); throw e; }
    },
    close: () => raw.close(),
  };
  db.pragma('journal_mode = WAL');
  db.pragma('busy_timeout = 3000');
  db.pragma('foreign_keys = ON');
  return db;
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
  nama TEXT NOT NULL, role TEXT NOT NULL CHECK (role IN ('mahasiswa','dosen','admin')),
  nim TEXT UNIQUE, aktif INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS devices (
  user_id INTEGER NOT NULL REFERENCES users(id), device_id TEXT NOT NULL,
  PRIMARY KEY (user_id, device_id)
);
CREATE TABLE IF NOT EXISTS kelas (
  id INTEGER PRIMARY KEY, nama TEXT NOT NULL, dosen_id INTEGER NOT NULL REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS nilai (
  id INTEGER PRIMARY KEY, kelas_id INTEGER NOT NULL REFERENCES kelas(id),
  nim TEXT NOT NULL, nilai REAL, final INTEGER NOT NULL DEFAULT 0,
  UNIQUE (kelas_id, nim)
);
CREATE TABLE IF NOT EXISTS transkrip (
  nim TEXT NOT NULL, kelas_id INTEGER NOT NULL, mata_kuliah TEXT NOT NULL,
  nilai REAL NOT NULL, PRIMARY KEY (nim, kelas_id)
);
CREATE TABLE IF NOT EXISTS refresh_tokens (
  jti TEXT PRIMARY KEY, user_id INTEGER NOT NULL, device_id TEXT NOT NULL,
  expires_at INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS service_clients (
  client_id TEXT PRIMARY KEY, secret_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY, waktu TEXT NOT NULL, subjek TEXT NOT NULL,
  endpoint TEXT NOT NULL, device TEXT, hasil TEXT NOT NULL, alasan TEXT NOT NULL
);
`;

module.exports = { open, SCHEMA };
