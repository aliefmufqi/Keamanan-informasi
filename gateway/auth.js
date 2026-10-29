// Bagian Policy Administrator: login, penerbitan & pencabutan token. Hanya gateway memegang private key.
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const jwt = require('jsonwebtoken');
const cfg = require('../shared/config');
const { verify } = require('../shared/crypto');

const privateKey = fs.readFileSync(cfg.PRIVATE_KEY_FILE);
const publicKey = fs.readFileSync(cfg.PUBLIC_KEY_FILE);
const sign = (claims, expiresIn, extra = {}) =>
  jwt.sign(claims, privateKey, { algorithm: 'RS256', expiresIn, issuer: cfg.ISSUER, ...extra });

// Dipakai juga oleh middleware gateway untuk memeriksa Authorization: Bearer
function verifyBearer(header) {
  const m = /^Bearer (.+)$/.exec(header || '');
  if (!m) return { error: 'access token tidak ada' };
  try {
    const p = jwt.verify(m[1], publicKey, { algorithms: ['RS256'], issuer: cfg.ISSUER });
    if (p.typ !== 'access' && p.typ !== 'service') return { error: 'jenis token salah (bukan access token)' };
    return { payload: p };
  } catch (e) {
    return { error: e.name === 'TokenExpiredError' ? 'access token kedaluwarsa' : 'access token tidak valid' };
  }
}

function authRouter(db, audit) {
  const r = express.Router();
  r.use(express.json({ limit: '10kb' }));

  const log = (req, subjek, hasil, alasan) =>
    audit({ subjek, endpoint: `${req.method} ${req.originalUrl.split('?')[0]}`, device: req.get('x-device-id'), hasil, alasan });

  const issueRefresh = (user, device) => {
    const jti = crypto.randomUUID();
    const token = sign({ typ: 'refresh' }, cfg.ttl.refresh, { subject: String(user.id), jwtid: jti });
    const exp = Math.floor(Date.now() / 1000) + 86400;
    db.prepare('INSERT INTO refresh_tokens (jti,user_id,device_id,expires_at) VALUES (?,?,?,?)').run(jti, user.id, device, exp);
    return token;
  };
  const issueAccess = (user, device) =>
    sign({ typ: 'access', role: user.role, dev: device }, cfg.ttl.access, { subject: String(user.id) });

  // --- POST /auth/login ---
  r.post('/login', (req, res) => {
    const { username, password } = req.body || {};
    const device = req.get('x-device-id');
    const u = typeof username === 'string' ? db.prepare('SELECT * FROM users WHERE username=?').get(username) : null;
    // Pesan ke klien sengaja seragam agar tidak membocorkan apakah username ada.
    const gagal = (alasan) => {
      log(req, username || '(anon)', 'deny', alasan);
      return res.status(401).json({ error: 'login ditolak' });
    };
    if (!u || !u.aktif || typeof password !== 'string' || !verify(password, u.password_hash)) return gagal('kredensial tidak valid');
    if (!device || !db.prepare('SELECT 1 FROM devices WHERE user_id=? AND device_id=?').get(u.id, device))
      return gagal('device tidak terdaftar untuk user ini');
    log(req, `${u.username}(${u.role})`, 'allow', 'login berhasil');
    res.json({ access_token: issueAccess(u, device), refresh_token: issueRefresh(u, device), token_type: 'Bearer', expires_in: 600 });
  });

  // --- POST /auth/refresh (dengan rotasi + deteksi pemakaian ulang) ---
  r.post('/refresh', (req, res) => {
    const device = req.get('x-device-id');
    const deny = (alasan, sub = '(refresh)') => { log(req, sub, 'deny', alasan); return res.status(401).json({ error: 'refresh ditolak' }); };
    let p;
    try { p = jwt.verify(req.body?.refresh_token, publicKey, { algorithms: ['RS256'], issuer: cfg.ISSUER }); }
    catch { return deny('refresh token tidak valid / kedaluwarsa'); }
    if (p.typ !== 'refresh') return deny('jenis token salah (bukan refresh token)');
    const row = db.prepare('SELECT * FROM refresh_tokens WHERE jti=?').get(p.jti);
    if (!row) return deny('refresh token tidak dikenal');
    if (row.revoked) {
      // Token yang sudah dicabut dipakai lagi => kemungkinan dicuri. Asumsikan breach: cabut semua sesi user.
      db.prepare('UPDATE refresh_tokens SET revoked=1 WHERE user_id=?').run(row.user_id);
      return deny('refresh token sudah dicabut dipakai ulang -> semua sesi user dicabut', `user#${row.user_id}`);
    }
    if (row.device_id !== device) return deny('device tidak cocok dengan sesi refresh', `user#${row.user_id}`);
    const u = db.prepare('SELECT * FROM users WHERE id=? AND aktif=1').get(row.user_id);
    if (!u) return deny('akun nonaktif');
    db.prepare('UPDATE refresh_tokens SET revoked=1 WHERE jti=?').run(row.jti); // rotasi
    log(req, `${u.username}(${u.role})`, 'allow', 'refresh berhasil (token lama dicabut)');
    res.json({ access_token: issueAccess(u, device), refresh_token: issueRefresh(u, device), token_type: 'Bearer', expires_in: 600 });
  });

  // --- POST /auth/logout ---
  r.post('/logout', (req, res) => {
    try {
      const p = jwt.verify(req.body?.refresh_token, publicKey, { algorithms: ['RS256'], issuer: cfg.ISSUER });
      if (p.typ !== 'refresh') throw new Error();
      const n = db.prepare('UPDATE refresh_tokens SET revoked=1 WHERE jti=?').run(p.jti).changes;
      log(req, `user#${p.sub}`, 'allow', n ? 'logout, refresh token dicabut' : 'logout (token tidak dikenal)');
      res.json({ ok: true });
    } catch {
      log(req, '(logout)', 'deny', 'refresh token tidak valid');
      res.status(401).json({ error: 'logout ditolak' });
    }
  });

  // --- POST /auth/service (client credentials untuk Service Nilai) ---
  r.post('/service', (req, res) => {
    const { client_id, client_secret } = req.body || {};
    const c = typeof client_id === 'string' ? db.prepare('SELECT * FROM service_clients WHERE client_id=?').get(client_id) : null;
    if (!c || typeof client_secret !== 'string' || !verify(client_secret, c.secret_hash)) {
      log(req, client_id || '(anon)', 'deny', 'client id/secret tidak valid');
      return res.status(401).json({ error: 'client ditolak' });
    }
    log(req, `${c.client_id}(service)`, 'allow', 'token service diterbitkan (5 menit)');
    res.json({ access_token: sign({ typ: 'service', role: 'service' }, cfg.ttl.service, { subject: c.client_id }), token_type: 'Bearer', expires_in: 300 });
  });

  return r;
}

module.exports = { authRouter, verifyBearer };
