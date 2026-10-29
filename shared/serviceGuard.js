// Pengaman di sisi SERVICE (assume breach: jangan percaya jaringan internal).
// Lapis 1: X-Gateway-Secret  -> request harus lewat gateway.
// Lapis 2: tanda tangan + masa berlaku token -> secret bocor pun tidak cukup.
const fs = require('fs');
const jwt = require('jsonwebtoken');
const cfg = require('./config');
const { safeEqual } = require('./crypto');

const publicKey = fs.readFileSync(cfg.PUBLIC_KEY_FILE); // service TIDAK punya private key

function guard({ nama }) {
  return (req, res, next) => {
    if (!cfg.GATEWAY_SECRET || !safeEqual(req.get('x-gateway-secret'), cfg.GATEWAY_SECRET)) {
      return res.status(403).json({ error: `${nama}: akses langsung ditolak (gateway secret tidak valid)` });
    }
    const m = /^Bearer (.+)$/.exec(req.get('authorization') || '');
    if (!m) return res.status(401).json({ error: `${nama}: token tidak ada` });
    try {
      const p = jwt.verify(m[1], publicKey, { algorithms: ['RS256'], issuer: cfg.ISSUER });
      if (p.typ !== 'access' && p.typ !== 'service') throw new Error('jenis token salah');
      req.auth = p; // { sub, role, typ, dev? }
      next();
    } catch (e) {
      res.status(401).json({ error: `${nama}: token tidak valid (${e.message})` });
    }
  };
}

module.exports = { guard };
