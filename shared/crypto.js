const crypto = require('crypto');

// scrypt bawaan Node: tidak perlu paket tambahan untuk hashing password/secret.
function hash(plain) {
  const salt = crypto.randomBytes(16);
  const dk = crypto.scryptSync(plain, salt, 32);
  return `${salt.toString('hex')}:${dk.toString('hex')}`;
}

function verify(plain, stored) {
  const [saltHex, dkHex] = String(stored).split(':');
  if (!saltHex || !dkHex) return false;
  const dk = crypto.scryptSync(String(plain), Buffer.from(saltHex, 'hex'), 32);
  return crypto.timingSafeEqual(dk, Buffer.from(dkHex, 'hex'));
}

// Perbandingan string waktu-konstan (untuk gateway secret).
function safeEqual(a, b) {
  const x = crypto.createHash('sha256').update(String(a ?? '')).digest();
  const y = crypto.createHash('sha256').update(String(b ?? '')).digest();
  return crypto.timingSafeEqual(x, y);
}

module.exports = { hash, verify, safeEqual };
