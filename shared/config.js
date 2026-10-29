// Konfigurasi terpusat. Rahasia dibaca dari .env (dibuat oleh `npm run setup`).
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');

// Pembaca .env minimalis (tanpa dependensi tambahan)
function loadEnv() {
  const file = path.join(ROOT, '.env');
  if (!fs.existsSync(file)) return;
  for (const line of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
    if (m && process.env[m[1]] === undefined) process.env[m[1]] = m[2];
  }
}
loadEnv();

const POLICY_FILE = path.join(ROOT, 'config', 'policy.json');

// Jam akses dibaca ULANG setiap request (hot reload), jadi saat demo cukup
// edit config/policy.json tanpa restart gateway.
function loadPolicyConfig() {
  return JSON.parse(fs.readFileSync(POLICY_FILE, 'utf8'));
}

module.exports = {
  ROOT,
  DB_FILE: path.join(ROOT, 'data', 'sistem.db'),
  PRIVATE_KEY_FILE: path.join(ROOT, 'keys', 'private.pem'), // hanya gateway
  PUBLIC_KEY_FILE: path.join(ROOT, 'keys', 'public.pem'),   // dipakai semua service
  ports: { gateway: 3000, nilai: 3001, transkrip: 3002 },
  GATEWAY_URL: process.env.GATEWAY_URL || 'http://127.0.0.1:3000',
  GATEWAY_SECRET: process.env.GATEWAY_SECRET,
  SERVICE_CLIENT_ID: process.env.SERVICE_CLIENT_ID || 'svc-nilai',
  SERVICE_CLIENT_SECRET: process.env.SERVICE_CLIENT_SECRET,
  ISSUER: 'zt-gateway',
  ttl: { access: '10m', refresh: '1d', service: '5m' },
  loadPolicyConfig,
};
