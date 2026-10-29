// API Gateway = Policy Enforcement Point (PEP), port 3000. Satu-satunya pintu masuk.
// Alur tiap request: verifikasi token -> minta keputusan ke Policy Engine -> audit log -> teruskan (atau tolak).
const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const cfg = require('../shared/config');
const { open } = require('../shared/db');
const { makeAudit } = require('./audit');
const { decide } = require('./policy');
const { authRouter, verifyBearer } = require('./auth');

if (!cfg.GATEWAY_SECRET) { console.error('GATEWAY_SECRET kosong. Jalankan `npm run setup` dulu.'); process.exit(1); }

const db = open();
const audit = makeAudit(db);
const app = express();
app.disable('x-powered-by');

// /auth/* ditangani gateway sendiri (PA)
app.use('/auth', authRouter(db, audit));

// Proxy ke service. Gateway menambahkan X-Gateway-Secret; header itu dari klien selalu ditimpa.
const makeProxy = (target) => createProxyMiddleware({
  target, changeOrigin: false,
  on: {
    proxyReq: (proxyReq) => proxyReq.setHeader('X-Gateway-Secret', cfg.GATEWAY_SECRET),
    error: (err, req, res) => {
      audit({ subjek: 'gateway', endpoint: `${req.method} ${req.url}`, device: '-', hasil: 'deny', alasan: `service tidak tersedia (${err.code})` });
      if (!res.headersSent) res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'service tidak tersedia' }));
    },
  },
});
const proxies = {
  nilai: makeProxy(`http://127.0.0.1:${cfg.ports.nilai}`),
  transkrip: makeProxy(`http://127.0.0.1:${cfg.ports.transkrip}`),
};

// PEP: berlaku untuk SEMUA yang bukan /auth/*
app.use((req, res, next) => {
  const url = new URL(req.originalUrl, 'http://x');
  const bearer = verifyBearer(req.get('authorization'));
  const ctx = {
    method: req.method, path: url.pathname.replace(/\/+$/, '') || '/',
    query: Object.fromEntries(url.searchParams), device: req.get('x-device-id'),
    auth: bearer.payload, authError: bearer.error, now: new Date(),
  };
  const d = decide(db, ctx);
  const subjek = ctx.user ? `${ctx.user.username}(${ctx.user.role})`
    : ctx.auth ? `${ctx.auth.sub}(${ctx.auth.role})` : '(tanpa token)';
  audit({ subjek, endpoint: `${req.method} ${url.pathname}${url.search}`, device: ctx.device, hasil: d.allow ? 'allow' : 'deny', alasan: d.reason });
  if (!d.allow) return res.status(403).json({ error: 'akses ditolak', alasan: d.reason });
  proxies[d.target](req, res, next);
});

app.listen(cfg.ports.gateway, '127.0.0.1', () =>
  console.log(`[gateway] PEP aktif di http://127.0.0.1:${cfg.ports.gateway}`));
