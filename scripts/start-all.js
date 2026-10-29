// Menjalankan gateway + 2 service sekaligus dalam satu terminal (log gateway = audit log langsung).
const { spawn } = require('child_process');
const path = require('path');
const root = path.join(__dirname, '..');
const procs = ['service-transkrip', 'service-nilai', 'gateway'].map((d) =>
  spawn(process.execPath, [path.join(root, d, 'index.js')], { stdio: 'inherit' }));
const stop = () => procs.forEach((p) => p.kill());
process.on('SIGINT', stop); process.on('SIGTERM', stop);
procs.forEach((p) => p.on('exit', (c) => { if (c) { console.error('proses berhenti, menutup semua'); stop(); process.exit(c); } }));
