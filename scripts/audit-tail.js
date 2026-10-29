// Penampil audit log berwarna. `npm run audit` (sekali) atau `npm run audit -- -f` (mengikuti terus, cocok untuk demo).
// Opsi: --deny (hanya penolakan) | -n 50 (jumlah baris terakhir)
const { open } = require('../shared/db');
const a = process.argv.slice(2);
const follow = a.includes('-f'), onlyDeny = a.includes('--deny');
const n = a.includes('-n') ? +a[a.indexOf('-n') + 1] : 25;
const db = open();
const col = { allow: '\x1b[32m', deny: '\x1b[31m', d: '\x1b[2m', o: '\x1b[0m' };
const print = (r) => console.log(
  `${col.d}${r.waktu.slice(11, 19)}${col.o} ${col[r.hasil]}${r.hasil.toUpperCase().padEnd(5)}${col.o} ` +
  `${r.subjek.padEnd(22)} ${r.endpoint.padEnd(34)} ${col.d}${r.device.padEnd(18)}${col.o} ${r.alasan}`);
const filter = onlyDeny ? "WHERE hasil='deny'" : '';
let last = 0;
for (const r of db.prepare(`SELECT * FROM (SELECT * FROM audit_log ${filter} ORDER BY id DESC LIMIT ?) ORDER BY id`).all(n)) { print(r); last = r.id; }
if (follow) setInterval(() => {
  for (const r of db.prepare(`SELECT * FROM audit_log WHERE id > ? ${onlyDeny ? "AND hasil='deny'" : ''} ORDER BY id`).all(last)) print(r);
  last = db.prepare('SELECT COALESCE(MAX(id),0) m FROM audit_log').get().m;
}, 500);
else db.close();
