// Audit log: setiap keputusan akses (waktu, subjek, endpoint, device, hasil, alasan)
// ditulis ke tabel audit_log DAN dicetak berwarna di konsol gateway.
const C = { allow: '\x1b[32m', deny: '\x1b[31m', dim: '\x1b[2m', off: '\x1b[0m' };

function makeAudit(db) {
  const ins = db.prepare(
    'INSERT INTO audit_log (waktu,subjek,endpoint,device,hasil,alasan) VALUES (?,?,?,?,?,?)');
  return function audit({ subjek, endpoint, device, hasil, alasan }) {
    const waktu = new Date().toISOString();
    ins.run(waktu, subjek, endpoint, device || '-', hasil, alasan);
    const warna = hasil === 'allow' ? C.allow : C.deny;
    console.log(
      `${C.dim}${waktu.slice(11, 19)}${C.off} ${warna}${hasil.toUpperCase().padEnd(5)}${C.off} ` +
      `${subjek.padEnd(22)} ${endpoint.padEnd(34)} ${C.dim}${(device || '-').padEnd(18)}${C.off} ${alasan}`);
  };
}

module.exports = { makeAudit };
