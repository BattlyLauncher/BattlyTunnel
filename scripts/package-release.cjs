const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');
const root = path.resolve(__dirname, '..');
const manifest = JSON.parse(fs.readFileSync(path.join(root, 'bin/manifest.json')));
const out = path.join(root, 'release');
fs.mkdirSync(out, { recursive: true });
const entries = manifest.entries.map(entry => {
  const bytes = fs.readFileSync(path.join(root, 'bin', entry.file));
  if (createHash('sha256').update(bytes).digest('hex') !== entry.sha256 || bytes.length !== entry.bytes) throw Error('Build manifest mismatch');
  const file = `battly-tunnel-${entry.role}-${entry.target}${entry.target.startsWith('win32-') ? '.exe' : ''}`;
  fs.writeFileSync(path.join(out, file), bytes, { mode: 0o755 });
  return { ...entry, file };
});
fs.writeFileSync(path.join(out, 'manifest.json'), JSON.stringify({ ...manifest, entries }, null, 2) + '\n');
fs.writeFileSync(path.join(out, 'SHA256SUMS'), entries.map(entry => `${entry.sha256}  ${entry.file}`).join('\n') + '\n');
for (const name of ['GO-LICENSE.txt', 'THIRD-PARTY-NOTICES.md']) fs.copyFileSync(path.join(root, name), path.join(out, name));
console.log(`Packaged ${entries.length} binaries for v${manifest.version}`);
