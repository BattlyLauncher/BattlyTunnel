const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');
const root = path.resolve(__dirname, '../bin');
const file = path.join(root, 'manifest.json');
const manifest = JSON.parse(fs.readFileSync(file, 'utf8'));
const refresh = process.argv[2] === '--refresh';
if (!refresh && process.argv[2] !== '--check') throw Error('Use --check before signing and --refresh after verification');
const targets = ['win32-x64', 'win32-ia32', 'win32-arm64', 'linux-x64', 'linux-arm64', 'darwin-x64', 'darwin-arm64'];
const expected = new Set(targets.flatMap(target => ['client', 'server'].map(role => `${target}/battly-tunnel-${role}${target.startsWith('win32-') ? '.exe' : ''}`)));
if (manifest.entries.length !== expected.size) throw Error('Expected fourteen binaries');
for (const entry of manifest.entries) {
  if (!expected.delete(entry.file) || entry.file !== `${entry.target}/battly-tunnel-${entry.role}${entry.target.startsWith('win32-') ? '.exe' : ''}`) throw Error('Unexpected manifest entry');
  const bytes = fs.readFileSync(path.join(root, entry.file));
  const sha256 = createHash('sha256').update(bytes).digest('hex');
  if (refresh && entry.target.startsWith('win32-')) {
    entry.sha256 = sha256;
    entry.bytes = bytes.length;
  } else if (sha256 !== entry.sha256 || bytes.length !== entry.bytes) throw Error(`Build manifest mismatch: ${entry.file}`);
}
if (refresh) fs.writeFileSync(file, JSON.stringify(manifest, null, 2) + '\n');
console.log(refresh ? 'Recorded signed Windows hashes; other binaries unchanged.' : 'Verified all unsigned build hashes.');
