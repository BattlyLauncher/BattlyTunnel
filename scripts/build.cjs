// Plain, reproducible Go binaries. No packers, obfuscators or dynamic installers.
const { spawnSync } = require('node:child_process');
const { mkdirSync, readFileSync, writeFileSync, copyFileSync } = require('node:fs');
const { createHash } = require('node:crypto');
const { resolve, join } = require('node:path');
const root = resolve(__dirname, '..');
const version = process.env.BATTLY_TUNNEL_VERSION || readFileSync(join(root, 'VERSION'), 'utf8').trim();
if (!/^[a-zA-Z0-9._-]{1,64}$/.test(version)) throw new Error('Invalid build version');
const targets = [
  ['windows', 'amd64', 'win32-x64'],
  ['windows', '386', 'win32-ia32'],
  ['windows', 'arm64', 'win32-arm64'],
  ['linux', 'amd64', 'linux-x64'],
  ['linux', 'arm64', 'linux-arm64'],
  ['darwin', 'amd64', 'darwin-x64'],
  ['darwin', 'arm64', 'darwin-arm64'],
];
const out = resolve(root, 'bin');
const entries = [];
const toolchain = spawnSync('go', ['version'], { encoding: 'utf8', windowsHide: true });
if (toolchain.status !== 0) throw new Error('Go is required');
for (const [GOOS, GOARCH, target] of targets) {
  const directory = join(out, target);
  mkdirSync(directory, { recursive: true });
  for (const role of ['client', 'server']) {
    const name = `battly-tunnel-${role}${GOOS === 'windows' ? '.exe' : ''}`;
    const path = join(directory, name);
    const build = spawnSync(
      'go',
      [
        'build',
        '-trimpath',
        '-buildvcs=false',
        '-ldflags',
        `-X main.version=${version}`,
        '-o',
        path,
        `./cmd/battly-tunnel-${role}`,
      ],
      {
        cwd: root,
        env: {
          ...process.env,
          GOOS,
          GOARCH,
          CGO_ENABLED: '0',
          GOPROXY: 'off',
          GOCACHE: join(root, '.cache/go-build'),
        },
        stdio: 'inherit',
        windowsHide: true,
      },
    );
    if (build.status !== 0) process.exit(build.status || 1);
    const bytes = readFileSync(path);
    entries.push({
      target,
      role,
      file: `${target}/${name}`,
      bytes: bytes.length,
      sha256: createHash('sha256').update(bytes).digest('hex'),
    });
    process.stdout.write(`${target}/${name}\n`);
  }
}
writeFileSync(
  join(out, 'manifest.json'),
  JSON.stringify({ version, toolchain: toolchain.stdout.trim(), entries }, null, 2) + '\n',
);
const sdk = spawnSync('go', ['env', 'GOROOT'], { encoding: 'utf8', windowsHide: true });
if (sdk.status !== 0) throw new Error('Cannot locate Go license');
copyFileSync(join(sdk.stdout.trim(), 'LICENSE'), join(out, 'GO-LICENSE.txt'));
copyFileSync(join(root, 'THIRD-PARTY-NOTICES.md'), join(out, 'THIRD-PARTY-NOTICES.md'));
