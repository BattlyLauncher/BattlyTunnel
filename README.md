# Battly Tunnel

A small TCP tunnel for Minecraft Java servers. The client connects a local server to a public port; the server checks authorization before opening that port.

One control connection coordinates the tunnel. Each player connection gets its own TLS connection. The client reconnects after a transport failure. Existing player connections are closed when a session ends.

## Download

Download the client or server for your platform from [Releases](https://github.com/BattlyLauncher/BattlyTunnel/releases). Each release includes `manifest.json`, SHA-256 checksums and license notices. Windows x64/x86/ARM64, Linux x64/ARM64 and macOS x64/ARM64 are built together.

## Run

Copy the configurations in `examples/` and replace the example values:

```sh
battly-tunnel-server -c server.json
battly-tunnel-client -verify -c client.json
battly-tunnel-client -c client.json
```

The server needs a TLS certificate and an authorization service. Set `BATTLY_TUNNEL_AUTH_SECRET` to a random operator credential of at least 32 bytes. Client credentials belong in a private configuration file, not command-line arguments or logs.

The destination is restricted to `127.0.0.1`, `::1` or `localhost`. TLS 1.3 and certificate verification are mandatory. This is a TCP relay, not an anticheat or a replacement for Minecraft authentication.

## Build and test

Go 1.22 is the minimum language version. Use a maintained Go toolchain for release builds. Node.js is used only by the packaging scripts.

```sh
go test ./... -timeout=120s
go vet ./...
go test -race ./... -timeout=120s
go test ./internal/tunnel -run '^$' -bench . -benchmem
node scripts/build.cjs
node scripts/package-release.cjs
```

The race detector needs a C compiler. Distributed binaries use `CGO_ENABLED=0`; there are no external Go modules. Build output goes to `bin/`, release assets to `release/`.

## Publishing

Push this repository to the `main` branch. GitHub Actions tests it on Windows, Linux and macOS, builds all targets, and publishes `v1.0.1` from `VERSION`. To publish the next release, change `VERSION` and push. A version already published is not overwritten. Pull requests run checks without publishing.

The workflow uses the repository's built-in `GITHUB_TOKEN` for publishing and a dedicated Azure OIDC identity to sign Windows executables. GitHub Actions must be enabled and allowed to create releases. See [Windows signing](docs/windows-signing.md) for permissions and builds without publication.

## Documentation

- [Authorization contract](docs/authorization.md)
- [Wire protocol](docs/protocol.md)
- [Operations](docs/operations.md)
- [Release layout](docs/releases.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)

Private identity-provider adapters and production deployment configuration are intentionally maintained outside this repository. The public server requires an operator-supplied authorizer.

Copyright TECNO BROS. No license for the project source is granted by this publication; see `LICENSE`. Go runtime notices are included separately.
