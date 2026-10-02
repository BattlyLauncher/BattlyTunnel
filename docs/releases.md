# Releases

`VERSION` is the release version, using `MAJOR.MINOR.PATCH`. Changes pushed to `main` run verification. The release job publishes `v<VERSION>` only when that release does not exist; bump the file for a new release. Release creation uses the commit checked out by the workflow. Concurrent publishing is serialized.

Assets use names such as `battly-tunnel-client-win32-x64.exe` and `battly-tunnel-server-linux-arm64`. `manifest.json` contains each asset's target, role, filename, byte count and SHA-256. `SHA256SUMS` provides a conventional checksum list. The Go license and notices accompany the binaries.

Consumers should select a tested version, download from its release URL and verify the selected asset before execution. Cache verified files and check their hash on reuse. Do not silently execute a different architecture or fall back to an unverified binary after a download failure.

Release assets are compiled without packing or obfuscation. Publishing does not configure Authenticode or macOS notarization. Add signing before generating the final manifest if distributing signed binaries.
