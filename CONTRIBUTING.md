# Contributing

Keep changes focused on TCP tunneling. Describe the behavior being changed and include a regression test for protocol or lifecycle changes. Run `go test`, `go vet` and the race detector before submitting a pull request.

Protocol changes must preserve version 1 compatibility or introduce a new protocol version. Do not add production endpoints, user records, credentials or private authorization adapters. Benchmarks should state the hardware, toolchain and fixture used; local throughput is not an Internet latency measurement.
