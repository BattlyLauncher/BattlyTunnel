# Protocol version 1

TLS 1.3, ALPN `battly-tunnel/1`. Control messages are JSON preceded by a big-endian uint32 length of 1–16,384 bytes. Every message has `version: 1` and a `type`. Invalid versions, frames or unexpected messages close the connection.

```text
client -> hello {token,name,port}
server -> registered {session,secret,port,host,heartbeatSeconds,idleSeconds,maxStreams}
server -> ping
client -> pong
server -> open {stream}
```

Registration follows authorization and binding the public port. Session, secret and stream identifiers are random 32-byte hexadecimal values. The session secret is compared in constant time and never emitted as a client event.

For each open request, the client establishes another TLS connection:

```text
client -> join {session,secret,stream}
server -> joined
both <-> opaque TCP bytes
```

Pending stream identifiers are consumed once. Data sockets cannot select arbitrary streams. After joining, bytes are forwarded without parsing Minecraft. EOF is propagated with half-close; errors and cancellation close both ends. Session loss closes all streams. Reconnection creates new capabilities; old streams are not resumed.

Client stdout events are `ready` (remotePort, publicHost, tunnelName), `reconnecting` (retryInMs) and `stopped`. Credentials never belong in events.
