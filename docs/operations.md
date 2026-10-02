# Operations

Use a DNS record that resolves directly to the TCP listener. An HTTP reverse proxy cannot relay this protocol. Allow the control port and configured public port range in the firewall.

Install the server under an unprivileged account. The systemd unit in `deploy/` is a starting point; provide the configuration, certificate and secret files with restrictive ownership. The server reads its certificate at startup. Renew it before expiry and restart the service to load the replacement; active player streams will disconnect during restart.

Defaults: 512 sessions, 4 per user, 128 streams per tunnel, 2,048 total streams and 128 concurrent handshakes. New-session authorization is limited to 32 requests per second with a burst of 64. Lease authorization is separate; consider backend capacity when reducing lease intervals. Heartbeats run every 15 seconds and expire after three missed intervals. Idle transfers expire after 300 seconds. Reconnect backoff uses jitter and grows to 30 seconds.

The server emits aggregate statistics once per minute. Monitor session counts, rejected registrations, authorization failures and resource usage. It does not include account credentials in logs.

Keep the previous binary and configuration for rollback. Stop the service, replace the binary, then start it again. Wire version 1 remains compatible; changing authorization configuration or port allocation can still require a coordinated migration.
