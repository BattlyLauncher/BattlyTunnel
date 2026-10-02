# Authorization

Configure `authUrl` on the server. Clients cannot choose this endpoint. HTTPS is required except for literal loopback HTTP. Redirects and environment HTTP proxies are disabled. Requests have an eight-second timeout and responses are limited to 1 MiB.

```http
POST /authorize
Authorization: Bearer <operator-secret>
Content-Type: application/json

{"token":"<client-token>","tunnelName":"my-world","requestedPort":30000}
```

Return HTTP 200 with:

```json
{"userId":"immutable-user-id","tunnelId":"immutable-tunnel-id","remotePort":30000}
```

The authorizer must validate the credential, account status, ownership and reserved port. `requestedPort: 0` requests the reserved assignment; any nonzero port must match it. Deny unauthorized requests with a non-200 status. Do not create DNS records or mutate allocations during lease renewal.

The same check runs periodically. Failure or a changed grant closes the tunnel and active connections. `leaseSeconds` controls the maximum normal revalidation interval; revocation is not instantaneous. The default is 300 seconds. Quotas use immutable user IDs.
