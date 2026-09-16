# Certificate health reporter

The trusted cluster generator may configure the default-absent Caddy app:

```json
{
  "apps": {
    "apx_certificate_health": {
      "endpoint": "https://APP-BASE-URL/api/internal/certificate-health/events",
      "proxy_server_id": 42,
      "machine_id": "{env.FLY_MACHINE_ID}",
      "token": "DERIVED-CERTIFICATE-HEALTH-PURPOSE-TOKEN",
      "address": "127.0.0.1:443",
      "client_auth": false
    }
  }
}
```

The token is HMAC-SHA256 of `certificate-health:<canonical decimal cluster ID>`
under the existing app internal secret, encoded as unpadded base64url. The plugin
receives only the derived token, never the app secret or a legacy fleet token.
The endpoint must come from the trusted app base URL, never customer analytics
configuration. The generated address is the numeric loopback TLS listener.
Only the exact existing `{env.FLY_MACHINE_ID}` placeholder is expanded; secret
strings are never passed through a replacer. Machine IDs must be14 lowercase hex
characters. No additional environment variable or feature flag is introduced.

Attach `{"module":"apx_certificate_health"}` as the handshake context only for
supported exact-host, single-SAN policies. Omit it for client-auth policies;
`client_auth: true` also prevents the local probe from dialing. Absence of the
reporter makes the production context hook a no-op. It never scans Redis.

## Lifecycle and bounds

Two workers own a single queue of at most256 roots, including active and delayed
work, with at most1024 public-fingerprint dedupe entries and one active root per
hostname. Queue contention/saturation drops work immediately. No handshake starts
a goroutine or performs an outbound request. Confirmation runs on those same two
workers; the older standalone ConfirmingSink helper is not used by the reporter.

Each root expires at its original enqueue time plus five minutes, capped by the
accepted server expiry. Retries and reloads cannot extend it. HTTP and loopback
TLS each have a three-second deadline, additionally capped by the root deadline.
HTTPS uses system roots, disallows redirects, and reads at most8192 response
bytes. The body sent is also bounded to8192 bytes. Each actual observation has a
fresh UUIDv4; up to three total delivery attempts reuse the exact event identity.
Transport failures and429/503 retry with jittered1–2s then2–4s scheduled delays.
204 ends work; other statuses are terminal. Terminal statuses never wait for a
body, so a stalled401/413 cannot become a transport retry.

Caddy app instances with identical cluster/machine/endpoint/token/listener/policy
share a reference-counted state through an opaque SHA256 identity. Replacement
states with changed configuration remain dormant while the old worker pool is
running. Caddy's core `stopping` event occurs only after successful replacement
and before old app drains: it releases that instance, cancels/joins the old pool
when unreferenced, and activates the replacement. Failed validation, failed Start,
and failed final setup clean up only provisional references. No HTTP handler must
run to initialize this lifecycle. Public Stats exposes fixed-cardinality counts;
rate-limited local diagnostics contain only drop/failure counts, never tokens,
nonces, key material or raw network errors. The plugin sends no alerts.

## Version1 wire events

POST the fixed endpoint with JSON Content-Type and exactly one
`apx-proxy-server-id` and `apx-key` header. Common fields are `version: 1`, `kind`,
`event_id`, integer `proxy_server_id`, `machine_id`, `hostname`, `issuer`,
`observed_at`, `tls_checked_at` and `tls_result`. Times are UTC RFC3339 whole
seconds with Z. Initial observed_at is candidate birth; checked_at is the fresh
TLS result. Only typed `tls_alert` or `certificate_invalid` are failures. Refusal,
timeout, cancellation, EOF and wrong/non-loopback listeners are inconclusive.

Initial `kind: mismatch` adds `leaf_sha256`, `cert_spki_sha256` and
`key_spki_sha256`, each64 lowercase hex characters; the two SPKI hashes differ.
It does not carry a report ID or nonce. No raw certificate, private key, storage
path or Redis record is transmitted.

A202 response must contain exactly `report_id` (canonical UUIDv4),
`verification_nonce` (unpadded base64url32bytes), `check_after_seconds: 30` and
`expires_at` (future UTC RFC3339 whole seconds, no more than five minutes ahead
with ten seconds allowed clock skew). Duplicate/unknown members and trailing JSON
are rejected. Local expiry remains the minimum of candidate birth+5min and server
expiry; a later server expiry is capped rather than rejected merely for being
later than candidate expiry.

At30-second intervals, a fresh verified TLS connection to the same loopback
listener supplies a new observation with a new event ID, the original `report_id`
and `verification_nonce`, and the same authenticated cluster/machine/host/issuer.
Failure retains the original three public hashes; it never rereads Redis itself.
Success uses `kind: verification`, `tls_result: valid`, and only
`served_leaf_sha256` (SHA256 of the freshly verified served leaf DER). Success does
not carry mismatch hashes. Observation timestamps must increase per root.
Continuation responses must retain the same report ID, nonce and expiry. A202
acceptance of a valid observation keeps the root scheduled for later fresh checks;
it is not proof of completed repair. A204 terminates work. The original capped
expiry remains fixed after every accepted success or failure.

## Validation boundary

See [integration/README.md](integration/README.md) for reproducible local tests and
the explicitly isolated macOS trust overlay. The later Linux built-image gate
must retain the production bundled-root import and use process-local test trust.
No published image, production rollout, provider lookup, app recovery, safe
storage writer, or real ACME issuance is established by this reporter's tests.
