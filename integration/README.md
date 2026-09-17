# Real Caddy / Redis handshake reproduction

This separate Go module uses the parent Redis plugin through a local `replace`.
It leaves the production module's Caddy/CertMagic dependencies unchanged.

## Run

Prerequisites: Go 1.25+, Docker, and the `redis:7-alpine` image (Docker will fetch
it if absent). All test traffic uses loopback. Each test creates its own randomly
named Redis container, random loopback port, and Redis namespace, then removes
only that container. No existing Redis configuration or credentials are used.

```sh
cd integration
./test-caddy-version.sh v2.11.3
./test-caddy-version.sh v2.11.4
```

The script reports resolved Caddy/CertMagic versions and runs the complete
integration suite with the race detector. Its temporary module files keep version
matrix testing out of checked-in dependency files. Set `GOCACHE` to a writable
location if necessary.

For focused development using the checked-in Caddy 2.11.3 / CertMagic 0.25.3 baseline:

```sh
APX_REDIS_INTEGRATION=1 go test -run 'TestStoredMismatchDoesNotSelfRepair|TestWarmCacheMasksStoredMismatch' -v -count=1 .
```

Tests skip unless explicitly enabled. Root `go test ./...` does not traverse this
nested module, so run the integration script separately. A skipped integration
run is not evidence that the real handshake behavior passes.

## What is exercised

- Each node is a fresh OS subprocess running real Caddy HTTP/TLS apps. Two nodes
  have independent CertMagic caches and share only their test Redis namespace.
- Certificates are valid, synthetic, single-name `fixture.example` leaves. A
  different valid PKCS#8 private key creates the stored mismatch. Certificate,
  private key, and ordinary CertMagic metadata are written through the actual
  Redis plugin, with AES encryption and flate compression configured. As in
  production, small values use the plugin's no-compression fallback when
  compression would increase their size.
- A test-only issuer records and rejects any issuance without networking. It is
  the sole issuer for the explicit fixture subject, so no public ACME service is
  contacted. The test root exists only in the TLS client's explicit trust pool;
  no system roots are modified and verification is never bypassed.
- Cold handshakes fail with a real remote TLS alert, and the exact stored wrapper
  bytes (including modification times) remain unchanged across repeated attempts.
  The server log identifies the certificate/private-key mismatch, and the issuer
  is never called: existing resource paths suppress acquisition.
- A warm process continues serving the exact trusted leaf after persistent data
  is corrupted. A simultaneous fresh process fails. A cache hit performs zero
  Redis GETs and no storage Load, while still invoking the handshake context hook.
- A test-only `tls.context` module inserts a typed marker. A thin observing storage
  wrapper asserts that real certificate Loads receive it, then calls unchanged
  `RedisStorage.Load`. Redis `INFO commandstats` measures actual GET traffic.
- Background storage cleanup is disabled only in the test Caddy configuration to
  isolate per-handshake transport accounting. Certificate loading and issuance
  paths remain real. The observed extension point adds no repair behavior.

## Limits / next work

This is failure characterization, not a recovery implementation. The issuer is a
controlled local fixture, so this does not cover ACME challenges, public issuance,
image contents, deployment, or production trust. The same fixture helpers support
fresh/warm nodes, observed loads, local trusted TLS confirmation, and Redis counts;
future recovery tests can extend the issuer to sign a CSR locally. Full ACME and
image/writer acceptance remain separate validation gates.

## Passive observer and local confirmation

The additional certificate-health tests use the production
`tls.context.apx_certificate_health` hook and a test-only reporter app. They cover:

- Exact-SNI EC/RSA mismatch fingerprints after successful storage decoding.
- Direct PROXY-wrapped TLS and the production caddy-l4 commit
  `40df11892606f71b11bdf3539588b255464e4c6b`, forwarding PROXY v2 to an inner
  loopback HTTP TLS listener. All listener ports are ephemeral.
- A test-only gate starts confirmation after the original cold handshake, making
  recursive-observation and Redis counts deterministic: six original GETs, six
  probe GETs, one accepted candidate, one recursive candidate dropped, and one
  confirmed report. With immediate confirmation, CertMagic may coalesce the
  concurrent cold loads, so fewer probe GETs are legitimate.
- Healthy cache/fallback issuer suppression, no reporter configured, and an
  actual client-authentication rejection with the observer hook omitted.

The production hook cannot determine client-auth policy from `ClientHelloInfo`.
The configuration generator must omit it on unsupported client-auth policies;
`LocalCertificateProbe.ClientAuth` also skips such policies before dialing.
This is a passive detector and confirmation primitive; delivery, app-side
validation, writer repair, deployment, and production trust remain later tasks.

### Certificate reporter lifecycle and trust fixture

Run `GOCACHE=/private/tmp/apx-cert-go-cache ./test-caddy-version.sh v2.11.3`
and the same command with `v2.11.4`. This executes the production reporter and
production handshake hook, including 20 actual Caddy reloads, failed replacement
configs, cancellation of blocked HTTPS requests on disable/credential changes,
and real nonce-bound verifications of the freshly served certificate at 30 and 60
seconds (a 202 success must keep the root scheduled until 204 or expiry).
The existing gated Task 2 observer tests use a renamed test app/context adapter;
they retain their exact direct/L4 recursive storage-read measurements.

The matrix script copies the exact version-resolved Caddy source into disposable
scratch and applies a Go build overlay removing only `cmd/x509rootsfallback.go`'s
blank import of the bundled fallback-root installer. It checks that import before
applying the overlay and never edits the module cache or production dependencies.
This is necessary because Go permits `x509.SetFallbackRoots` only once. Each test
child installs only the fixture leaf CA and fake HTTPS app CA, using test-only
`GODEBUG=x509usefallbackroots=1`; production `RootCAs` stays nil for both connections.
No OS/user trust store is changed. Raw opt-in `go test` runs fail with instructions
for the real reporter tests if the script's overlay marker is absent, rather than
silently treating them as covered.

This overlay is a test-harness divergence. The later Linux built-image gate must
retain Caddy's actual compiled fallback import and use process-local
`SSL_CERT_FILE`/`SSL_CERT_DIR` trust for its synthetic endpoint. These tests do not
claim that image gate, production deployment, app recovery, or ACME issuance.
