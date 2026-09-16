package integration

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"github.com/caddyserver/caddy/v2"
	_ "github.com/caddyserver/caddy/v2/modules/caddyhttp/proxyprotocol"
	"github.com/caddyserver/certmagic"
	_ "github.com/mholt/caddy-l4/layer4"
	_ "github.com/mholt/caddy-l4/modules/l4proxy"
	storageredis "github.com/pberkel/caddy-storage-redis"
	"github.com/stretchr/testify/require"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

// Test-only app: no production callback URL or instrumentation option.
type fixtureHealthApp struct {
	Events     string `json:"events"`
	Address    string `json:"address"`
	Roots      string `json:"roots"`
	ClientAuth bool   `json:"client_auth"`
	sink       *storageredis.ConfirmingSink
	Gate       string `json:"gate"`
	gated      atomic.Bool
	ctx        context.Context
}
type fixtureReportSink struct{ events string }

func (s fixtureReportSink) TryEnqueue(c storageredis.MismatchCandidate) bool {
	appendEvent(s.events, event{Kind: "confirmed", Candidate: &c})
	return true
}
func (*fixtureHealthApp) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "apx_certificate_health", New: func() caddy.Module { return new(fixtureHealthApp) }}
}
func (a *fixtureHealthApp) Provision(ctx caddy.Context) error {
	a.ctx = ctx
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(a.Roots))
	a.sink = storageredis.NewConfirmingSink(ctx, storageredis.LocalCertificateProbe{Address: a.Address, RootCAs: roots, ClientAuth: a.ClientAuth}, fixtureReportSink{a.Events})
	return nil
}
func (*fixtureHealthApp) Start() error  { return nil }
func (a *fixtureHealthApp) Stop() error { a.sink.Close(); return nil }
func (a *fixtureHealthApp) TryEnqueue(c storageredis.MismatchCandidate) bool {
	if a.Gate != "" && a.gated.CompareAndSwap(false, true) {
		go func() {
			ticker := time.NewTicker(time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-a.ctx.Done():
					return
				case <-ticker.C:
					if _, err := os.Stat(a.Gate); err == nil {
						a.enqueue(c)
						return
					}
				}
			}
		}()
		return true
	}
	return a.enqueue(c)
}
func (a *fixtureHealthApp) enqueue(c storageredis.MismatchCandidate) bool {
	accepted := a.sink.TryEnqueue(c)
	kind := "candidate_dropped"
	if accepted {
		kind = "candidate"
	}
	appendEvent(a.Events, event{Kind: kind, Candidate: &c})
	return accepted
}
func init() { caddy.RegisterModule(&fixtureHealthApp{}) }
func (f *fixture) startHealthNode(t *testing.T, auth bool, options ...bool) *node {
	l4 := len(options) > 0 && options[0]
	gate := len(options) > 1 && options[1]
	return f.startNodeConfigured(t, func(config map[string]any, n *node) {
		apps := config["apps"].(map[string]any)
		apps["apx_certificate_health"] = map[string]any{"events": n.events, "address": n.address, "roots": string(f.rootPEM), "client_auth": auth}
		if gate {
			apps["apx_certificate_health"].(map[string]any)["gate"] = n.events + ".probe-ready"
		}
		server := apps["http"].(map[string]any)["servers"].(map[string]any)["fixture"].(map[string]any)
		server["listener_wrappers"] = []any{map[string]any{"wrapper": "proxy_protocol", "timeout": "5s", "fallback_policy": "use"}, map[string]any{"wrapper": "tls"}}
		if l4 {
			l, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			front := l.Addr().String()
			require.NoError(t, l.Close())
			handler := map[string]any{"handler": "proxy", "proxy_protocol": "v2", "upstreams": []any{map[string]any{"dial": []string{n.address}}}}
			frontServer := map[string]any{"listen": []string{front}, "routes": []any{map[string]any{"handle": []any{handler}}}}
			apps["layer4"] = map[string]any{"servers": map[string]any{"front": frontServer}}
			n.address = front
		}
		policy := server["tls_connection_policies"].([]any)[0].(map[string]any)
		if auth {
			delete(policy, "handshake_context")
			policy["client_authentication"] = map[string]any{"mode": "require"}
		} else {
			policy["handshake_context"] = map[string]any{"module": "apx_certificate_health"}
		}
	})
}
func countEvents(t *testing.T, n *node, kind string) int {
	num := 0
	for _, e := range n.observations(t) {
		if e.Kind == kind {
			num++
		}
	}
	return num
}
func TestStoredMismatchObserverConfirmed(t *testing.T) {
	for _, l4 := range []bool{false, true} {
		t.Run(map[bool]string{false: "direct", true: "L4_PROXY_v2"}[l4], func(t *testing.T) {
			f := newFixture(t)
			f.seed(t, true)
			before := f.snapshot(t)
			n := f.startHealthNode(t, false, l4, true)
			gets := f.redisGets(t)
			conn, err := f.connect(n)
			if conn != nil {
				conn.Close()
			}
			require.Error(t, err)
			require.Equal(t, 6, f.redisGets(t)-gets)
			require.NoError(t, os.WriteFile(n.events+".probe-ready", []byte("go"), 0600))
			require.Eventually(t, func() bool { return countEvents(t, n, "confirmed") == 1 }, 5*time.Second, 10*time.Millisecond, "%s", n.log(t))
			require.Equal(t, 1, countEvents(t, n, "candidate"))
			t.Logf("Redis GET delta=%d", f.redisGets(t)-gets)
			require.Equal(t, 1, countEvents(t, n, "candidate_dropped"), "probe's own handshake must be guarded")
			require.Equal(t, 12, f.redisGets(t)-gets, "six original GETs plus six confirming-probe GETs")
			require.Equal(t, before, f.snapshot(t))
			for _, e := range n.observations(t) {
				if e.Kind == "confirmed" {
					require.Equal(t, fixtureName, e.Candidate.Hostname)
					require.Equal(t, f.paths[0], e.Candidate.CertificatePath)
					require.Equal(t, f.paths[1], e.Candidate.KeyPath)
					require.Len(t, e.Candidate.LeafSHA256, 64)
					require.NotEqual(t, e.Candidate.CertificateSPKISHA256, e.Candidate.KeySPKISHA256)
					b, _ := json.Marshal(e.Candidate)
					require.NotContains(t, string(b), "PRIVATE KEY")
				}
			}
		})
	}
}
func TestCertificateObserverWarmCacheAndClientAuth(t *testing.T) {
	f := newFixture(t)
	f.seed(t, false)
	n := f.startHealthNode(t, false)
	f.assertHealthy(t, n)
	require.Zero(t, countEvents(t, n, "candidate"))
	f.seed(t, true)
	gets := f.redisGets(t)
	loads := countEvents(t, n, "load")
	f.assertHealthy(t, n)
	require.Equal(t, gets, f.redisGets(t))
	require.Equal(t, loads, countEvents(t, n, "load"))
	require.Zero(t, countEvents(t, n, "candidate"))
	require.Zero(t, countEvents(t, n, "confirmed"))
	p := storageredis.LocalCertificateProbe{Address: n.address, RootCAs: f.roots}
	require.False(t, p.Confirm(context.Background(), fixtureName), "valid cached certificate discards stale mismatch")
	f.seed(t, false)
	m := f.startHealthNode(t, true)
	conn, err := tls.Dial("tcp", m.address, &tls.Config{ServerName: fixtureName, RootCAs: f.roots, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12})
	if conn != nil {
		conn.Close()
	}
	require.Error(t, err)
	require.Zero(t, countEvents(t, m, "candidate"))
	require.Zero(t, countEvents(t, m, "confirmed"))
}

func TestStoredMismatchHealthyFallbackIssuer(t *testing.T) {
	f := newFixture(t)
	f.seed(t, true)
	cert, key, _, leaf, roots, rootPEM := certificates(t, time.Minute)
	for ext, value := range map[string][]byte{".crt": cert, ".key": key, ".json": []byte(`{"sans":["fixture.example"],"issuer_data":{"fixture":true}}`)} {
		require.NoError(t, f.store.Store(context.Background(), "certificates/fallback-fixture/fixture.example/fixture.example"+ext, value))
	}
	roots.AppendCertsFromPEM(f.rootPEM)
	f.roots = roots
	f.rootPEM = append(f.rootPEM, rootPEM...)
	f.leaf = leaf
	n := f.startNodeConfigured(t, func(config map[string]any, n *node) {
		apps := config["apps"].(map[string]any)
		apps["apx_certificate_health"] = map[string]any{"events": n.events, "address": n.address, "roots": string(f.rootPEM), "gate": n.events + ".probe-ready"}
		policy := apps["tls"].(map[string]any)["automation"].(map[string]any)["policies"].([]any)[0].(map[string]any)
		policy["issuers"] = []any{map[string]any{"module": "test_fixture", "events": n.events}, map[string]any{"module": "test_fixture", "events": n.events, "key": "fallback-fixture"}}
		server := apps["http"].(map[string]any)["servers"].(map[string]any)["fixture"].(map[string]any)
		server["tls_connection_policies"].([]any)[0].(map[string]any)["handshake_context"] = map[string]any{"module": "apx_certificate_health"}
	})
	gets := f.redisGets(t)
	f.assertHealthy(t, n)
	t.Logf("fallback events=%+v", n.observations(t))
	require.Equal(t, 7, f.redisGets(t)-gets, "both issuers read plus one existing OCSP cache lookup")
	// A recorded mismatch exists on the older issuer, but verified local TLS is healthy.
	p := storageredis.LocalCertificateProbe{Address: n.address, RootCAs: f.roots}
	require.False(t, p.Confirm(context.Background(), fixtureName))
	require.Zero(t, countEvents(t, n, "confirmed"))
	require.NoError(t, os.WriteFile(n.events+".probe-ready", []byte("go"), 0600))
	require.Eventually(t, func() bool { return countEvents(t, n, "candidate") == 1 }, time.Second, 10*time.Millisecond)
	require.Equal(t, 7, f.redisGets(t)-gets, "local valid cached fallback uses zero storage GETs")
	// Metadata remains an ordinary CertMagic record; the observer does not parse it.
	require.Equal(t, certmagic.StorageKeys.SiteCert(fixtureIssuerKey, fixtureName), f.paths[0])
}

func TestCertificateObserverAbsentReporter(t *testing.T) {
	f := newFixture(t)
	f.seed(t, true)
	n := f.startNodeConfigured(t, func(config map[string]any, n *node) {
		apps := config["apps"].(map[string]any)
		server := apps["http"].(map[string]any)["servers"].(map[string]any)["fixture"].(map[string]any)
		server["tls_connection_policies"].([]any)[0].(map[string]any)["handshake_context"] = map[string]any{"module": "apx_certificate_health"}
	})
	gets := f.redisGets(t)
	conn, err := f.connect(n)
	if conn != nil {
		conn.Close()
	}
	require.Error(t, err)
	require.Equal(t, 6, f.redisGets(t)-gets)
	require.Zero(t, countEvents(t, n, "candidate"))
	require.Zero(t, countEvents(t, n, "confirmed"))
}
