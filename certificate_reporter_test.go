package storageredis

import (
	"context"
	"crypto/tls"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func reporterConfig(endpoint string) *CertificateReporter {
	return &CertificateReporter{Endpoint: endpoint + certificateHealthPath, ProxyServerID: 42, MachineID: "123456789abcde", Token: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), Address: "127.0.0.1:443"}
}
func reportCandidate(host string) MismatchCandidate {
	return MismatchCandidate{Hostname: host, IssuerKey: "test-issuer", LeafSHA256: strings.Repeat("a", 64), CertificateSPKISHA256: strings.Repeat("b", 64), KeySPKISHA256: strings.Repeat("c", 64)}
}
func failedProbe(context.Context, string) CertificateProbeResult {
	return CertificateProbeResult{Result: TLSAlert, CheckedAt: time.Now().UTC().Truncate(time.Second)}
}
func acceptedResponse(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(202)
	json.NewEncoder(w).Encode(map[string]any{"report_id": "12345678-1234-4234-8234-123456789abc", "verification_nonce": base64.RawURLEncoding.EncodeToString(make([]byte, 32)), "check_after_seconds": 30, "expires_at": time.Now().Add(5*time.Minute).UTC().Format(time.RFC3339)})
}
func TestCertificateReporterConfiguration(t *testing.T) {
	for _, modify := range []func(*CertificateReporter){
		func(c *CertificateReporter) { c.Endpoint = "http://app.example" + certificateHealthPath },
		func(c *CertificateReporter) { c.Endpoint += "?secret=1" },
		func(c *CertificateReporter) { c.Endpoint = "https://user:pass@app.example" + certificateHealthPath },
		func(c *CertificateReporter) { c.Endpoint += "/" },
		func(c *CertificateReporter) { c.Token = "fleet-key" },
		func(c *CertificateReporter) { c.MachineID = "{env.NOT_DEFINED}" },
		func(c *CertificateReporter) { c.Address = "example.com:443" },
		func(c *CertificateReporter) { c.ProxyServerID = 0 },
	} {
		c := reporterConfig("https://app.example")
		modify(c)
		require.Error(t, c.validate())
	}
	c := reporterConfig("https://app.example")
	require.NoError(t, c.validate())
	t.Setenv("FLY_MACHINE_ID", "abcdef12345678")
	c.MachineID = "{env.FLY_MACHINE_ID}"
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	// Placeholder handling is deliberately separate from token handling.
	require.NoError(t, c.provisionConfiguration(ctx))
	require.Equal(t, "abcdef12345678", c.MachineID)
	require.Equal(t, reporterConfig("https://app.example").Token, c.Token)
}
func TestCertificateReporterDelivery(t *testing.T) {
	for _, status := range []int{204, 400, 401, 413, 429, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var mu sync.Mutex
			var bodies []string
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, certificateHealthPath, r.URL.Path)
				require.Equal(t, "42", r.Header.Get("apx-proxy-server-id"))
				require.Len(t, r.Header.Values("apx-key"), 1)
				var event certificateEvent
				require.NoError(t, json.NewDecoder(r.Body).Decode(&event))
				mu.Lock(); bodies = append(bodies, event.EventID); mu.Unlock()
				w.WriteHeader(status)
			}))
			defer server.Close()
			s := newTestCertificateReporterState(reporterConfig(server.URL), server.Client(), failedProbe, nil)
			defer s.stop()
			require.Eventually(t, func() bool { return s.TryEnqueue(reportCandidate("fixture.example")) }, time.Second, time.Millisecond)
			want := 1
			if status == 429 || status == 503 { want = 3 }
			require.Eventually(t, func() bool { return s.snapshot().Active == 0 }, 12*time.Second, 10*time.Millisecond)
			mu.Lock(); defer mu.Unlock()
			require.Len(t, bodies, want)
			for _, id := range bodies { require.Equal(t, bodies[0], id) }
			require.False(t, s.TryEnqueue(reportCandidate("fixture.example")), "terminal dedupe retained for root lifetime")
		})
	}
}
func TestCertificateReporterResponseLostAfterCommit(t *testing.T) {
	var requests atomic.Int32
	var mu sync.Mutex
	var ids []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var event certificateEvent
		require.NoError(t, json.NewDecoder(r.Body).Decode(&event))
		mu.Lock(); ids = append(ids, event.EventID); mu.Unlock()
		if requests.Add(1) == 1 {
			c, _, err := w.(http.Hijacker).Hijack(); require.NoError(t, err); c.Close(); return
		}
		acceptedResponse(w)
	}))
	defer server.Close()
	s := newTestCertificateReporterState(reporterConfig(server.URL), server.Client(), failedProbe, nil)
	defer s.stop()
	require.Eventually(t, func() bool { return s.TryEnqueue(reportCandidate("fixture.example")) }, time.Second, time.Millisecond)
	require.Eventually(t, func() bool { return s.snapshot().Accepted == 1 }, 6*time.Second, time.Millisecond)
	mu.Lock(); defer mu.Unlock()
	require.Len(t, ids, 2)
	require.Equal(t, ids[0], ids[1])
	require.Equal(t, 1, s.snapshot().Active)
}
func TestLocalCertificateProbeTypedResult(t *testing.T) {
	cert, key, _ := testPair(t, false)
	pair, err := tls.X509KeyPair(cert, key)
	require.NoError(t, err)
	address := probeListener(t, &tls.Config{Certificates: []tls.Certificate{pair}})
	p := LocalCertificateProbe{Address: address}
	result := p.Check(context.Background(), "fixture.example")
	require.Equal(t, CertificateInvalid, result.Result)
	require.Empty(t, result.ServedLeafSHA256)
	require.WithinDuration(t, time.Now(), result.CheckedAt, 2*time.Second)
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	require.NoError(t, err)
	p.RootCAs = x509.NewCertPool()
	p.RootCAs.AddCert(leaf)
	valid := p.Check(context.Background(), "fixture.example")
	require.Equal(t, TLSValid, valid.Result)
	require.Equal(t, fmt.Sprintf("%x", sha256.Sum256(leaf.Raw)), valid.ServedLeafSHA256)

}

func TestCertificateReporterInitialObservationAndLifetime(t *testing.T) {
	events := make(chan certificateEvent, 2)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var event certificateEvent
		require.NoError(t, json.NewDecoder(r.Body).Decode(&event))
		events <- event
		acceptedResponse(w)
	}))
	defer server.Close()
	s := newTestCertificateReporterState(reporterConfig(server.URL), server.Client(), failedProbe, nil)
	defer s.stop()
	birth := time.Now().Add(-20*time.Second).UTC().Truncate(time.Second)
	// Deterministically seed an already-waiting candidate before a worker sees it.
	s.mu.Lock()
	w := &certificateWork{candidate: reportCandidate("fixture.example"), birth: birth, due: time.Now(), expires: birth.Add(certificateLifetime)}
	s.work["fixture.example"] = w
	s.mu.Unlock()
	var event certificateEvent
	select { case event = <-events: case <-time.After(time.Second): t.Fatal("no initial report") }
	require.Equal(t, birth.Format(time.RFC3339), event.ObservedAt, "initial observation must retain candidate birth")
	require.NotEqual(t, event.ObservedAt, event.TLSCheckedAt)
	require.Eventually(t, func() bool { s.mu.Lock(); defer s.mu.Unlock(); return !w.busy && w.acceptance != nil }, time.Second, time.Millisecond)
	s.mu.Lock()
	require.Equal(t, birth.Add(certificateLifetime), w.expires, "server acceptance may not extend candidate lifetime")
	s.mu.Unlock()
}
func TestCertificateReporterAcceptanceValidation(t *testing.T) {
	valid := `{"report_id":"12345678-1234-4234-8234-123456789abc","verification_nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","check_after_seconds":30,"expires_at":"` + time.Now().Add(time.Minute).UTC().Format(time.RFC3339) + `"}`
	_, err := parseCertificateAcceptance([]byte(valid), time.Now())
	require.NoError(t, err)
	for _, payload := range []string{
		strings.Replace(valid, `"check_after_seconds":30`, `"check_after_seconds":31`, 1),
		strings.Replace(valid, `"check_after_seconds":30`, `"check_after_seconds":"30"`, 1),
		strings.Replace(valid, `"check_after_seconds":30`, `"check_after_seconds":30,"check_after_seconds":30`, 1),
		strings.Replace(valid, `"check_after_seconds":30`, `"check_after_seconds":30,"extra":1`, 1),
		strings.Replace(valid, `12345678-1234-4234`, `12345678-1234-1234`, 1),
		strings.Replace(valid, `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`, `abc`, 1),
		strings.Replace(valid, time.Now().Add(time.Minute).UTC().Format(time.RFC3339), time.Now().Add(6*time.Minute).UTC().Format(time.RFC3339), 1),
		strings.Replace(valid, time.Now().Add(time.Minute).UTC().Format(time.RFC3339), time.Now().Add(-time.Minute).UTC().Format(time.RFC3339), 1),
		strings.Replace(valid, `Z"}`, `+00:00"}`, 1),
		strings.Replace(valid, `Z"}`, `.123Z"}`, 1),
		valid + `{}`, `null`,
	} {
		_, err := parseCertificateAcceptance([]byte(payload), time.Now())
		require.Error(t, err)
	}
}
func TestCertificateReporterTransportBounds(t *testing.T) {
	t.Run("redirect", func(t *testing.T) {
		var followed atomic.Int32
		target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { followed.Add(1) }))
		defer target.Close()
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 307) }))
		defer server.Close()
		s := newTestCertificateReporterState(reporterConfig(server.URL), server.Client(), failedProbe, nil)
		defer s.stop()
		require.Eventually(t, func() bool { return s.TryEnqueue(reportCandidate("fixture.example")) }, time.Second, time.Millisecond)
		require.Eventually(t, func() bool { return s.snapshot().Active == 0 }, time.Second, time.Millisecond)
		require.Zero(t, followed.Load())
		require.Equal(t, uint64(1), s.snapshot().Failures)
	})
	t.Run("response bound", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(202); w.Write([]byte(strings.Repeat(" ", 8193))) }))
		defer server.Close()
		s := newTestCertificateReporterState(reporterConfig(server.URL), server.Client(), failedProbe, nil)
		defer s.stop()
		require.Eventually(t, func() bool { return s.TryEnqueue(reportCandidate("fixture.example")) }, time.Second, time.Millisecond)
		require.Eventually(t, func() bool { return s.snapshot().Active == 0 }, time.Second, time.Millisecond)
		require.Equal(t, uint64(1), s.snapshot().Failures)
		require.Zero(t, s.snapshot().Accepted)
	})
	t.Run("total timeout and cancellation", func(t *testing.T) {
		entered := make(chan struct{}, 4)
		release := make(chan struct{})
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { entered <- struct{}{}; select { case <-r.Context().Done(): case <-release: } }))
		defer server.Close()
		defer close(release)
		s := newTestCertificateReporterState(reporterConfig(server.URL), server.Client(), failedProbe, nil)
		defer s.stop()
		start := time.Now()
		require.Eventually(t, func() bool { return s.TryEnqueue(reportCandidate("fixture.example")) }, time.Second, time.Millisecond)
		<-entered
		require.Eventually(t, func() bool { return s.snapshot().Failures > 0 }, 4*time.Second, 10*time.Millisecond)
		require.GreaterOrEqual(t, time.Since(start), 2900*time.Millisecond)
		<-entered
		start = time.Now()
		s.stop()
		require.Less(t, time.Since(start), time.Second)
		require.Zero(t, s.snapshot().Workers)
		require.Zero(t, s.snapshot().Active)
	})
}
func TestCertificateReporterQueueBoundsAndEviction(t *testing.T) {
	entered := make(chan struct{}, 2)
	probe := func(ctx context.Context, _ string) CertificateProbeResult { entered <- struct{}{}; <-ctx.Done(); return CertificateProbeResult{} }
	s := newTestCertificateReporterState(reporterConfig("https://app.example"), &http.Client{}, probe, nil)
	defer s.stop()
	for i := 0; i < certificateQueueCapacity; i++ {
		candidate := reportCandidate(fmt.Sprintf("host%d.example", i))
		require.Eventually(t, func() bool { return s.TryEnqueue(candidate) }, time.Second, time.Millisecond)
	}
	<-entered; <-entered
	require.Equal(t, 256, s.snapshot().Active)
	require.Equal(t, 2, s.snapshot().Workers)
	require.False(t, s.TryEnqueue(reportCandidate("overflow.example")))
	require.False(t, s.TryEnqueue(reportCandidate("host0.example")))
	// Expiry cleanup retains the two bounded in-flight entries until cancellation.
	s.mu.Lock()
	s.prune(time.Now().Add(6*time.Minute))
	require.Len(t, s.work, 2)
	require.Empty(t, s.dedupe)
	for i := 0; i < 1024; i++ {
		var key [32]byte
		key[0], key[1] = byte(i), byte(i>>8)
		s.dedupe[key] = time.Now().Add(time.Minute)
	}
	s.mu.Unlock()
	require.Eventually(t, func() bool { return s.TryEnqueue(reportCandidate("after-eviction.example")) }, time.Second, time.Millisecond)
	require.Equal(t, 1024, s.snapshot().Dedupe)
	s.stop()
	require.Zero(t, s.snapshot().Active)
	require.Zero(t, s.snapshot().Workers)
	require.Zero(t, s.snapshot().Dedupe)
}

func TestCertificateReporterContinuation(t *testing.T) {
	for _, healthy := range []bool{false, true} {
		t.Run(fmt.Sprint(healthy), func(t *testing.T) {
			events := make(chan certificateEvent, 4)
			expires := time.Now().Add(certificateLifetime).UTC().Format(time.RFC3339)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var event certificateEvent
				require.NoError(t, json.NewDecoder(r.Body).Decode(&event))
				events <- event
				w.WriteHeader(202)
				json.NewEncoder(w).Encode(certificateAcceptance{ReportID: "12345678-1234-4234-8234-123456789abc", VerificationNonce: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), CheckAfterSeconds: 30, ExpiresAt: expires})
			}))
			defer server.Close()
			var probes atomic.Int32
			probe := func(context.Context, string) CertificateProbeResult {
				n := probes.Add(1)
				result := CertificateProbeResult{Result: TLSAlert, CheckedAt: time.Now().Add(time.Duration(n-1)*time.Second).UTC().Truncate(time.Second)}
				if n > 1 && healthy { result.Result, result.ServedLeafSHA256 = TLSValid, strings.Repeat("d", 64) }
				return result
			}
			s := newTestCertificateReporterState(reporterConfig(server.URL), server.Client(), probe, nil)
			defer s.stop()
			require.Eventually(t, func() bool { return s.TryEnqueue(reportCandidate("fixture.example")) }, time.Second, time.Millisecond)
			first := <-events
			require.Eventually(t, func() bool {
				s.mu.Lock(); defer s.mu.Unlock()
				w := s.work["fixture.example"]
				if w == nil || w.busy || w.acceptance == nil { return false }
				require.Greater(t, time.Until(w.due), 29*time.Second)
				w.due = time.Now()
				return true
			}, time.Second, time.Millisecond)
			var next certificateEvent
			select { case next = <-events: case <-time.After(time.Second): t.Fatal("no continuation") }
			require.NotEqual(t, first.EventID, next.EventID)
			require.Equal(t, "12345678-1234-4234-8234-123456789abc", next.ReportID)
			require.Equal(t, base64.RawURLEncoding.EncodeToString(make([]byte, 32)), next.VerificationNonce)
			require.Equal(t, first.MachineID, next.MachineID)
			require.Equal(t, first.Hostname, next.Hostname)
			require.Greater(t, next.ObservedAt, first.ObservedAt)
			if healthy {
				require.Equal(t, "verification", next.Kind)
				require.Empty(t, next.LeafSHA256)
				require.Empty(t, next.CertificateSPKISHA256)
				require.Empty(t, next.KeySPKISHA256)
				require.Equal(t, strings.Repeat("d",64), next.ServedLeafSHA256)
				var originalExpiry time.Time
				require.Eventually(t, func() bool {
					s.mu.Lock(); defer s.mu.Unlock()
					w := s.work["fixture.example"]
					if w == nil || w.busy || w.event != nil { return false }
					originalExpiry = w.expires
					require.Equal(t, expires, w.acceptance.ExpiresAt)
					w.due = time.Now()
					return true
				}, time.Second, time.Millisecond, "202 accepts verification; only204 or expiry ends the root")
				var later certificateEvent
				select { case later = <-events: case <-time.After(time.Second): t.Fatal("no later accepted-success observation") }
				require.Equal(t, "verification", later.Kind)
				require.NotEqual(t, next.EventID, later.EventID)
				require.Greater(t, later.ObservedAt, next.ObservedAt)
				require.Equal(t, next.ReportID, later.ReportID)
				require.Equal(t, next.VerificationNonce, later.VerificationNonce)
				require.Eventually(t, func() bool {
					s.mu.Lock(); defer s.mu.Unlock()
					w := s.work["fixture.example"]
					if w == nil || w.busy { return false }
					require.Equal(t, originalExpiry, w.expires)
					return true
				}, time.Second, time.Millisecond)
			} else {
				require.Equal(t, "mismatch", next.Kind)
				require.Equal(t, first.LeafSHA256, next.LeafSHA256)
				require.Equal(t, first.CertificateSPKISHA256, next.CertificateSPKISHA256)
				require.Equal(t, first.KeySPKISHA256, next.KeySPKISHA256)
				require.Empty(t, next.ServedLeafSHA256)
			}
		})
	}
}
func TestCertificateReporterRootDeadlineCancelsDelivery(t *testing.T) {
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { entered <- struct{}{}; select { case <-r.Context().Done(): case <-release: } }))
	defer server.Close()
	defer close(release)
	s := newTestCertificateReporterState(reporterConfig(server.URL), server.Client(), failedProbe, nil)
	defer s.stop()
	now := time.Now()
	s.mu.Lock()
	s.work["fixture.example"] = &certificateWork{candidate: reportCandidate("fixture.example"), birth: now.Add(-certificateLifetime+time.Second), due: now, expires: now.Add(time.Second)}
	s.mu.Unlock()
	select { case <-entered: case <-time.After(time.Second): t.Fatal("no report") }
	require.Eventually(t, func() bool { return s.snapshot().Active == 0 }, 2*time.Second, time.Millisecond)
	require.Equal(t, uint64(1), s.snapshot().Failures)
	require.Less(t, time.Since(now), 2*time.Second)
}

func newTestCertificateReporterState(config *CertificateReporter, client *http.Client, probe func(context.Context, string) CertificateProbeResult, logger *zap.Logger) *certificateReporterState {
	s := newCertificateReporterState(config, client, probe, logger)
	s.start()
	return s
}
func TestCertificateReporterProvisionalPool(t *testing.T) {
	old := reporterConfig("https://app.example")
	require.NoError(t, old.Start())
	defer old.Stop()
	require.Eventually(t, func() bool { return old.Stats().Workers == 2 }, time.Second, time.Millisecond)
	newConfig := reporterConfig("https://app.example")
	newConfig.Token = base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))
	require.NoError(t, newConfig.Start())
	defer newConfig.Stop()
	require.Zero(t, newConfig.Stats().Workers)
	require.Equal(t, 2, old.Stats().Workers)
	// A failed provisional reload leaves the old worker pool and state untouched.
	require.NoError(t, newConfig.Cleanup())
	require.Equal(t, 2, old.Stats().Workers)
	newConfig = reporterConfig("https://other-app.example")
	require.NoError(t, newConfig.Start())
	defer newConfig.Stop()
	require.Zero(t, newConfig.Stats().Workers)
	require.NoError(t, old.Stop())
	require.Zero(t, old.Stats().Workers)
	require.Eventually(t, func() bool { return newConfig.Stats().Workers == 2 }, time.Second, time.Millisecond)
}

func TestCertificateReporterTerminalStatusDoesNotWaitForBody(t *testing.T) {
	for _, status := range []int{204, 400, 401, 413} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			release := make(chan struct{})
			var requests atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.WriteHeader(status)
				w.(http.Flusher).Flush()
				select { case <-release: case <-r.Context().Done(): }
			}))
			defer server.Close()
			defer close(release)
			s := newTestCertificateReporterState(reporterConfig(server.URL), server.Client(), failedProbe, nil)
			defer s.stop()
			require.Eventually(t, func() bool { return s.TryEnqueue(reportCandidate("fixture.example")) }, time.Second, time.Millisecond)
			require.Eventually(t, func() bool { return s.snapshot().Active == 0 }, time.Second, time.Millisecond)
			require.Equal(t, int32(1), requests.Load())
		})
	}
}

func TestCertificateReporterConcurrentReferencesAndProvisionalCleanup(t *testing.T) {
	original := reporterConfig("https://app.example")
	require.NoError(t, original.Start())
	defer original.Stop()
	var wg sync.WaitGroup
	copies := make([]*CertificateReporter, 20)
	for i := range copies {
		copies[i] = reporterConfig("https://app.example")
		wg.Add(1)
		go func(c *CertificateReporter) { defer wg.Done(); require.NoError(t, c.Start()) }(copies[i])
	}
	wg.Wait()
	for _, copy := range copies { require.Same(t, original.state.Load(), copy.state.Load()); require.NoError(t, copy.Stop()) }
	require.Eventually(t, func() bool { return original.Stats().Workers == 2 }, time.Second, time.Millisecond)
	first := reporterConfig("https://first.example")
	second := reporterConfig("https://second.example")
	require.NoError(t, first.Start())
	defer first.Stop()
	require.NoError(t, second.Start())
	defer second.Stop()
	require.NoError(t, first.Cleanup())
	require.Never(t, func() bool { return original.Stats().Workers + second.Stats().Workers > 2 }, 200*time.Millisecond, time.Millisecond, "failed provisional cleanup cannot activate another pool alongside the current pool")
}
