package integration

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	storageredis "github.com/pberkel/caddy-storage-redis"
	"github.com/stretchr/testify/require"
)

// Test child only: no production clock, trust override or failure injection.
var currentReporter *storageredis.CertificateReporter

type reporterMonitor struct {
	Events    string `json:"events"`
	FailStart bool   `json:"fail_start"`
	reporter  *storageredis.CertificateReporter
}

func (reporterMonitor) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "test_reporter_monitor", New: func() caddy.Module { return new(reporterMonitor) }}
}
func (m *reporterMonitor) Provision(ctx caddy.Context) error {
	app, err := ctx.AppIfConfigured("apx_certificate_health")
	if err == nil {
		m.reporter, _ = app.(*storageredis.CertificateReporter)
	}
	currentReporter = m.reporter
	return nil
}
func (m *reporterMonitor) Start() error {
	if m.FailStart {
		return errors.New("test-only failed Start")
	}
	return nil
}
func (m *reporterMonitor) Stop() error {
	if m.reporter != nil {
		stats := m.reporter.Stats()
		appendEvent(m.Events, event{Kind: "reporter_monitor_stop", Stats: &stats})
	}
	return nil
}
func init() { caddy.RegisterModule(reporterMonitor{}) }

type childCommand struct {
	Config json.RawMessage `json:"config,omitempty"`
}
type childResponse struct {
	Error           string
	Stats, Previous storageredis.CertificateReporterStats
	Goroutines      int
}

func (n *node) command(t *testing.T, config map[string]any) childResponse {
	t.Helper()
	n.sequence++
	command := childCommand{}
	if config != nil {
		var err error
		command.Config, err = json.Marshal(config)
		require.NoError(t, err)
	}
	require.NoError(t, json.NewEncoder(n.input).Encode(command))
	path := fmt.Sprintf("%s.command-%d", n.configPath, n.sequence)
	require.Eventually(t, func() bool { _, err := os.Stat(path); return err == nil }, 10*time.Second, 5*time.Millisecond, "%s", n.log(t))
	encoded, err := os.ReadFile(path)
	require.NoError(t, err)
	var response childResponse
	require.NoError(t, json.Unmarshal(encoded, &response))
	return response
}
func cloneConfig(t *testing.T, config map[string]any) map[string]any {
	encoded, err := json.Marshal(config)
	require.NoError(t, err)
	var result map[string]any
	require.NoError(t, json.Unmarshal(encoded, &result))
	return result
}
func (f *fixture) startReporterNode(t *testing.T, endpoint *httptest.Server) *node {
	require.Equal(t, "1", os.Getenv("APX_CERTIFICATE_TEST_OVERLAY"), "run ./test-caddy-version.sh for real reporter integration with isolated trust")
	return f.startNodeConfigured(t, func(config map[string]any, n *node) {
		n.testRoots = append(append([]byte{}, f.rootPEM...), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: endpoint.Certificate().Raw})...)
		apps := config["apps"].(map[string]any)
		apps["apx_certificate_health"] = map[string]any{"endpoint": endpoint.URL + "/api/internal/certificate-health/events", "proxy_server_id": 42, "machine_id": "{env.FLY_MACHINE_ID}", "token": base64.RawURLEncoding.EncodeToString(make([]byte, 32)), "address": n.address}
		apps["test_reporter_monitor"] = map[string]any{"events": n.events}
		server := apps["http"].(map[string]any)["servers"].(map[string]any)["fixture"].(map[string]any)
		server["listener_wrappers"] = []any{map[string]any{"wrapper": "proxy_protocol", "timeout": "5s", "fallback_policy": "use"}, map[string]any{"wrapper": "tls"}}
		server["tls_connection_policies"].([]any)[0].(map[string]any)["handshake_context"] = map[string]any{"module": "apx_certificate_health"}
	})
}
func TestCertificateReporterRepeatedReload(t *testing.T) {
	f := newFixture(t)
	f.seed(t, true)
	before := f.snapshot(t)
	var mu sync.Mutex
	var received []map[string]any
	var expires string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/internal/certificate-health/events", r.URL.Path)
		require.Equal(t, "42", r.Header.Get("apx-proxy-server-id"))
		require.Equal(t, base64.RawURLEncoding.EncodeToString(make([]byte, 32)), r.Header.Get("apx-key"))
		var event map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&event))
		mu.Lock()
		received = append(received, event)
		if expires == "" {
			expires = time.Now().Add(64 * time.Second).UTC().Format(time.RFC3339)
		}
		expiry := expires
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(202)
		json.NewEncoder(w).Encode(map[string]any{"report_id": "12345678-1234-4234-8234-123456789abc", "verification_nonce": base64.RawURLEncoding.EncodeToString(make([]byte, 32)), "check_after_seconds": 30, "expires_at": expiry})
	}))
	defer server.Close()
	n := f.startReporterNode(t, server)
	baseline := n.command(t, nil)
	conn, err := f.connect(n)
	if conn != nil {
		conn.Close()
	}
	require.Error(t, err)
	require.Eventually(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(received) == 1 }, 5*time.Second, 10*time.Millisecond, "%s", n.log(t))
	require.Eventually(t, func() bool { return n.command(t, nil).Stats.Accepted == 1 }, time.Second, 10*time.Millisecond)
	for i := 0; i < 20; i++ {
		response := n.command(t, n.config)
		require.Empty(t, response.Error)
		require.Equal(t, 2, response.Stats.Workers)
		require.Equal(t, 1, response.Stats.Active)
		require.Equal(t, 1, response.Stats.Dedupe)
		require.Equal(t, uint64(1), response.Stats.Accepted)
	}
	for _, failure := range []string{"provision", "start", "finish"} {
		config := cloneConfig(t, n.config)
		apps := config["apps"].(map[string]any)
		health := apps["apx_certificate_health"].(map[string]any)
		health["token"] = base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))
		switch failure {
		case "provision":
			health["address"] = "outside.example:443"
		case "start":
			apps["test_reporter_monitor"].(map[string]any)["fail_start"] = true
		case "finish":
			config["admin"].(map[string]any)["remote"] = map[string]any{"listen": "127.0.0.1:invalid-port"}
		}
		response := n.command(t, config)
		require.NotEmpty(t, response.Error)
		require.Equal(t, 2, response.Stats.Workers)
		require.Equal(t, 1, response.Stats.Active)
		require.Equal(t, uint64(1), response.Stats.Accepted)
		t.Logf("rejected %s reload with prior reporter intact: %s", failure, response.Error)
	}
	// The fixture repairs storage; the plugin must independently verify the served
	// leaf at its next scheduled check, without any writer or success alert.
	require.Equal(t, before, f.snapshot(t))
	f.seed(t, false)
	afterFixtureRepair := f.snapshot(t)
	require.Eventually(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(received) == 2 }, 36*time.Second, 50*time.Millisecond, "%s", n.log(t))
	mu.Lock()
	first, next := received[0], received[1]
	mu.Unlock()
	require.Equal(t, "123456789abcde", first["machine_id"])
	require.Equal(t, float64(42), first["proxy_server_id"])
	require.NotEqual(t, first["event_id"], next["event_id"])
	require.Nil(t, first["report_id"])
	require.Equal(t, "12345678-1234-4234-8234-123456789abc", next["report_id"])
	require.Equal(t, "verification", next["kind"])
	require.Equal(t, "valid", next["tls_result"])
	require.Equal(t, fmt.Sprintf("%x", sha256.Sum256(f.leaf.Raw)), next["served_leaf_sha256"])
	for _, key := range []string{"leaf_sha256", "cert_spki_sha256", "key_spki_sha256"} {
		require.Nil(t, next[key])
	}
	//202 acknowledges evidence, not completed repair: a later fresh success is
	// still emitted with the same nonce, allowing strictly post-attempt proof.
	require.Equal(t, 1, n.command(t, nil).Stats.Active)
	require.Eventually(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(received) == 3 }, 36*time.Second, 50*time.Millisecond)
	mu.Lock()
	later := received[2]
	mu.Unlock()
	require.Equal(t, "verification", later["kind"])
	require.Equal(t, next["report_id"], later["report_id"])
	require.Equal(t, next["verification_nonce"], later["verification_nonce"])
	require.Equal(t, next["served_leaf_sha256"], later["served_leaf_sha256"])
	require.NotEqual(t, next["event_id"], later["event_id"])
	require.Greater(t, later["observed_at"].(string), next["observed_at"].(string))
	require.Eventually(t, func() bool { return n.command(t, nil).Stats.Active == 0 }, 5*time.Second, 20*time.Millisecond)
	response := n.command(t, nil)
	require.Equal(t, 2, response.Stats.Workers)
	require.Equal(t, 1, response.Stats.Dedupe)
	require.LessOrEqual(t, response.Goroutines, baseline.Goroutines+10)
	require.Equal(t, afterFixtureRepair, f.snapshot(t))
	t.Logf("20 reloads: workers=%d active=%d dedupe=%d goroutines baseline=%d final=%d; three reports including two fresh successes, original root expiry", response.Stats.Workers, response.Stats.Active, response.Stats.Dedupe, baseline.Goroutines, response.Goroutines)
}
func TestCertificateReporterReloadCancelsBlockedDelivery(t *testing.T) {
	for _, mode := range []string{"disable", "changed-token"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			f.seed(t, true)
			entered := make(chan struct{}, 2)
			release := make(chan struct{})
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				entered <- struct{}{}
				select {
				case <-r.Context().Done():
				case <-release:
				}
			}))
			defer server.Close()
			defer close(release)
			n := f.startReporterNode(t, server)
			conn, err := f.connect(n)
			if conn != nil {
				conn.Close()
			}
			require.Error(t, err)
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("no reporter request")
			}
			config := cloneConfig(t, n.config)
			apps := config["apps"].(map[string]any)
			if mode == "disable" {
				delete(apps, "apx_certificate_health")
			} else {
				apps["apx_certificate_health"].(map[string]any)["token"] = base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))
			}
			start := time.Now()
			response := n.command(t, config)
			require.Empty(t, response.Error)
			require.Less(t, time.Since(start), 2*time.Second)
			require.Zero(t, response.Previous.Active)
			require.Zero(t, response.Previous.Workers)
			require.Zero(t, response.Previous.Dedupe)
			for _, event := range n.observations(t) {
				if event.Kind == "reporter_monitor_stop" {
					require.Zero(t, event.Stats.Workers, "cancel before any old app Stop/drain")
				}
			}
			if mode == "changed-token" {
				require.Equal(t, 2, response.Stats.Workers)
			} else {
				require.Zero(t, response.Stats.Workers)
			}
		})
	}
}
