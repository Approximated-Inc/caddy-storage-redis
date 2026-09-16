package integration

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	_ "github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/certmagic"
	storageredis "github.com/pberkel/caddy-storage-redis"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

const fixtureName = "fixture.example"
const fixtureIssuerKey = "local-fixture"
const testEncryptionKey = "integration-test-only-key-32-byte"

type handshakeMarker struct{}
type event struct {
	Kind      string                                 `json:"kind"`
	Candidate *storageredis.MismatchCandidate        `json:"candidate,omitempty"`
	Key       string                                 `json:"key,omitempty"`
	Stats     *storageredis.CertificateReporterStats `json:"stats,omitempty"`
	Handshake bool                                   `json:"handshake,omitempty"`
}

var eventMu sync.Mutex

func appendEvent(filename string, e event) {
	eventMu.Lock()
	defer eventMu.Unlock()
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	if err := json.NewEncoder(f).Encode(e); err != nil {
		panic(err)
	}
}

// Observation only: every operation delegates to actual RedisStorage and wire I/O.
type observedStorage struct {
	storageredis.RedisStorage
	Events string `json:"events"`
}

func (observedStorage) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "caddy.storage.test_observed_redis", New: func() caddy.Module { return &observedStorage{RedisStorage: *storageredis.New()} }}
}
func (s *observedStorage) CertMagicStorage() (certmagic.Storage, error) { return s, nil }
func (s *observedStorage) Load(ctx context.Context, key string) ([]byte, error) {
	appendEvent(s.Events, event{Kind: "load", Key: key, Handshake: ctx.Value(handshakeMarker{}) == fixtureName})
	return s.RedisStorage.Load(ctx, key)
}

// Proves the extension point; no health checks, mutation, or recovery.
type markerContext struct {
	Events string `json:"events"`
}

func (markerContext) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "tls.context.test_marker", New: func() caddy.Module { return new(markerContext) }}
}
func (m *markerContext) HandshakeContext(hello *tls.ClientHelloInfo) (context.Context, error) {
	appendEvent(m.Events, event{Kind: "handshake", Key: hello.ServerName})
	return context.WithValue(hello.Context(), handshakeMarker{}, hello.ServerName), nil
}

// No ACME client or network capability. Unexpected issuance is recorded/rejected.
type fixtureIssuer struct {
	Key    string `json:"key"`
	Events string `json:"events"`
}

func (fixtureIssuer) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "tls.issuance.test_fixture", New: func() caddy.Module { return new(fixtureIssuer) }}
}
func (i *fixtureIssuer) IssuerKey() string {
	if i.Key != "" {
		return i.Key
	}
	return fixtureIssuerKey
}
func (i *fixtureIssuer) Issue(context.Context, *x509.CertificateRequest) (*certmagic.IssuedCertificate, error) {
	appendEvent(i.Events, event{Kind: "issue"})
	return nil, errors.New("test fixture does not issue certificates")
}
func init() {
	caddy.RegisterModule(observedStorage{})
	caddy.RegisterModule(markerContext{})
	caddy.RegisterModule(fixtureIssuer{})
}

// Separate OS processes isolate all CertMagic globals and certificate caches.
func TestCaddyProcess(t *testing.T) {
	path := os.Getenv("APX_TEST_CADDY_CONFIG")
	if path == "" {
		t.Skip("subprocess entry point")
	}
	if rootsPath := os.Getenv("APX_TEST_FALLBACK_ROOTS"); rootsPath != "" {
		pem, err := os.ReadFile(rootsPath)
		require.NoError(t, err)
		pool := x509.NewCertPool()
		require.True(t, pool.AppendCertsFromPEM(pem))
		x509.SetFallbackRoots(pool)
	}
	config, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, caddy.Load(config, true))
	require.NoError(t, os.WriteFile(path+".ready", []byte("ready"), 0600))
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	sequence := 0
	for scanner.Scan() {
		sequence++
		var command childCommand
		require.NoError(t, json.Unmarshal(scanner.Bytes(), &command))
		previous := currentReporter
		response := childResponse{}
		if len(command.Config) > 0 {
			if err := caddy.Load(command.Config, true); err != nil {
				response.Error = err.Error()
				currentReporter = previous
			}
		}
		if currentReporter != nil {
			response.Stats = currentReporter.Stats()
		}
		if previous != nil {
			response.Previous = previous.Stats()
		}
		response.Goroutines = runtime.NumGoroutine()
		encoded, err := json.Marshal(response)
		require.NoError(t, err)
		responsePath := fmt.Sprintf("%s.command-%d", path, sequence)
		require.NoError(t, os.WriteFile(responsePath+".tmp", encoded, 0600))
		require.NoError(t, os.Rename(responsePath+".tmp", responsePath))
	}
	require.NoError(t, scanner.Err())
	require.NoError(t, caddy.Stop())
}

type fixture struct {
	store               *storageredis.RedisStorage
	redis               *redis.Client
	storageConfig       map[string]any
	cert, key, otherKey []byte
	leaf                *x509.Certificate
	roots               *x509.CertPool
	rootPEM             []byte
	paths               []string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	if os.Getenv("APX_REDIS_INTEGRATION") != "1" {
		t.Skip("set APX_REDIS_INTEGRATION=1 for isolated Docker Redis + Caddy integration")
	}
	address := startRedis(t)
	prefix := "integration-" + randomID(t)
	f := &fixture{storageConfig: map[string]any{"module": "test_observed_redis", "address": []string{address}, "key_prefix": prefix, "encryption_key": testEncryptionKey, "compression": "flate", "db": 0}}
	f.redis = redis.NewClient(&redis.Options{Addr: address})
	t.Cleanup(func() { _ = f.redis.Close() })
	f.store = storageredis.New()
	f.store.Address = []string{address}
	f.store.KeyPrefix = prefix
	f.store.EncryptionKey = testEncryptionKey
	f.store.Compression = storageredis.CompressionFlate
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)
	require.NoError(t, f.store.Provision(ctx))
	t.Cleanup(func() { _ = f.store.Cleanup() })
	f.cert, f.key, f.otherKey, f.leaf, f.roots, f.rootPEM = certificates(t)
	f.paths = []string{certmagic.StorageKeys.SiteCert(fixtureIssuerKey, fixtureName), certmagic.StorageKeys.SitePrivateKey(fixtureIssuerKey, fixtureName), certmagic.StorageKeys.SiteMeta(fixtureIssuerKey, fixtureName)}
	return f
}
func randomID(t *testing.T) string {
	t.Helper()
	var b [12]byte
	_, err := rand.Read(b[:])
	require.NoError(t, err)
	return fmt.Sprintf("%x", b)
}
func startRedis(t *testing.T) string {
	t.Helper()
	name := "apx-cert-integration-" + randomID(t)
	out, err := exec.Command("docker", "run", "--detach", "--rm", "--name", name, "--publish", "127.0.0.1::6379", "redis:7-alpine", "redis-server", "--save", "", "--appendonly", "no").CombinedOutput()
	require.NoError(t, err, "starting isolated Redis: %s", out)
	t.Cleanup(func() {
		out, err := exec.Command("docker", "rm", "--force", name).CombinedOutput()
		if err != nil {
			t.Errorf("removing test Redis %s: %s: %v", name, out, err)
		}
	})
	out, err = exec.Command("docker", "port", name, "6379/tcp").CombinedOutput()
	require.NoError(t, err, "%s", out)
	address := strings.TrimSpace(string(out))
	host, _, err := net.SplitHostPort(address)
	require.NoError(t, err)
	require.Equal(t, "127.0.0.1", host)
	client := redis.NewClient(&redis.Options{Addr: address})
	defer client.Close()
	require.Eventually(t, func() bool { return client.Ping(context.Background()).Err() == nil }, 10*time.Second, 25*time.Millisecond)
	return address
}
func certificates(t *testing.T, offset ...time.Duration) ([]byte, []byte, []byte, *x509.Certificate, *x509.CertPool, []byte) {
	t.Helper()
	newKey := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		return k
	}
	encodeKey := func(k *ecdsa.PrivateKey) []byte {
		der, err := x509.MarshalPKCS8PrivateKey(k)
		require.NoError(t, err)
		return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	}
	caKey, leafKey, otherKey := newKey(), newKey(), newKey()
	now := time.Now()
	if len(offset) > 0 {
		now = now.Add(offset[0])
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Integration test root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	ca, err = x509.ParseCertificate(caDER)
	require.NoError(t, err)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{fixtureName}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, caKey)
	require.NoError(t, err)
	leaf, err = x509.ParseCertificate(der)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), encodeKey(leafKey), encodeKey(otherKey), leaf, roots, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
}
func (f *fixture) seed(t *testing.T, mismatched bool) {
	t.Helper()
	key := f.key
	if mismatched {
		key = f.otherKey
	}
	metadata, err := json.Marshal(certmagic.CertificateResource{SANs: []string{fixtureName}, IssuerData: json.RawMessage(`{"fixture":true}`)})
	require.NoError(t, err)
	for i, value := range [][]byte{f.cert, key, metadata} {
		require.NoError(t, f.store.Store(context.Background(), f.paths[i], value))
	}
}

// Raw wrapper bytes include modification timestamps, encryption and compression.
func (f *fixture) snapshot(t *testing.T) map[string]string {
	t.Helper()
	result := map[string]string{}
	for _, key := range f.paths {
		raw, err := f.redis.Get(context.Background(), f.store.KeyPrefix+"/"+key).Result()
		require.NoError(t, err)
		var wrapper storageredis.StorageData
		require.NoError(t, json.Unmarshal([]byte(raw), &wrapper))
		require.Equal(t, 1, wrapper.Encryption)
		if strings.HasSuffix(key, ".crt") {
			require.Equal(t, 1, wrapper.Compression)
		} else {
			require.Contains(t, []int{0, 1}, wrapper.Compression)
		}
		result[key] = raw
	}
	return result
}
func (f *fixture) assertMismatch(t *testing.T) {
	t.Helper()
	cert, err := f.store.Load(context.Background(), f.paths[0])
	require.NoError(t, err)
	key, err := f.store.Load(context.Background(), f.paths[1])
	require.NoError(t, err)
	_, err = tls.X509KeyPair(cert, key)
	require.ErrorContains(t, err, "private key does not match public key")
}

type node struct {
	address, events, logs string
	configPath            string
	config                map[string]any
	input                 io.WriteCloser
	sequence              int
	testRoots             []byte
}

func (f *fixture) startNode(t *testing.T) *node { return f.startNodeConfigured(t, nil) }
func (f *fixture) startNodeConfigured(t *testing.T, configure func(map[string]any, *node)) *node {
	t.Helper()
	dir := t.TempDir()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().String()
	require.NoError(t, listener.Close())
	n := &node{address: address, events: filepath.Join(dir, "events.jsonl"), logs: filepath.Join(dir, "caddy.log")}
	storageConfig := map[string]any{}
	for k, v := range f.storageConfig {
		storageConfig[k] = v
	}
	storageConfig["events"] = n.events
	config := map[string]any{
		"admin":   map[string]any{"disabled": true, "config": map[string]any{"persist": false}},
		"storage": storageConfig,
		"logging": map[string]any{"logs": map[string]any{"default": map[string]any{"level": "DEBUG"}}},
		"apps": map[string]any{
			"tls": map[string]any{
				// Keep unrelated background reads out of handshake transport measurements.
				"disable_storage_clean": true,
				"automation": map[string]any{"policies": []any{map[string]any{
					"subjects":  []string{fixtureName},
					"on_demand": true,
					"issuers":   []any{map[string]any{"module": "test_fixture", "events": n.events}},
				}}},
			},
			"http": map[string]any{"servers": map[string]any{"fixture": map[string]any{
				"listen":          []string{address},
				"protocols":       []string{"h1"},
				"automatic_https": map[string]any{"disable": true},
				"tls_connection_policies": []any{map[string]any{
					"handshake_context": map[string]any{"module": "test_marker", "events": n.events},
				}},
			}}},
		},
	}
	if configure != nil {
		configure(config, n)
	}
	configBytes, err := json.Marshal(config)
	require.NoError(t, err)
	configPath := filepath.Join(dir, "caddy.json")
	n.configPath, n.config = configPath, config
	require.NoError(t, os.WriteFile(configPath, configBytes, 0600))
	executable, err := os.Executable()
	require.NoError(t, err)
	cmd := exec.Command(executable, "-test.run=^TestCaddyProcess$", "-test.v")
	// No user Redis credentials/config; no root trust installation.
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "XDG_DATA_HOME=" + dir, "XDG_CONFIG_HOME=" + dir, "APX_TEST_CADDY_CONFIG=" + configPath}
	if len(n.testRoots) > 0 {
		rootPath := filepath.Join(dir, "fallback-roots.pem")
		require.NoError(t, os.WriteFile(rootPath, n.testRoots, 0600))
		cmd.Env = append(cmd.Env, "APX_TEST_FALLBACK_ROOTS="+rootPath, "GODEBUG=x509usefallbackroots=1", "FLY_MACHINE_ID=123456789abcde")
	}
	input, err := cmd.StdinPipe()
	require.NoError(t, err)
	n.input = input
	logFile, err := os.Create(n.logs)
	require.NoError(t, err)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	require.NoError(t, cmd.Start())
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	t.Cleanup(func() {
		_ = input.Close()
		select {
		case err := <-exited:
			if err != nil {
				t.Errorf("Caddy subprocess: %v\n%s", err, n.log(t))
			}
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
			<-exited
			t.Error("Caddy did not stop")
		}
		_ = logFile.Close()
	})
	require.Eventually(t, func() bool { _, err := os.Stat(configPath + ".ready"); return err == nil }, 15*time.Second, 25*time.Millisecond, "Caddy failed to start; logs: %s", n.logs)
	return n
}
func (n *node) log(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(n.logs)
	require.NoError(t, err)
	return string(b)
}
func (n *node) observations(t *testing.T) []event {
	t.Helper()
	b, err := os.ReadFile(n.events)
	if os.IsNotExist(err) {
		return nil
	}
	require.NoError(t, err)
	decoder := json.NewDecoder(bytes.NewReader(b))
	var events []event
	for {
		var e event
		err = decoder.Decode(&e)
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		events = append(events, e)
	}
	return events
}
func (f *fixture) connect(n *node) (*tls.Conn, error) {
	return tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", n.address, &tls.Config{ServerName: fixtureName, RootCAs: f.roots, MinVersion: tls.VersionTLS12})
}
func (f *fixture) assertHealthy(t *testing.T, n *node) {
	t.Helper()
	conn, err := f.connect(n)
	require.NoError(t, err, "%s", n.log(t))
	defer conn.Close()
	require.Equal(t, f.leaf.Raw, conn.ConnectionState().PeerCertificates[0].Raw, "exact seeded leaf must be served")
	require.NotEmpty(t, conn.ConnectionState().VerifiedChains)
}
func (f *fixture) redisGets(t *testing.T) int {
	t.Helper()
	info, err := f.redis.Info(context.Background(), "commandstats").Result()
	require.NoError(t, err)
	for _, line := range strings.Split(info, "\n") {
		if strings.HasPrefix(line, "cmdstat_get:calls=") {
			count, err := strconv.Atoi(strings.Split(strings.TrimPrefix(line, "cmdstat_get:calls="), ",")[0])
			require.NoError(t, err)
			return count
		}
	}
	return 0
}
func assertHandshakeLoads(t *testing.T, n *node, paths []string) {
	t.Helper()
	seen := map[string]bool{}
	for _, e := range n.observations(t) {
		require.NotEqual(t, "issue", e.Kind, "existing bad resources suppress issuance")
		if e.Kind == "load" && strings.HasPrefix(e.Key, "certificates/") {
			require.True(t, e.Handshake, "certificate Load must carry handshake marker: %s", e.Key)
			seen[e.Key] = true
		}
	}
	for _, path := range paths {
		require.True(t, seen[path], "real handshake must load %s", path)
	}
}
func TestStoredMismatchDoesNotSelfRepair(t *testing.T) {
	f := newFixture(t)
	f.seed(t, true)
	f.assertMismatch(t)
	before := f.snapshot(t)
	n := f.startNode(t)
	for attempt := 0; attempt < 2; attempt++ {
		gets := f.redisGets(t)
		conn, err := f.connect(n)
		if conn != nil {
			conn.Close()
		}
		require.ErrorContains(t, err, "remote error: tls: internal error", "%s", n.log(t))
		require.Greater(t, f.redisGets(t), gets, "cold failure must reach real Redis")
		t.Logf("cold attempt %d: Redis GET delta=%d", attempt+1, f.redisGets(t)-gets)
		logTLSFailure(t, err)
		require.Equal(t, before, f.snapshot(t), "failed handshake must leave stored wrapper bytes unchanged")
	}
	f.assertMismatch(t)
	assertHandshakeLoads(t, n, f.paths)
	require.Contains(t, n.log(t), "private key does not match public key")
	t.Log("two real cold handshakes failed with TLS internal error; all encrypted/compressed records unchanged; no issuer calls; context marker reached all three loads")
}
func TestWarmCacheMasksStoredMismatch(t *testing.T) {
	f := newFixture(t)
	f.seed(t, false)
	warm := f.startNode(t)
	gets := f.redisGets(t)
	f.assertHealthy(t, warm)
	require.Greater(t, f.redisGets(t), gets)
	assertHandshakeLoads(t, warm, f.paths)
	f.seed(t, true)
	f.assertMismatch(t)
	before := f.snapshot(t)
	observations := len(warm.observations(t))
	gets = f.redisGets(t)
	f.assertHealthy(t, warm)
	require.Equal(t, gets, f.redisGets(t), "cache hit must not issue Redis GET")
	after := warm.observations(t)
	require.Len(t, after, observations+1, "cache hit invokes context hook without Load")
	require.Equal(t, "handshake", after[len(after)-1].Kind)
	cold := f.startNode(t)
	conn, err := f.connect(cold)
	if conn != nil {
		conn.Close()
	}
	require.ErrorContains(t, err, "remote error: tls: internal error", "%s", cold.log(t))
	assertHandshakeLoads(t, cold, f.paths)
	require.Equal(t, before, f.snapshot(t))
	f.assertHealthy(t, warm)
	t.Log("warm process served exact trusted leaf after storage corruption with zero Redis GETs; simultaneous fresh process failed; stored records unchanged")
}

// Record concrete TCP TLS errors for the next task's narrowly scoped classifier.
func logTLSFailure(t *testing.T, err error) {
	t.Helper()
	var opError *net.OpError
	require.ErrorAs(t, err, &opError)
	require.Equal(t, "remote error", opError.Op)
	var alert tls.AlertError
	require.False(t, errors.As(err, &alert), "TCP alert is not the exported QUIC AlertError")
	for current := err; current != nil; current = errors.Unwrap(current) {
		t.Logf("TCP TLS error: %T: %v", current, current)
	}
}
