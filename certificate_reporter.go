package storageredis

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyevents"
	"go.uber.org/zap"
)

const certificateHealthPath = "/api/internal/certificate-health/events"
const certificateQueueCapacity = 256
const certificateDedupeCapacity = 1024
const certificateLifetime = 5 * time.Minute

// CertificateReporter is configured only by the trusted cluster generator.
// Token is the already-derived certificate-health purpose token, never a fleet key.
// No custom trust roots, insecure TLS, timing, or capacity settings are exposed.
type CertificateReporter struct {
	Endpoint      string `json:"endpoint"`
	ProxyServerID int64  `json:"proxy_server_id"`
	MachineID     string `json:"machine_id"`
	Token         string `json:"token"`
	Address       string `json:"address"`
	ClientAuth    bool   `json:"client_auth,omitempty"`

	state    atomic.Pointer[certificateReporterState]
	mu       sync.Mutex
	released bool
	logger   *zap.Logger
}

var certificateReporters = struct {
	sync.Mutex
	states map[[32]byte]*certificateReporterState
	active *certificateReporterState
}{states: make(map[[32]byte]*certificateReporterState)}

func init() { caddy.RegisterModule(&CertificateReporter{}) }
func (*CertificateReporter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "apx_certificate_health", New: func() caddy.Module { return new(CertificateReporter) }}
}
func (a *CertificateReporter) provisionConfiguration(_ caddy.Context) error {
	// Expand only this exact pre-existing provider placeholder. Never expand secrets.
	if a.MachineID == "{env.FLY_MACHINE_ID}" {
		a.MachineID = caddy.NewReplacer().ReplaceAll(a.MachineID, "")
	}
	return a.validate()
}
func (a *CertificateReporter) validate() error {
	u, err := url.Parse(a.Endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != certificateHealthPath || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return errors.New("certificate health requires the fixed HTTPS intake endpoint")
	}
	if a.ProxyServerID <= 0 || !lowerHex(a.MachineID, 14) || !validProbeAddress(a.Address) || !validBearer(a.Token) {
		return errors.New("invalid certificate health cluster, machine, listener or purpose token")
	}
	return nil
}
func (a *CertificateReporter) Provision(ctx caddy.Context) error {
	if err := a.provisionConfiguration(ctx); err != nil {
		return err
	}
	a.logger = ctx.Logger()
	events, err := ctx.App("events")
	if err != nil {
		return errors.New("certificate health lifecycle events unavailable")
	}
	app, ok := events.(*caddyevents.App)
	if !ok {
		return errors.New("certificate health lifecycle events unavailable")
	}
	return app.On("stopping", a)
}
func (a *CertificateReporter) identity() [32]byte {
	// Fixed ordered encoding; credentials never appear in registry keys or diagnostics.
	b, _ := json.Marshal([]any{a.ProxyServerID, a.MachineID, a.Endpoint, a.Token, a.Address, a.ClientAuth})
	return sha256.Sum256(b)
}
func (a *CertificateReporter) Start() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.released || a.state.Load() != nil {
		return nil
	}
	certificateReporters.Lock()
	defer certificateReporters.Unlock()
	id := a.identity()
	s := certificateReporters.states[id]
	if s == nil {
		transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, MaxIdleConns: 2, MaxIdleConnsPerHost: 2, MaxConnsPerHost: 2, IdleConnTimeout: 30 * time.Second, DisableCompression: true}
		client := &http.Client{Transport: transport}
		probe := LocalCertificateProbe{Address: a.Address, ClientAuth: a.ClientAuth}
		s = newCertificateReporterState(a, client, probe.Check, a.logger)
		certificateReporters.states[id] = s
		if certificateReporters.active == nil {
			certificateReporters.active = s
			s.start()
		}
	}
	s.refs++
	a.state.Store(s)
	return nil
}
func (a *CertificateReporter) Handle(_ context.Context, event caddy.Event) error {
	if event.Origin() != nil {
		return nil
	}
	if event.Name() == "stopping" {
		// Caddy emits this only after a successful replacement (before any app
		// drains). Failed provisional configurations release only their own ref.
		return a.Stop()
	}
	return nil
}
func (a *CertificateReporter) Stop() error {
	a.mu.Lock()
	if a.released {
		a.mu.Unlock()
		return nil
	}
	a.released = true
	s := a.state.Load()
	a.mu.Unlock()
	if s == nil {
		return nil
	}
	certificateReporters.Lock()
	defer certificateReporters.Unlock()
	s.refs--
	if s.refs == 0 {
		delete(certificateReporters.states, a.identity())
		// Joining under this control-plane mutex prevents concurrent Start from
		// creating another running pool before this one has fully stopped.
		s.stop()
		if certificateReporters.active == s {
			certificateReporters.active = nil
			for _, remaining := range certificateReporters.states {
				certificateReporters.active = remaining
				remaining.start()
				break
			}
		}
	}
	return nil
}
func (a *CertificateReporter) Cleanup() error { return a.Stop() }
func (a *CertificateReporter) TryEnqueue(c MismatchCandidate) bool {
	s := a.state.Load()
	return s != nil && s.TryEnqueue(c)
}

// CertificateReporterStats contains only fixed-cardinality public counters.
type CertificateReporterStats struct {
	Active, Dedupe, Workers                int
	Dropped, Delivered, Accepted, Failures uint64
}

func (a *CertificateReporter) Stats() CertificateReporterStats {
	if s := a.state.Load(); s != nil {
		return s.snapshot()
	}
	return CertificateReporterStats{}
}

type certificateEvent struct {
	Version               int                  `json:"version"`
	Kind                  string               `json:"kind"`
	EventID               string               `json:"event_id"`
	ProxyServerID         int64                `json:"proxy_server_id"`
	MachineID             string               `json:"machine_id"`
	Hostname              string               `json:"hostname"`
	Issuer                string               `json:"issuer"`
	ObservedAt            string               `json:"observed_at"`
	TLSCheckedAt          string               `json:"tls_checked_at"`
	TLSResult             CertificateTLSResult `json:"tls_result"`
	LeafSHA256            string               `json:"leaf_sha256,omitempty"`
	CertificateSPKISHA256 string               `json:"cert_spki_sha256,omitempty"`
	KeySPKISHA256         string               `json:"key_spki_sha256,omitempty"`
	ReportID              string               `json:"report_id,omitempty"`
	VerificationNonce     string               `json:"verification_nonce,omitempty"`
	ServedLeafSHA256      string               `json:"served_leaf_sha256,omitempty"`
}
type certificateAcceptance struct {
	ReportID          string `json:"report_id"`
	VerificationNonce string `json:"verification_nonce"`
	CheckAfterSeconds int    `json:"check_after_seconds"`
	ExpiresAt         string `json:"expires_at"`
}
type certificateWork struct {
	candidate                            MismatchCandidate
	birth, expires, due, lastObservation time.Time
	busy                                 bool
	event                                *certificateEvent
	attempts                             int
	acceptance                           *certificateAcceptance
}
type certificateReporterState struct {
	mu                                     sync.Mutex
	lifecycleMu                            sync.Mutex
	started                                bool
	ctx                                    context.Context
	cancel                                 context.CancelFunc
	wg                                     sync.WaitGroup
	wake                                   chan struct{}
	work                                   map[string]*certificateWork
	dedupe                                 map[[32]byte]time.Time
	refs                                   int // guarded by registry mutex
	cluster                                int64
	machine, endpoint, token               string
	client                                 *http.Client
	probe                                  func(context.Context, string) CertificateProbeResult
	logger                                 *zap.Logger
	lastDiagnostic                         time.Time
	dropped, delivered, accepted, failures atomic.Uint64
	workers                                atomic.Int32
}

func newCertificateReporterState(config *CertificateReporter, client *http.Client, probe func(context.Context, string) CertificateProbeResult, logger *zap.Logger) *certificateReporterState {
	ctx, cancel := context.WithCancel(context.Background())
	// Copy the supplied client; tests may supply a transport with ephemeral roots.
	boundedClient := *client
	boundedClient.Timeout = 3 * time.Second
	boundedClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	s := &certificateReporterState{ctx: ctx, cancel: cancel, wake: make(chan struct{}, 2), work: make(map[string]*certificateWork), dedupe: make(map[[32]byte]time.Time), cluster: config.ProxyServerID, machine: config.MachineID, endpoint: config.Endpoint, token: config.Token, client: &boundedClient, probe: probe, logger: logger}
	return s
}
func (s *certificateReporterState) start() {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	if s.started || s.ctx.Err() != nil {
		return
	}
	s.started = true
	s.wg.Add(2)
	for i := 0; i < 2; i++ {
		go s.run()
	}
}
func (s *certificateReporterState) TryEnqueue(c MismatchCandidate) bool {
	if !s.mu.TryLock() {
		s.dropped.Add(1)
		return false
	}
	defer s.mu.Unlock()
	if s.ctx.Err() != nil || !validHealthHostname(c.Hostname) || !validHealthIssuer(c.IssuerKey) || !lowerHex(c.LeafSHA256, 64) || !lowerHex(c.CertificateSPKISHA256, 64) || !lowerHex(c.KeySPKISHA256, 64) || c.CertificateSPKISHA256 == c.KeySPKISHA256 {
		s.dropped.Add(1)
		return false
	}
	// Retain only bounded public identity and hashes, not storage paths.
	c.CertificatePath, c.KeyPath = "", ""
	b, _ := json.Marshal(c)
	key := sha256.Sum256(b)
	now := time.Now()
	s.prune(now)
	if s.work[c.Hostname] != nil || now.Before(s.dedupe[key]) || len(s.work) >= certificateQueueCapacity {
		s.dropped.Add(1)
		return false
	}
	if len(s.dedupe) >= certificateDedupeCapacity {
		var oldest [32]byte
		var earliest time.Time
		for k, expiry := range s.dedupe {
			if earliest.IsZero() || expiry.Before(earliest) {
				oldest, earliest = k, expiry
			}
		}
		delete(s.dedupe, oldest)
	}
	expires := now.Add(certificateLifetime)
	s.dedupe[key] = expires
	s.work[c.Hostname] = &certificateWork{candidate: c, birth: now, expires: expires, due: now}
	select {
	case s.wake <- struct{}{}:
	default:
	}
	return true
}
func (s *certificateReporterState) prune(now time.Time) {
	for key, expiry := range s.dedupe {
		if !now.Before(expiry) {
			delete(s.dedupe, key)
		}
	}
	for host, work := range s.work {
		if !work.busy && !now.Before(work.expires) {
			delete(s.work, host)
		}
	}
}
func (s *certificateReporterState) run() {
	s.workers.Add(1)
	defer s.wg.Done()
	defer s.workers.Add(-1)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if s.ctx.Err() != nil {
			return
		}
		s.mu.Lock()
		now := time.Now()
		s.prune(now)
		var selected *certificateWork
		for _, w := range s.work {
			if !w.busy && !now.Before(w.due) && (selected == nil || w.due.Before(selected.due)) {
				selected = w
			}
		}
		if selected != nil {
			selected.busy = true
		}
		if s.logger != nil && now.Sub(s.lastDiagnostic) >= time.Minute && (s.dropped.Load() > 0 || s.failures.Load() > 0) {
			s.lastDiagnostic = now
			s.logger.Warn("certificate health work dropped or delivery failed", zap.Uint64("dropped", s.dropped.Load()), zap.Uint64("failures", s.failures.Load()))
		}
		s.mu.Unlock()
		if selected != nil {
			keep := s.process(selected)
			s.mu.Lock()
			selected.busy = false
			if !keep || s.ctx.Err() != nil || !time.Now().Before(selected.expires) {
				delete(s.work, selected.candidate.Hostname)
			}
			s.mu.Unlock()
			continue
		}
		select {
		case <-s.ctx.Done():
			return
		case <-s.wake:
		case <-ticker.C:
		}
	}
}
func (s *certificateReporterState) process(w *certificateWork) bool {
	ctx, cancel := context.WithDeadline(s.ctx, w.expires)
	defer cancel()
	if ctx.Err() != nil {
		return false
	}
	if w.event == nil {
		result := s.probe(ctx, w.candidate.Hostname)
		if ctx.Err() != nil {
			return false
		}
		if result.Result == "" {
			if w.acceptance == nil {
				return false
			}
			w.due = time.Now().Add(30 * time.Second)
			return true
		}
		if result.Result == TLSValid && w.acceptance == nil {
			return false
		}
		observed := result.CheckedAt.UTC().Truncate(time.Second)
		if !observed.After(w.lastObservation) {
			w.due = time.Now().Add(time.Second)
			return true
		}
		id, err := certificateUUID()
		if err != nil {
			s.failures.Add(1)
			return false
		}
		w.lastObservation = observed
		e := &certificateEvent{Version: 1, Kind: "mismatch", EventID: id, ProxyServerID: s.cluster, MachineID: s.machine, Hostname: w.candidate.Hostname, Issuer: w.candidate.IssuerKey, ObservedAt: observed.Format(time.RFC3339), TLSCheckedAt: observed.Format(time.RFC3339), TLSResult: result.Result}
		if w.acceptance == nil {
			e.ObservedAt = w.birth.UTC().Truncate(time.Second).Format(time.RFC3339)
		}
		if result.Result == TLSValid {
			e.Kind, e.ServedLeafSHA256 = "verification", result.ServedLeafSHA256
		} else {
			e.LeafSHA256, e.CertificateSPKISHA256, e.KeySPKISHA256 = w.candidate.LeafSHA256, w.candidate.CertificateSPKISHA256, w.candidate.KeySPKISHA256
		}
		if w.acceptance != nil {
			e.ReportID, e.VerificationNonce = w.acceptance.ReportID, w.acceptance.VerificationNonce
		}
		w.event, w.attempts = e, 0
	}
	w.attempts++
	acceptance, retry := s.deliver(ctx, w.event)
	if acceptance == nil {
		if retry && w.attempts < 3 {
			// Jittered 1-2s then 2-4s delays, scheduled without holding a worker.
			jitter, err := rand.Int(rand.Reader, big.NewInt(1000))
			if err != nil {
				return false
			}
			w.due = time.Now().Add(time.Duration(1000+jitter.Int64()) * time.Millisecond * time.Duration(w.attempts))
			return w.due.Before(w.expires)
		}
		return false
	}
	if w.acceptance != nil && (acceptance.ReportID != w.acceptance.ReportID || acceptance.VerificationNonce != w.acceptance.VerificationNonce || acceptance.ExpiresAt != w.acceptance.ExpiresAt) {
		s.failures.Add(1)
		return false
	}
	s.accepted.Add(1)
	if w.acceptance == nil {
		w.acceptance = acceptance
		expires, _ := time.Parse(time.RFC3339, acceptance.ExpiresAt)
		if expires.Before(w.expires) {
			w.expires = expires
		}
	}
	w.event = nil
	w.due = time.Now().Add(30 * time.Second)
	return true
}
func (s *certificateReporterState) deliver(ctx context.Context, event *certificateEvent) (*certificateAcceptance, bool) {
	body, err := json.Marshal(event)
	if err != nil || len(body) > 8192 {
		s.failures.Add(1)
		return nil, false
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, bytes.NewReader(body))
	if err != nil {
		s.failures.Add(1)
		return nil, false
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("apx-proxy-server-id", strconv.FormatInt(s.cluster, 10))
	request.Header.Set("apx-key", s.token)
	response, err := s.client.Do(request)
	if err != nil {
		s.failures.Add(1)
		return nil, true
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNoContent {
		s.delivered.Add(1)
		return nil, false
	}
	if response.StatusCode != http.StatusAccepted {
		s.failures.Add(1)
		return nil, response.StatusCode == 429 || response.StatusCode == 503
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, 8193))
	if err != nil {
		s.failures.Add(1)
		return nil, true
	}
	if len(payload) > 8192 {
		s.failures.Add(1)
		return nil, false
	}
	acceptance, err := parseCertificateAcceptance(payload, time.Now())
	if err != nil {
		s.failures.Add(1)
		return nil, false
	}
	s.delivered.Add(1)
	return acceptance, false
}
func parseCertificateAcceptance(payload []byte, now time.Time) (*certificateAcceptance, error) {
	// Decode members individually to reject duplicate and unknown JSON keys.
	d := json.NewDecoder(bytes.NewReader(payload))
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return nil, errors.New("invalid acceptance")
	}
	seen := make(map[string]bool, 4)
	a := new(certificateAcceptance)
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] {
			return nil, errors.New("invalid acceptance")
		}
		seen[key] = true
		switch key {
		case "report_id":
			err = d.Decode(&a.ReportID)
		case "verification_nonce":
			err = d.Decode(&a.VerificationNonce)
		case "check_after_seconds":
			err = d.Decode(&a.CheckAfterSeconds)
		case "expires_at":
			err = d.Decode(&a.ExpiresAt)
		default:
			return nil, errors.New("invalid acceptance")
		}
		if err != nil {
			return nil, errors.New("invalid acceptance")
		}
	}
	if _, err := d.Token(); err != nil {
		return nil, errors.New("invalid acceptance")
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("invalid acceptance")
	}
	expires, err := time.Parse(time.RFC3339, a.ExpiresAt)
	if len(seen) != 4 || !validCertificateUUID(a.ReportID) || !validBearer(a.VerificationNonce) || a.CheckAfterSeconds != 30 || err != nil || expires.UTC().Format(time.RFC3339) != a.ExpiresAt || !expires.After(now) || expires.After(now.Add(certificateLifetime+10*time.Second)) {
		return nil, errors.New("invalid acceptance")
	}
	return a, nil
}
func (s *certificateReporterState) snapshot() CertificateReporterStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return CertificateReporterStats{Active: len(s.work), Dedupe: len(s.dedupe), Workers: int(s.workers.Load()), Dropped: s.dropped.Load(), Delivered: s.delivered.Load(), Accepted: s.accepted.Load(), Failures: s.failures.Load()}
}
func (s *certificateReporterState) stop() {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	s.cancel()
	s.wg.Wait()
	s.client.CloseIdleConnections()
	s.mu.Lock()
	clear(s.work)
	clear(s.dedupe)
	s.mu.Unlock()
}
func lowerHex(s string, size int) bool {
	if len(s) != size {
		return false
	}
	for _, ch := range s {
		if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f') {
			return false
		}
	}
	return true
}
func validBearer(s string) bool {
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	return err == nil && len(b) == 32 && base64.RawURLEncoding.EncodeToString(b) == s
}
func certificateUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6], b[8] = b[6]&0x0f|0x40, b[8]&0x3f|0x80
	h := hex.EncodeToString(b[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], nil
}
func validCertificateUUID(s string) bool {
	return len(s) == 36 && s[8] == '-' && s[13] == '-' && s[18] == '-' && s[23] == '-' && s[14] == '4' && strings.ContainsRune("89ab", rune(s[19])) && lowerHex(strings.ReplaceAll(s, "-", ""), 32)
}

var _ caddy.App = (*CertificateReporter)(nil)
var _ caddy.Provisioner = (*CertificateReporter)(nil)
var _ caddy.CleanerUpper = (*CertificateReporter)(nil)
var _ MismatchSink = (*CertificateReporter)(nil)
