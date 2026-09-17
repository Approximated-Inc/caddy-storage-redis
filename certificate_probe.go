package storageredis

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"strconv"
	"sync"
	"time"
)

// LocalCertificateProbe dials only a configured numeric loopback address. RootCAs
// is nil in production (system trust); fixtures may supply a private test CA.
// ClientAuth must reflect the selected inbound policy; those policies are unsupported.
type LocalCertificateProbe struct {
	Address    string
	RootCAs    *x509.CertPool
	ClientAuth bool
}

type CertificateTLSResult string

const (
	TLSAlert           CertificateTLSResult = "tls_alert"
	CertificateInvalid CertificateTLSResult = "certificate_invalid"
	TLSValid           CertificateTLSResult = "valid"
)

// An empty Result is inconclusive and must never be sent as failure evidence.
type CertificateProbeResult struct {
	Result           CertificateTLSResult
	CheckedAt        time.Time
	ServedLeafSHA256 string
}

func (p LocalCertificateProbe) Confirm(ctx context.Context, hostname string) bool {
	r := p.Check(ctx, hostname)
	return r.Result == TLSAlert || r.Result == CertificateInvalid
}

func validProbeAddress(address string) bool {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	n, err := strconv.Atoi(port)
	return ip != nil && ip.IsLoopback() && err == nil && n > 0 && n <= 65535
}

func (p LocalCertificateProbe) Check(ctx context.Context, hostname string) CertificateProbeResult {
	result := CertificateProbeResult{}
	if p.ClientAuth || !validHealthHostname(hostname) || ctx.Err() != nil || !validProbeAddress(p.Address) {
		return result
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 3 * time.Second}, Config: &tls.Config{ServerName: hostname, RootCAs: p.RootCAs, MinVersion: tls.VersionTLS12}}
	conn, err := d.DialContext(ctx, "tcp", p.Address)
	result.CheckedAt = time.Now().UTC().Truncate(time.Second)
	if err == nil {
		defer conn.Close()
		state := conn.(*tls.Conn).ConnectionState()
		if len(state.VerifiedChains) > 0 && len(state.PeerCertificates) > 0 {
			hash := sha256.Sum256(state.PeerCertificates[0].Raw)
			result.Result, result.ServedLeafSHA256 = TLSValid, hex.EncodeToString(hash[:])
		}
		return result
	}
	if ctx.Err() != nil {
		return result
	}
	var verification *tls.CertificateVerificationError
	if errors.As(err, &verification) {
		result.Result = CertificateInvalid
		return result
	}
	// The TCP TLS path wraps its unexported alert in a typed remote operation.
	var remote *net.OpError
	if errors.As(err, &remote) && remote.Op == "remote error" {
		result.Result = TLSAlert
	}
	return result
}

// ConfirmingSink holds a hostname guard before starting a probe. The local
// handshake therefore cannot recursively enqueue the same candidate. At most
// 16 probes exist at once; contention or saturation drops work immediately.
// Task 4's reporter owns delivery and any longer-lived deduplication.
type ConfirmingSink struct {
	mu       sync.Mutex
	inFlight map[string]bool
	ctx      context.Context
	cancel   context.CancelFunc
	probe    LocalCertificateProbe
	sink     MismatchSink
	closed   bool
	wg       sync.WaitGroup
}

func NewConfirmingSink(ctx context.Context, probe LocalCertificateProbe, sink MismatchSink) *ConfirmingSink {
	ctx, cancel := context.WithCancel(ctx)
	return &ConfirmingSink{ctx: ctx, cancel: cancel, probe: probe, sink: sink, inFlight: make(map[string]bool)}
}
func (s *ConfirmingSink) TryEnqueue(c MismatchCandidate) bool {
	if !s.mu.TryLock() {
		return false
	}
	if s.closed || s.ctx.Err() != nil || s.sink == nil || s.inFlight[c.Hostname] || len(s.inFlight) >= 16 || !validHealthHostname(c.Hostname) {
		s.mu.Unlock()
		return false
	}
	s.inFlight[c.Hostname] = true
	s.wg.Add(1)
	s.mu.Unlock()
	go func() {
		defer s.wg.Done()
		defer func() { s.mu.Lock(); delete(s.inFlight, c.Hostname); s.mu.Unlock() }()
		if s.probe.Confirm(s.ctx, c.Hostname) && s.ctx.Err() == nil {
			s.sink.TryEnqueue(c)
		}
	}()
	return true
}
func (s *ConfirmingSink) Close() {
	s.mu.Lock()
	s.closed = true
	s.cancel()
	s.mu.Unlock()
	s.wg.Wait()
}
