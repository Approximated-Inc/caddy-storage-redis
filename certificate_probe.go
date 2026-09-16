package storageredis

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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

func (p LocalCertificateProbe) Confirm(ctx context.Context, hostname string) bool {
	if p.ClientAuth || !validHealthHostname(hostname) || ctx.Err() != nil {
		return false
	}
	host, port, err := net.SplitHostPort(p.Address)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	n, err := strconv.Atoi(port)
	if ip == nil || !ip.IsLoopback() || err != nil || n < 1 || n > 65535 {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 3 * time.Second}, Config: &tls.Config{ServerName: hostname, RootCAs: p.RootCAs, MinVersion: tls.VersionTLS12}}
	conn, err := d.DialContext(ctx, "tcp", p.Address)
	if err == nil {
		conn.Close()
		return false
	}
	if ctx.Err() != nil {
		return false
	}
	var verification *tls.CertificateVerificationError
	if errors.As(err, &verification) {
		return true
	}
	// TCP TLS alerts wrap an unexported tls.alert in this typed remote operation.
	// Only errors returned by the standard TLS dial path are classified here.
	var remote *net.OpError
	return errors.As(err, &remote) && remote.Op == "remote error"
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
