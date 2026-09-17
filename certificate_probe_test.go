package storageredis

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func probeListener(t *testing.T, config *tls.Config) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				if config == nil {
					c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
					return
				}
				_ = tls.Server(c, config).Handshake()
			}()
		}
	}()
	return l.Addr().String()
}
func TestLocalCertificateProbe(t *testing.T) {
	cert, key, _ := testPair(t, false)
	pair, err := tls.X509KeyPair(cert, key)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	healthy := probeListener(t, &tls.Config{Certificates: []tls.Certificate{pair}})
	failing := probeListener(t, &tls.Config{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return nil, errors.New("controlled certificate load failure")
	}})
	wrong := probeListener(t, nil)
	for _, tc := range []struct {
		name, address string
		roots         *x509.CertPool
		auth          bool
		want          bool
	}{
		{"healthy", healthy, roots, false, false}, {"certificate verification", healthy, x509.NewCertPool(), false, true}, {"typed remote alert", failing, roots, false, true}, {"wrong listener", wrong, roots, false, false}, {"mTLS unsupported", failing, roots, true, false}, {"DNS dial forbidden", "localhost:443", roots, false, false}, {"external dial forbidden", "192.0.2.1:443", roots, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := LocalCertificateProbe{Address: tc.address, RootCAs: tc.roots, ClientAuth: tc.auth}
			require.Equal(t, tc.want, p.Confirm(context.Background(), "fixture.example"))
		})
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	closed := l.Addr().String()
	l.Close()
	p := LocalCertificateProbe{Address: closed}
	require.False(t, p.Confirm(context.Background(), "fixture.example"))
	p.Address = failing
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.False(t, p.Confirm(ctx, "fixture.example"))
	l, err = net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	accepted := make(chan net.Conn, 1)
	go func() { c, _ := l.Accept(); accepted <- c }()
	p.Address = l.Addr().String()
	start := time.Now()
	require.False(t, p.Confirm(context.Background(), "fixture.example"))
	require.Less(t, time.Since(start), 4*time.Second)
	select {
	case c := <-accepted:
		c.Close()
	case <-time.After(100 * time.Millisecond):
		t.Fatal("probe did not dial timeout listener")
	}
	eof, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer eof.Close()
	go func() { c, _ := eof.Accept(); c.Close() }()
	p.Address = eof.Addr().String()
	require.False(t, p.Confirm(context.Background(), "fixture.example"))
}
func TestLocalCertificateProbeGuard(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var probes atomic.Int32
	address := probeListener(t, &tls.Config{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		if probes.Add(1) == 1 {
			close(entered)
		}
		<-release
		return nil, errors.New("bad certificate")
	}})
	downstream := new(candidateSink)
	sink := NewConfirmingSink(context.Background(), LocalCertificateProbe{Address: address}, downstream)
	require.True(t, sink.TryEnqueue(MismatchCandidate{Hostname: "fixture.example"}))
	<-entered
	require.False(t, sink.TryEnqueue(MismatchCandidate{Hostname: "fixture.example"}))
	close(release)
	sink.Close()
	require.Equal(t, int32(1), probes.Load())
	// Close cancels pending probes; no report can be relied on after cancellation.
	require.False(t, sink.TryEnqueue(MismatchCandidate{Hostname: "fixture.example"}))
}

func TestLocalCertificateProbeHealthySinkDiscardsCandidate(t *testing.T) {
	cert, key, _ := testPair(t, false)
	pair, err := tls.X509KeyPair(cert, key)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	address := probeListener(t, &tls.Config{Certificates: []tls.Certificate{pair}})
	downstream := new(candidateSink)
	sink := NewConfirmingSink(context.Background(), LocalCertificateProbe{Address: address, RootCAs: roots}, downstream)
	defer sink.Close()
	require.True(t, sink.TryEnqueue(MismatchCandidate{Hostname: "fixture.example"}))
	require.Eventually(t, func() bool { sink.mu.Lock(); defer sink.mu.Unlock(); return len(sink.inFlight) == 0 }, time.Second, time.Millisecond)
	downstream.mu.Lock()
	defer downstream.mu.Unlock()
	require.Empty(t, downstream.candidates)
}
