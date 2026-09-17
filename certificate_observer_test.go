package storageredis

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type candidateSink struct {
	mu         sync.Mutex
	candidates []MismatchCandidate
}

func (s *candidateSink) TryEnqueue(c MismatchCandidate) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.candidates = append(s.candidates, c)
	return true
}
func testPair(t *testing.T, rsaKey bool) ([]byte, []byte, crypto.Signer) {
	t.Helper()
	var k crypto.Signer
	var err error
	if rsaKey {
		k, err = rsa.GenerateKey(rand.Reader, 2048)
	} else {
		k, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	require.NoError(t, err)
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"fixture.example"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, k.Public(), k)
	require.NoError(t, err)
	key, err := x509.MarshalPKCS8PrivateKey(k)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), k
}
func TestCertificateObserverPairs(t *testing.T) {
	ec, ek, ep := testPair(t, false)
	ec2, ek2, _ := testPair(t, false)
	rc, rk, _ := testPair(t, true)
	_, rk2, _ := testPair(t, true)
	for _, tc := range []struct {
		name      string
		cert, key []byte
		want      int
	}{
		{"healthy EC", ec, ek, 0}, {"healthy RSA", rc, rk, 0}, {"mismatch EC", ec, ek2, 1}, {"mismatch RSA", rc, rk2, 1}, {"cross algorithm", rc, ek, 1},
		{"malformed cert", []byte("oops"), ek, 0}, {"malformed key", ec, []byte("oops"), 0}, {"missing key", ec, nil, 0}, {"oversized key", ec, []byte(strings.Repeat("x", 100000)), 0}, {"oversized cert", []byte(strings.Repeat("x", 100000)), ek, 0}, {"ambiguous key", ec, append(append([]byte{}, ek...), ek2...), 0}, {"junk prefix", append([]byte("junk"), ec...), ek2, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := new(candidateSink)
			o := newCertificateObserver("fixture.example", s)
			for i := 0; i < 3; i++ {
				o.Observe("certificates/issuer/fixture.example/fixture.example.key", tc.key)
				o.Observe("certificates/issuer/fixture.example/fixture.example.crt", tc.cert)
			}
			require.Len(t, s.candidates, tc.want)
		})
	}
	s := new(candidateSink)
	o := newCertificateObserver("fixture.example", s)
	o.Observe("certificates/issuer/fixture.example/fixture.example.crt", ec2)
	o.Observe("certificates/issuer/fixture.example/fixture.example.key", ek)
	require.Len(t, s.candidates, 1)
	c := s.candidates[0]
	leaf, _ := pem.Decode(ec2)
	h := sha256.Sum256(leaf.Bytes)
	require.Equal(t, hex.EncodeToString(h[:]), c.LeafSHA256)
	pub, _ := x509.MarshalPKIXPublicKey(ep.Public())
	h = sha256.Sum256(pub)
	require.Equal(t, hex.EncodeToString(h[:]), c.KeySPKISHA256)
	require.Equal(t, "fixture.example", c.Hostname)
	require.Equal(t, "issuer", c.IssuerKey)
	require.NotEqual(t, c.KeySPKISHA256, c.CertificateSPKISHA256)
}
func TestCertificateObserverPathsAndConcurrency(t *testing.T) {
	cert, _, _ := testPair(t, false)
	_, key, _ := testPair(t, false)
	for _, p := range []string{"certificates/issuer/wildcard_.example/wildcard_.example", "certificates/issuer/other.example/other.example", "certificates/../fixture.example/fixture.example", "certificates/issuer/fixture.example/other"} {
		s := new(candidateSink)
		o := newCertificateObserver("fixture.example", s)
		o.Observe(p+".crt", cert)
		o.Observe(p+".key", key)
		require.Empty(t, s.candidates)
	}
	s := new(candidateSink)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			o := newCertificateObserver("fixture.example", s)
			o.Observe("certificates/a/fixture.example/fixture.example.key", key)
			o.Observe("certificates/a/fixture.example/fixture.example.crt", cert)
		}()
	}
	wg.Wait()
	require.Len(t, s.candidates, 20)
	observeCertificateLoad(context.Background(), "certificates/a/fixture.example/fixture.example.key", key)
}

func TestCertificateObserverRejectsNoncanonicalScope(t *testing.T) {
	cert, _, _ := testPair(t, false)
	_, key, _ := testPair(t, false)
	require.False(t, validHealthHostname("127.0.0.1"))
	for _, issuer := range []string{"has space", "issuer%2fother", strings.Repeat("a", 129)} {
		s := new(candidateSink)
		o := newCertificateObserver("fixture.example", s)
		base := "certificates/" + issuer + "/fixture.example/fixture.example"
		o.Observe(base+".key", key)
		o.Observe(base+".crt", cert)
		require.Empty(t, s.candidates)
	}
}

func TestCertificateObserverStoragePreservesResult(t *testing.T) {
	rs, ctx := provisionRedisStorage(t)
	cert, _, _ := testPair(t, false)
	_, key, _ := testPair(t, false)
	sink := new(candidateSink)
	observer := newCertificateObserver("fixture.example", sink)
	observed := context.WithValue(ctx, observerContextKey{}, observer)
	base := "certificates/a/fixture.example/fixture.example"
	for ext, value := range map[string][]byte{".crt": cert, ".key": key} {
		require.NoError(t, rs.Store(ctx, base+ext, value))
		plain, err := rs.Load(ctx, base+ext)
		require.NoError(t, err)
		actual, err := rs.Load(observed, base+ext)
		require.NoError(t, err)
		require.Equal(t, plain, actual)
	}
	require.Len(t, sink.candidates, 1)
	for _, raw := range []string{`invalid`, `{"value":"aW52YWxpZA==","encryption":1}`, `{"value":"aW52YWxpZA==","compression":1}`} {
		require.NoError(t, rs.client.Set(ctx, rs.prefixKey(base+".crt"), raw, 0).Err())
		fresh := newCertificateObserver("fixture.example", sink)
		badctx := context.WithValue(ctx, observerContextKey{}, fresh)
		original, err := rs.Load(ctx, base+".crt")
		actual, gotErr := rs.Load(badctx, base+".crt")
		require.Equal(t, original, actual)
		require.Equal(t, err.Error(), gotErr.Error())
		require.Empty(t, fresh.pairs)
	}
}

func TestCertificateObserverSupportedKeysAndInvalidKeys(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		k, err := ecdsa.GenerateKey(curve, rand.Reader)
		require.NoError(t, err)
		der, err := x509.MarshalECPrivateKey(k)
		require.NoError(t, err)
		pub, err := x509.MarshalPKIXPublicKey(k.Public())
		require.NoError(t, err)
		h := sha256.Sum256(pub)
		require.Equal(t, hex.EncodeToString(h[:]), privateKeyFingerprint(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})))
		other, err := ecdsa.GenerateKey(curve, rand.Reader)
		require.NoError(t, err)
		k.PublicKey = other.PublicKey
		der, err = x509.MarshalECPrivateKey(k)
		require.NoError(t, err)
		require.Empty(t, privateKeyFingerprint(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})))
	}
	for _, bits := range []int{1024, 4096} {
		k, err := rsa.GenerateKey(rand.Reader, bits)
		require.NoError(t, err)
		encoded := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
		got := privateKeyFingerprint(encoded)
		if bits == 1024 {
			require.Empty(t, got)
		} else {
			pub, err := x509.MarshalPKIXPublicKey(k.Public())
			require.NoError(t, err)
			h := sha256.Sum256(pub)
			require.Equal(t, hex.EncodeToString(h[:]), got)
		}
	}
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(ed)
	require.NoError(t, err)
	require.Empty(t, privateKeyFingerprint(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})))
}

func TestCertificateObserverWorkBound(t *testing.T) {
	cert, _, _ := testPair(t, false)
	_, key, _ := testPair(t, false)
	sink := new(candidateSink)
	o := newCertificateObserver("fixture.example", sink)
	for i := 0; i < 100; i++ {
		base := fmt.Sprintf("certificates/issuer%d/fixture.example/fixture.example", i)
		o.Observe(base+".crt", cert)
		o.Observe(base+".key", key)
	}
	require.Len(t, sink.candidates, 4)
	require.Len(t, o.pairs, 4)
	require.Equal(t, 16, o.reads)
}

func TestCertificateObserverRejectsAmbiguousLeafScope(t *testing.T) {
	_, _, signer := testPair(t, false)
	_, mismatchedKey, _ := testPair(t, false)
	uri, err := url.Parse("https://fixture.example")
	require.NoError(t, err)
	alternativeSAN, err := asn1.Marshal([]asn1.RawValue{{Class: 2, Tag: 2, Bytes: []byte("fixture.example")}, {Class: 2, Tag: 8, Bytes: []byte{0x2a, 0x03}}})
	require.NoError(t, err)
	for _, tc := range []struct {
		name   string
		change func(*x509.Certificate)
		want   int
	}{
		{"exact single DNS", func(*x509.Certificate) {}, 1},
		{"wildcard", func(c *x509.Certificate) { c.DNSNames = []string{"*.example"} }, 0},
		{"shared DNS", func(c *x509.Certificate) { c.DNSNames = append(c.DNSNames, "other.example") }, 0},
		{"duplicate DNS", func(c *x509.Certificate) { c.DNSNames = append(c.DNSNames, "fixture.example") }, 0},
		{"DNS plus IP", func(c *x509.Certificate) { c.IPAddresses = []net.IP{net.ParseIP("192.0.2.1")} }, 0},
		{"DNS plus email", func(c *x509.Certificate) { c.EmailAddresses = []string{"owner@fixture.example"} }, 0},
		{"DNS plus URI", func(c *x509.Certificate) { c.URIs = []*url.URL{uri} }, 0},
		{"DNS plus unexposed registeredID", func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: alternativeSAN}}
		}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"fixture.example"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
			tc.change(c)
			der, err := x509.CreateCertificate(rand.Reader, c, c, signer.Public(), signer)
			require.NoError(t, err)
			leaf, err := x509.ParseCertificate(der)
			require.NoError(t, err)
			require.NoError(t, leaf.VerifyHostname("fixture.example"), "all regression leaves match hostname under the old permissive check")
			sink := new(candidateSink)
			o := newCertificateObserver("fixture.example", sink)
			o.Observe("certificates/a/fixture.example/fixture.example.key", mismatchedKey)
			o.Observe("certificates/a/fixture.example/fixture.example.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
			require.Len(t, sink.candidates, tc.want)
		})
	}
}

func TestCertificateObserverRejectsSkippedPEMBlocks(t *testing.T) {
	cert, _, _ := testPair(t, false)
	_, key, _ := testPair(t, false)
	for _, prefix := range []string{"-----BEGIN BROKEN-----\n", "-----BEGIN CERTIFICATE-----\ninvalid base64!\n-----END CERTIFICATE-----\n", "-----BEGIN PRIVATE KEY-----\ninvalid base64!\n-----END PRIVATE KEY-----\n"} {
		for _, part := range []string{"certificate", "key"} {
			t.Run(part+"/"+prefix, func(t *testing.T) {
				c, k := cert, key
				if part == "certificate" {
					c = append([]byte(prefix), cert...)
				} else {
					k = append([]byte(prefix), key...)
				}
				sink := new(candidateSink)
				o := newCertificateObserver("fixture.example", sink)
				o.Observe("certificates/a/fixture.example/fixture.example.key", k)
				o.Observe("certificates/a/fixture.example/fixture.example.crt", c)
				require.Empty(t, sink.candidates)
			})
		}
	}
	// The strict initial-block check also applies between certificate-chain blocks.
	c := append(append(append([]byte{}, cert...), []byte("-----BEGIN BROKEN-----\n")...), cert...)
	sink := new(candidateSink)
	o := newCertificateObserver("fixture.example", sink)
	o.Observe("certificates/a/fixture.example/fixture.example.key", key)
	o.Observe("certificates/a/fixture.example/fixture.example.crt", c)
	require.Empty(t, sink.candidates)
}
