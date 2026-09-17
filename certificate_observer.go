package storageredis

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"sync"
)

// MismatchCandidate contains public fingerprints only, never private-key material.
// It is evidence of a stored mismatch, not evidence that local TLS is failing.
type MismatchCandidate struct {
	Hostname              string `json:"hostname"`
	IssuerKey             string `json:"issuer_key"`
	CertificatePath       string `json:"certificate_path"`
	KeyPath               string `json:"key_path"`
	LeafSHA256            string `json:"leaf_sha256"`
	CertificateSPKISHA256 string `json:"cert_spki_sha256"`
	KeySPKISHA256         string `json:"key_spki_sha256"`
}

// MismatchSink must return immediately; queueing and confirmation run off the handshake.
type MismatchSink interface{ TryEnqueue(MismatchCandidate) bool }
type observerContextKey struct{}
type observedPair struct {
	certSeen, keySeen, done bool
	leaf, cert, key         string
}
type certificateObserver struct {
	mu       sync.Mutex
	hostname string
	sink     MismatchSink
	pairs    map[string]*observedPair
	reads    int
}

func newCertificateObserver(hostname string, sink MismatchSink) *certificateObserver {
	return &certificateObserver{hostname: hostname, sink: sink, pairs: make(map[string]*observedPair)}
}
func observeCertificateLoad(ctx context.Context, key string, value []byte) {
	if o, ok := ctx.Value(observerContextKey{}).(*certificateObserver); ok {
		o.Observe(key, value)
	}
}
func validHealthHostname(s string) bool {
	if len(s) == 0 || len(s) > 253 || s != strings.ToLower(s) || net.ParseIP(s) != nil {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
func validHealthIssuer(s string) bool {
	if s == "" || s == "." || s == ".." || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}
func (o *certificateObserver) Observe(storageKey string, plaintext []byte) {
	if o == nil || o.sink == nil || !validHealthHostname(o.hostname) {
		return
	}
	parts := strings.Split(storageKey, "/")
	if len(parts) != 4 || parts[0] != "certificates" || !validHealthIssuer(parts[1]) || parts[2] != o.hostname {
		return
	}
	ext := strings.TrimPrefix(parts[3], o.hostname)
	if parts[3] != o.hostname+ext || (ext != ".crt" && ext != ".key") {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	// Bound both issuer cardinality and expensive work for the lifetime of a handshake.
	if o.reads >= 16 {
		return
	}
	o.reads++
	p := o.pairs[parts[1]]
	if p == nil {
		if len(o.pairs) >= 4 {
			return
		}
		p = &observedPair{}
		o.pairs[parts[1]] = p
	}
	if p.done {
		return
	}
	if ext == ".crt" {
		if p.certSeen {
			return
		}
		p.certSeen = true
		p.leaf, p.cert = certificateFingerprints(plaintext, o.hostname)
	} else {
		if p.keySeen {
			return
		}
		p.keySeen = true
		p.key = privateKeyFingerprint(plaintext)
	}
	if !p.certSeen || !p.keySeen {
		return
	}
	p.done = true
	if p.cert == "" || p.key == "" || p.cert == p.key {
		return
	}
	base := "certificates/" + parts[1] + "/" + o.hostname + "/" + o.hostname
	o.sink.TryEnqueue(MismatchCandidate{o.hostname, parts[1], base + ".crt", base + ".key", p.leaf, p.cert, p.key})
}
func fingerprint(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func decodePEM(b []byte) (*pem.Block, []byte) {
	b = bytes.TrimSpace(b)
	if !bytes.HasPrefix(b, []byte("-----BEGIN ")) {
		return nil, nil
	}
	block, rest := pem.Decode(b)
	if block == nil || len(block.Headers) != 0 {
		return nil, nil
	}
	// pem.Decode searches forward after malformed blocks. Exactly one opening
	// marker in the consumed span, matching its first line, proves it decoded
	// the initial block without skipping another candidate block or prefix.
	consumed := b[:len(b)-len(rest)]
	lineEnd := bytes.IndexByte(consumed, '\n')
	if lineEnd < 0 || bytes.Count(consumed, []byte("-----BEGIN ")) != 1 ||
		!bytes.Equal(bytes.TrimSuffix(consumed[:lineEnd], []byte("\r")), []byte("-----BEGIN "+block.Type+"-----")) {
		return nil, nil
	}
	return block, bytes.TrimSpace(rest)
}
func certificateFingerprints(b []byte, hostname string) (string, string) {
	if len(b) > 64*1024 {
		return "", ""
	}
	block, rest := decodePEM(b)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", ""
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !singleHostnameSAN(leaf, hostname) || !supportedPublicKey(leaf.PublicKey) {
		return "", ""
	}
	// Accept ordinary certificate chains, but no ambiguous extra key or arbitrary trailing data.
	for count := 1; len(rest) > 0; count++ {
		if count >= 8 {
			return "", ""
		}
		var next *pem.Block
		next, rest = decodePEM(rest)
		if next == nil || next.Type != "CERTIFICATE" {
			return "", ""
		}
		if _, err := x509.ParseCertificate(next.Bytes); err != nil {
			return "", ""
		}
	}
	pub, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return "", ""
	}
	return fingerprint(leaf.Raw), fingerprint(pub)
}

// Inspect the raw GeneralNames sequence because x509 exposes only selected SAN
// alternatives. A single exact dNSName excludes wildcards, shared certificates,
// and additional names that the parsed DNS/IP/email/URI fields might omit.
func singleHostnameSAN(leaf *x509.Certificate, hostname string) bool {
	for _, extension := range leaf.Extensions {
		if !extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
			continue
		}
		var sequence, name asn1.RawValue
		rest, err := asn1.Unmarshal(extension.Value, &sequence)
		if err != nil || len(rest) != 0 || sequence.Class != asn1.ClassUniversal || sequence.Tag != asn1.TagSequence || !sequence.IsCompound {
			return false
		}
		rest, err = asn1.Unmarshal(sequence.Bytes, &name)
		return err == nil && len(rest) == 0 && name.Class == asn1.ClassContextSpecific && name.Tag == 2 && !name.IsCompound && string(name.Bytes) == hostname
	}
	return false
}

func supportedPublicKey(k any) bool {
	switch k := k.(type) {
	case *ecdsa.PublicKey:
		return (k.Curve == elliptic.P256() || k.Curve == elliptic.P384() || k.Curve == elliptic.P521()) && k.X != nil && k.Y != nil && k.Curve.IsOnCurve(k.X, k.Y)
	case *rsa.PublicKey:
		return k.N != nil && k.N.BitLen() >= 2048 && k.N.BitLen() <= 4096 && k.E >= 3 && k.E <= 2147483647 && k.E%2 == 1
	}
	return false
}

// Check RSA dimensions before x509 parsing can precompute CRT values on attacker-sized integers.
func boundedRSA(der []byte) bool {
	var raw struct {
		Version               int
		N                     *big.Int
		E                     int
		D, P, Q, DP, DQ, QInv *big.Int
		Extra                 []asn1.RawValue `asn1:"optional"`
	}
	rest, err := asn1.Unmarshal(der, &raw)
	if err != nil || len(rest) != 0 || raw.Version != 0 || len(raw.Extra) != 0 {
		return false
	}
	if !supportedPublicKey(&rsa.PublicKey{N: raw.N, E: raw.E}) {
		return false
	}
	for _, v := range []*big.Int{raw.D, raw.P, raw.Q, raw.DP, raw.DQ, raw.QInv} {
		if v == nil || v.Sign() <= 0 || v.BitLen() > 4096 {
			return false
		}
	}
	return true
}

// Reject contradictory embedded EC public points even on Go versions whose
// x509 parser derives and silently replaces them from the private scalar.
func consistentECEncoding(der []byte, key *ecdsa.PrivateKey) bool {
	var raw struct {
		Version    int
		PrivateKey []byte
		Curve      asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
		PublicKey  asn1.BitString        `asn1:"optional,explicit,tag:1"`
	}
	rest, err := asn1.Unmarshal(der, &raw)
	if err != nil || len(rest) != 0 || raw.Version != 1 {
		return false
	}
	if raw.PublicKey.BitLength == 0 {
		return true
	}
	expected := elliptic.Marshal(key.Curve, key.X, key.Y)
	return raw.PublicKey.BitLength == len(expected)*8 && bytes.Equal(raw.PublicKey.Bytes, expected)
}
func privateKeyFingerprint(b []byte) string {
	if len(b) > 8*1024 {
		return ""
	}
	block, rest := decodePEM(b)
	if block == nil || len(rest) != 0 {
		return ""
	}
	var key any
	var ecDER []byte
	var err error
	switch block.Type {
	case "RSA PRIVATE KEY":
		if !boundedRSA(block.Bytes) {
			return ""
		}
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		ecDER = block.Bytes
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		var info struct {
			Version    int
			Algorithm  pkix.AlgorithmIdentifier
			PrivateKey []byte
		}
		extra, e := asn1.Unmarshal(block.Bytes, &info)
		if e != nil || len(extra) != 0 || info.Version != 0 {
			return ""
		}
		if info.Algorithm.Algorithm.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}) {
			if !boundedRSA(info.PrivateKey) {
				return ""
			}
		} else if !info.Algorithm.Algorithm.Equal(asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}) {
			return ""
		}
		ecDER = info.PrivateKey
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return ""
	}
	if err != nil {
		return ""
	}
	var public any
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		if !consistentECEncoding(ecDER, k) {
			return ""
		}
		if !supportedPublicKey(&k.PublicKey) || k.D == nil || k.D.Sign() <= 0 || k.D.Cmp(k.Curve.Params().N) >= 0 {
			return ""
		}
		x, y := k.Curve.ScalarBaseMult(k.D.Bytes())
		if x.Cmp(k.X) != 0 || y.Cmp(k.Y) != 0 {
			return ""
		}
		public = &ecdsa.PublicKey{Curve: k.Curve, X: x, Y: y}
	case *rsa.PrivateKey:
		if !supportedPublicKey(&k.PublicKey) || len(k.Primes) != 2 || k.Validate() != nil {
			return ""
		}
		public = &k.PublicKey
	default:
		return ""
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return ""
	}
	return fingerprint(der)
}
