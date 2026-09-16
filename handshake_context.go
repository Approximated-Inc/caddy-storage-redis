package storageredis

import (
	"context"
	"crypto/tls"

	"github.com/caddyserver/caddy/v2"
)

// CertificateHealthContext passively observes only successful certificate storage
// loads in this handshake. Without a configured reporter it is a no-op.
type CertificateHealthContext struct{ sink MismatchSink }

func init() { caddy.RegisterModule(CertificateHealthContext{}) }
func (CertificateHealthContext) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "tls.context.apx_certificate_health", New: func() caddy.Module { return new(CertificateHealthContext) }}
}
func (h *CertificateHealthContext) Provision(ctx caddy.Context) error {
	app, err := ctx.AppIfConfigured("apx_certificate_health")
	if err != nil {
		return nil
	}
	h.sink, _ = app.(MismatchSink)
	return nil
}
func (h *CertificateHealthContext) HandshakeContext(hello *tls.ClientHelloInfo) (context.Context, error) {
	ctx := hello.Context()
	if h.sink == nil || !validHealthHostname(hello.ServerName) {
		return ctx, nil
	}
	return context.WithValue(ctx, observerContextKey{}, newCertificateObserver(hello.ServerName, h.sink)), nil
}

// NewCertificateHealthContext binds the passive observer to a nonblocking sink.
// Embedders and the gated integration fixture can supply a sink without changing
// the production module's fixed app lookup or adding a JSON configuration knob.
func NewCertificateHealthContext(sink MismatchSink) *CertificateHealthContext {
	return &CertificateHealthContext{sink: sink}
}
