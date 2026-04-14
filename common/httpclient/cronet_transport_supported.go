//go:build with_naive_outbound

package httpclient

import (
	"context"
	"encoding/pem"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sagernet/cronet-go"
	_ "github.com/sagernet/cronet-go/all"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	singLogger "github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
)

type cronetTransportShared struct {
	roundTripper *cronet.RoundTripper
	refs         atomic.Int32
}

type cronetTransport struct {
	shared *cronetTransportShared
}

func newCronetTransport(ctx context.Context, logger singLogger.ContextLogger, rawDialer N.Dialer, options option.HTTPClientOptions) (adapter.HTTPTransport, error) {
	version := options.Version
	if version == 0 {
		version = 2
	}
	switch version {
	case 1, 2, 3:
	default:
		return nil, E.New("unknown HTTP version: ", version)
	}
	if options.DisableVersionFallback && version != 3 {
		return nil, E.New("disable_version_fallback is unsupported in Cronet HTTP engine unless version is 3")
	}
	switch version {
	case 1:
		if options.HTTP2Options != (option.HTTP2Options{}) {
			return nil, E.New("HTTP/2 options are unsupported in Cronet HTTP engine for HTTP/1.1")
		}
		if options.HTTP3Options != (option.QUICOptions{}) {
			return nil, E.New("QUIC options are unsupported in Cronet HTTP engine for HTTP/1.1")
		}
	case 2:
		if options.HTTP2Options.IdleTimeout != 0 ||
			options.HTTP2Options.KeepAlivePeriod != 0 ||
			options.HTTP2Options.MaxConcurrentStreams > 0 {
			return nil, E.New("selected HTTP/2 options are unsupported in Cronet HTTP engine")
		}
	case 3:
		if options.HTTP3Options.KeepAlivePeriod != 0 ||
			options.HTTP3Options.InitialPacketSize > 0 ||
			options.HTTP3Options.DisablePathMTUDiscovery ||
			options.HTTP3Options.MaxConcurrentStreams > 0 {
			return nil, E.New("selected QUIC options are unsupported in Cronet HTTP engine")
		}
	}

	tlsOptions := common.PtrValueOrDefault(options.TLS)
	if tlsOptions.Engine != "" {
		return nil, E.New("tls.engine is unsupported in Cronet HTTP engine")
	}
	if tlsOptions.DisableSNI {
		return nil, E.New("disable_sni is unsupported in Cronet HTTP engine")
	}
	if tlsOptions.Insecure {
		return nil, E.New("tls.insecure is unsupported in Cronet HTTP engine")
	}
	if len(tlsOptions.ALPN) > 0 {
		return nil, E.New("tls.alpn is unsupported in Cronet HTTP engine")
	}
	if tlsOptions.MinVersion != "" || tlsOptions.MaxVersion != "" {
		return nil, E.New("tls.min_version/max_version is unsupported in Cronet HTTP engine")
	}
	if len(tlsOptions.CipherSuites) > 0 {
		return nil, E.New("cipher_suites is unsupported in Cronet HTTP engine")
	}
	if len(tlsOptions.CurvePreferences) > 0 {
		return nil, E.New("curve_preferences is unsupported in Cronet HTTP engine")
	}
	if len(tlsOptions.ClientCertificate) > 0 || len(tlsOptions.ClientCertificatePath) > 0 {
		return nil, E.New("client certificate is unsupported in Cronet HTTP engine")
	}
	if len(tlsOptions.ClientKey) > 0 || tlsOptions.ClientKeyPath != "" {
		return nil, E.New("client key is unsupported in Cronet HTTP engine")
	}
	if tlsOptions.Fragment || tlsOptions.RecordFragment {
		return nil, E.New("tls fragment is unsupported in Cronet HTTP engine")
	}
	if tlsOptions.KernelTx || tlsOptions.KernelRx {
		return nil, E.New("ktls is unsupported in Cronet HTTP engine")
	}
	if tlsOptions.HandshakeTimeout != 0 {
		return nil, E.New("tls.handshake_timeout is unsupported in Cronet HTTP engine")
	}
	if tlsOptions.UTLS != nil && tlsOptions.UTLS.Enabled {
		return nil, E.New("utls is unsupported in Cronet HTTP engine")
	}
	if tlsOptions.Reality != nil && tlsOptions.Reality.Enabled {
		return nil, E.New("reality is unsupported in Cronet HTTP engine")
	}

	trustedRootCertificates, err := readCronetRootCertificates(tlsOptions)
	if err != nil {
		return nil, err
	}

	echEnabled, echConfigList, echQueryServerName, err := readCronetECH(tlsOptions)
	if err != nil {
		return nil, err
	}

	dnsResolver := newCronetDNSResolver(ctx, logger, rawDialer)
	if echEnabled && dnsResolver == nil {
		return nil, E.New("ECH requires a configured DNS resolver in Cronet HTTP engine")
	}

	roundTripper, err := cronet.NewRoundTripper(cronet.RoundTripperOptions{
		Logger:                 logger,
		Version:                version,
		DisableVersionFallback: options.DisableVersionFallback,
		Dialer:                 rawDialer,
		DNSResolver:            dnsResolver,
		TLS: cronet.RoundTripperTLSOptions{
			ServerName:              tlsOptions.ServerName,
			TrustedRootCertificates: trustedRootCertificates,
			PinnedPublicKeySHA256:   tlsOptions.CertificatePublicKeySHA256,
			ECHEnabled:              echEnabled,
			ECHConfigList:           echConfigList,
			ECHQueryServerName:      echQueryServerName,
		},
		HTTP2: cronet.RoundTripperHTTP2Options{
			StreamReceiveWindow:     options.HTTP2Options.StreamReceiveWindow.Value(),
			ConnectionReceiveWindow: options.HTTP2Options.ConnectionReceiveWindow.Value(),
		},
		QUIC: cronet.RoundTripperQUICOptions{
			StreamReceiveWindow:     options.HTTP3Options.StreamReceiveWindow.Value(),
			ConnectionReceiveWindow: options.HTTP3Options.ConnectionReceiveWindow.Value(),
			IdleTimeout:             time.Duration(options.HTTP3Options.IdleTimeout),
		},
	})
	if err != nil {
		return nil, err
	}
	shared := &cronetTransportShared{
		roundTripper: roundTripper,
	}
	shared.refs.Store(1)
	return &cronetTransport{shared: shared}, nil
}

func readCronetRootCertificates(tlsOptions option.OutboundTLSOptions) (string, error) {
	if len(tlsOptions.Certificate) > 0 {
		return strings.Join(tlsOptions.Certificate, "\n"), nil
	}
	if tlsOptions.CertificatePath == "" {
		return "", nil
	}
	content, err := os.ReadFile(tlsOptions.CertificatePath)
	if err != nil {
		return "", E.Cause(err, "read certificate")
	}
	return string(content), nil
}

func readCronetECH(tlsOptions option.OutboundTLSOptions) (bool, []byte, string, error) {
	if tlsOptions.ECH == nil || !tlsOptions.ECH.Enabled {
		return false, nil, "", nil
	}
	//nolint:staticcheck
	if tlsOptions.ECH.PQSignatureSchemesEnabled || tlsOptions.ECH.DynamicRecordSizingDisabled {
		return false, nil, "", E.New("legacy ECH options are deprecated in sing-box 1.12.0 and removed in sing-box 1.13.0")
	}
	var echConfig []byte
	if len(tlsOptions.ECH.Config) > 0 {
		echConfig = []byte(strings.Join(tlsOptions.ECH.Config, "\n"))
	} else if tlsOptions.ECH.ConfigPath != "" {
		content, err := os.ReadFile(tlsOptions.ECH.ConfigPath)
		if err != nil {
			return false, nil, "", E.Cause(err, "read ECH config")
		}
		echConfig = content
	}
	if len(echConfig) == 0 {
		return true, nil, tlsOptions.ECH.QueryServerName, nil
	}
	block, rest := pem.Decode(echConfig)
	if block == nil || block.Type != "ECH CONFIGS" || len(rest) > 0 {
		return false, nil, "", E.New("invalid ECH configs pem")
	}
	return true, block.Bytes, tlsOptions.ECH.QueryServerName, nil
}

func newCronetDNSResolver(ctx context.Context, logger singLogger.ContextLogger, rawDialer N.Dialer) cronet.DNSResolverFunc {
	resolveDialer, isResolveDialer := rawDialer.(dialer.ResolveDialer)
	if !isResolveDialer {
		return nil
	}
	dnsRouter := service.FromContext[adapter.DNSRouter](ctx)
	if dnsRouter == nil {
		return nil
	}
	queryOptions := resolveDialer.QueryOptions()
	return func(dnsContext context.Context, request *mDNS.Msg) *mDNS.Msg {
		response, err := dnsRouter.Exchange(dnsContext, request, queryOptions)
		if err == nil {
			return response
		}
		logger.Error("DNS exchange failed: ", err)
		failure := new(mDNS.Msg)
		failure.SetReply(request)
		failure.Rcode = mDNS.RcodeServerFailure
		return failure
	}
}

func (t *cronetTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return t.shared.roundTripper.RoundTrip(request)
}

func (t *cronetTransport) CloseIdleConnections() {
	t.shared.roundTripper.CloseIdleConnections()
}

func (t *cronetTransport) Clone() adapter.HTTPTransport {
	t.shared.refs.Add(1)
	return &cronetTransport{shared: t.shared}
}

func (t *cronetTransport) Close() error {
	if t.shared.refs.Add(-1) == 0 {
		return t.shared.roundTripper.Close()
	}
	return nil
}
