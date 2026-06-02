package utils

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"
)

func NewServer(handler http.Handler, tlsConfig *tls.Config) *http.Server {
	if tlsConfig == nil {
		proto := new(http.Protocols)
		proto.SetHTTP1(true)
		proto.SetUnencryptedHTTP2(true)
		h1s := &http.Server{
			Handler:   handler,
			Protocols: proto,
		}

		return h1s
	} else {
		server := &http.Server{
			TLSConfig: tlsConfig,
			Handler:   handler,
		}
		applyTLSFingerprinter(server)
		return server
	}
}

func SelectHTTPHandler(backends map[string]http.Handler, host string) http.Handler {
	backend, ok := backends[host]
	if !ok {
		// do wildcard match
		wildcard := "*." + strings.Join(strings.Split(host, ".")[1:], ".")
		backend, ok = backends[wildcard]

		if !ok {
			// return fallback
			backend = backends["*"]
		}
	}
	return backend
}

func EnsureNoOpenRedirect(redirect string) (string, error) {
	uri, err := url.Parse(redirect)
	if err != nil {
		return "", err
	}
	uri.Scheme = ""
	uri.Host = ""
	uri.User = nil
	uri.Opaque = ""
	uri.OmitHost = true

	if uri.Path != "" && !strings.HasPrefix(uri.Path, "/") && strings.HasPrefix(uri.Path, "//") {
		return "", errors.New("invalid redirect path")
	}

	return uri.String(), nil
}

func MakeReverseProxy(target string, goDns bool, dialTimeout time.Duration) (*httputil.ReverseProxy, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("failed to parse target URL: %w", err)
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{}

	// https://github.com/oauth2-proxy/oauth2-proxy/blob/4e2100a2879ef06aea1411790327019c1a09217c/pkg/upstream/http.go#L124
	if u.Scheme == "unix" {
		// clean path up so we don't use the socket path in proxied requests
		addr := u.Path
		u.Path = ""
		// tell transport how to dial unix sockets
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			dialer := net.Dialer{
				Timeout: dialTimeout,
			}
			return dialer.DialContext(ctx, "unix", addr)
		}
		// tell transport how to handle the unix url scheme
		transport.RegisterProtocol("unix", UnixRoundTripper{Transport: transport})
	} else if goDns {
		dialer := &net.Dialer{
			Resolver: &net.Resolver{
				PreferGo: true,
			},
			Timeout: dialTimeout,
		}
		transport.DialContext = dialer.DialContext
	} else {
		dialer := &net.Dialer{
			Timeout: dialTimeout,
		}
		transport.DialContext = dialer.DialContext
	}

	rp := httputil.NewSingleHostReverseProxy(u)

	rp.Transport = transport

	return rp, nil
}

func GetRequestScheme(r *http.Request) string {
	if proto := r.Header.Get("X-Forwarded-Proto"); proto == "http" || proto == "https" {
		return proto
	}

	if r.TLS != nil {
		return "https"
	}

	return "http"
}

func GetRequestAddress(r *http.Request, clientHeader string) netip.AddrPort {
	strVal := r.RemoteAddr

	if clientHeader != "" {
		strVal = r.Header.Get(clientHeader)
	}
	if strVal != "" {
		// handle X-Forwarded-For
		strVal = strings.Split(strVal, ",")[0]
	}

	// fallback
	if strVal == "" {
		strVal = r.RemoteAddr
	}

	addrPort, err := netip.ParseAddrPort(strVal)
	if err != nil {
		addr, err2 := netip.ParseAddr(strVal)
		if err2 != nil {
			return netip.AddrPort{}
		}
		addrPort = netip.AddrPortFrom(addr, 0)
	}
	return addrPort
}

type remoteAddress struct{}

func SetRemoteAddress(r *http.Request, addrPort netip.AddrPort) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), remoteAddress{}, addrPort))
}
func GetRemoteAddress(ctx context.Context) *netip.AddrPort {
	ip, ok := ctx.Value(remoteAddress{}).(netip.AddrPort)
	if !ok {
		return nil
	}
	return &ip
}

func RandomCacheBust(n int) string {
	buf := make([]byte, n)
	_, _ = rand.Read(buf)
	return base64.RawURLEncoding.EncodeToString(buf)
}

var staticCacheBust = RandomCacheBust(16)

func StaticCacheBust() string {
	return staticCacheBust
}

func ParseRawQuery(rawQuery string) (m url.Values, err error) {
	m = make(url.Values)
	for rawQuery != "" {
		var key string
		key, rawQuery, _ = strings.Cut(rawQuery, "&")
		if strings.Contains(key, ";") {
			err = fmt.Errorf("invalid semicolon separator in query")
			continue
		}
		if key == "" {
			continue
		}
		key, value, _ := strings.Cut(key, "=")
		m[key] = append(m[key], value)
	}
	return m, err
}

func EncodeRawQuery(v url.Values) string {
	if len(v) == 0 {
		return ""
	}
	var buf strings.Builder
	for _, k := range slices.Sorted(maps.Keys(v)) {
		vs := v[k]
		for _, v := range vs {
			if buf.Len() > 0 {
				buf.WriteByte('&')
			}
			buf.WriteString(k)
			buf.WriteByte('=')
			buf.WriteString(v)
		}
	}
	return buf.String()
}
