package settings

import (
	"context"
	"crypto/tls"
	"fmt"
	"git.gammaspectra.live/git/go-away/utils"
	"github.com/pires/go-proxyproto"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

type TLSEntry struct {
	// Certificate Path to the certificate file
	Certificate string `yaml:"certificate"`
	// Key Path to the corresponding key file
	Key string `yaml:"key"`
}

type Bind struct {
	Address    string `yaml:"address"`
	Network    string `yaml:"network"`
	SocketMode string `yaml:"socket-mode"`
	Proxy      bool   `yaml:"proxy"`

	Passthrough bool `yaml:"passthrough"`

	// TLSAcmeAutoCert URL to ACME directory, or letsencrypt
	TLSAcmeAutoCert string `yaml:"tls-acme-autocert"`

	// TLSEntries Alternate to TLSAcmeAutoCert. Allows multiple entries with matching.
	// Entries on this list can be live-reloaded if application implements SIGHUP handling
	TLSEntries []TLSEntry `yaml:"tls-entries"`

	// TLSCertificate Alternate to TLSAcmeAutoCert. Preferred over TLSEntries if specified.
	TLSCertificate string `yaml:"tls-certificate"`
	// TLSPrivateKey Alternate to TLSAcmeAutoCert. Preferred over TLSEntries if specified.
	TLSPrivateKey string `yaml:"tls-key"`

	// General TLS config
	// TLSMinVersion TLS Minimum supported version.
	// Default is Golang's default, at writing time it's TLS 1.2. Lowest supported is TLS 1.0
	TLSMinVersion string `yaml:"tls-min-version"`

	// TLSMaxVersion TLS Maximum supported version.
	// Default is Golang's default, at writing time it's TLS 1.3, and is automatically increased.
	// Lowest supported is TLS 1.2
	TLSMaxVersion string `yaml:"tls-max-version"`

	// TLSCurves List of supported TLS curve ids from Golang internals
	// See this list https://github.com/golang/go/blob/go1.24.0/src/crypto/tls/common.go#L138-L153 for supported values
	// Default values are chosen by Golang. It's recommended to leave the default
	TLSCurves []tls.CurveID `yaml:"tls-curves"`

	// TLSCiphers List of supported TLS ciphers from Golang internals, case sensitive. TLS 1.3 suites are not configurable.
	// See this list https://github.com/golang/go/blob/go1.24.0/src/crypto/tls/cipher_suites.go#L56-L73 for supported values
	// Default values are chosen by Golang. It's recommended to leave the default
	TLSCiphers []string `yaml:"tls-ciphers"`

	// ReadTimeout is the maximum duration for reading the entire
	// request, including the body. A zero or negative value means
	// there will be no timeout.
	//
	// Because ReadTimeout does not let Handlers make per-request
	// decisions on each request body's acceptable deadline or
	// upload rate, most users will prefer to use
	// ReadHeaderTimeout. It is valid to use them both.
	ReadTimeout time.Duration `yaml:"read-timeout"`

	// ReadHeaderTimeout is the amount of time allowed to read
	// request headers. The connection's read deadline is reset
	// after reading the headers and the Handler can decide what
	// is considered too slow for the body. If zero, the value of
	// ReadTimeout is used. If negative, or if zero and ReadTimeout
	// is zero or negative, there is no timeout.
	ReadHeaderTimeout time.Duration `yaml:"read-header-timeout"`

	// WriteTimeout is the maximum duration before timing out
	// writes of the response. It is reset whenever a new
	// request's header is read. Like ReadTimeout, it does not
	// let Handlers make decisions on a per-request basis.
	// A zero or negative value means there will be no timeout.
	WriteTimeout time.Duration `yaml:"write-timeout"`

	// IdleTimeout is the maximum amount of time to wait for the
	// next request when keep-alives are enabled. If zero, the value
	// of ReadTimeout is used. If negative, or if zero and ReadTimeout
	// is zero or negative, there is no timeout.
	IdleTimeout time.Duration `yaml:"idle-timeout"`
}

func (b *Bind) Listener() (net.Listener, string) {
	return setupListener(b.Network, b.Address, b.SocketMode, b.Proxy)
}

func (b *Bind) Server(backends map[string]http.Handler, acmeCachePath string) (*http.Server, func(http.Handler), error) {

	var tlsConfig *tls.Config

	if b.TLSAcmeAutoCert != "" {
		switch b.TLSAcmeAutoCert {
		case "letsencrypt":
			b.TLSAcmeAutoCert = acme.LetsEncryptURL
		}

		acmeManager := newACMEManager(b.TLSAcmeAutoCert, backends)
		if acmeCachePath != "" {
			err := os.MkdirAll(acmeCachePath, 0755)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to create acme cache directory: %w", err)
			}
			acmeManager.Cache = autocert.DirCache(acmeCachePath)
		}
		slog.Warn(
			"acme-autocert enabled",
			"directory", b.TLSAcmeAutoCert,
		)
		tlsConfig = acmeManager.TLSConfig()
	} else if b.TLSCertificate != "" && b.TLSPrivateKey != "" {
		tlsConfig = &tls.Config{}
		var err error
		tlsConfig.Certificates = make([]tls.Certificate, 1)
		tlsConfig.Certificates[0], err = tls.LoadX509KeyPair(b.TLSCertificate, b.TLSPrivateKey)
		if err != nil {
			return nil, nil, err
		}
		slog.Warn(
			"TLS enabled",
			"certificate", b.TLSCertificate,
		)
	} else if len(b.TLSEntries) > 0 {
		tlsConfig = &tls.Config{}
		var err error

		var certificatesPtr atomic.Pointer[[]tls.Certificate]

		swapTls := func() error {
			certs := make([]tls.Certificate, 0, len(b.TLSEntries))
			for _, entry := range b.TLSEntries {
				cert, err := tls.LoadX509KeyPair(entry.Certificate, entry.Key)
				if err != nil {
					return fmt.Errorf("failed to load TLS certificate %s: %w", entry.Certificate, err)
				}
				certs = append(certs, cert)
			}
			certificatesPtr.Swap(&certs)
			return nil
		}

		tlsConfig.GetCertificate = func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			certs := certificatesPtr.Load()

			if certs == nil || len(*certs) == 0 {
				panic("no certificates found")
			}

			for _, cert := range *certs {
				if err := clientHello.SupportsCertificate(&cert); err == nil {
					return &cert, nil
				}
			}

			// if none match, return first
			return &(*certs)[0], nil
		}

		err = swapTls()
		if err != nil {
			return nil, nil, err
		}

		slog.Warn(
			"TLS enabled with multiple certificates",
			"certificates", len(b.TLSEntries),
		)
	}

	if tlsConfig != nil {
		if b.TLSMinVersion != "" {
			switch strings.NewReplacer("-", "", "_", "", " ", "", ".", "").Replace(strings.ToLower(b.TLSMinVersion)) {
			case "13", "tls13":
				tlsConfig.MinVersion = tls.VersionTLS13
			case "12", "tls12":
				tlsConfig.MinVersion = tls.VersionTLS12
			case "11", "tls11":
				tlsConfig.MinVersion = tls.VersionTLS11
			case "10", "tls10":
				tlsConfig.MinVersion = tls.VersionTLS10
			default:
				return nil, nil, fmt.Errorf("unsupported minimum TLS version: %s", b.TLSMinVersion)
			}
		}

		if b.TLSMaxVersion != "" {
			switch strings.NewReplacer("-", "", "_", "", " ", "", ".", "").Replace(strings.ToLower(b.TLSMaxVersion)) {
			case "13", "tls13":
				tlsConfig.MaxVersion = tls.VersionTLS13
			case "12", "tls12":
				tlsConfig.MaxVersion = tls.VersionTLS12
			default:
				return nil, nil, fmt.Errorf("unsupported maximum TLS version: %s", b.TLSMinVersion)
			}
		}

		if len(b.TLSCiphers) > 0 {
			for _, cipher := range b.TLSCiphers {
				if c := func() *tls.CipherSuite {
					for _, c := range tls.CipherSuites() {
						if c.Name == cipher {
							return c
						}
					}
					for _, c := range tls.InsecureCipherSuites() {
						if c.Name == cipher {
							return c
						}
					}
					return nil
				}(); c != nil {
					tlsConfig.CipherSuites = append(tlsConfig.CipherSuites, c.ID)
				} else {
					return nil, nil, fmt.Errorf("unsupported TLS cipher suite: %s", cipher)
				}
			}
		}

		if len(b.TLSCurves) > 0 {
			tlsConfig.CurvePreferences = append(tlsConfig.CurvePreferences, b.TLSCurves...)
		}
	}

	var serverHandler atomic.Pointer[http.Handler]
	server := utils.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if handler := serverHandler.Load(); handler == nil {
			http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		} else {
			(*handler).ServeHTTP(w, r)
		}
	}), tlsConfig)

	server.ReadTimeout = b.ReadTimeout
	server.ReadHeaderTimeout = b.ReadHeaderTimeout
	server.WriteTimeout = b.WriteTimeout
	server.IdleTimeout = b.IdleTimeout

	swap := func(handler http.Handler) {
		serverHandler.Store(&handler)
	}

	if b.Passthrough {
		// setup a passthrough handler temporarily
		swap(http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			backend := utils.SelectHTTPHandler(backends, r.Host)
			if backend == nil {
				slog.Debug("no backend for host", "host", r.Host)
				http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
			} else {
				backend.ServeHTTP(w, r)
			}
		})))
	}

	return server, swap, nil

}

func setupListener(network, address, socketMode string, proxy bool) (net.Listener, string) {
	if network == "proxy" {
		network = "tcp"
		proxy = true
	}

	formattedAddress := ""
	switch network {
	case "unix":
		formattedAddress = "unix:" + address
	case "tcp":
		formattedAddress = "http://localhost" + address
	default:
		formattedAddress = fmt.Sprintf(`(%s) %s`, network, address)
	}

	listener, err := net.Listen(network, address)
	if err != nil {
		panic(fmt.Errorf("failed to bind to %s: %w", formattedAddress, err))
	}

	// additional permission handling for unix sockets
	if network == "unix" {
		mode, err := strconv.ParseUint(socketMode, 8, 0)
		if err != nil {
			listener.Close()
			panic(fmt.Errorf("could not parse socket mode %s: %w", socketMode, err))
		}

		err = os.Chmod(address, os.FileMode(mode))
		if err != nil {
			listener.Close()
			panic(fmt.Errorf("could not change socket mode: %w", err))
		}
	}

	if proxy {
		slog.Warn("listener PROXY enabled")
		formattedAddress += " +PROXY"
		listener = &proxyproto.Listener{
			Listener: listener,
		}
	}

	return listener, formattedAddress
}

func newACMEManager(clientDirectory string, backends map[string]http.Handler) *autocert.Manager {
	manager := &autocert.Manager{
		Prompt: autocert.AcceptTOS,
		HostPolicy: autocert.HostPolicy(func(ctx context.Context, host string) error {
			if utils.SelectHTTPHandler(backends, host) != nil {
				return nil
			}
			return fmt.Errorf("acme/autocert: host %s not configured in backends", host)
		}),
		Client: &acme.Client{
			HTTPClient:   http.DefaultClient,
			DirectoryURL: clientDirectory,
		},
	}
	return manager
}
