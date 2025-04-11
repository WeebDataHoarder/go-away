package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"git.gammaspectra.live/git/go-away/lib"
	"git.gammaspectra.live/git/go-away/lib/policy"
	"git.gammaspectra.live/git/go-away/utils"
	"github.com/pires/go-proxyproto"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"gopkg.in/yaml.v3"
	"log"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"os"
	"path"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"
)

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
		log.Fatal(fmt.Errorf("failed to bind to %s: %w", formattedAddress, err))
	}

	// additional permission handling for unix sockets
	if network == "unix" {
		mode, err := strconv.ParseUint(socketMode, 8, 0)
		if err != nil {
			listener.Close()
			log.Fatal(fmt.Errorf("could not parse socket mode %s: %w", socketMode, err))
		}

		err = os.Chmod(address, os.FileMode(mode))
		if err != nil {
			listener.Close()
			log.Fatal(fmt.Errorf("could not change socket mode: %w", err))
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

var internalPackageName = func() string {

	buildInfo, ok := debug.ReadBuildInfo()
	if !ok {
		return "go-away"
	}
	return buildInfo.Path
}()

type MultiVar []string

func (v *MultiVar) String() string {
	return fmt.Sprintf("%v", *v)
}

func (v *MultiVar) Set(value string) error {
	*v = append(*v, value)
	return nil
}

func newServer(handler http.Handler, manager *autocert.Manager) *http.Server {

	if manager == nil {
		h2s := &http2.Server{}

		// TODO: use Go 1.24 Server.Protocols to add H2C
		// https://pkg.go.dev/net/http#Server.Protocols
		h1s := &http.Server{
			Handler: h2c.NewHandler(handler, h2s),
		}

		return h1s
	} else {
		return &http.Server{
			TLSConfig: manager.TLSConfig(),
			Handler:   handler,
		}
	}
}

func newACMEManager(clientDirectory string, backends map[string]http.Handler) *autocert.Manager {

	var domains []string
	for d := range backends {
		parts := strings.Split(d, ":")
		d = parts[0]
		if net.ParseIP(d) != nil {
			continue
		}
		domains = append(domains, d)
	}

	manager := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(domains...),
		Client: &acme.Client{
			HTTPClient:   http.DefaultClient,
			DirectoryURL: clientDirectory,
		},
	}
	return manager
}

func main() {
	bind := flag.String("bind", ":8080", "network address to bind HTTP/HTTP(s) to")
	bindNetwork := flag.String("bind-network", "tcp", "network family to bind HTTP to, e.g. unix, tcp")
	bindProxy := flag.Bool("bind-proxy", false, "use PROXY protocol in front of the listener")
	socketMode := flag.String("socket-mode", "0770", "socket mode (permissions) for unix domain sockets.")

	slogLevel := flag.String("slog-level", "WARN", "logging level (see https://pkg.go.dev/log/slog#hdr-Levels)")
	debugMode := flag.Bool("debug", false, "debug mode with logs and server timings")
	passThrough := flag.Bool("passthrough", false, "passthrough mode sends all requests to matching backends until state is loaded")
	acmeAutocert := flag.String("acme-autocert", "", "enables HTTP(s) mode and uses the provided ACME server URL or available service (available: letsencrypt)")

	clientIpHeader := flag.String("client-ip-header", "", "Client HTTP header to fetch their IP address from (X-Real-Ip, X-Client-Ip, X-Forwarded-For, Cf-Connecting-Ip, etc.)")
	backendIpHeader := flag.String("backend-ip-header", "", "Backend HTTP header to set the client IP address from, if empty defaults to leaving Client header alone (X-Real-Ip, X-Client-Ip, X-Forwarded-For, Cf-Connecting-Ip, etc.)")

	dnsbl := flag.String("dnsbl", "dnsbl.dronebl.org", "blocklist for DNSBL (default DroneBL)")

	cachePath := flag.String("cache", path.Join(os.TempDir(), "go_away_cache"), "path to temporary cache directory")

	policyFile := flag.String("policy", "", "path to policy YAML file")
	challengeTemplate := flag.String("challenge-template", "anubis", "name or path of the challenge template to use (anubis, forgejo)")
	challengeTemplateTheme := flag.String("challenge-template-theme", "", "name of the challenge template theme to use (forgejo => [forgejo-dark, forgejo-light, gitea...])")

	packageName := flag.String("package-path", internalPackageName, "package name to expose in .well-known url path")

	jwtPrivateKeySeed := flag.String("jwt-private-key-seed", "", "Seed for the jwt private key, or on JWT_PRIVATE_KEY_SEED env. One be generated by passing \"generate\" as a value, follows RFC 8032 private key definition. Defaults to random")

	var backends MultiVar
	flag.Var(&backends, "backend", "backend definition in the form of an.example.com=http://backend:1234 (can be specified multiple times)")

	flag.Parse()

	var err error

	{
		var programLevel slog.Level
		if err = (&programLevel).UnmarshalText([]byte(*slogLevel)); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "invalid log level %s: %v, using info\n", *slogLevel, err)
			programLevel = slog.LevelInfo
		}

		leveler := &slog.LevelVar{}
		leveler.Set(programLevel)

		h := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
			AddSource: *debugMode,
			Level:     leveler,
		})
		slog.SetDefault(slog.New(h))
	}

	var seed []byte

	var kValue string
	if kValue = os.Getenv("JWT_PRIVATE_KEY_SEED"); kValue != "" {

	} else if *jwtPrivateKeySeed != "" {
		kValue = *jwtPrivateKeySeed
	}

	if kValue != "" {
		if strings.ToLower(kValue) == "generate" {
			_, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				log.Fatal(fmt.Errorf("failed to generate private key: %w", err))
			}
			fmt.Printf("%x\n", priv.Seed())
			os.Exit(0)
		}

		seed, err = hex.DecodeString(kValue)
		if err != nil {
			log.Fatal(fmt.Errorf("failed to decode seed: %w", err))
		}

		if len(seed) != ed25519.SeedSize {
			log.Fatal(fmt.Errorf("invalid seed length: %d, expected %d", len(seed), ed25519.SeedSize))
		}

	}

	policyData, err := os.ReadFile(*policyFile)
	if err != nil {
		log.Fatal(fmt.Errorf("failed to read policy file: %w", err))
	}

	var p policy.Policy

	if err = yaml.Unmarshal(policyData, &p); err != nil {
		log.Fatal(fmt.Errorf("failed to parse policy file: %w", err))
	}

	createdBackends := make(map[string]http.Handler)

	parsedBackends := make(map[string]string)
	//TODO: deprecate
	maps.Copy(parsedBackends, p.Backends)
	for _, backend := range backends {
		parts := strings.Split(backend, "=")
		if len(parts) != 2 {
			log.Fatal(fmt.Errorf("invalid backend definition: %s", backend))
		}
		parsedBackends[parts[0]] = parts[1]
	}

	for k, v := range parsedBackends {
		backend, err := utils.MakeReverseProxy(v)
		if err != nil {
			log.Fatal(fmt.Errorf("backend %s: failed to make reverse proxy: %w", k, err))
		}

		backend.ErrorLog = slog.NewLogLogger(slog.With("backend", k).Handler(), slog.LevelError)
		createdBackends[k] = backend
	}

	if *cachePath != "" {
		err = os.MkdirAll(*cachePath, 0755)
		if err != nil {
			log.Fatal(fmt.Errorf("failed to create cache directory: %w", err))
		}
	}

	var acmeManager *autocert.Manager

	if *acmeAutocert != "" {
		switch *acmeAutocert {
		case "letsencrypt":
			*acmeAutocert = "https://acme-v02.api.letsencrypt.org/directory"
		}

		acmeManager = newACMEManager(*acmeAutocert, createdBackends)
		if *cachePath != "" {
			err = os.MkdirAll(path.Join(*cachePath, "acme"), 0755)
			if err != nil {
				log.Fatal(fmt.Errorf("failed to create acme cache directory: %w", err))
			}
			acmeManager.Cache = autocert.DirCache(path.Join(*cachePath, "acme"))
		}
		slog.Warn(
			"acme-autocert enabled",
			"directory", *acmeAutocert,
		)
	}

	var wg sync.WaitGroup

	passThroughCtx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()

	if *passThrough {
		wg.Add(1)
		go func() {
			defer wg.Done()

			server := newServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				backend, ok := createdBackends[r.Host]
				if !ok {
					http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
					return
				}

				backend.ServeHTTP(w, r)
			}), acmeManager)

			listener, listenUrl := setupListener(*bindNetwork, *bind, *socketMode, *bindProxy)
			slog.Warn(
				"listening passthrough",
				"url", listenUrl,
			)
			defer listener.Close()

			wg.Add(1)
			go func() {
				defer wg.Done()

				if acmeManager != nil {
					if err := server.ServeTLS(listener, "", ""); !errors.Is(err, http.ErrServerClosed) {
						log.Fatal(err)
					}
				} else {
					if err := server.Serve(listener); !errors.Is(err, http.ErrServerClosed) {
						log.Fatal(err)
					}
				}
			}()

			<-passThroughCtx.Done()

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			if err := server.Shutdown(ctx); err != nil {
				log.Fatal(err)
			}
			_ = server.Close()
		}()
	}

	settings := lib.StateSettings{
		Backends:               createdBackends,
		Debug:                  *debugMode,
		PackageName:            *packageName,
		ChallengeTemplate:      *challengeTemplate,
		ChallengeTemplateTheme: *challengeTemplateTheme,
		PrivateKeySeed:         seed,
		ClientIpHeader:         *clientIpHeader,
		BackendIpHeader:        *backendIpHeader,
	}

	if *dnsbl != "" {
		settings.DNSBL = utils.NewDNSBL(*dnsbl, net.DefaultResolver)
	}

	state, err := lib.NewState(p, settings)

	if err != nil {
		log.Fatal(fmt.Errorf("failed to create state: %w", err))
	}

	// cancel the existing server listener
	cancelFunc()
	wg.Wait()

	listener, listenUrl := setupListener(*bindNetwork, *bind, *socketMode, *bindProxy)
	slog.Warn(
		"listening",
		"url", listenUrl,
	)

	server := newServer(state, acmeManager)

	if acmeManager != nil {
		if err := server.ServeTLS(listener, "", ""); !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	} else {

		if err := server.Serve(listener); !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}

}
