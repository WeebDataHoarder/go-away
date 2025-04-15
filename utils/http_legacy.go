//go:build go1.22 || go1.23

package utils

import (
	"crypto/tls"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"net/http"
)

func NewServer(handler http.Handler, tlsConfig *tls.Config) *http.Server {
	if tlsConfig == nil {
		h2s := &http2.Server{}

		h1s := &http.Server{
			Handler: h2c.NewHandler(handler, h2s),
		}

		return h1s
	} else {
		server := &http.Server{
			TLSConfig: tlsConfig,
			Handler:   handler,
		}
		return server
	}
}
