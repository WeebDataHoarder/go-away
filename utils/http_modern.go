//go:build !go1.22 && !go1.23

package utils

import (
	"crypto/tls"
	"net/http"
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
