package utils

import (
	"net"
	"net/http"
	"time"
)

var DefaultCookiePrefix = ".go-away-"

// getValidHost Gets a valid host for an http.Cookie Domain field
// TODO: bug: does not work with IPv6, see https://github.com/golang/go/issues/65521
func getValidHost(host string) string {
	ipStr, _, err := net.SplitHostPort(host)
	if err != nil {
		return host
	}
	return ipStr
}

func getBaseCookie(name, value string, expiry time.Time, w http.ResponseWriter, r *http.Request) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Expires:  expiry,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
		//Domain:   getValidHost(r.Host),
	}
}

func SetCookie(name, value string, expiry time.Time, w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, getBaseCookie(name, value, expiry, w, r))
}

func ClearCookie(name string, w http.ResponseWriter, r *http.Request) {
	base := getBaseCookie(name, "", time.Unix(0, 0), w, r)
	base.MaxAge = -1

	http.SetCookie(w, base)
}
