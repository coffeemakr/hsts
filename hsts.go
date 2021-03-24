// Package hsts provides access to the Chromium HSTS preloaded list.
package hsts

import (
	"net/http"
	"strings"

	"golang.org/x/net/idna"
)

//go:generate go run generate/generate.go -out hsts_preload.go
//go:generate go fmt hsts_preload.go

func NthLastIndexOf(s string, b byte, n int) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == b {
			n--
			if n == 0 {
				return i
			}
		}
	}
	return -1
}

// IsPreloaded reports whether host appears in the HSTS preloaded list.
func IsPreloaded(host string) bool {

	host = strings.TrimSuffix(host, ".")
	host, _ = idna.ToASCII(host)
	if host == "" {
		return false
	}

	extraDotIndex := NthLastIndexOf(host, '.', 4)
	if extraDotIndex >= 0 {
		host = host[extraDotIndex:]
	} else {
		if domains[host] {
			return true
		}
	}

	host = strings.ToLower(host)
	for {
		if domainsIncludingSubdomains[host] {
			return true
		}
		idx := strings.IndexByte(host, '.')
		if idx < 0 {
			break
		}
		host = host[idx+1:]
	}
	return false
}

// Transport is a http.RoundTripper that transparently upgrades insecure http
// requests to secure https requests for hosts that appear in the HSTS
// preloaded list.
type Transport struct {
	// Base is the underlying http.RoundTripper to use or
	// http.DefaultTransport if nil.
	Base http.RoundTripper
}

// RoundTrip implements http.RoundTripper.
func (rt *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	hostname := req.URL.Hostname()
	port := req.URL.Port()
	if req.URL.Scheme == "http" &&
		(port == "" || port == "80") &&
		IsPreloaded(hostname) {
		// WithContext currently copies the http.Request URL field and
		// is more lightweight than Clone. See golang.org/issue/23544.
		req = req.WithContext(req.Context())
		req.URL.Scheme = "https"
		req.URL.Host = hostname // Remove port from URL.
	}

	base := http.DefaultTransport
	if rt.Base != nil {
		base = rt.Base
	}

	return base.RoundTrip(req)
}
