package pkg

import (
	"net/url"
	"testing"
)

func urlMustParse(rawURL string) *url.URL {
	url, err := url.Parse(rawURL)
	if err != nil {
		panic(err)
	}

	return url
}

func assertAllowlistMatch(t *testing.T, allowlist *Allowlist, method string, rawURL string, shouldMatch bool) {
	_, match := allowlist.FindMatch(method, urlMustParse(rawURL))
	if match != shouldMatch {
		t.Errorf("%v %v match result was %v, expected %v", method, rawURL, match, shouldMatch)
	}
}

func TestAllowlistSchemeMatch(t *testing.T) {
	allowlist := &Allowlist{
		AllowlistItem{
			URL:     "https://foo.com/https-only",
			Methods: ParseHttpMethods([]string{"GET"}),
		},
		AllowlistItem{
			URL:     "http://foo.com/http-only",
			Methods: ParseHttpMethods([]string{"GET"}),
		},
	}

	assertAllowlistMatch(t, allowlist, "GET", "https://foo.com/https-only", true)
	assertAllowlistMatch(t, allowlist, "GET", "https://foo.com/http-only", false)
	assertAllowlistMatch(t, allowlist, "GET", "http://foo.com/https-only", false)
	assertAllowlistMatch(t, allowlist, "GET", "http://foo.com/http-only", true)
}

func TestAllowlistMethodMatch(t *testing.T) {
	allowlist := &Allowlist{
		AllowlistItem{
			URL:     "https://foo.com/get-only",
			Methods: ParseHttpMethods([]string{"GET"}),
		},
		AllowlistItem{
			URL:     "https://foo.com/post-only",
			Methods: ParseHttpMethods([]string{"POST"}),
		},
		AllowlistItem{
			URL:     "https://foo.com/get-or-post",
			Methods: ParseHttpMethods([]string{"GET", "POST"}),
		},
	}

	assertAllowlistMatch(t, allowlist, "GET", "https://foo.com/get-only", true)
	assertAllowlistMatch(t, allowlist, "POST", "https://foo.com/get-only", false)
	assertAllowlistMatch(t, allowlist, "DELETE", "https://foo.com/get-only", false)

	assertAllowlistMatch(t, allowlist, "GET", "https://foo.com/post-only", false)
	assertAllowlistMatch(t, allowlist, "POST", "https://foo.com/post-only", true)
	assertAllowlistMatch(t, allowlist, "DELETE", "https://foo.com/post-only", false)

	assertAllowlistMatch(t, allowlist, "GET", "https://foo.com/get-or-post", true)
	assertAllowlistMatch(t, allowlist, "POST", "https://foo.com/get-or-post", true)
	assertAllowlistMatch(t, allowlist, "DELETE", "https://foo.com/get-or-post", false)
}

func TestAllowlistDomainMatch(t *testing.T) {
	allowlist := &Allowlist{
		AllowlistItem{
			URL:     "https://foo.com/*",
			Methods: ParseHttpMethods([]string{"GET"}),
		},
		AllowlistItem{
			URL:     "https://bar.com/*",
			Methods: ParseHttpMethods([]string{"GET"}),
		},
	}

	assertAllowlistMatch(t, allowlist, "GET", "https://foo.com/get-only", true)
	assertAllowlistMatch(t, allowlist, "GET", "https://bar.com/bar-only", true)
	assertAllowlistMatch(t, allowlist, "GET", "https://baz.com/baz", false)
}

func TestAllowlistPathMatch(t *testing.T) {
	allowlist := &Allowlist{
		AllowlistItem{
			URL:     "https://foo.com/hardcoded-path",
			Methods: ParseHttpMethods([]string{"GET"}),
		},
		AllowlistItem{
			URL:     "https://foo.com/wildcard-path/*",
			Methods: ParseHttpMethods([]string{"GET"}),
		},
		AllowlistItem{
			URL:     "https://foo.com/variable-path/:variable",
			Methods: ParseHttpMethods([]string{"GET"}),
		},
		AllowlistItem{
			URL:     "https://foo.com/variable-path/:variable/suffix",
			Methods: ParseHttpMethods([]string{"GET"}),
		},
	}

	// test path matching
	assertAllowlistMatch(t, allowlist, "GET", "https://foo.com/wildcard-path/a", true)
	assertAllowlistMatch(t, allowlist, "GET", "https://foo.com/wildcard-path/a/b", true)
	assertAllowlistMatch(t, allowlist, "GET", "https://foo.com/variable-path/a", true)
	assertAllowlistMatch(t, allowlist, "GET", "https://foo.com/variable-path/a/b", false)
	assertAllowlistMatch(t, allowlist, "GET", "https://foo.com/hardcoded-path", true)
	assertAllowlistMatch(t, allowlist, "GET", "https://foo.com/hardcoded-path/bla", false)

	assertAllowlistMatch(t, allowlist, "GET", "https://foo.com/variable-path/bla%2Fbla/suffix", true)
	assertAllowlistMatch(t, allowlist, "GET", "https://foo.com/variable-path/bla/bla/suffix", false)
}
