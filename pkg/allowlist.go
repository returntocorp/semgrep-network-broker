package pkg

import (
	"net/url"

	"github.com/ucarion/urlpath"
)

func (config AllowlistItem) Matches(method string, url *url.URL) bool {
	m := LookupHttpMethod(method)
	if m == MethodUnknown || !config.Methods.Test(m) {
		return false
	}

	parsedUrl, err := url.Parse(config.URL)
	if err != nil {
		return false
	}

	if parsedUrl.Scheme != url.Scheme || parsedUrl.Host != url.Host {
		return false
	}

	matcher := urlpath.New(parsedUrl.EscapedPath())
	if _, matches := matcher.Match(url.EscapedPath()); matches {
		return true
	}

	return false
}

func (allowlist Allowlist) FindMatch(method string, url *url.URL) (*AllowlistItem, bool) {
	for i := range allowlist {
		if allowlist[i].Matches(method, url) {
			return &allowlist[i], true
		}
	}
	return nil, false
}
