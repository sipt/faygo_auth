package util

import (
	"encoding/base64"
	"strings"
)

// ParseBasicAuth parses an HTTP Basic Authentication string.
// "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==" returns ("Aladdin", "open sesame", true).
func ParseBasicAuth(auth string) (username, password string, ok bool) {
	const prefix = "Basic "
	if !strings.HasPrefix(auth, prefix) {
		return
	}
	c, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return
	}
	cs := string(c)
	s := strings.IndexByte(cs, ':')
	if s < 0 {
		return
	}
	return cs[:s], cs[s+1:], true
}

// ParseBearerAuth parses an HTTP Bearer Authentication string.
func ParseBearerAuth(auth string) (token string) {
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		return
	}
	return string(auth[len(prefix):])
}
