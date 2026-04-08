package htpasswd

import (
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/go-fuego/fuego"
)

func NewBasicAuthMiddleware(ht HTPasswd) func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			user, password, ok := r.BasicAuth()
			if !ok {
				// Fallback to DNS-API headers
				user = r.Header.Get("X-Api-User")
				password = r.Header.Get("X-Api-Key")
				ok = len(user) > 0 && len(password) > 0
			}
			if ok {
				ok, _ = ht.Authenticate(user, password)
			}
			if ok {
				h.ServeHTTP(w, r)
				return
			}

			err := fuego.HTTPError{
				Title:  "unauthorized access",
				Detail: "wrong username or password",
				Status: http.StatusUnauthorized,
			}

			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			fuego.SendJSONError(w, nil, err)
		})
	}
}

func NewAPIKeyMiddleware(ht HTPasswd) func(http.Handler) http.Handler {
	return NewAPIKeyMiddlewareWithUnauthorized(ht, func(w http.ResponseWriter, _ *http.Request) {
		err := fuego.HTTPError{
			Title:  "unauthorized access",
			Detail: "wrong api key",
			Status: http.StatusUnauthorized,
		}

		fuego.SendJSONError(w, nil, err)
	})
}

func NewAPIKeyMiddlewareWithUnauthorized(ht HTPasswd, onUnauthorized func(http.ResponseWriter, *http.Request)) func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, password, ok := r.BasicAuth()
			if ok {
				ok, _ = ht.Authenticate(user, password)
			} else {
				ok = AuthenticateAPIKeyHeader(ht, r.Header.Get("X-API-Key"))
			}

			if ok {
				h.ServeHTTP(w, r)
				return
			}

			onUnauthorized(w, r)
		})
	}
}

func AuthenticateAPIKeyHeader(ht HTPasswd, headerValue string) bool {
	headerValue = strings.TrimSpace(headerValue)
	if headerValue == "" {
		return false
	}

	decoded, err := base64.StdEncoding.DecodeString(headerValue)
	if err != nil {
		return false
	}

	// Be tolerant of credentials generated via `echo user:pass | base64`,
	// which encode a trailing newline into the decoded payload.
	creds := strings.TrimRight(string(decoded), "\r\n")

	user, password, ok := strings.Cut(creds, ":")
	if !ok || user == "" {
		return false
	}

	ok, _ = ht.Authenticate(user, password)
	return ok
}
