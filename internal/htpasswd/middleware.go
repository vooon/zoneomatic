package htpasswd

import (
	"net/http"

	"github.com/go-fuego/fuego"
)

func NewBasicAuthMiddleware(ht HTPasswd) func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			user, password, ok := r.BasicAuth()
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
