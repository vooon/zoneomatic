package server

import (
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/go-fuego/fuego"
	"golang.org/x/time/rate"
)

// maxBodyMiddleware refuses request bodies over limit bytes. A declared
// Content-Length above the limit gets 413 at once; a longer body without one
// (chunked) is cut off while reading, which the JSON decoders report as a
// bad request.
func maxBodyMiddleware(limit int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ContentLength > limit {
				fuego.SendJSONError(w, r, fuego.HTTPError{
					Title:  "request body too large",
					Detail: "the request body must not exceed " + strconv.FormatInt(limit, 10) + " bytes",
					Status: http.StatusRequestEntityTooLarge,
				})
				return
			}
			if r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, limit)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// clientLimiter rate-limits requests per client address with a token bucket
// per address. Idle buckets are dropped after idleTTL so the map does not
// grow with every address ever seen.
type clientLimiter struct {
	limit   rate.Limit
	burst   int
	idleTTL time.Duration
	now     func() time.Time

	mu      sync.Mutex
	clients map[netip.Addr]*client
	sweep   time.Time
}

type client struct {
	limiter *rate.Limiter
	seen    time.Time
}

func newClientLimiter(perSecond float64, burst int) *clientLimiter {
	return &clientLimiter{
		limit:   rate.Limit(perSecond),
		burst:   max(burst, 1),
		idleTTL: 10 * time.Minute,
		now:     time.Now,
		clients: make(map[netip.Addr]*client),
	}
}

// allow reports whether a request from addr may proceed now.
func (l *clientLimiter) allow(addr netip.Addr) bool {
	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()

	if now.Sub(l.sweep) > l.idleTTL {
		for a, c := range l.clients {
			if now.Sub(c.seen) > l.idleTTL {
				delete(l.clients, a)
			}
		}
		l.sweep = now
	}

	c, ok := l.clients[addr]
	if !ok {
		c = &client{limiter: rate.NewLimiter(l.limit, l.burst)}
		l.clients[addr] = c
	}
	c.seen = now
	return c.limiter.AllowN(now, 1)
}

// middleware answers 429 to clients over their rate. The client is the
// connection's remote address, which the PROXY protocol listener has already
// replaced with the real client when --accept-proxy is on.
func (l *clientLimiter) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		addr, err := netip.ParseAddrPort(r.RemoteAddr)
		if err == nil && !l.allow(addr.Addr().Unmap()) {
			w.Header().Set("Retry-After", "1")
			fuego.SendJSONError(w, r, fuego.HTTPError{
				Title:  "too many requests",
				Detail: "rate limit exceeded, retry later",
				Status: http.StatusTooManyRequests,
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}
