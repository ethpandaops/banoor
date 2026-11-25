package server

import (
	"context"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/ethpandaops/banoor/api/rest"
)

// operations implements the ogen-generated operations. Adding an operation
// to api/openapi.yaml and running `make generate` fails the build until its
// method is added here.
type operations struct {
	log     *slog.Logger
	version string
	lists   Lists
	metrics Metrics
	users   *userLabels
}

var _ rest.Handler = (*operations)(nil)

func (o *operations) GetList(ctx context.Context, params rest.GetListParams) (rest.GetListRes, error) {
	f := fetcherFrom(ctx)
	if f.address != "" && userLabel.MatchString(f.user) {
		o.lists.Seen(f.user, f.address)
	}

	user := o.users.label(f.user)

	c := o.lists.Current()
	if c == nil {
		o.metrics.Add("banoor_fetches_total", 1, "user", user, "result", "unavailable")

		return problem(http.StatusServiceUnavailable, "no list has been published yet"), nil
	}

	if matches(params.IfNoneMatch.Or(""), c.ETag) {
		o.metrics.Add("banoor_fetches_total", 1, "user", user, "result", "not_modified")

		return &rest.GetListNotModified{CacheControl: "no-cache", ETag: c.ETag}, nil
	}

	o.metrics.Add("banoor_fetches_total", 1, "user", user, "result", "ok")

	return &rest.EnvelopeHeaders{
		CacheControl: "no-cache",
		ETag:         c.ETag,
		Response:     rest.Envelope{Payload: c.Payload, Signature: c.Signature},
	}, nil
}

func (o *operations) GetHealth(context.Context) (*rest.Health, error) {
	h := &rest.Health{Status: rest.HealthStatusOk, Version: o.version}

	if c := o.lists.Current(); c != nil {
		h.Generation = int64(min(c.Generation, 1<<63-1))
	}

	if t := o.lists.LastSuccess(); !t.IsZero() {
		h.LastSuccess = rest.NewOptDateTime(t.UTC())
	}

	return h, nil
}

// NewError turns an unexpected handler error into a 500 problem.
func (o *operations) NewError(ctx context.Context, err error) *rest.ProblemStatusCode {
	o.log.ErrorContext(ctx, "api handler failed", "error", err)

	return problem(http.StatusInternalServerError, "")
}

func problem(status int, detail string) *rest.ProblemStatusCode {
	p := rest.Problem{Title: http.StatusText(status), Status: status}
	if detail != "" {
		p.Detail = rest.NewOptString(detail)
	}

	return &rest.ProblemStatusCode{StatusCode: status, Response: p}
}

// matches reports whether an If-None-Match header names etag, with the weak
// comparison RFC 9110 specifies for it.
func matches(header, etag string) bool {
	for t := range strings.SplitSeq(header, ",") {
		t = strings.TrimPrefix(strings.TrimSpace(t), "W/")
		if t == "*" || t == etag {
			return true
		}
	}

	return false
}

type fetcherKey struct{}

type fetcher struct {
	user    string
	address string
}

// withFetcher puts who fetched, and from where, on the request context, from
// the headers the proxy in front sets.
func withFetcher(userHeader, addressHeader string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var f fetcher
		if userHeader != "" {
			f.user = r.Header.Get(userHeader)
		}

		if addressHeader != "" {
			f.address = r.Header.Get(addressHeader)
		}

		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), fetcherKey{}, f)))
	})
}

func fetcherFrom(ctx context.Context) fetcher {
	f, _ := ctx.Value(fetcherKey{}).(fetcher)

	return f
}

// maxUserLabels bounds the fetch metric's user label: the header comes from
// whoever reaches the port.
const maxUserLabels = 256

var userLabel = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

type userLabels struct {
	mu   sync.Mutex
	max  int
	seen map[string]bool
}

func newUserLabels(limit int) *userLabels {
	return &userLabels{max: limit, seen: map[string]bool{}}
}

// label returns the metric label for a user: unknown for none, invalid for
// a malformed one or one named like these labels, other once the label
// budget is spent.
func (u *userLabels) label(user string) string {
	switch {
	case user == "":
		return "unknown"
	case !userLabel.MatchString(user), user == "unknown", user == "invalid", user == "other":
		return "invalid"
	}

	u.mu.Lock()
	defer u.mu.Unlock()

	if !u.seen[user] {
		if len(u.seen) >= u.max {
			return "other"
		}

		u.seen[user] = true
	}

	return user
}
