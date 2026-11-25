package scorer

import (
	"context"
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/ethpandaops/banoor/pkg/netaddr"
)

// storeEvery is how often a fetcher still fetching is stored again, so a
// restart remembers it for the whole window.
const storeEvery = time.Hour

// maxAddressesPerUser bounds what one user, such as a stolen credential, can
// allowlist: past it, the address it fetched from longest ago is dropped. A
// consumer alternating address families needs two.
const maxAddressesPerUser = 16

// maxUsers bounds how many users the fetchers allowlist holds, so a
// credential or proxy that can name any user cannot grow it without end.
// Past it, a new user is not recorded until one ages out.
const maxUsers = 4096

// fetch is when a user last fetched from one address, and when that was
// last stored.
type fetch struct {
	seen   time.Time
	stored time.Time
}

// fetchRow is a fetch to store.
type fetchRow struct {
	user    string
	address string
	at      time.Time
}

// fetchers remembers the addresses consumers fetched the list from.
type fetchers struct {
	users  *regexp.Regexp
	window time.Duration

	mu sync.Mutex
	// byUser maps a user to its addresses.
	byUser map[string]map[string]*fetch
}

func newFetchers(users string, window time.Duration) *fetchers {
	return &fetchers{
		users:  regexp.MustCompile(users), // checked by config.Validate
		window: window,
		byUser: map[string]map[string]*fetch{},
	}
}

// Seen records that user fetched the list from address. Users the
// configuration does not name, and anything that is not one address, are
// ignored.
func (s *Scorer) Seen(user, address string) {
	if s.fetchers != nil {
		s.fetchers.put(user, address, s.now().UTC())
	}
}

// put records that user fetched from address at t and returns the record,
// or nil when it was ignored.
func (f *fetchers) put(user, address string, t time.Time) *fetch {
	if !f.users.MatchString(user) {
		return nil
	}

	h, err := netaddr.Host(address)
	if err != nil {
		return nil
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	addrs := f.byUser[user]
	if addrs == nil {
		if len(f.byUser) >= maxUsers {
			return nil
		}

		addrs = map[string]*fetch{}
		f.byUser[user] = addrs
	}

	key := h.Addr().String()

	r := addrs[key]
	if r == nil {
		r = &fetch{}
		addrs[key] = r
	}

	if t.After(r.seen) {
		r.seen = t
	}

	if len(addrs) > maxAddressesPerUser {
		oldest := ""
		for a, o := range addrs {
			if oldest == "" || o.seen.Before(addrs[oldest].seen) {
				oldest = a
			}
		}

		delete(addrs, oldest)
	}

	return r
}

// allowed returns the addresses seen within the window, and forgets the
// rest.
func (f *fetchers) allowed(now time.Time) *netaddr.Set {
	f.mu.Lock()
	defer f.mu.Unlock()

	set := netaddr.NewSet()

	for user, addrs := range f.byUser {
		for a, r := range addrs {
			if now.Sub(r.seen) >= f.window {
				delete(addrs, a)

				continue
			}

			if h, err := netaddr.Host(a); err == nil {
				set.Add(h)
			}
		}

		if len(addrs) == 0 {
			delete(f.byUser, user)
		}
	}

	return set
}

// due returns the fetches to store: new ones, and ones last stored over
// storeEvery before they were last seen.
func (f *fetchers) due() []fetchRow {
	f.mu.Lock()
	defer f.mu.Unlock()

	var out []fetchRow

	for user, addrs := range f.byUser {
		for a, r := range addrs {
			if !r.stored.IsZero() && r.seen.Sub(r.stored) < storeEvery {
				continue
			}

			out = append(out, fetchRow{user: user, address: a, at: r.seen})
		}
	}

	return out
}

func (f *fetchers) markStored(rows []fetchRow) {
	f.mu.Lock()
	defer f.mu.Unlock()

	for _, row := range rows {
		if r := f.byUser[row.user][row.address]; r != nil && row.at.After(r.stored) {
			r.stored = row.at
		}
	}
}

// restore loads a stored fetch. Users the configuration no longer names are
// skipped, so narrowing users takes effect for stored addresses too, and so
// is anything stored that is not one address.
func (f *fetchers) restore(user, address string, at time.Time) {
	if r := f.put(user, address, at); r != nil {
		f.mu.Lock()
		defer f.mu.Unlock()

		if at.After(r.stored) {
			r.stored = at
		}
	}
}

// storeFetchers keeps new and still-fetching addresses in the state table.
// A failure only means a restart would forget them until they fetch again,
// so it is logged and retried at the next run.
func (s *Scorer) storeFetchers(ctx context.Context) {
	if s.fetchers == nil {
		return
	}

	due := s.fetchers.due()
	if len(due) == 0 {
		return
	}

	rows := make([][]any, len(due))
	for i, r := range due {
		rows[i] = []any{r.at, r.user, r.address}
	}

	if err := s.src.Insert(ctx, s.cfg.Tables.Fetchers, []string{"Time", "User", "Address"}, rows); err != nil {
		s.metrics.Add("banoor_source_errors_total", 1, "query", "fetchers")
		s.log.WarnContext(ctx, "could not store fetch addresses", "error", err)

		return
	}

	s.fetchers.markStored(due)
}

func (s *Scorer) restoreFetchers(ctx context.Context) error {
	if s.fetchers == nil {
		return nil
	}

	q := fmt.Sprintf(`SELECT User AS user, Address AS address, toUnixTimestamp(max(Time)) AS seen
FROM %s WHERE Time >= now() - toIntervalSecond({window:UInt32}) GROUP BY user, address`, s.cfg.Tables.Fetchers)

	err := s.src.Select(ctx, q, map[string]string{"window": seconds(s.fetchers.window)}, func(row map[string]any) error {
		s.fetchers.restore(str(row["user"]), str(row["address"]), time.Unix(integer(row["seen"]), 0).UTC())

		return nil
	})
	if err != nil {
		s.metrics.Add("banoor_source_errors_total", 1, "query", "fetchers")

		return err
	}

	return nil
}
