package scorer

import (
	"context"
	"fmt"
	"net/netip"
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

type fetcherKey struct {
	user    string
	address string
}

// fetchers remembers the addresses consumers fetched the list from.
type fetchers struct {
	users  *regexp.Regexp
	window time.Duration

	mu     sync.Mutex
	seen   map[fetcherKey]time.Time
	stored map[fetcherKey]time.Time
}

func newFetchers(users string, window time.Duration) *fetchers {
	return &fetchers{
		users:  regexp.MustCompile(users), // checked by config.Validate
		window: window,
		seen:   map[fetcherKey]time.Time{},
		stored: map[fetcherKey]time.Time{},
	}
}

// Seen records that user fetched the list from address. Users the
// configuration does not name, and anything that is not one address, are
// ignored.
func (s *Scorer) Seen(user, address string) {
	f := s.fetchers
	if f == nil || !f.users.MatchString(user) {
		return
	}

	a, err := netip.ParseAddr(address)
	if err != nil {
		return
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	f.put(fetcherKey{user: user, address: a.Unmap().WithZone("").String()}, s.now().UTC())
}

// put records k as seen at t, keeping at most maxAddressesPerUser addresses
// per user. The caller holds mu.
func (f *fetchers) put(k fetcherKey, t time.Time) {
	f.seen[k] = t

	var (
		n      int
		oldest fetcherKey
	)

	for o, ot := range f.seen {
		if o.user != k.user {
			continue
		}

		if n == 0 || ot.Before(f.seen[oldest]) {
			oldest = o
		}

		n++
	}

	if n > maxAddressesPerUser {
		delete(f.seen, oldest)
		delete(f.stored, oldest)
	}
}

// allowed returns the addresses seen within the window.
func (f *fetchers) allowed(now time.Time) *netaddr.Set {
	f.mu.Lock()
	defer f.mu.Unlock()

	set := netaddr.NewSet()

	for k, t := range f.seen {
		if now.Sub(t) >= f.window {
			delete(f.seen, k)
			delete(f.stored, k)

			continue
		}

		if p, err := netaddr.ParseAllow(k.address); err == nil {
			set.Add(p)
		}
	}

	return set
}

// due returns the fetchers to store: new ones, and ones last stored over
// storeEvery before they were last seen.
func (f *fetchers) due() (keys []fetcherKey, rows [][]any) {
	f.mu.Lock()
	defer f.mu.Unlock()

	for k, t := range f.seen {
		if last, ok := f.stored[k]; ok && t.Sub(last) < storeEvery {
			continue
		}

		keys = append(keys, k)
		rows = append(rows, []any{t, k.user, k.address})
	}

	return keys, rows
}

func (f *fetchers) markStored(keys []fetcherKey, rows [][]any) {
	f.mu.Lock()
	defer f.mu.Unlock()

	for i, k := range keys {
		if t, ok := rows[i][0].(time.Time); ok {
			f.stored[k] = t
		}
	}
}

// restore loads a stored fetch. Users the configuration no longer names are
// skipped, so narrowing users takes effect for stored addresses too.
func (f *fetchers) restore(user, address string, at time.Time) {
	if !f.users.MatchString(user) {
		return
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	k := fetcherKey{user: user, address: address}
	if at.After(f.seen[k]) {
		f.put(k, at)
		f.stored[k] = at
	}
}

// storeFetchers keeps new and still-fetching addresses in the state table.
// A failure only means a restart would forget them until they fetch again,
// so it is logged and retried at the next run.
func (s *Scorer) storeFetchers(ctx context.Context) {
	if s.fetchers == nil {
		return
	}

	keys, rows := s.fetchers.due()
	if len(rows) == 0 {
		return
	}

	if err := s.src.Insert(ctx, s.cfg.Tables.Fetchers, []string{"Time", "User", "Address"}, rows); err != nil {
		s.metrics.Add("banoor_source_errors_total", 1, "query", "fetchers")
		s.log.WarnContext(ctx, "could not store fetch addresses", "error", err)

		return
	}

	s.fetchers.markStored(keys, rows)
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
