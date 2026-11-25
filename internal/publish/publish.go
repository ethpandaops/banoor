// Package publish signs the ban list and keeps it fresh.
//
// The generation only goes up and changes only when the entries or the mode
// change. In between, the same generation is signed again every refresh with
// a new generated_at, so consumers can reject stale or replayed lists.
// Publishing is two steps, Prepare and Commit, so the caller can record a new
// generation before anyone is served it.
package publish

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/ethpandaops/banoor/pkg/engine"
)

// Version is the payload format version.
const Version = 1

// Payload is the signed list. Its field names are the published v1 format.
type Payload struct {
	Version            int            `json:"version"`
	Generation         uint64         `json:"generation"`
	PreviousGeneration uint64         `json:"previous_generation"` //nolint:tagliatelle // the v1 list format is a published contract
	GeneratedAt        int64          `json:"generated_at"`        //nolint:tagliatelle // the v1 list format is a published contract
	Mode               engine.Mode    `json:"mode"`
	Entries            []engine.Entry `json:"entries"`
}

// Signer signs payload bytes.
type Signer interface {
	Sign(message []byte) string
}

// Current is the list being served.
type Current struct {
	// Payload is the base64 of the exact payload bytes Signature covers.
	Payload     string
	Signature   string
	ETag        string
	Generation  uint64
	GeneratedAt time.Time
}

// Change describes a new generation.
type Change struct {
	Generation         uint64
	PreviousGeneration uint64
	Mode               engine.Mode
	CIDRs              []string
	Added              int
	Removed            int
	PayloadSHA256      string
}

// Prepared is a signed list ready to serve. Change is nil when the list is
// only signed again.
type Prepared struct {
	Change  *Change
	current *Current
	state   state
}

type state struct {
	generation uint64
	previous   uint64
	mode       engine.Mode
	entries    []engine.Entry
	started    bool
}

// Publisher holds the current signed list.
type Publisher struct {
	signer  Signer
	refresh time.Duration

	mu      sync.RWMutex
	state   state
	current *Current
}

// New returns a publisher whose next generation will be above last, the
// highest generation published before, with lastCIDRs, its prefixes, as what
// the first change adds to and removes from.
func New(signer Signer, refresh time.Duration, last uint64, lastCIDRs []string) *Publisher {
	held := make([]engine.Entry, len(lastCIDRs))
	for i, c := range lastCIDRs {
		held[i] = engine.Entry{CIDR: c}
	}

	return &Publisher{signer: signer, refresh: refresh, state: state{generation: last, entries: held}}
}

func unixSeconds(t time.Time) uint64 {
	if s := t.Unix(); s > 0 {
		return uint64(s)
	}

	return 0
}

// Next returns the generation a change at now would get.
func (p *Publisher) Next(now time.Time) uint64 {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return max(p.state.generation+1, unixSeconds(now))
}

// Prepare signs mode and entries at now. It cuts a new generation when they
// differ from the current list, and signs again when they do or when the
// current signature is older than the refresh interval. It returns nil when
// there is nothing to do. Nothing is served until Commit.
func (p *Publisher) Prepare(now time.Time, mode engine.Mode, entries []engine.Entry) (*Prepared, error) {
	p.mu.RLock()
	cur, st := p.current, p.state
	p.mu.RUnlock()

	if entries == nil {
		entries = []engine.Entry{}
	}

	next := st
	pr := &Prepared{}

	switch {
	case !st.started || mode != st.mode || !slices.Equal(entries, st.entries):
		next = state{
			generation: max(st.generation+1, unixSeconds(now)),
			previous:   st.generation,
			mode:       mode,
			entries:    slices.Clone(entries),
			started:    true,
		}
		pr.Change = newChange(st.entries, next)
	case cur != nil && now.Sub(cur.GeneratedAt) < p.refresh:
		return nil, nil //nolint:nilnil // nothing to publish is not an error
	}

	payload, err := json.Marshal(Payload{
		Version:            Version,
		Generation:         next.generation,
		PreviousGeneration: next.previous,
		GeneratedAt:        now.Unix(),
		Mode:               next.mode,
		Entries:            next.entries,
	})
	if err != nil {
		return nil, fmt.Errorf("encode payload: %w", err)
	}

	sig := p.signer.Sign(payload)
	tag := sha256.Sum256(append(payload, sig...))
	pr.state = next
	pr.current = &Current{
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signature:   sig,
		ETag:        `"` + hex.EncodeToString(tag[:16]) + `"`,
		Generation:  next.generation,
		GeneratedAt: now,
	}

	if pr.Change != nil {
		sum := sha256.Sum256(payload)
		pr.Change.PayloadSHA256 = hex.EncodeToString(sum[:])
	}

	return pr, nil
}

// Commit serves a prepared list.
func (p *Publisher) Commit(pr *Prepared) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.state, p.current = pr.state, pr.current
}

// Current returns the list being served, or nil before the first Commit.
func (p *Publisher) Current() *Current {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return p.current
}

func newChange(old []engine.Entry, next state) *Change {
	before := make(map[string]bool, len(old))
	for _, e := range old {
		before[e.CIDR] = true
	}

	c := &Change{Generation: next.generation, PreviousGeneration: next.previous, Mode: next.mode, CIDRs: make([]string, 0, len(next.entries))}
	after := make(map[string]bool, len(next.entries))

	for _, e := range next.entries {
		c.CIDRs = append(c.CIDRs, e.CIDR)
		after[e.CIDR] = true

		if !before[e.CIDR] {
			c.Added++
		}
	}

	for cidr := range before {
		if !after[cidr] {
			c.Removed++
		}
	}

	return c
}
