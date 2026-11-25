// Package publish signs the ban list and keeps it fresh.
//
// The served body is an envelope holding the exact payload bytes and their
// signature, so the two can never come from different generations:
//
//	{"payload": "<base64 of the payload JSON>", "signature": "-----BEGIN SSH SIGNATURE-----\n..."}
//
// The generation only goes up and changes only when the entries or the mode
// change. In between, the same generation is signed again every refresh with
// a new generated_at, so consumers can reject stale or replayed lists.
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

	"github.com/ethpandaops/banoor/internal/engine"
)

// Version is the payload format version.
const Version = 1

// Payload is the signed list.
type Payload struct {
	Version            int            `json:"version"`
	Generation         uint64         `json:"generation"`
	PreviousGeneration uint64         `json:"previous_generation"`
	GeneratedAt        int64          `json:"generated_at"`
	Mode               engine.Mode    `json:"mode"`
	Entries            []engine.Entry `json:"entries"`
}

// Envelope is the served body.
type Envelope struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// Signer signs payload bytes.
type Signer interface {
	Sign(message []byte) string
}

// Change describes a new generation.
type Change struct {
	Generation         uint64
	PreviousGeneration uint64
	Mode               engine.Mode
	Entries            int
	Added              int
	Removed            int
	PayloadSHA256      string
}

// Current is the list being served.
type Current struct {
	Body        []byte
	ETag        string
	Generation  uint64
	GeneratedAt time.Time
}

// Publisher holds the current signed list.
type Publisher struct {
	signer  Signer
	refresh time.Duration

	mu         sync.RWMutex
	generation uint64
	previous   uint64
	mode       engine.Mode
	entries    []engine.Entry
	started    bool
	current    *Current
}

// New returns a publisher whose next generation will be above last, the
// highest generation published before.
func New(signer Signer, refresh time.Duration, last uint64) *Publisher {
	return &Publisher{signer: signer, refresh: refresh, generation: last}
}

// Update publishes mode and entries at now. It cuts a new generation when
// they differ from the current list, and signs again when they do or when
// the current signature is older than the refresh interval. It returns the
// change when it cut a generation.
func (p *Publisher) Update(now time.Time, mode engine.Mode, entries []engine.Entry) (*Change, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if entries == nil {
		entries = []engine.Entry{}
	}
	var change *Change
	if !p.started || mode != p.mode || !slices.Equal(entries, p.entries) {
		next := max(p.generation+1, unixSeconds(now))
		added, removed := diff(p.entries, entries)
		change = &Change{
			Generation:         next,
			PreviousGeneration: p.generation,
			Mode:               mode,
			Entries:            len(entries),
			Added:              added,
			Removed:            removed,
		}
		p.previous, p.generation = p.generation, next
		p.mode, p.entries, p.started = mode, slices.Clone(entries), true
	} else if p.current != nil && now.Sub(p.current.GeneratedAt) < p.refresh {
		return nil, nil
	}

	payload, err := json.Marshal(Payload{
		Version:            Version,
		Generation:         p.generation,
		PreviousGeneration: p.previous,
		GeneratedAt:        now.Unix(),
		Mode:               p.mode,
		Entries:            p.entries,
	})
	if err != nil {
		return nil, fmt.Errorf("encode payload: %w", err)
	}
	body, err := json.Marshal(Envelope{
		Payload:   base64.StdEncoding.EncodeToString(payload),
		Signature: p.signer.Sign(payload),
	})
	if err != nil {
		return nil, fmt.Errorf("encode envelope: %w", err)
	}
	sum := sha256.Sum256(body)
	p.current = &Current{
		Body:        body,
		ETag:        `"` + hex.EncodeToString(sum[:16]) + `"`,
		Generation:  p.generation,
		GeneratedAt: now,
	}
	if change != nil {
		payloadSum := sha256.Sum256(payload)
		change.PayloadSHA256 = hex.EncodeToString(payloadSum[:])
	}
	return change, nil
}

// Next returns the generation the next change at now would get.
func (p *Publisher) Next(now time.Time) uint64 {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return max(p.generation+1, unixSeconds(now))
}

func unixSeconds(t time.Time) uint64 {
	if s := t.Unix(); s > 0 {
		return uint64(s)
	}
	return 0
}

// Current returns the list being served, or nil before the first Update.
func (p *Publisher) Current() *Current {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.current
}

func diff(old, next []engine.Entry) (added, removed int) {
	before := make(map[string]bool, len(old))
	for _, e := range old {
		before[e.CIDR] = true
	}
	after := make(map[string]bool, len(next))
	for _, e := range next {
		after[e.CIDR] = true
		if !before[e.CIDR] {
			added++
		}
	}
	for c := range before {
		if !after[c] {
			removed++
		}
	}
	return added, removed
}
