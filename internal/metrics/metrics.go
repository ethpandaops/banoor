// Package metrics is a minimal registry that writes the Prometheus text
// exposition format.
package metrics

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
)

type family struct {
	help    string
	kind    string // counter or gauge
	samples map[string]float64
}

// Registry holds metric families.
type Registry struct {
	mu       sync.Mutex
	families map[string]*family
}

// New returns an empty registry.
func New() *Registry { return &Registry{families: map[string]*family{}} }

func (r *Registry) define(name, kind, help string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.families[name]; ok {
		panic("metrics: " + name + " defined twice")
	}
	r.families[name] = &family{help: help, kind: kind, samples: map[string]float64{}}
}

// Counter defines a counter.
func (r *Registry) Counter(name, help string) { r.define(name, "counter", help) }

// Gauge defines a gauge.
func (r *Registry) Gauge(name, help string) { r.define(name, "gauge", help) }

func labelString(labels []string) string {
	if len(labels)%2 != 0 {
		panic("metrics: labels must be name, value pairs")
	}
	if len(labels) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteByte('{')
	for i := 0; i < len(labels); i += 2 {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(labels[i])
		b.WriteString(`="`)
		v := strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`).Replace(labels[i+1])
		b.WriteString(v)
		b.WriteByte('"')
	}
	b.WriteByte('}')
	return b.String()
}

func (r *Registry) family(name string) *family {
	f, ok := r.families[name]
	if !ok {
		panic("metrics: " + name + " is not defined")
	}
	return f
}

// Add adds v to a counter.
func (r *Registry) Add(name string, v float64, labels ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.family(name).samples[labelString(labels)] += v
}

// Set sets a gauge.
func (r *Registry) Set(name string, v float64, labels ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.family(name).samples[labelString(labels)] = v
}

// Write writes every family in the text exposition format.
func (r *Registry) Write(w io.Writer) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	names := make([]string, 0, len(r.families))
	for n := range r.families {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		f := r.families[n]
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", n, f.help, n, f.kind)
		keys := make([]string, 0, len(f.samples))
		for k := range f.samples {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			b.WriteString(n)
			b.WriteString(k)
			b.WriteByte(' ')
			b.WriteString(strconv.FormatFloat(f.samples[k], 'g', -1, 64))
			b.WriteByte('\n')
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}
