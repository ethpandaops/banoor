package metrics

import (
	"strings"
	"testing"
)

func TestWrite(t *testing.T) {
	r := New()
	r.Counter("x_total", "Things.")
	r.Gauge("y", "Level.")
	r.Add("x_total", 1, "kind", "a")
	r.Add("x_total", 2, "kind", "a")
	r.Add("x_total", 1, "kind", `b"q`)
	r.Set("y", 0.5)
	var b strings.Builder
	if err := r.Write(&b); err != nil {
		t.Fatal(err)
	}
	want := `# HELP x_total Things.
# TYPE x_total counter
x_total{kind="a"} 3
x_total{kind="b\"q"} 1
# HELP y Level.
# TYPE y gauge
y 0.5
`
	if b.String() != want {
		t.Fatalf("got\n%s\nwant\n%s", b.String(), want)
	}
}
