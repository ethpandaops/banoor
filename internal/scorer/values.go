package scorer

import (
	"fmt"
	"math"
)

// The source returns typed column values; these read them whatever integer
// or float width the query produced.

func str(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	default:
		return fmt.Sprint(x)
	}
}

func num(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case float32:
		return float64(x), true
	case int:
		return float64(x), true
	case int8:
		return float64(x), true
	case int16:
		return float64(x), true
	case int32:
		return float64(x), true
	case int64:
		return float64(x), true
	case uint:
		return float64(x), true
	case uint8:
		return float64(x), true
	case uint16:
		return float64(x), true
	case uint32:
		return float64(x), true
	case uint64:
		return float64(x), true
	default:
		return 0, false
	}
}

func float(v any) float64 {
	f, _ := num(v)

	return f
}

func integer(v any) int64 {
	switch x := v.(type) {
	case int64:
		return x
	case int32:
		return int64(x)
	case uint32:
		return int64(x)
	case uint8:
		return int64(x)
	case uint64:
		return int64(min(x, math.MaxInt64))
	}

	f, ok := num(v)
	if !ok || math.IsNaN(f) {
		return 0
	}

	return int64(f)
}

func strList(v any) []string {
	switch x := v.(type) {
	case []string:
		return x
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			out = append(out, str(e))
		}

		return out
	default:
		return nil
	}
}
