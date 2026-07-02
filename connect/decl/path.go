package decl

import (
	"strconv"
	"strings"
)

// path.go — a minimal hand-written dotted-path extractor over decoded JSON
// (map[string]any / []any). There is deliberately no jsonpath dependency (none
// is in go.mod): the declarative engine needs only dotted keys with optional
// array indices, e.g. "data.items", "events", "items[0].id", "a[0][1].b".
//
// Path grammar: segments split on '.'; each segment is an optional key followed
// by zero or more "[n]" array indices. An empty path selects the root. A missing
// key, out-of-range index, or type mismatch yields (nil, false) — the caller
// skips or defaults, never panics.

// walkPath resolves path against root, returning the value and whether it was
// found. root is a value decoded from JSON via encoding/json into interface{}.
func walkPath(root any, path string) (any, bool) {
	cur := root
	if strings.TrimSpace(path) == "" {
		return cur, true
	}
	for _, seg := range strings.Split(path, ".") {
		key, indices, ok := parseSegment(seg)
		if !ok {
			return nil, false
		}
		if key != "" {
			m, ok := cur.(map[string]any)
			if !ok {
				return nil, false
			}
			cur, ok = m[key]
			if !ok {
				return nil, false
			}
		}
		for _, idx := range indices {
			arr, ok := cur.([]any)
			if !ok || idx < 0 || idx >= len(arr) {
				return nil, false
			}
			cur = arr[idx]
		}
	}
	return cur, true
}

// parseSegment splits a single dotted segment into its key and any trailing
// array indices: "items[0]" -> ("items", [0]); "[2]" -> ("", [2]);
// "a[0][1]" -> ("a", [0,1]). A malformed bracket expression fails (ok=false).
func parseSegment(seg string) (key string, indices []int, ok bool) {
	i := strings.IndexByte(seg, '[')
	if i < 0 {
		return seg, nil, true
	}
	key = seg[:i]
	rest := seg[i:]
	for len(rest) > 0 {
		if rest[0] != '[' {
			return "", nil, false
		}
		end := strings.IndexByte(rest, ']')
		if end < 0 {
			return "", nil, false
		}
		n, err := strconv.Atoi(rest[1:end])
		if err != nil {
			return "", nil, false
		}
		indices = append(indices, n)
		rest = rest[end+1:]
	}
	return key, indices, true
}

// pathString resolves path and coerces the result to a string. A JSON string is
// returned as-is; a JSON number is rendered without a trailing ".0" for integer
// values (so an integer id "42" is not "42.000000"). Anything else yields "".
func pathString(root any, path string) string {
	v, ok := walkPath(root, path)
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	default:
		return ""
	}
}

// pathSlice resolves path and returns it as a []any when it is a JSON array,
// else (nil, false).
func pathSlice(root any, path string) ([]any, bool) {
	v, ok := walkPath(root, path)
	if !ok {
		return nil, false
	}
	arr, ok := v.([]any)
	return arr, ok
}
