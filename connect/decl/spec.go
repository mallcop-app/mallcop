package decl

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

// Auth schemes a declarative connector spec may declare.
const (
	AuthBearer = "bearer" // Authorization: Bearer <credential>
	AuthHeader = "header" // <HeaderName>: <credential>
	AuthBasic  = "basic"  // Authorization: Basic base64(<credential>) — credential is "user:pass"
	AuthNone   = "none"   // no auth header
)

// Pagination modes an endpoint may declare.
const (
	PageNone       = "none"        // single page
	PageLinkHeader = "link_header" // follow rel="next" in the Link header
	PagePageParam  = "page_param"  // increment a numeric page query param
	PageCursor     = "cursor"      // follow a response cursor field into a query param
)

// Spec is a declarative connector: the DATA the self-extension loop authors to
// teach mallcop a new source. It is interpreted by the human-written engine in
// this package (never agent-authored transport code). It carries NO inline
// secret — the only credential surface is CredentialRef, an ENV VAR NAME
// resolved at construction; a spec YAML with any other field (e.g. `token:`)
// fails the strict KnownFields decode.
type Spec struct {
	SourceID string `yaml:"source_id"`
	BaseURL  string `yaml:"base_url"`

	// AuthScheme is one of the Auth* constants. HeaderName is required for the
	// "header" scheme. CredentialRef is an ENV VAR NAME (never a secret value);
	// it is required for every scheme except "none".
	AuthScheme    string `yaml:"auth_scheme"`
	HeaderName    string `yaml:"header_name"`
	CredentialRef string `yaml:"credential_ref"`

	Endpoints []Endpoint `yaml:"endpoints"`
}

// Endpoint is one path to pull, with its pagination strategy, the dotted path to
// the event array in the response, the field map for building each event, and
// the raw-action -> event_type classification map.
type Endpoint struct {
	Path       string `yaml:"path"`
	Pagination string `yaml:"pagination"`

	// PageParam names the numeric page query param (page_param mode).
	PageParam string `yaml:"page_param"`
	// CursorPath is the dotted path to the next-cursor value in a response;
	// CursorParam names the query param the cursor is sent back in (cursor mode).
	CursorPath  string `yaml:"cursor_path"`
	CursorParam string `yaml:"cursor_param"`

	// ResponsePath is the dotted path to the event array in a page body. Empty
	// means the whole body IS the array.
	ResponsePath string `yaml:"response_path"`

	FieldMap FieldMap `yaml:"field_map"`

	// ActionMap maps a raw action string (read via FieldMap.Action) to a
	// normalized event_type. Every target is validated against
	// detect.KnownEventTypes() at construction.
	ActionMap map[string]string `yaml:"action_map"`
}

// FieldMap holds dotted paths into a single event item for the fields the
// detector floor reads. TimestampFormat is a Go time layout (default RFC3339).
type FieldMap struct {
	ID              string `yaml:"id"`
	Timestamp       string `yaml:"timestamp"`
	TimestampFormat string `yaml:"timestamp_format"`
	Actor           string `yaml:"actor"`
	Org             string `yaml:"org"`
	Action          string `yaml:"action"`
}

// LoadSpecFile reads and strictly decodes a spec YAML from path.
func LoadSpecFile(path string) (*Spec, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("decl: read spec %q: %w", path, err)
	}
	spec, err := ParseSpec(data)
	if err != nil {
		return nil, fmt.Errorf("decl: spec %q: %w", path, err)
	}
	return spec, nil
}

// ParseSpec strictly decodes spec YAML bytes. KnownFields(true) makes any
// unrecognized field — including any inline-secret field the author might try to
// smuggle in — a hard error, so the only credential surface is CredentialRef.
func ParseSpec(data []byte) (*Spec, error) {
	var spec Spec
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&spec); err != nil && err != io.EOF {
		return nil, fmt.Errorf("decode (strict): %w", err)
	}
	return &spec, nil
}
