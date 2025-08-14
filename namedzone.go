
package namedzone

import (
	"fmt"
	"net"
	"os"
	"slices"
	"strings"

	nc "github.com/dlukt/namedconf"
)

// Config wraps a parsed named.conf and provides zone CRUD helpers (view-aware).
type Config struct {
	Path string
	File *nc.File
}

// Load parses a named.conf from disk.
func Load(path string) (*Config, error) {
	f, err := nc.ParseFile(path, nil)
	if err != nil {
		return nil, err
	}
	return &Config{Path: path, File: f}, nil
}

// Save writes the current AST back to Path (atomically via temp file + rename).
func (c *Config) Save() error {
	if c.Path == "" || c.File == nil {
		return fmt.Errorf("invalid config: missing Path or File")
	}
	tmp := c.Path + ".tmp"
	if err := os.WriteFile(tmp, []byte(c.File.String()), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, c.Path)
}

// Zone models a zone { ... } block commonly found in named.conf.
type Zone struct {
	// Header
	Name  string // "example.com"
	Class string // "IN" (optional; empty means omit)
	Type  string // master|slave|hint|stub|forward|redirect (not validated)
	File  string // path to zone file (if applicable)

	// Address-match lists (rendered as single-arg MatchGroup)
	AllowQuery    *nc.MatchGroup
	AllowUpdate   *nc.MatchGroup
	AllowTransfer *nc.MatchGroup
	AllowNotify   *nc.MatchGroup
	AlsoNotify    *nc.MatchGroup
	Masters       *nc.MatchGroup
	Forwarders    *nc.MatchGroup

	// Simple fields
	Forward string // "only"|"first"
	Notify  string // "yes"|"no"|"explicit"

	// Booleans
	InlineSigning       *bool // yes|no
	IXFRFromDifferences *bool // yes|no
	NotifyToSoa         *bool // yes|no

	// Strings
	AutoDNSSEC   string // off|allow|maintain (string to be future-proof)
	DNSSECPolicy string // policy name
	Journal      string // quoted path
	MaxJournalSize string // raw token like 1G, 250M

	// Complex blocks preserved as-is
	UpdatePolicy *nc.Block

	// Unknown/less common directives preserved as name -> occurrences -> args
	Extras map[string][][]string

	// internal
	ast *nc.Directive
}

// ---------- High-level API (top-level zones) ----------

func (c *Config) List() []Zone { return c.ListInView("") }
func (c *Config) Get(name string) *Zone { return c.GetInView(name, "") }
func (c *Config) Create(z Zone) error { return c.CreateInView(z, "") }
func (c *Config) Update(name string, fn func(*Zone) error) error { return c.UpdateInView(name, "", fn) }
func (c *Config) Delete(name string) bool { return c.DeleteInView(name, "") }

// ---------- View-aware API ----------

// ListInView returns all zones in the given view (empty string for top-level).
func (c *Config) ListInView(view string) []Zone {
	var zs []Zone
	for _, zd := range c.zonesIn(view) {
		if len(zd.Args) >= 1 {
			if name, ok := zd.Args[0].(nc.StringLit); ok {
				z := zoneFromDirective(zd, name.Value)
				zs = append(zs, z)
			}
		}
	}
	return zs
}

// GetInView finds a zone by name in the given view (empty for top-level).
func (c *Config) GetInView(name, view string) *Zone {
	for _, d := range c.zonesIn(view) {
		if len(d.Args) >= 1 {
			if s, ok := d.Args[0].(nc.StringLit); ok && s.Value == name {
				z := zoneFromDirective(d, name)
				return &z
			}
		}
	}
	return nil
}

// CreateInView creates a zone inside the given view (creates the view if missing).
func (c *Config) CreateInView(z Zone, view string) error {
	if z.Name == "" {
		return fmt.Errorf("zone name is required")
	}
	if c.GetInView(z.Name, view) != nil {
		return fmt.Errorf("zone %q already exists in view %q", z.Name, view)
	}
	dir := zoneToDirective(z)
	* c.zoneContainer(view) = append(*c.zoneContainer(view), dir)
	return nil
}

// UpdateInView finds the zone and lets fn mutate it.
func (c *Config) UpdateInView(name, view string, fn func(*Zone) error) error {
	if fn == nil {
		return fmt.Errorf("update function is nil")
	}
	cont := c.zoneContainer(view)
	for i := range *cont {
		d := (*cont)[i]
		if strings.EqualFold(d.Name, "zone") && len(d.Args) >= 1 {
			if s, ok := d.Args[0].(nc.StringLit); ok && s.Value == name {
				z := zoneFromDirective(d, name)
				if err := fn(&z); err != nil {
					return err
				}
				(*cont)[i] = zoneToDirective(z)
				return nil
			}
		}
	}
	return fmt.Errorf("zone %q not found in view %q", name, view)
}

// DeleteInView removes a zone; returns true if removed.
func (c *Config) DeleteInView(name, view string) bool {
	cont := c.zoneContainer(view)
	for i := range *cont {
		d := (*cont)[i]
		if strings.EqualFold(d.Name, "zone") && len(d.Args) >= 1 {
			if s, ok := d.Args[0].(nc.StringLit); ok && s.Value == name {
				*cont = slices.Delete(*cont, i, i+1)
				return true
			}
		}
	}
	return false
}

// ---------- Internals ----------

// zonesIn gets all zone directives in the given view.
func (c *Config) zonesIn(view string) []*nc.Directive {
	if view == "" {
		var out []*nc.Directive
		for _, d := range c.File.Directives {
			if strings.EqualFold(d.Name, "zone") {
				out = append(out, d)
			}
		}
		return out
	}
	// find view
	for _, d := range c.File.Directives {
		if strings.EqualFold(d.Name, "view") && len(d.Args) >= 1 {
			if s, ok := d.Args[0].(nc.StringLit); ok && s.Value == view {
				if d.Block == nil {
					return nil
				}
				var out []*nc.Directive
				for _, cd := range d.Block.Directives {
					if strings.EqualFold(cd.Name, "zone") {
						out = append(out, cd)
					}
				}
				return out
			}
		}
	}
	return nil
}

// zoneContainer returns the slice of directives to append/modify for zones for a view.
// If the view doesn't exist and view != "", it will be created.
func (c *Config) zoneContainer(view string) *[]*nc.Directive {
	if view == "" {
		return &c.File.Directives
	}
	// search view
	for _, d := range c.File.Directives {
		if strings.EqualFold(d.Name, "view") && len(d.Args) >= 1 {
			if s, ok := d.Args[0].(nc.StringLit); ok && s.Value == view {
				if d.Block == nil {
					d.Block = &nc.Block{}
				}
				return &d.Block.Directives
			}
		}
	}
	// create view
	v := &nc.Directive{
		Name: "view",
		Args: []nc.Expr{nc.StringLit{Value: view}},
		Block: &nc.Block{},
	}
	c.File.Directives = append(c.File.Directives, v)
	return &v.Block.Directives
}

// zoneFromDirective converts an AST zone directive to Zone struct.
func zoneFromDirective(d *nc.Directive, name string) Zone {
	z := Zone{
		Name:   name,
		Class:  zoneClassFromArgs(d.Args),
		Extras: map[string][][]string{},
		ast:    d,
	}
	if d.Block != nil {
		for _, cd := range d.Block.Directives {
			switch strings.ToLower(cd.Name) {
			case "type":
				if len(cd.Args) >= 1 {
					z.Type = rawToken(cd.Args[0])
				}
			case "file":
				if len(cd.Args) >= 1 {
					// store as raw string
					z.File = rawToken(cd.Args[0])
				}
			case "allow-query":
				if mg := asMatchGroup(cd); mg != nil { z.AllowQuery = mg }
			case "allow-update":
				if mg := asMatchGroup(cd); mg != nil { z.AllowUpdate = mg }
			case "allow-transfer":
				if mg := asMatchGroup(cd); mg != nil { z.AllowTransfer = mg }
			case "allow-notify":
				if mg := asMatchGroup(cd); mg != nil { z.AllowNotify = mg }
			case "also-notify":
				if mg := asMatchGroup(cd); mg != nil { z.AlsoNotify = mg }
			case "masters":
				if mg := asMatchGroup(cd); mg != nil { z.Masters = mg }
			case "forwarders":
				if mg := asMatchGroup(cd); mg != nil { z.Forwarders = mg }
			case "forward":
				if len(cd.Args) >= 1 {
					z.Forward = strings.ToLower(rawToken(cd.Args[0]))
				}
			case "notify":
				if len(cd.Args) >= 1 {
					z.Notify = strings.ToLower(rawToken(cd.Args[0]))
				}
			case "notify-to-soa":
				if b, ok := asBool(cd); ok { z.NotifyToSoa = &b }
			case "inline-signing":
				if b, ok := asBool(cd); ok { z.InlineSigning = &b }
			case "ixfr-from-differences":
				if b, ok := asBool(cd); ok { z.IXFRFromDifferences = &b }
			case "auto-dnssec":
				if len(cd.Args) >= 1 { z.AutoDNSSEC = rawToken(cd.Args[0]) }
			case "dnssec-policy":
				if len(cd.Args) >= 1 { z.DNSSECPolicy = rawToken(cd.Args[0]) }
			case "journal":
				if len(cd.Args) >= 1 { z.Journal = rawToken(cd.Args[0]) }
			case "max-journal-size":
				if len(cd.Args) >= 1 { z.MaxJournalSize = rawToken(cd.Args[0]) }
			case "update-policy":
				// keep block as-is
				if cd.Block != nil {
					z.UpdatePolicy = cd.Block
				}
			default:
				args := exprsToStrings(cd.Args)
				z.Extras[cd.Name] = append(z.Extras[cd.Name], args)
			}
		}
	}
	return z
}

func zoneClassFromArgs(args []nc.Expr) string {
	// zone "example" IN { ... };
	if len(args) >= 2 {
		if id, ok := args[1].(nc.Ident); ok {
			return id.Value
		}
	}
	return ""
}

// zoneToDirective converts a Zone struct back to an AST directive.
func zoneToDirective(z Zone) *nc.Directive {
	args := []nc.Expr{nc.StringLit{Value: z.Name}}
	if z.Class != "" {
		args = append(args, nc.Ident{Value: z.Class})
	}
	dir := &nc.Directive{
		Name: "zone",
		Args: args,
		Pos:  nc.Position{},
	}
	blk := &nc.Block{}

	// Basic
	if z.Type != "" {
		blk.Directives = append(blk.Directives, &nc.Directive{
			Name: "type",
			Args: []nc.Expr{nc.Ident{Value: z.Type}},
		})
	}
	if z.File != "" {
		blk.Directives = append(blk.Directives, &nc.Directive{
			Name: "file",
			Args: []nc.Expr{nc.StringLit{Value: z.File}},
		})
	}

	// Match groups
	if z.AllowQuery != nil {
		blk.Directives = append(blk.Directives, &nc.Directive{Name: "allow-query", Args: []nc.Expr{*z.AllowQuery}})
	}
	if z.AllowUpdate != nil {
		blk.Directives = append(blk.Directives, &nc.Directive{Name: "allow-update", Args: []nc.Expr{*z.AllowUpdate}})
	}
	if z.AllowTransfer != nil {
		blk.Directives = append(blk.Directives, &nc.Directive{Name: "allow-transfer", Args: []nc.Expr{*z.AllowTransfer}})
	}
	if z.AllowNotify != nil {
		blk.Directives = append(blk.Directives, &nc.Directive{Name: "allow-notify", Args: []nc.Expr{*z.AllowNotify}})
	}
	if z.AlsoNotify != nil {
		blk.Directives = append(blk.Directives, &nc.Directive{Name: "also-notify", Args: []nc.Expr{*z.AlsoNotify}})
	}
	if z.Masters != nil {
		blk.Directives = append(blk.Directives, &nc.Directive{Name: "masters", Args: []nc.Expr{*z.Masters}})
	}
	if z.Forwarders != nil {
		blk.Directives = append(blk.Directives, &nc.Directive{Name: "forwarders", Args: []nc.Expr{*z.Forwarders}})
	}

	// Simple tokens
	if z.Forward != "" {
		blk.Directives = append(blk.Directives, &nc.Directive{Name: "forward", Args: []nc.Expr{nc.Ident{Value: z.Forward}}})
	}
	if z.Notify != "" {
		blk.Directives = append(blk.Directives, &nc.Directive{Name: "notify", Args: []nc.Expr{nc.Ident{Value: z.Notify}}})
	}

	// Booleans
	if z.InlineSigning != nil {
		blk.Directives = append(blk.Directives, &nc.Directive{Name: "inline-signing", Args: []nc.Expr{boolIdent(*z.InlineSigning)}})
	}
	if z.IXFRFromDifferences != nil {
		blk.Directives = append(blk.Directives, &nc.Directive{Name: "ixfr-from-differences", Args: []nc.Expr{boolIdent(*z.IXFRFromDifferences)}})
	}
	if z.NotifyToSoa != nil {
		blk.Directives = append(blk.Directives, &nc.Directive{Name: "notify-to-soa", Args: []nc.Expr{boolIdent(*z.NotifyToSoa)}})
	}

	// Strings
	if z.AutoDNSSEC != "" {
		blk.Directives = append(blk.Directives, &nc.Directive{Name: "auto-dnssec", Args: []nc.Expr{nc.Ident{Value: z.AutoDNSSEC}}})
	}
	if z.DNSSECPolicy != "" {
		blk.Directives = append(blk.Directives, &nc.Directive{Name: "dnssec-policy", Args: []nc.Expr{nc.Ident{Value: z.DNSSECPolicy}}})
	}
	if z.Journal != "" {
		blk.Directives = append(blk.Directives, &nc.Directive{Name: "journal", Args: []nc.Expr{nc.StringLit{Value: z.Journal}}})
	}
	if z.MaxJournalSize != "" {
		blk.Directives = append(blk.Directives, &nc.Directive{Name: "max-journal-size", Args: []nc.Expr{nc.Ident{Value: z.MaxJournalSize}}})
	}

	// Complex
	if z.UpdatePolicy != nil {
		blk.Directives = append(blk.Directives, &nc.Directive{Name: "update-policy", Block: z.UpdatePolicy})
	}

	// Extras (deterministic order by key)
	keys := make([]string, 0, len(z.Extras))
	for k := range z.Extras {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		for _, occ := range z.Extras[k] {
			blk.Directives = append(blk.Directives, &nc.Directive{Name: k, Args: stringsToExprs(occ)})
		}
	}

	dir.Block = blk
	return dir
}

// ----- tiny helpers for conversions -----

func boolIdent(b bool) nc.Expr {
	if b {
		return nc.Ident{Value: "yes"}
	}
	return nc.Ident{Value: "no"}
}

func rawToken(e nc.Expr) string {
	switch v := e.(type) {
	case nc.StringLit:
		return v.Value
	case nc.Ident:
		return v.Value
	case nc.NumberLit:
		return v.Raw
	case nc.AddrLit:
		return v.Raw
	case nc.CIDRLit:
		return v.Raw
	default:
		return fmt.Sprintf("%T", v)
	}
}

func exprsToStrings(xs []nc.Expr) []string {
	out := make([]string, 0, len(xs))
	for _, e := range xs {
		out = append(out, rawToken(e))
	}
	return out
}

func stringsToExprs(ss []string) []nc.Expr {
	out := make([]nc.Expr, 0, len(ss))
	for _, s := range ss {
		out = append(out, guessExpr(s))
	}
	return out
}

// guessExpr chooses a token representation for a raw string (best effort).
func guessExpr(s string) nc.Expr {
	if s == "" {
		return nc.StringLit{Value: s}
	}
	if strings.IndexFunc(s, func(r rune) bool {
		switch r {
		case ' ', '\t', ';', '{', '}', '"':
			return true
		default:
			return false
		}
	}) != -1 {
		return nc.StringLit{Value: s}
	}
	// Try CIDR/IP
	if _, _, err := net.ParseCIDR(s); err == nil {
		return nc.CIDRLit{Raw: s}
	}
	if ip := net.ParseIP(s); ip != nil {
		return nc.AddrLit{Raw: s, IP: ip}
	}
	// fall back to ident
	return nc.Ident{Value: s}
}

// asMatchGroup extracts a MatchGroup from a directive either via arg or block.
func asMatchGroup(d *nc.Directive) *nc.MatchGroup {
	// arg form
	if len(d.Args) == 1 {
		if g, ok := d.Args[0].(nc.MatchGroup); ok {
			return &g
		}
	}
	// block form: rebuild a MatchGroup from block items
	if d.Block != nil {
		g := blockToMG(d.Block)
		return &g
	}
	return nil
}

// asBool parses yes|no from the first arg.
func asBool(d *nc.Directive) (bool, bool) {
	if len(d.Args) < 1 {
		return false, false
	}
	switch strings.ToLower(rawToken(d.Args[0])) {
	case "yes", "true", "on":
		return true, true
	case "no", "false", "off":
		return false, true
	default:
		return false, false
	}
}

// blockToMG reconstructs a MatchGroup from a block (best effort).
// Mirrors the parser's internal logic.
func blockToMG(blk *nc.Block) nc.MatchGroup {
	mg := nc.MatchGroup{Pos: blk.Pos}
	for _, d := range blk.Directives {
		item := directiveToMatchItem(d)
		mg.Items = append(mg.Items, &item)
	}
	return mg
}

func directiveToMatchItem(d *nc.Directive) nc.MatchItem {
	parts := make([]nc.Expr, 0, 1+len(d.Args))
	pos := d.Pos
	name := d.Name
	neg := false
	if strings.HasPrefix(name, "!") {
		neg = true
		name = strings.TrimPrefix(name, "!")
	}
	// classify name
	if _, _, err := net.ParseCIDR(name); err == nil {
		parts = append(parts, nc.CIDRLit{Raw: name, Pos: pos})
	} else if ip := net.ParseIP(name); ip != nil {
		parts = append(parts, nc.AddrLit{Raw: name, IP: ip, Pos: pos})
	} else {
		parts = append(parts, nc.Ident{Value: name, Pos: pos})
	}
	parts = append(parts, d.Args...)
	return nc.MatchItem{Parts: parts, Negated: neg, Pos: pos}
}

// ---------- Public helpers to build match-groups ----------

func MG(items ...nc.MatchItem) nc.MatchGroup {
	mg := nc.MatchGroup{Items: []*nc.MatchItem{}}
	for i := range items {
		it := items[i]
		mg.Items = append(mg.Items, &it)
	}
	return mg
}

func Item(negated bool, parts ...nc.Expr) nc.MatchItem {
	return nc.MatchItem{Negated: negated, Parts: parts}
}

// Id, Str, IP, CIDR helpers.
func Ident(s string) nc.Expr { return nc.Ident{Value: s} }
func Str(s string) nc.Expr   { return nc.StringLit{Value: s} }
func IP(raw string) nc.Expr  { return nc.AddrLit{Raw: raw} }
func CIDR(raw string) nc.Expr { return nc.CIDRLit{Raw: raw} }
