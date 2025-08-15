package namedzone

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	nc "github.com/dlukt/namedconf"
)

// LoadOptions configures how Load behaves.
type LoadOptions struct {
	// InlineIncludes makes the parser inline regular includes. Defaults to true.
	InlineIncludes bool
	// ExpandGlobs expands include paths containing '*' or '?', parsing the matched files.
	// Defaults to true.
	ExpandGlobs bool
}

// Config wraps one or more parsed named.conf files
// and provides zone CRUD helpers across them.
type Config struct {
	RootPath string
	Root     *nc.File
	Files    map[string]*nc.File // absolute path -> parsed file
}

// Load parses a named.conf from disk with sane defaults
// (inline includes + expand wildcard include paths).
func Load(path string) (*Config, error) { return LoadWith(path, nil) }

func LoadWith(path string, opts *LoadOptions) (*Config, error) {
	if opts == nil {
		opts = &LoadOptions{InlineIncludes: true, ExpandGlobs: true}
	}
	root, err := nc.ParseFile(path, &nc.ParseOptions{InlineIncludes: opts.InlineIncludes})
	if err != nil {
		return nil, err
	}
	cfg := &Config{
		RootPath: path,
		Root:     root,
		Files:    map[string]*nc.File{},
	}
	cfg.Files[abs(path)] = root

	// Gather include paths and expand globs if asked.
	if opts.ExpandGlobs {
		baseDir := filepath.Dir(abs(path))
		for _, inc := range cfg.findIncludePaths(root) {
			p := inc
			if !filepath.IsAbs(p) {
				p = filepath.Join(baseDir, inc)
			}
			p = filepath.Clean(p)
			if hasGlob(p) {
				matches, _ := filepath.Glob(p)
				sort.Strings(matches)
				for _, m := range matches {
					mAbs := abs(m)
					if _, seen := cfg.Files[mAbs]; seen {
						continue
					}
					if f, err := nc.ParseFile(mAbs, &nc.ParseOptions{InlineIncludes: opts.InlineIncludes}); err == nil {
						cfg.Files[mAbs] = f
					}
				}
			} else if !opts.InlineIncludes {
				// If not inlining, also parse regular includes so SaveAll can write them.
				pAbs := abs(p)
				if _, seen := cfg.Files[pAbs]; !seen {
					if f, err := nc.ParseFile(pAbs, &nc.ParseOptions{InlineIncludes: false}); err == nil {
						cfg.Files[pAbs] = f
					}
				}
			}
		}
	}
	return cfg, nil
}

func abs(p string) string {
	a, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return a
}

func hasGlob(p string) bool { return strings.ContainsAny(p, "*?") }

// Save writes only the root file.
func (c *Config) Save() error {
	return atomicWrite(c.Root.Path, []byte(c.Root.String()), 0o644)
}

// SaveAll writes every parsed file back to disk (atomic temp+rename).
func (c *Config) SaveAll() error {
	for _, f := range c.Files {
		if err := atomicWrite(f.Path, []byte(f.String()), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func atomicWrite(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Zone represents a zone { ... } block.
type Zone struct {
	Name  string `json:"name,omitempty"`
	Class string `json:"class,omitempty"`
	Type  string `json:"type,omitempty"` // master|slave|hint|stub|forward|redirect
	File  string `json:"file,omitempty"`

	// Typed fields for common directives
	AllowQuery    *nc.MatchGroup `json:"allow_query,omitempty"`
	AllowUpdate   *nc.MatchGroup `json:"allow_update,omitempty"`
	AllowTransfer *nc.MatchGroup `json:"allow_transfer,omitempty"`
	AllowNotify   *nc.MatchGroup `json:"allow_notify,omitempty"`
	AlsoNotify    *nc.MatchGroup `json:"also_notify,omitempty"`
	Masters       *nc.MatchGroup `json:"masters,omitempty"`
	Primaries     *nc.MatchGroup `json:"primaries,omitempty"`
	Forwarders    *nc.MatchGroup `json:"forwarders,omitempty"`

	Forward string `json:"forward,omitempty"` // only|first
	Notify  string `json:"notify,omitempty"`  // yes|no|explicit

	InlineSigning       *bool `json:"inline_signing,omitempty"`
	IXFRFromDifferences *bool `json:"ixfr_from_differences,omitempty"`
	NotifyToSoa         *bool `json:"notify_to_soa,omitempty"`

	AutoDNSSEC     string `json:"autoDNSSEC,omitempty"`
	DNSSECPolicy   string `json:"dns_sec_policy,omitempty"`
	Journal        string `json:"journal,omitempty"`
	MaxJournalSize string `json:"max_journal_size,omitempty"`

	UpdatePolicy *nc.Block `json:"updatePolicy,omitempty"` // keep raw

	Extras map[string][][]string `json:"extras,omitempty"`

	// internal
	filePath string // which file this zone lives in
	ast      *nc.Directive
}

// ========== View helpers ==========

func isView(d *nc.Directive) (string, bool) {
	if !strings.EqualFold(d.Name, "view") {
		return "", false
	}
	if len(d.Args) == 0 {
		return "", false
	}
	switch v := d.Args[0].(type) {
	case nc.StringLit:
		return v.Value, true
	case nc.Ident:
		return v.Value, true
	default:
		return "", false
	}
}

// List returns all top-level zones across all files.
func (c *Config) List() []Zone { return c.ListInView("") }

// ListInView returns zones for the given view name (empty = top-level).
func (c *Config) ListInView(view string) []Zone {
	var out []Zone
	for _, f := range c.Files {
		if view == "" {
			for _, d := range f.Directives {
				if isZone(d) {
					z := zoneFromDirective(d, srcName(d), f.Path)
					out = append(out, z)
				}
			}
			continue
		}
		// scan views
		for _, d := range f.Directives {
			if vname, ok := isView(d); ok && vname == view && d.Block != nil {
				for _, cd := range d.Block.Directives {
					if isZone(cd) {
						z := zoneFromDirective(cd, srcName(cd), f.Path)
						out = append(out, z)
					}
				}
			}
		}
	}
	return out
}

func isZone(d *nc.Directive) bool {
	return strings.EqualFold(d.Name, "zone") && len(d.Args) >= 1
}

func srcName(d *nc.Directive) string {
	if len(d.Args) == 0 {
		return ""
	}
	if s, ok := d.Args[0].(nc.StringLit); ok {
		return s.Value
	}
	if id, ok := d.Args[0].(nc.Ident); ok {
		return id.Value
	}
	return ""
}

// Get finds a top-level zone by name across files.
func (c *Config) Get(name string) *Zone { return c.GetInView(name, "") }

// GetInView finds a zone by name within a view (empty = top-level).
func (c *Config) GetInView(name, view string) *Zone {
	for _, f := range c.Files {
		if view == "" {
			for _, d := range f.Directives {
				if isZone(d) && srcName(d) == name {
					z := zoneFromDirective(d, name, f.Path)
					return &z
				}
			}
			continue
		}
		for _, d := range f.Directives {
			if vname, ok := isView(d); ok && vname == view && d.Block != nil {
				for _, cd := range d.Block.Directives {
					if isZone(cd) && srcName(cd) == name {
						z := zoneFromDirective(cd, name, f.Path)
						return &z
					}
				}
			}
		}
	}
	return nil
}

// Create adds a top-level zone; chooses a reasonable target file.
func (c *Config) Create(z Zone) error { return c.createInternal(z, "") }

// CreateInView adds a zone inside the given view. Prefers file that already has that view.
func (c *Config) CreateInView(z Zone, view string) error { return c.createInternal(z, view) }

func (c *Config) createInternal(z Zone, view string) error {
	if z.Name == "" {
		return fmt.Errorf("zone name is required")
	}
	if c.GetInView(z.Name, view) != nil {
		return fmt.Errorf("zone %q already exists in view %q", z.Name, view)
	}
	dir := zoneToDirective(z)
	target := c.chooseTargetFile(view)
	if view == "" {
		c.Files[target].Directives = append(c.Files[target].Directives, dir)
	} else {
		vd := ensureViewBlock(c.Files[target], view)
		vd.Block.Directives = append(vd.Block.Directives, dir)
	}
	return nil
}

// Update mutates a top-level zone.
func (c *Config) Update(name string, fn func(*Zone) error) error {
	return c.UpdateInView(name, "", fn)
}

// UpdateInView mutates a zone in a specific view.
func (c *Config) UpdateInView(name, view string, fn func(*Zone) error) error {
	for _, f := range c.Files {
		if view == "" {
			for i := range f.Directives {
				d := f.Directives[i]
				if isZone(d) && srcName(d) == name {
					z := zoneFromDirective(d, name, f.Path)
					if err := fn(&z); err != nil {
						return err
					}
					f.Directives[i] = zoneToDirective(z)
					f.Directives[i].Pos = d.Pos
					return nil
				}
			}
			continue
		}
		for i := range f.Directives {
			d := f.Directives[i]
			if vname, ok := isView(d); ok && vname == view && d.Block != nil {
				for j := range d.Block.Directives {
					cd := d.Block.Directives[j]
					if isZone(cd) && srcName(cd) == name {
						z := zoneFromDirective(cd, name, f.Path)
						if err := fn(&z); err != nil {
							return err
						}
						d.Block.Directives[j] = zoneToDirective(z)
						d.Block.Directives[j].Pos = cd.Pos
						return nil
					}
				}
			}
		}
	}
	return fmt.Errorf("zone %q not found in view %q", name, view)
}

// Delete removes a top-level zone.
func (c *Config) Delete(name string) bool { return c.DeleteInView(name, "") }

// DeleteInView removes a zone from a specific view.
func (c *Config) DeleteInView(name, view string) bool {
	for _, f := range c.Files {
		if view == "" {
			for i := range f.Directives {
				d := f.Directives[i]
				if isZone(d) && srcName(d) == name {
					f.Directives = slices.Delete(f.Directives, i, i+1)
					return true
				}
			}
			continue
		}
		for i := range f.Directives {
			d := f.Directives[i]
			if vname, ok := isView(d); ok && vname == view && d.Block != nil {
				for j := range d.Block.Directives {
					cd := d.Block.Directives[j]
					if isZone(cd) && srcName(cd) == name {
						d.Block.Directives = slices.Delete(d.Block.Directives, j, j+1)
						return true
					}
				}
			}
		}
	}
	return false
}

func (c *Config) chooseTargetFile(view string) string {
	// Prefer a file that already has zones (top-level or in the view), else the root.
	candidates := make([]string, 0, len(c.Files))
	for p, f := range c.Files {
		if view == "" {
			for _, d := range f.Directives {
				if isZone(d) {
					candidates = append(candidates, p)
					break
				}
			}
		} else {
			for _, d := range f.Directives {
				if vname, ok := isView(d); ok && vname == view {
					candidates = append(candidates, p)
					break
				}
			}
		}
	}
	if len(candidates) == 0 {
		return abs(c.RootPath)
	}
	sort.Strings(candidates)
	return candidates[0]
}

func ensureViewBlock(f *nc.File, view string) *nc.Directive {
	for _, d := range f.Directives {
		if vname, ok := isView(d); ok && vname == view {
			if d.Block == nil {
				d.Block = &nc.Block{}
			}
			return d
		}
	}
	// create new view
	vd := &nc.Directive{
		Name:  "view",
		Args:  []nc.Expr{nc.StringLit{Value: view}},
		Block: &nc.Block{},
	}
	f.Directives = append(f.Directives, vd)
	return vd
}

// ========== Include discovery ==========

func (c *Config) findIncludePaths(f *nc.File) []string {
	var paths []string
	f.Walk(func(d *nc.Directive) bool {
		if strings.EqualFold(d.Name, "include") && len(d.Args) == 1 {
			if ie, ok := d.Args[0].(nc.IncludeExpr); ok && ie.Inc != nil {
				paths = append(paths, ie.Inc.Path)
			}
		}
		return true
	})
	return paths
}

// ========== Zone <-> AST ==========

func zoneFromDirective(d *nc.Directive, name string, filePath string) Zone {
	z := Zone{
		Name:     name,
		Class:    zoneClassFromArgs(d.Args),
		Type:     "",
		File:     "",
		Extras:   map[string][][]string{},
		filePath: filePath,
		ast:      d,
	}
	if d.Block != nil {
		for _, cd := range d.Block.Directives {
			switch strings.ToLower(cd.Name) {
			case "type":
				if len(cd.Args) >= 1 {
					switch a := cd.Args[0].(type) {
					case nc.Ident:
						z.Type = a.Value
					case nc.StringLit:
						z.Type = a.Value
					}
				}
			case "file":
				if len(cd.Args) >= 1 {
					switch a := cd.Args[0].(type) {
					case nc.StringLit:
						z.File = a.Value
					case nc.Ident:
						z.File = a.Value
					}
				}
			case "allow-query":
				if len(cd.Args) == 1 {
					if mg, ok := cd.Args[0].(nc.MatchGroup); ok {
						z.AllowQuery = &mg
					}
				}
			case "allow-update":
				if len(cd.Args) == 1 {
					if mg, ok := cd.Args[0].(nc.MatchGroup); ok {
						z.AllowUpdate = &mg
					}
				}
			case "allow-transfer":
				if len(cd.Args) == 1 {
					if mg, ok := cd.Args[0].(nc.MatchGroup); ok {
						z.AllowTransfer = &mg
					}
				}
			case "allow-notify":
				if len(cd.Args) == 1 {
					if mg, ok := cd.Args[0].(nc.MatchGroup); ok {
						z.AllowNotify = &mg
					}
				}
			case "also-notify":
				if len(cd.Args) == 1 {
					if mg, ok := cd.Args[0].(nc.MatchGroup); ok {
						z.AlsoNotify = &mg
					}
				}
			case "masters":
				if len(cd.Args) == 1 {
					if mg, ok := cd.Args[0].(nc.MatchGroup); ok {
						z.Masters = &mg
					}
				}
			case "primaries":
				if len(cd.Args) == 1 {
					if mg, ok := cd.Args[0].(nc.MatchGroup); ok {
						z.Primaries = &mg
					}
				}
			case "forwarders":
				if len(cd.Args) == 1 {
					if mg, ok := cd.Args[0].(nc.MatchGroup); ok {
						z.Forwarders = &mg
					}
				}
			case "forward":
				if len(cd.Args) >= 1 {
					if id, ok := cd.Args[0].(nc.Ident); ok {
						z.Forward = id.Value
					} else if s, ok := cd.Args[0].(nc.StringLit); ok {
						z.Forward = s.Value
					}
				}
			case "notify":
				if len(cd.Args) >= 1 {
					if id, ok := cd.Args[0].(nc.Ident); ok {
						z.Notify = id.Value
					} else if s, ok := cd.Args[0].(nc.StringLit); ok {
						z.Notify = s.Value
					} else if mg, ok := cd.Args[0].(nc.MatchGroup); ok {
						// Some configs use notify { ... }; treat as group stored in AllowNotify
						z.AllowNotify = &mg
					}
				}
			case "inline-signing":
				if len(cd.Args) >= 1 {
					if id, ok := cd.Args[0].(nc.Ident); ok {
						val := strings.EqualFold(id.Value, "yes")
						z.InlineSigning = &val
					}
				}
			case "ixfr-from-differences":
				if len(cd.Args) >= 1 {
					if id, ok := cd.Args[0].(nc.Ident); ok {
						val := strings.EqualFold(id.Value, "yes")
						z.IXFRFromDifferences = &val
					}
				}
			case "notify-to-soa":
				if len(cd.Args) >= 1 {
					if id, ok := cd.Args[0].(nc.Ident); ok {
						val := strings.EqualFold(id.Value, "yes")
						z.NotifyToSoa = &val
					}
				}
			case "auto-dnssec":
				if len(cd.Args) >= 1 {
					if id, ok := cd.Args[0].(nc.Ident); ok {
						z.AutoDNSSEC = id.Value
					} else if s, ok := cd.Args[0].(nc.StringLit); ok {
						z.AutoDNSSEC = s.Value
					}
				}
			case "dnssec-policy":
				if len(cd.Args) >= 1 {
					if s, ok := cd.Args[0].(nc.StringLit); ok {
						z.DNSSECPolicy = s.Value
					} else if id, ok := cd.Args[0].(nc.Ident); ok {
						z.DNSSECPolicy = id.Value
					}
				}
			case "journal":
				if len(cd.Args) >= 1 {
					if s, ok := cd.Args[0].(nc.StringLit); ok {
						z.Journal = s.Value
					}
				}
			case "max-journal-size":
				if len(cd.Args) >= 1 {
					switch a := cd.Args[0].(type) {
					case nc.NumberLit:
						z.MaxJournalSize = a.Raw
					case nc.Ident:
						z.MaxJournalSize = a.Value
					case nc.StringLit:
						z.MaxJournalSize = a.Value
					}
				}
			case "update-policy":
				// Keep raw block if present
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
	if len(args) >= 2 {
		if id, ok := args[1].(nc.Ident); ok {
			return id.Value
		}
	}
	return ""
}

func zoneToDirective(z Zone) *nc.Directive {
	args := []nc.Expr{nc.StringLit{Value: z.Name}}
	if z.Class != "" {
		args = append(args, nc.Ident{Value: z.Class})
	}
	dir := &nc.Directive{
		Name: "zone",
		Args: args,
	}
	blk := &nc.Block{}

	add := func(name string, a ...nc.Expr) {
		blk.Directives = append(blk.Directives, &nc.Directive{
			Name: name,
			Args: a,
		})
	}

	if z.Type != "" {
		add("type", nc.Ident{Value: z.Type})
	}
	if z.File != "" {
		add("file", nc.StringLit{Value: z.File})
	}
	if z.AllowQuery != nil {
		add("allow-query", *z.AllowQuery)
	}
	if z.AllowUpdate != nil {
		add("allow-update", *z.AllowUpdate)
	}
	if z.AllowTransfer != nil {
		add("allow-transfer", *z.AllowTransfer)
	}
	if z.AllowNotify != nil {
		add("allow-notify", *z.AllowNotify)
	}
	if z.AlsoNotify != nil {
		add("also-notify", *z.AlsoNotify)
	}
	if z.Masters != nil {
		add("masters", *z.Masters)
	}
	if z.Primaries != nil {
		add("primaries", *z.Primaries)
	}
	if z.Forwarders != nil {
		add("forwarders", *z.Forwarders)
	}
	if z.Forward != "" {
		add("forward", nc.Ident{Value: z.Forward})
	}
	if z.Notify != "" {
		add("notify", nc.Ident{Value: z.Notify})
	}
	if z.InlineSigning != nil {
		if *z.InlineSigning {
			add("inline-signing", nc.Ident{Value: "yes"})
		} else {
			add("inline-signing", nc.Ident{Value: "no"})
		}
	}
	if z.IXFRFromDifferences != nil {
		if *z.IXFRFromDifferences {
			add("ixfr-from-differences", nc.Ident{Value: "yes"})
		} else {
			add("ixfr-from-differences", nc.Ident{Value: "no"})
		}
	}
	if z.NotifyToSoa != nil {
		if *z.NotifyToSoa {
			add("notify-to-soa", nc.Ident{Value: "yes"})
		} else {
			add("notify-to-soa", nc.Ident{Value: "no"})
		}
	}
	if z.AutoDNSSEC != "" {
		add("auto-dnssec", nc.Ident{Value: z.AutoDNSSEC})
	}
	if z.DNSSECPolicy != "" {
		add("dnssec-policy", nc.StringLit{Value: z.DNSSECPolicy})
	}
	if z.Journal != "" {
		add("journal", nc.StringLit{Value: z.Journal})
	}
	if z.MaxJournalSize != "" {
		add("max-journal-size", nc.Ident{Value: z.MaxJournalSize})
	}
	if z.UpdatePolicy != nil {
		blk.Directives = append(blk.Directives, &nc.Directive{
			Name:  "update-policy",
			Block: z.UpdatePolicy,
		})
	}

	// extras (deterministic key order)
	keys := make([]string, 0, len(z.Extras))
	for k := range z.Extras {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, occ := range z.Extras[k] {
			blk.Directives = append(blk.Directives, &nc.Directive{
				Name: k,
				Args: stringsToExprs(occ),
			})
		}
	}

	dir.Block = blk
	return dir
}

func exprsToStrings(xs []nc.Expr) []string {
	out := make([]string, 0, len(xs))
	for _, e := range xs {
		switch v := e.(type) {
		case nc.StringLit:
			out = append(out, v.Value)
		case nc.Ident:
			out = append(out, v.Value)
		case nc.NumberLit:
			out = append(out, v.Raw)
		case nc.AddrLit:
			out = append(out, v.Raw)
		case nc.CIDRLit:
			out = append(out, v.Raw)
		// NOTE: we cannot render MatchGroup here without access to a public renderer;
		// we store a placeholder to avoid compile errors and keep Extras lossless for non-groups.
		case nc.MatchGroup:
			out = append(out, "{...}")
		default:
			out = append(out, fmt.Sprintf("%T", v))
		}
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
	return nc.Ident{Value: s}
}

// ===== Helpers to build match groups (optional niceties) =====

func MG(items ...nc.MatchItem) *nc.MatchGroup {
	g := nc.MatchGroup{Items: []*nc.MatchItem{}}
	for i := range items {
		it := items[i]
		g.Items = append(g.Items, &it)
	}
	return &g
}

func Item(negated bool, parts ...nc.Expr) nc.MatchItem {
	return nc.MatchItem{Negated: negated, Parts: parts}
}

func Ident(s string) nc.Expr { return nc.Ident{Value: s} }
func Str(s string) nc.Expr   { return nc.StringLit{Value: s} }
func IP(s string) nc.Expr    { return nc.AddrLit{Raw: s} }
func CIDR(s string) nc.Expr  { return nc.CIDRLit{Raw: s} }
