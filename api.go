// File: pkg/namedzone/api.go
package namedzone

import (
	"errors"
)

// GetZone returns the first zone with the given name (top-level or within any view).
func (c *Config) GetZone(name string) *Zone {
	for i := range c.Zones {
		if c.Zones[i].Name == name {
			return &c.Zones[i]
		}
	}
	for i := range c.Views {
		for j := range c.Views[i].Zones {
			if c.Views[i].Zones[j].Name == name {
				return &c.Views[i].Zones[j]
			}
		}
	}
	return nil
}

// UpsertZone inserts or replaces a top-level zone by name.
func (c *Config) UpsertZone(z Zone) {
	for i := range c.Zones {
		if c.Zones[i].Name == z.Name {
			c.Zones[i] = z
			return
		}
	}
	c.Zones = append(c.Zones, z)
}

// RemoveZone removes a top-level zone by name and returns true if found.
func (c *Config) RemoveZone(name string) bool {
	out := c.Zones[:0]
	removed := false
	for _, z := range c.Zones {
		if z.Name == name {
			removed = true
			continue
		}
		out = append(out, z)
	}
	c.Zones = out
	return removed
}

// FindView returns a pointer to the view with the given name.
func (c *Config) FindView(name string) *View {
	for i := range c.Views {
		if c.Views[i].Name == name {
			return &c.Views[i]
		}
	}
	return nil
}

// UpsertView inserts or replaces a view by name.
func (c *Config) UpsertView(v View) {
	for i := range c.Views {
		if c.Views[i].Name == v.Name {
			c.Views[i] = v
			return
		}
	}
	c.Views = append(c.Views, v)
}

// RemoveView removes a view by name and returns true if found.
func (c *Config) RemoveView(name string) bool {
	out := c.Views[:0]
	removed := false
	for _, v := range c.Views {
		if v.Name == name {
			removed = true
			continue
		}
		out = append(out, v)
	}
	c.Views = out
	return removed
}

// SetRecursion sets global options.recursion (creates Options if absent).
func (c *Config) SetRecursion(b bool) {
	if c.Options == nil {
		c.Options = &Options{}
	}
	c.Options.Recursion = BoolPtr(b)
}

// Save applies the typed config back to the underlying AST and writes the file.
// It requires that the Config originated from FromFile (i.e., has c.ast populated).
func (c *Config) Save(path string) error {
	if c.ast == nil {
		return errors.New("namedzone: no underlying AST; call FromFile first")
	}
	if err := c.Apply(c.ast); err != nil {
		return err
	}
	return c.ast.Save(path)
}

// ---- View-scoped helpers (for web APIs) ----

// UpsertZone inserts/replaces a zone inside a specific view by name. If the
// view does not exist, it is created with default settings.
func (c *Config) UpsertZoneInView(viewName string, z Zone) {
	v := c.FindView(viewName)
	if v == nil {
		c.Views = append(c.Views, View{Name: viewName, Zones: []Zone{z}})
		return
	}
	for i := range v.Zones {
		if v.Zones[i].Name == z.Name {
			v.Zones[i] = z
			return
		}
	}
	v.Zones = append(v.Zones, z)
}

// RemoveZoneInView removes a zone by name from a specific view.
func (c *Config) RemoveZoneInView(viewName, zoneName string) bool {
	v := c.FindView(viewName)
	if v == nil {
		return false
	}
	out := v.Zones[:0]
	removed := false
	for _, z := range v.Zones {
		if z.Name == zoneName {
			removed = true
			continue
		}
		out = append(out, z)
	}
	v.Zones = out
	return removed
}

// SetTrustAnchorsInView replaces (or sets) trust-anchors inside the given view.
func (c *Config) SetTrustAnchorsInView(viewName string, ta TrustAnchors) {
	v := c.FindView(viewName)
	if v == nil {
		c.Views = append(c.Views, View{Name: viewName, TrustAnchors: &ta})
		return
	}
	v.TrustAnchors = &ta
}
