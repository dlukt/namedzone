// File: pkg/namedzone/parse_helpers.go
package namedzone

import (
	"regexp"
	"strconv"
	"strings"

	namedconf "github.com/dlukt/namedconf"
)

func trimQuotes(s string) string { return strings.Trim(strings.TrimSpace(s), "\"") }

func boolWord(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func quoteEach(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = "\"" + s + "\""
	}
	return out
}

func parseBoolPtr(raw string) *bool {
	w := strings.Fields(raw)
	if len(w) == 0 {
		return nil
	}
	switch strings.ToLower(w[0]) {
	case "yes":
		t := true
		return &t
	case "no":
		f := false
		return &f
	}
	return nil
}

func parseIntPtr(raw string) *int {
	w := strings.Fields(raw)
	if len(w) == 0 {
		return nil
	}
	if n, err := strconv.Atoi(w[0]); err == nil {
		return &n
	}
	return nil
}

func parseStringList(raw string) []string {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "{") {
		raw = strings.TrimSuffix(strings.TrimPrefix(raw, "{"), "}")
	}
	parts := strings.Split(raw, ";")
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, trimQuotes(p))
	}
	return out
}

var rxHeadName = regexp.MustCompile(`^[a-z-]+\s+\"([^\"]+)\"`)
var rxHeadClass = regexp.MustCompile(`^[a-z-]+\s+\"[^\"]+\"\s+([A-Za-z]+)`)

func headNameAfter(s *namedconf.Stmt, kw string) string {
	h := strings.TrimSpace(s.HeadRaw)
	if m := rxHeadName.FindStringSubmatch(h); len(m) == 2 {
		return m[1]
	}
	f := strings.Fields(h)
	if len(f) > 1 {
		return trimQuotes(f[1])
	}
	return ""
}

func headClassAfter(s *namedconf.Stmt, kw string) string {
	h := strings.TrimSpace(s.HeadRaw)
	if m := rxHeadClass.FindStringSubmatch(h); len(m) == 2 {
		return m[1]
	}
	return ""
}

// --- RRset order ---

func parseRRsetOrder(st *namedconf.Stmt) []RRsetOrder {
	if len(st.Body) == 0 {
		return nil
	}
	if r, ok := st.Body[0].(*namedconf.Raw); ok {
		txt := strings.TrimSpace(r.Text)
		parts := strings.Split(txt, ";")
		var out []RRsetOrder
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			ro := RRsetOrder{}
			f := strings.Fields(p)
			for i := 0; i < len(f); i++ {
				switch f[i] {
				case "type":
					if i+1 < len(f) {
						ro.Type = f[i+1]
						i++
					}
				case "name":
					if i+1 < len(f) {
						ro.Name = trimQuotes(f[i+1])
						i++
					}
				case "order":
					if i+1 < len(f) {
						ro.Order = f[i+1]
						i++
					}
				}
			}
			if ro.Order == "" && len(f) > 0 {
				ro.Order = f[len(f)-1]
			}
			out = append(out, ro)
		}
		return out
	}
	return nil
}

func serializeRRsetOrder(list []RRsetOrder) string {
	var parts []string
	for _, ro := range list {
		var p []string
		if ro.Type != "" {
			p = append(p, "type "+ro.Type)
		}
		if ro.Name != "" {
			p = append(p, "name \""+ro.Name+"\"")
		}
		p = append(p, "order "+ro.Order)
		parts = append(parts, strings.Join(p, " "))
	}
	return strings.Join(parts, "; ") + ";"
}

// --- Address match lists ---

func parseMatchList(raw string) []MatchTerm {
	if !strings.Contains(raw, "{") {
		return nil
	}
	return parseMatchListFromBodyRaw(raw)
}

func parseMatchListFromBody(s *namedconf.Stmt) []MatchTerm {
	if len(s.Body) == 0 {
		return nil
	}
	if r, ok := s.Body[0].(*namedconf.Raw); ok {
		return parseMatchListFromBodyRaw(r.Text)
	}
	var out []MatchTerm
	for _, n := range s.Body {
		if st, ok := n.(*namedconf.Stmt); ok {
			out = append(out, MatchTerm{Address: strings.TrimSpace(strings.TrimSuffix(st.HeadRaw, ";"))})
		}
	}
	return out
}

func parseMatchListFromBodyRaw(raw string) []MatchTerm {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "{") {
		raw = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(raw, "{"), "}"))
	}
	parts := strings.Split(raw, ";")
	var out []MatchTerm
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		mt := MatchTerm{}
		if strings.HasPrefix(p, "!") {
			mt.Not = true
			p = strings.TrimSpace(strings.TrimPrefix(p, "!"))
		}
		if strings.HasPrefix(p, "key ") {
			mt.Key = trimQuotes(strings.TrimPrefix(p, "key "))
			out = append(out, mt)
			continue
		}
		if strings.HasPrefix(p, "{") {
			mt.Nested = parseMatchListFromBodyRaw(p)
			out = append(out, mt)
			continue
		}
		if strings.Contains(p, "/") || strings.Count(p, ":") > 1 || strings.Count(p, ".") == 3 {
			mt.Address = p
		} else {
			mt.ACLRef = trimQuotes(p)
		}
		out = append(out, mt)
	}
	return out
}

func serializeMatchList(terms []MatchTerm) string {
	var b strings.Builder
	b.WriteString("{ ")
	for i, t := range terms {
		if i > 0 {
			b.WriteString(" ")
		}
		if t.Not {
			b.WriteString("!")
		}
		switch {
		case len(t.Nested) > 0:
			b.WriteString(serializeMatchList(t.Nested))
		case t.Key != "":
			b.WriteString("key \"")
			b.WriteString(t.Key)
			b.WriteString("\"")
		case t.Address != "":
			b.WriteString(t.Address)
		case t.ACLRef != "":
			if needsQuotes(t.ACLRef) {
				b.WriteString("\"")
				b.WriteString(t.ACLRef)
				b.WriteString("\"")
			} else {
				b.WriteString(t.ACLRef)
			}
		}
		b.WriteString(";")
	}
	b.WriteString(" }")
	return b.String()
}

func needsQuotes(s string) bool { return strings.ContainsAny(s, ".-* ") }

// --- listen/forwarders helpers ---

func parseListen(raw string) *Listen {
	L := &Listen{}
	lb := strings.Index(raw, "{")
	if lb >= 0 {
		L.Addrs = parseMatchListFromBodyRaw(strings.TrimSpace(raw[lb:]))
		raw = strings.TrimSpace(raw[:lb])
	}
	fields := strings.Fields(raw)
	for i := 0; i < len(fields); i++ {
		switch fields[i] {
		case "port":
			if i+1 < len(fields) {
				if n, err := strconv.Atoi(fields[i+1]); err == nil {
					L.Port = &n
				}
				i++
			}
		case "tls":
			if i+1 < len(fields) {
				L.TLS = trimQuotes(fields[i+1])
				i++
			}
		case "http":
			if i+1 < len(fields) {
				L.HTTP = trimQuotes(fields[i+1])
				i++
			}
		}
	}
	return L
}

func serializeListen(l Listen) string {
	var pre []string
	if l.Port != nil {
		pre = append(pre, "port "+strconv.Itoa(*l.Port))
	}
	if l.TLS != "" {
		pre = append(pre, "tls \""+l.TLS+"\"")
	}
	if l.HTTP != "" {
		pre = append(pre, "http \""+l.HTTP+"\"")
	}
	return strings.TrimSpace(strings.Join(pre, " ")) + " " + serializeMatchList(l.Addrs)
}

func parseForwarders(raw string) []Forwarder {
	items := []Forwarder{}
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "{") {
		raw = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(raw, "{"), "}"))
	}
	parts := strings.Split(raw, ";")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		fields := strings.Fields(p)
		if len(fields) == 0 {
			continue
		}
		it := Forwarder{Address: fields[0]}
		for i := 1; i < len(fields); i++ {
			switch fields[i] {
			case "port":
				if i+1 < len(fields) {
					if n, err := strconv.Atoi(fields[i+1]); err == nil {
						it.Port = &n
					}
					i++
				}
			case "tls":
				if i+1 < len(fields) {
					it.TLS = trimQuotes(fields[i+1])
					i++
				}
			}
		}
		items = append(items, it)
	}
	return items
}

func serializeForwarders(ff []Forwarder) string {
	var items []string
	for _, f := range ff {
		s := f.Address
		if f.Port != nil {
			s += " port " + strconv.Itoa(*f.Port)
		}
		if f.TLS != "" {
			s += " tls \"" + f.TLS + "\""
		}
		items = append(items, s)
	}
	return "{ " + strings.Join(items, "; ") + "; }"
}

// --- remote-servers ---

func parseRemoteServerItem(raw string) RemoteServerItem {
	fields := strings.Fields(raw)
	it := RemoteServerItem{}
	if len(fields) > 0 {
		it.Address = fields[0]
	}
	for i := 1; i < len(fields); i++ {
		switch fields[i] {
		case "port":
			if i+1 < len(fields) {
				if n, err := strconv.Atoi(fields[i+1]); err == nil {
					it.Port = &n
				}
				i++
			}
		case "key":
			if i+1 < len(fields) {
				it.Key = trimQuotes(fields[i+1])
				i++
			}
		case "tls":
			if i+1 < len(fields) {
				it.TLS = trimQuotes(fields[i+1])
				i++
			}
		}
	}
	return it
}

func serializeRemoteServerItem(it RemoteServerItem) string {
	s := it.Address
	if it.Port != nil {
		s += " port " + strconv.Itoa(*it.Port)
	}
	if it.Key != "" {
		s += " key \"" + it.Key + "\""
	}
	if it.TLS != "" {
		s += " tls \"" + it.TLS + "\""
	}
	return s
}

func parseRemoteServerListBody(raw string) []RemoteServerItem {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "{") {
		raw = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(raw, "{"), "}"))
	}
	var items []RemoteServerItem
	for _, line := range strings.Split(raw, ";") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		items = append(items, parseRemoteServerItem(line))
	}
	return items
}

func serializeRemoteServerList(items []RemoteServerItem) string {
	parts := make([]string, 0, len(items))
	for _, it := range items {
		parts = append(parts, serializeRemoteServerItem(it))
	}
	return "{ " + strings.Join(parts, "; ") + "; }"
}

// --- controls ---

func parseControlInet(raw string) ControlInet {
	ci := ControlInet{}
	raw = strings.TrimPrefix(raw, "inet ")
	if idx := strings.Index(raw, " allow "); idx >= 0 {
		allow := raw[idx+len(" allow "):]
		ci.Allow = parseMatchList(allow)
		raw = strings.TrimSpace(raw[:idx])
	}
	if idx := strings.Index(raw, " keys "); idx >= 0 {
		keys := raw[idx+len(" keys "):]
		ci.Keys = parseStringList(keys)
		raw = strings.TrimSpace(raw[:idx])
	}
	if strings.Contains(raw, " read-only ") {
		parts := strings.Split(raw, " read-only ")
		b := parseBoolPtr(strings.TrimSpace(parts[1]))
		ci.ReadOnly = b
		raw = strings.TrimSpace(parts[0])
	}
	fields := strings.Fields(raw)
	if len(fields) > 0 {
		ci.Address = fields[0]
	}
	for i := 1; i < len(fields); i++ {
		if fields[i] == "port" && i+1 < len(fields) {
			if n, err := strconv.Atoi(fields[i+1]); err == nil {
				ci.Port = &n
			}
			i++
		}
	}
	return ci
}

func serializeControlInet(ci ControlInet) string {
	s := "inet " + ci.Address
	if ci.Port != nil {
		s += " port " + strconv.Itoa(*ci.Port)
	}
	s += " allow " + serializeMatchList(ci.Allow)
	if len(ci.Keys) > 0 {
		s += " keys { " + strings.Join(quoteEach(ci.Keys), "; ") + "; }"
	}
	if ci.ReadOnly != nil {
		s += " read-only " + boolWord(*ci.ReadOnly)
	}
	return s
}

func parseControlUnix(raw string) ControlUnix {
	cu := ControlUnix{}
	raw = strings.TrimPrefix(raw, "unix ")
	if idx := strings.Index(raw, " keys "); idx >= 0 {
		keys := raw[idx+len(" keys "):]
		cu.Keys = parseStringList(keys)
		raw = strings.TrimSpace(raw[:idx])
	}
	if strings.Contains(raw, " read-only ") {
		parts := strings.Split(raw, " read-only ")
		b := parseBoolPtr(strings.TrimSpace(parts[1]))
		cu.ReadOnly = b
		raw = strings.TrimSpace(parts[0])
	}
	fields := strings.Fields(raw)
	if len(fields) >= 8 {
		cu.Path = trimQuotes(fields[0])
		cu.Perm, _ = strconv.Atoi(fields[2])
		cu.Owner, _ = strconv.Atoi(fields[4])
		cu.Group, _ = strconv.Atoi(fields[6])
	}
	return cu
}

func serializeControlUnix(cu ControlUnix) string {
	s := "unix \"" + cu.Path + "\" perm " + strconv.Itoa(cu.Perm) + " owner " + strconv.Itoa(cu.Owner) + " group " + strconv.Itoa(cu.Group)
	if len(cu.Keys) > 0 {
		s += " keys { " + strings.Join(quoteEach(cu.Keys), "; ") + "; }"
	}
	if cu.ReadOnly != nil {
		s += " read-only " + boolWord(*cu.ReadOnly)
	}
	return s
}
