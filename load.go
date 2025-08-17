// File: pkg/namedzone/load.go
package namedzone

import (
	"fmt"
	"strconv"
	"strings"

	nc "github.com/dlukt/namedconf"
)

// FromFile builds a typed Config from a parsed AST. Unknown statements remain untouched in the AST.
func FromFile(f *nc.File) (*Config, error) {
	cfg := &Config{ast: f}
	for _, n := range f.Nodes {
		s, ok := n.(*nc.Stmt)
		if !ok {
			continue
		}
		switch s.Keyword {
		case "include":
			path := trimQuotes(strings.TrimSpace(strings.TrimSuffix(s.HeadRaw, ";")))
			cfg.Includes = append(cfg.Includes, Include{Path: path, stmt: s})
		case "acl":
			cfg.ACLs = append(cfg.ACLs, parseACL(s))
		case "key":
			cfg.Keys = append(cfg.Keys, parseKey(s))
		case "key-store":
			cfg.KeyStores = append(cfg.KeyStores, parseKeyStore(s))
		case "remote-servers":
			cfg.RemoteServers = append(cfg.RemoteServers, parseRemoteServers(s))
		case "tls":
			cfg.TLS = append(cfg.TLS, parseTLS(s))
		case "http":
			cfg.HTTP = append(cfg.HTTP, parseHTTP(s))
		case "controls":
			c := parseControls(s)
			cfg.Controls = &c
		case "logging":
			lg := parseLogging(s)
			cfg.Logging = &lg
		case "options":
			op := parseOptions(s)
			cfg.Options = &op
		case "trust-anchors":
			ta := parseTrustAnchors(s)
			cfg.TrustAnchors = append(cfg.TrustAnchors, ta)
		case "view":
			v := parseView(s)
			cfg.Views = append(cfg.Views, v)
		case "zone":
			z := parseZone(s)
			cfg.Zones = append(cfg.Zones, z)
		default:
			// unknown: preserved by AST
		}
	}
	return cfg, nil
}

// Apply mutates the underlying AST to reflect typed changes and keep lossless round-trip for untouched parts.
func (c *Config) Apply(f *nc.File) error {
	if f == nil {
		f = c.ast
	}
	if f == nil {
		return fmt.Errorf("Apply: nil file")
	}

	// top-level simple lists/blocks
	syncIncludes(f, c.Includes)
	syncBlocks(f, "acl", c.ACLs, buildACL)
	syncBlocks(f, "key", c.Keys, buildKey)
	syncBlocks(f, "key-store", c.KeyStores, buildKeyStore)
	syncBlocks(f, "remote-servers", c.RemoteServers, buildRemoteServers)
	syncBlocks(f, "tls", c.TLS, buildTLS)
	syncBlocks(f, "http", c.HTTP, buildHTTP)
	syncSingleton(f, "controls", c.Controls, buildControls)
	syncSingleton(f, "logging", c.Logging, buildLogging)
	syncSingleton(f, "options", c.Options, buildOptions)
	syncBlocks(f, "trust-anchors", c.TrustAnchors, buildTrustAnchors)
	syncBlocks(f, "view", c.Views, buildView)
	syncBlocks(f, "zone", c.Zones, buildZone)

	c.ast = f
	return nil
}

// ---------------- Parsers ----------------

func parseACL(s *nc.Stmt) ACL {
	name := headNameAfter(s, "acl")
	terms := parseMatchListFromBody(s)
	return ACL{Name: name, Elements: terms, stmt: s}
}

func parseKey(s *nc.Stmt) Key {
	name := headNameAfter(s, "key")
	var alg, secret string
	for _, n := range s.Body {
		if st, ok := n.(*nc.Stmt); ok {
			kw := st.Keyword
			v := strings.TrimSpace(strings.TrimSuffix(st.HeadRaw, ";"))
			v = trimQuotes(v)
			switch kw {
			case "algorithm":
				alg = v
			case "secret":
				secret = v
			}
		}
	}
	return Key{Name: name, Algorithm: alg, Secret: secret, stmt: s}
}

func parseKeyStore(s *nc.Stmt) KeyStore {
	name := headNameAfter(s, "key-store")
	var uri string
	for _, n := range s.Body {
		if st, ok := n.(*nc.Stmt); ok && st.Keyword == "pkcs11-uri" {
			uri = trimQuotes(strings.TrimSpace(strings.TrimSuffix(st.HeadRaw, ";")))
		}
	}
	return KeyStore{Name: name, PKCS11URI: uri, stmt: s}
}

func parseRemoteServers(s *nc.Stmt) RemoteServers {
	name := headNameAfter(s, "remote-servers")
	items := []RemoteServerItem{}
	for _, n := range s.Body {
		st, ok := n.(*nc.Stmt)
		if !ok {
			continue
		}
		raw := strings.TrimSpace(strings.TrimSuffix(st.HeadRaw, ";"))
		if raw == "" {
			continue
		}
		items = append(items, parseRemoteServerItem(raw))
	}
	return RemoteServers{Name: name, Servers: items, stmt: s}
}

func parseTLS(s *nc.Stmt) TLS {
	t := TLS{Name: headNameAfter(s, "tls"), stmt: s}
	for _, n := range s.Body {
		st, ok := n.(*nc.Stmt)
		if !ok {
			continue
		}
		v := strings.TrimSpace(strings.TrimSuffix(st.HeadRaw, ";"))
		vq := trimQuotes(v)
		switch st.Keyword {
		case "ca-file":
			t.CAFile = vq
		case "cert-file":
			t.CertFile = vq
		case "key-file":
			t.KeyFile = vq
		case "cipher-suites":
			t.CipherSuites = vq
		case "ciphers":
			t.Ciphers = vq
		case "dhparam-file":
			t.DHParamFile = vq
		case "prefer-server-ciphers":
			t.PreferServer = parseBoolPtr(v)
		case "protocols":
			t.Protocols = parseStringList(v)
		case "remote-hostname":
			t.RemoteHost = vq
		case "session-tickets":
			t.SessionTickets = parseBoolPtr(v)
		}
	}
	return t
}

func parseHTTP(s *nc.Stmt) HTTP {
	h := HTTP{Name: headNameAfter(s, "http"), stmt: s}
	for _, n := range s.Body {
		st, ok := n.(*nc.Stmt)
		if !ok {
			continue
		}
		v := strings.TrimSpace(strings.TrimSuffix(st.HeadRaw, ";"))
		switch st.Keyword {
		case "endpoints":
			h.Endpoints = parseStringList(v)
		case "listener-clients":
			h.ListenerClients = parseIntPtr(v)
		case "streams-per-connection":
			h.StreamsPerConnection = parseIntPtr(v)
		}
	}
	return h
}

func parseControls(s *nc.Stmt) Controls {
	c := Controls{stmt: s}
	for _, n := range s.Body {
		st, ok := n.(*nc.Stmt)
		if !ok {
			continue
		}
		raw := strings.TrimSpace(strings.TrimSuffix(st.HeadRaw, ";"))
		if strings.HasPrefix(raw, "inet ") {
			c.Inet = append(c.Inet, parseControlInet(raw))
		} else if strings.HasPrefix(raw, "unix ") {
			c.Unix = append(c.Unix, parseControlUnix(raw))
		}
	}
	return c
}

func parseLogging(s *nc.Stmt) Logging {
	lg := Logging{stmt: s}
	for _, n := range s.Body {
		st, ok := n.(*nc.Stmt)
		if !ok {
			continue
		}
		if st.Keyword == "channel" {
			lg.Channels = append(lg.Channels, parseLogChannel(st))
		} else if st.Keyword == "category" {
			lg.Categories = append(lg.Categories, parseLogCategory(st))
		}
	}
	return lg
}

func parseOptions(s *nc.Stmt) Options {
	op := Options{stmt: s}
	for _, n := range s.Body {
		st, ok := n.(*nc.Stmt)
		if !ok {
			continue
		}
		raw := strings.TrimSpace(strings.TrimSuffix(st.HeadRaw, ";"))
		switch st.Keyword {
		case "directory":
			op.Directory = trimQuotes(raw)
		case "recursion":
			op.Recursion = parseBoolPtr(raw)
		case "allow-query":
			op.AllowQuery = parseMatchList(raw)
		case "allow-transfer":
			op.AllowTransfer = parseMatchList(raw)
		case "allow-update":
			op.AllowUpdate = parseMatchList(raw)
		case "listen-on":
			op.ListenOn = parseListen(raw)
		case "listen-on-v6":
			op.ListenOnV6 = parseListen(raw)
		case "forwarders":
			op.Forwarders = parseForwarders(raw)
		case "forward":
			if f := strings.Fields(raw); len(f) > 0 {
				op.Forward = f[0]
			}
		case "dnssec-validation":
			if f := strings.Fields(raw); len(f) > 0 {
				op.DNSSECValidation = f[0]
			}
		case "rrset-order":
			op.RRsetOrder = parseRRsetOrder(st)
		default:
			op.Other = append(op.Other, RawKV{Name: st.Keyword, Raw: raw})
		}
	}
	return op
}

func parseView(s *nc.Stmt) View {
	v := View{Name: headNameAfter(s, "view"), stmt: s}
	v.Class = headClassAfter(s, "view")
	for _, n := range s.Body {
		st, ok := n.(*nc.Stmt)
		if !ok {
			continue
		}
		raw := strings.TrimSpace(strings.TrimSuffix(st.HeadRaw, ";"))
		switch st.Keyword {
		case "match-clients":
			v.MatchClients = parseMatchList(raw)
		case "match-destinations":
			v.MatchDestinations = parseMatchList(raw)
		case "recursion":
			v.Recursion = parseBoolPtr(raw)
		case "trust-anchors":
			ta := parseTrustAnchors(st)
			v.TrustAnchors = &ta
		case "zone":
			vz := parseZone(st)
			v.Zones = append(v.Zones, vz)
		case "include":
			v.Includes = append(v.Includes, Include{Path: trimQuotes(raw), stmt: st})
		}
	}
	return v
}

func parseZone(s *nc.Stmt) Zone {
	z := Zone{Name: headNameAfter(s, "zone"), Class: headClassAfter(s, "zone"), stmt: s}
	for _, n := range s.Body {
		st, ok := n.(*nc.Stmt)
		if !ok {
			continue
		}
		raw := strings.TrimSpace(strings.TrimSuffix(st.HeadRaw, ";"))
		switch st.Keyword {
		case "type":
			if f := strings.Fields(raw); len(f) > 0 {
				z.Type = ZoneType(f[0])
			}
		case "file":
			z.File = trimQuotes(raw)
		case "primaries":
			if strings.HasPrefix(raw, "{") {
				z.Primaries = parseRemoteServerListBody(raw)
			} else {
				z.PrimariesRef = strings.TrimSpace(raw)
			}
		case "forwarders":
			z.Forwarders = parseForwarders(raw)
		case "forward":
			if f := strings.Fields(raw); len(f) > 0 {
				z.Forward = f[0]
			}
		case "allow-update":
			z.AllowUpdate = parseMatchList(raw)
		case "allow-transfer":
			z.AllowTransfer = parseMatchList(raw)
		case "also-notify":
			z.AlsoNotify = parseRemoteServerListBody(raw)
		case "dnssec-policy":
			z.DNSSECPolicy = trimQuotes(raw)
		}
	}
	return z
}

func parseTrustAnchors(st *nc.Stmt) TrustAnchors {
	ta := TrustAnchors{stmt: st}
	for _, n := range st.Body {
		ss, ok := n.(*nc.Stmt)
		if !ok {
			continue
		}
		raw := strings.TrimSpace(strings.TrimSuffix(ss.HeadRaw, ";"))
		// Capture either static-ds/static-key or initial-ds/initial-key lines in a generic way.
		fields := strings.Fields(raw)
		if len(fields) == 0 {
			continue
		}
		name := trimQuotes(fields[0])
		rest := strings.TrimSpace(strings.TrimPrefix(raw, fields[0]+" "))
		if strings.Contains(rest, "ds") {
			ta.Items = append(ta.Items, TrustAnchorItem{Name: name, DS: rest})
		} else if strings.Contains(rest, "key") {
			ta.Items = append(ta.Items, TrustAnchorItem{Name: name, DNSKey: rest})
		}
	}
	return ta
}

// ---------------- Builders/Sync ----------------

type builder[T any] func(T) *nc.Stmt

func syncBlocks[T any](f *nc.File, keyword string, items []T, b builder[T]) {
	var out []nc.Node
	for _, n := range f.Nodes {
		s, ok := n.(*nc.Stmt)
		if ok && s.Keyword == keyword {
			continue
		}
		out = append(out, n)
	}
	for _, it := range items {
		out = append(out, b(it))
	}
	f.Nodes = out
}

func syncSingleton[T any](f *nc.File, keyword string, item *T, b builder[T]) {
	if item == nil {
		var out []nc.Node
		for _, n := range f.Nodes {
			s, ok := n.(*nc.Stmt)
			if ok && s.Keyword == keyword {
				continue
			}
			out = append(out, n)
		}
		f.Nodes = out
		return
	}
	syncBlocks(f, keyword, []T{*item}, b)
}

func syncIncludes(f *nc.File, incs []Include) {
	var out []nc.Node
	for _, n := range f.Nodes {
		s, ok := n.(*nc.Stmt)
		if ok && s.Keyword == "include" {
			continue
		}
		out = append(out, n)
	}
	for _, in := range incs {
		out = append(out, nc.NewSimpleStmt("include \""+in.Path+"\""))
	}
	f.Nodes = out
}

func buildACL(a ACL) *nc.Stmt {
	head := "acl \"" + a.Name + "\""
	body := []nc.Node{&nc.Raw{Text: serializeMatchList(a.Elements)}}
	return nc.NewBlockStmt(head, body)
}

func buildKey(k Key) *nc.Stmt {
	body := []nc.Node{
		nc.NewSimpleStmt("algorithm \"" + k.Algorithm + "\""),
		nc.NewSimpleStmt("secret \"" + k.Secret + "\""),
	}
	return nc.NewBlockStmt("key \""+k.Name+"\"", body)
}

func buildKeyStore(ks KeyStore) *nc.Stmt {
	body := []nc.Node{}
	if ks.PKCS11URI != "" {
		body = append(body, nc.NewSimpleStmt("pkcs11-uri \""+ks.PKCS11URI+"\""))
	}
	return nc.NewBlockStmt("key-store \""+ks.Name+"\"", body)
}

func buildRemoteServers(rs RemoteServers) *nc.Stmt {
	body := []nc.Node{}
	for _, it := range rs.Servers {
		body = append(body, nc.NewSimpleStmt(serializeRemoteServerItem(it)))
	}
	return nc.NewBlockStmt("remote-servers \""+rs.Name+"\"", body)
}

func buildTLS(t TLS) *nc.Stmt {
	body := []nc.Node{}
	add := func(k, v string) {
		if v != "" {
			body = append(body, nc.NewSimpleStmt(k+" \""+v+"\""))
		}
	}
	add("ca-file", t.CAFile)
	add("cert-file", t.CertFile)
	add("key-file", t.KeyFile)
	if t.CipherSuites != "" {
		body = append(body, nc.NewSimpleStmt("cipher-suites \""+t.CipherSuites+"\""))
	}
	if t.Ciphers != "" {
		body = append(body, nc.NewSimpleStmt("ciphers \""+t.Ciphers+"\""))
	}
	add("dhparam-file", t.DHParamFile)
	if t.PreferServer != nil {
		body = append(body, nc.NewSimpleStmt("prefer-server-ciphers "+boolWord(*t.PreferServer)))
	}
	if len(t.Protocols) > 0 {
		body = append(body, nc.NewSimpleStmt("protocols { "+strings.Join(quoteEach(t.Protocols), "; ")+"; }"))
	}
	add("remote-hostname", t.RemoteHost)
	if t.SessionTickets != nil {
		body = append(body, nc.NewSimpleStmt("session-tickets "+boolWord(*t.SessionTickets)))
	}
	return nc.NewBlockStmt("tls \""+t.Name+"\"", body)
}

func buildHTTP(h HTTP) *nc.Stmt {
	body := []nc.Node{}
	if len(h.Endpoints) > 0 {
		body = append(body, nc.NewSimpleStmt("endpoints { "+strings.Join(quoteEach(h.Endpoints), "; ")+"; }"))
	}
	if h.ListenerClients != nil {
		body = append(body, nc.NewSimpleStmt("listener-clients "+strconv.Itoa(*h.ListenerClients)))
	}
	if h.StreamsPerConnection != nil {
		body = append(body, nc.NewSimpleStmt("streams-per-connection "+strconv.Itoa(*h.StreamsPerConnection)))
	}
	return nc.NewBlockStmt("http \""+h.Name+"\"", body)
}

func buildControls(c Controls) *nc.Stmt {
	body := []nc.Node{}
	for _, in := range c.Inet {
		body = append(body, nc.NewSimpleStmt(serializeControlInet(in)))
	}
	for _, ux := range c.Unix {
		body = append(body, nc.NewSimpleStmt(serializeControlUnix(ux)))
	}
	return nc.NewBlockStmt("controls", body)
}

func buildLogging(l Logging) *nc.Stmt {
	body := []nc.Node{}
	for _, ch := range l.Channels {
		body = append(body, buildLogChannel(ch))
	}
	for _, cat := range l.Categories {
		body = append(body, buildLogCategory(cat))
	}
	return nc.NewBlockStmt("logging", body)
}

func buildLogChannel(ch LogChannel) *nc.Stmt {
	body := []nc.Node{}
	if ch.File != nil {
		parts := []string{"\"" + ch.File.Path + "\""}
		if ch.File.Versions != nil {
			parts = append(parts, "versions "+strconv.Itoa(*ch.File.Versions))
		}
		if ch.File.Size != "" {
			parts = append(parts, "size "+ch.File.Size)
		}
		if ch.File.Suffix != "" {
			parts = append(parts, "suffix "+ch.File.Suffix)
		}
		if ch.File.Severity != "" {
			parts = append(parts, "severity "+ch.File.Severity)
		}
		body = append(body, nc.NewSimpleStmt("file "+strings.Join(parts, " ")))
	}
	if ch.Syslog != nil {
		if ch.Syslog.Facility != "" {
			body = append(body, nc.NewSimpleStmt("syslog "+ch.Syslog.Facility))
		} else {
			body = append(body, nc.NewSimpleStmt("syslog"))
		}
	}
	if ch.Stderr {
		body = append(body, nc.NewSimpleStmt("stderr"))
	}
	if ch.Null {
		body = append(body, nc.NewSimpleStmt("null"))
	}
	if ch.Severity != "" {
		body = append(body, nc.NewSimpleStmt("severity "+ch.Severity))
	}
	if ch.PrintTime != nil {
		body = append(body, nc.NewSimpleStmt("print-time "+boolWord(*ch.PrintTime)))
	}
	if ch.PrintCategory != nil {
		body = append(body, nc.NewSimpleStmt("print-category "+boolWord(*ch.PrintCategory)))
	}
	if ch.PrintSeverity != nil {
		body = append(body, nc.NewSimpleStmt("print-severity "+boolWord(*ch.PrintSeverity)))
	}
	if ch.Buffered != nil {
		body = append(body, nc.NewSimpleStmt("buffered "+boolWord(*ch.Buffered)))
	}
	return nc.NewBlockStmt("channel \""+ch.Name+"\"", body)
}

func parseLogChannel(st *nc.Stmt) LogChannel {
	name := headNameAfter(st, "channel")
	lc := LogChannel{Name: name}
	for _, n := range st.Body {
		ss, ok := n.(*nc.Stmt)
		if !ok {
			continue
		}
		raw := strings.TrimSpace(strings.TrimSuffix(ss.HeadRaw, ";"))
		switch ss.Keyword {
		case "file":
			args := strings.Fields(raw)
			lf := LogFileDest{Path: trimQuotes(args[0])}
			for i := 1; i < len(args); i++ {
				switch args[i] {
				case "versions":
					if i+1 < len(args) {
						if n, err := strconv.Atoi(args[i+1]); err == nil {
							lf.Versions = &n
						}
						i++
					}
				case "size":
					if i+1 < len(args) {
						lf.Size = args[i+1]
						i++
					}
				case "suffix":
					if i+1 < len(args) {
						lf.Suffix = args[i+1]
						i++
					}
				case "severity":
					if i+1 < len(args) {
						lf.Severity = args[i+1]
						i++
					}
				}
			}
			lc.File = &lf
		case "syslog":
			args := strings.Fields(raw)
			sf := LogSyslogDest{}
			if len(args) > 0 {
				sf.Facility = args[0]
			}
			lc.Syslog = &sf
		case "stderr":
			lc.Stderr = true
		case "null":
			lc.Null = true
		case "severity":
			lc.Severity = raw
		case "print-time":
			lc.PrintTime = parseBoolPtr(raw)
		case "print-category":
			lc.PrintCategory = parseBoolPtr(raw)
		case "print-severity":
			lc.PrintSeverity = parseBoolPtr(raw)
		case "buffered":
			lc.Buffered = parseBoolPtr(raw)
		}
	}
	return lc
}

func parseLogCategory(st *nc.Stmt) LogCategory {
	name := headNameAfter(st, "category")
	lc := LogCategory{Name: name}
	if len(st.Body) > 0 {
		if r, ok := st.Body[0].(*nc.Raw); ok {
			names := parseStringList(r.Text)
			lc.Channels = names
		}
	}
	return lc
}

func buildLogCategory(cat LogCategory) *nc.Stmt {
	return nc.NewSimpleStmt("category \"" + cat.Name + "\" { " + strings.Join(quoteEach(cat.Channels), "; ") + "; }")
}

func buildOptions(o Options) *nc.Stmt {
	body := []nc.Node{}
	add := func(stmt string) { body = append(body, nc.NewSimpleStmt(stmt)) }
	if o.Directory != "" {
		add("directory \"" + o.Directory + "\"")
	}
	if o.Recursion != nil {
		add("recursion " + boolWord(*o.Recursion))
	}
	if len(o.AllowQuery) > 0 {
		add("allow-query " + serializeMatchList(o.AllowQuery))
	}
	if len(o.AllowTransfer) > 0 {
		add("allow-transfer " + serializeMatchList(o.AllowTransfer))
	}
	if len(o.AllowUpdate) > 0 {
		add("allow-update " + serializeMatchList(o.AllowUpdate))
	}
	if o.ListenOn != nil {
		add("listen-on " + serializeListen(*o.ListenOn))
	}
	if o.ListenOnV6 != nil {
		add("listen-on-v6 " + serializeListen(*o.ListenOnV6))
	}
	if len(o.Forwarders) > 0 {
		add("forwarders " + serializeForwarders(o.Forwarders))
	}
	if o.Forward != "" {
		add("forward " + o.Forward)
	}
	if o.DNSSECValidation != "" {
		add("dnssec-validation " + o.DNSSECValidation)
	}
	if len(o.RRsetOrder) > 0 {
		add("rrset-order { " + serializeRRsetOrder(o.RRsetOrder) + " }")
	}
	for _, kv := range o.Other {
		add(kv.Name + " " + kv.Raw)
	}
	return nc.NewBlockStmt("options", body)
}

func buildView(v View) *nc.Stmt {
	head := "view \"" + v.Name + "\""
	if v.Class != "" {
		head += " " + v.Class
	}
	body := []nc.Node{}
	add := func(stmt string) { body = append(body, nc.NewSimpleStmt(stmt)) }
	if len(v.MatchClients) > 0 {
		add("match-clients " + serializeMatchList(v.MatchClients))
	}
	if len(v.MatchDestinations) > 0 {
		add("match-destinations " + serializeMatchList(v.MatchDestinations))
	}
	if v.Recursion != nil {
		add("recursion " + boolWord(*v.Recursion))
	}
	if v.TrustAnchors != nil {
		body = append(body, buildTrustAnchors(*v.TrustAnchors))
	}
	for _, z := range v.Zones {
		body = append(body, buildZone(z))
	}
	for _, inc := range v.Includes {
		add("include \"" + inc.Path + "\"")
	}
	return nc.NewBlockStmt(head, body)
}

func buildZone(z Zone) *nc.Stmt {
	head := "zone \"" + z.Name + "\""
	if z.Class != "" {
		head += " " + z.Class
	}
	body := []nc.Node{}
	add := func(stmt string) { body = append(body, nc.NewSimpleStmt(stmt)) }
	if z.Type != "" {
		add("type " + string(z.Type))
	}
	if z.File != "" {
		add("file \"" + z.File + "\"")
	}
	if z.PrimariesRef != "" {
		add("primaries " + z.PrimariesRef)
	}
	if len(z.Primaries) > 0 {
		add("primaries " + serializeRemoteServerList(z.Primaries))
	}
	if len(z.Forwarders) > 0 {
		add("forwarders " + serializeForwarders(z.Forwarders))
	}
	if z.Forward != "" {
		add("forward " + z.Forward)
	}
	if len(z.AllowUpdate) > 0 {
		add("allow-update " + serializeMatchList(z.AllowUpdate))
	}
	if len(z.AllowTransfer) > 0 {
		add("allow-transfer " + serializeMatchList(z.AllowTransfer))
	}
	if len(z.AlsoNotify) > 0 {
		add("also-notify " + serializeRemoteServerList(z.AlsoNotify))
	}
	if z.DNSSECPolicy != "" {
		add("dnssec-policy \"" + z.DNSSECPolicy + "\"")
	}
	return nc.NewBlockStmt(head, body)
}

func buildTrustAnchors(t TrustAnchors) *nc.Stmt {
	body := []nc.Node{}
	for _, it := range t.Items {
		if it.DS != "" {
			body = append(body, nc.NewSimpleStmt("\""+it.Name+"\" "+it.DS))
		} else if it.DNSKey != "" {
			body = append(body, nc.NewSimpleStmt("\""+it.Name+"\" "+it.DNSKey))
		}
	}
	return nc.NewBlockStmt("trust-anchors", body)
}
