package namedzone

import (
	"strings"

	nc "github.com/dlukt/namedconf"
)

// StringSeqToMatchGroup turns a list of strings (slice or *slice) into a nc.MatchGroup.
// Semantics:
//   - nil *[]string  => field absent => returns nil
//   - []string or non-nil *[]string with len==0 (or nil slice) => empty group {}
//   - otherwise => items parsed as ACL terms (CIDR/IP/ident), supporting "!" negation.
func StringSeqToMatchGroup[T ~[]string | *[]string](list T) *nc.MatchGroup {
	switch v := any(list).(type) {
	case *[]string:
		if v == nil {
			return nil // field absent
		}
		return sliceToMatchGroup(*v)
	case []string:
		return sliceToMatchGroup(v)
	default:
		return nil
	}
}

func sliceToMatchGroup(ss []string) *nc.MatchGroup {
	// Present but empty (or nil slice) -> {} (empty group)
	if len(ss) == 0 {
		return MG()
	}
	items := make([]nc.MatchItem, 0, len(ss))
	for _, s := range ss {
		neg := false
		if strings.HasPrefix(s, "!") {
			neg, s = true, strings.TrimPrefix(s, "!")
		}
		var part nc.Expr
		switch {
		case strings.Contains(s, "/"):
			part = CIDR(s)
		case strings.Contains(s, ":") || strings.Count(s, ".") >= 1:
			part = IP(s) // IPv6 or IPv4 literal
		default:
			part = Ident(s) // e.g. any, none, localhost, ACL names
		}
		items = append(items, Item(neg, part))
	}
	return MG(items...)
}

// MatchGroupToStringSeq is the reverse of StringSeqToMatchGroup.
// Semantics:
//   - nil *nc.MatchGroup => nil (field absent on the wire)
//   - empty group (no items) => []string{}
//   - otherwise: one string per item, "!" prefix preserved, using the first part of each item.
//     (This mirrors sliceToMatchGroup, which constructs items with a single Expr.)
func MatchGroupToStringSeq(mg *nc.MatchGroup) []string {
	if mg == nil {
		return nil
	}
	if len(mg.Items) == 0 {
		return []string{}
	}
	out := make([]string, 0, len(mg.Items))
	for _, it := range mg.Items {
		if it == nil || len(it.Parts) == 0 {
			continue
		}
		// Reuse local helper from namedzone.go to render the first part.
		parts := exprsToStrings(it.Parts)
		s := parts[0]
		if it.Negated {
			s = "!" + s
		}
		out = append(out, s)
	}
	return out
}
