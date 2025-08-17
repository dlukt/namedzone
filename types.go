// File: pkg/namedzone/types.go
package namedzone

import "github.com/dlukt/namedconf"

// Config is a JSON-friendly projection of named.conf.
// Unknown statements are preserved via underlying AST references.
type Config struct {
	Includes      []Include       `json:"includes,omitempty"`
	ACLs          []ACL           `json:"acls,omitempty"`
	Keys          []Key           `json:"keys,omitempty"`
	KeyStores     []KeyStore      `json:"keyStores,omitempty"`
	RemoteServers []RemoteServers `json:"remoteServers,omitempty"`
	TLS           []TLS           `json:"tls,omitempty"`
	HTTP          []HTTP          `json:"http,omitempty"`
	Controls      *Controls       `json:"controls,omitempty"`
	Logging       *Logging        `json:"logging,omitempty"`
	Options       *Options        `json:"options,omitempty"`
	TrustAnchors  []TrustAnchors  `json:"trustAnchors,omitempty"`
	Views         []View          `json:"views,omitempty"`
	Zones         []Zone          `json:"zones,omitempty"`

	ast *namedconf.File `json:"-"`
}

// Include directive.
type Include struct {
	Path string          `json:"path"`
	stmt *namedconf.Stmt `json:"-"`
}

// ACL block.
type ACL struct {
	Name     string          `json:"name"`
	Elements []MatchTerm     `json:"elements"`
	stmt     *namedconf.Stmt `json:"-"`
}

// MatchTerm is a simplified address_match_element for JSON.
type MatchTerm struct {
	Not     bool        `json:"not,omitempty"`
	Address string      `json:"address,omitempty"`
	Key     string      `json:"key,omitempty"`
	ACLRef  string      `json:"aclRef,omitempty"`
	Nested  []MatchTerm `json:"nested,omitempty"`
}

// Key block for TSIG/rndc.
type Key struct {
	Name      string          `json:"name"`
	Algorithm string          `json:"algorithm"`
	Secret    string          `json:"secret"`
	stmt      *namedconf.Stmt `json:"-"`
}

// KeyStore block (PKCS#11 etc.).
type KeyStore struct {
	Name      string          `json:"name"`
	PKCS11URI string          `json:"pkcs11Uri,omitempty"`
	stmt      *namedconf.Stmt `json:"-"`
}

// RemoteServers block: reusable named server lists.
type RemoteServers struct {
	Name    string             `json:"name"`
	Servers []RemoteServerItem `json:"servers"`
	stmt    *namedconf.Stmt    `json:"-"`
}

type RemoteServerItem struct {
	Address string `json:"address"`
	Port    *int   `json:"port,omitempty"`
	Key     string `json:"key,omitempty"`
	TLS     string `json:"tls,omitempty"`
}

// TLS block (for DoT/DoH).
type TLS struct {
	Name           string          `json:"name"`
	CAFile         string          `json:"caFile,omitempty"`
	CertFile       string          `json:"certFile,omitempty"`
	KeyFile        string          `json:"keyFile,omitempty"`
	CipherSuites   string          `json:"cipherSuites,omitempty"`
	Ciphers        string          `json:"ciphers,omitempty"`
	DHParamFile    string          `json:"dhparamFile,omitempty"`
	PreferServer   *bool           `json:"preferServerCiphers,omitempty"`
	Protocols      []string        `json:"protocols,omitempty"`
	RemoteHost     string          `json:"remoteHostname,omitempty"`
	SessionTickets *bool           `json:"sessionTickets,omitempty"`
	stmt           *namedconf.Stmt `json:"-"`
}

// HTTP block (DoH endpoints).
type HTTP struct {
	Name                 string          `json:"name"`
	Endpoints            []string        `json:"endpoints,omitempty"`
	ListenerClients      *int            `json:"listenerClients,omitempty"`
	StreamsPerConnection *int            `json:"streamsPerConnection,omitempty"`
	stmt                 *namedconf.Stmt `json:"-"`
}

// Controls channels.
type Controls struct {
	Inet []ControlInet   `json:"inet,omitempty"`
	Unix []ControlUnix   `json:"unix,omitempty"`
	stmt *namedconf.Stmt `json:"-"`
}

type ControlInet struct {
	Address  string      `json:"address"`
	Port     *int        `json:"port,omitempty"`
	Allow    []MatchTerm `json:"allow"`
	Keys     []string    `json:"keys,omitempty"`
	ReadOnly *bool       `json:"readOnly,omitempty"`
}

type ControlUnix struct {
	Path     string   `json:"path"`
	Perm     int      `json:"perm"`
	Owner    int      `json:"owner"`
	Group    int      `json:"group"`
	Keys     []string `json:"keys,omitempty"`
	ReadOnly *bool    `json:"readOnly,omitempty"`
}

// Logging config.
type Logging struct {
	Channels   []LogChannel    `json:"channels,omitempty"`
	Categories []LogCategory   `json:"categories,omitempty"`
	stmt       *namedconf.Stmt `json:"-"`
}

type LogChannel struct {
	Name          string         `json:"name"`
	File          *LogFileDest   `json:"file,omitempty"`
	Syslog        *LogSyslogDest `json:"syslog,omitempty"`
	Stderr        bool           `json:"stderr,omitempty"`
	Null          bool           `json:"null,omitempty"`
	Severity      string         `json:"severity,omitempty"`
	PrintTime     *bool          `json:"printTime,omitempty"`
	PrintCategory *bool          `json:"printCategory,omitempty"`
	PrintSeverity *bool          `json:"printSeverity,omitempty"`
	Buffered      *bool          `json:"buffered,omitempty"`
}

type LogFileDest struct {
	Path     string `json:"path"`
	Versions *int   `json:"versions,omitempty"`
	Size     string `json:"size,omitempty"`
	Suffix   string `json:"suffix,omitempty"`
	Severity string `json:"severity,omitempty"`
}

type LogSyslogDest struct {
	Facility string `json:"facility,omitempty"`
}

// LogCategory lists channels bound to a named category.
type LogCategory struct {
	Name     string   `json:"name"`
	Channels []string `json:"channels"`
}

// Options (subset of widely used, non-deprecated settings).
type Options struct {
	Directory        string          `json:"directory,omitempty"`
	Recursion        *bool           `json:"recursion,omitempty"`
	AllowQuery       []MatchTerm     `json:"allowQuery,omitempty"`
	AllowTransfer    []MatchTerm     `json:"allowTransfer,omitempty"`
	AllowUpdate      []MatchTerm     `json:"allowUpdate,omitempty"`
	ListenOn         *Listen         `json:"listenOn,omitempty"`
	ListenOnV6       *Listen         `json:"listenOnV6,omitempty"`
	Forwarders       []Forwarder     `json:"forwarders,omitempty"`
	Forward          string          `json:"forward,omitempty"`
	DNSSECValidation string          `json:"dnssecValidation,omitempty"`
	RRsetOrder       []RRsetOrder    `json:"rrsetOrder,omitempty"`
	Other            []RawKV         `json:"other,omitempty"`
	stmt             *namedconf.Stmt `json:"-"`
}

type Listen struct {
	Port  *int        `json:"port,omitempty"`
	TLS   string      `json:"tls,omitempty"`
	HTTP  string      `json:"http,omitempty"`
	Addrs []MatchTerm `json:"addrs"`
}

type Forwarder struct {
	Address string `json:"address"`
	Port    *int   `json:"port,omitempty"`
	TLS     string `json:"tls,omitempty"`
}

type TrustAnchors struct {
	Items []TrustAnchorItem `json:"items"`
	stmt  *namedconf.Stmt   `json:"-"`
}

type TrustAnchorItem struct {
	Name   string `json:"name"`
	DS     string `json:"ds,omitempty"`
	DNSKey string `json:"dnskey,omitempty"`
}

type RRsetOrder struct {
	Name  string `json:"name,omitempty"`
	Type  string `json:"type,omitempty"`
	Order string `json:"order"`
}

type RawKV struct {
	Name string `json:"name"`
	Raw  string `json:"raw"`
}

// View block.
type View struct {
	Name              string          `json:"name"`
	Class             string          `json:"class,omitempty"`
	MatchClients      []MatchTerm     `json:"matchClients,omitempty"`
	MatchDestinations []MatchTerm     `json:"matchDestinations,omitempty"`
	Recursion         *bool           `json:"recursion,omitempty"`
	TrustAnchors      *TrustAnchors   `json:"trustAnchors,omitempty"`
	Zones             []Zone          `json:"zones,omitempty"`
	Includes          []Include       `json:"includes,omitempty"`
	stmt              *namedconf.Stmt `json:"-"`
}

// Zones.
type ZoneType string

const (
	ZonePrimary    ZoneType = "primary"
	ZoneSecondary  ZoneType = "secondary"
	ZoneStub       ZoneType = "stub"
	ZoneMirror     ZoneType = "mirror"
	ZoneRedirect   ZoneType = "redirect"
	ZoneForward    ZoneType = "forward"
	ZoneStaticStub ZoneType = "static-stub"
	ZoneHint       ZoneType = "hint"
)

type Zone struct {
	Name  string   `json:"name"`
	Class string   `json:"class,omitempty"`
	Type  ZoneType `json:"type"`
	File  string   `json:"file,omitempty"`

	PrimariesRef string             `json:"primariesRef,omitempty"`
	Primaries    []RemoteServerItem `json:"primaries,omitempty"`

	Forwarders []Forwarder `json:"forwarders,omitempty"`
	Forward    string      `json:"forward,omitempty"`

	AllowUpdate   []MatchTerm        `json:"allowUpdate,omitempty"`
	AllowTransfer []MatchTerm        `json:"allowTransfer,omitempty"`
	AlsoNotify    []RemoteServerItem `json:"alsoNotify,omitempty"`

	DNSSECPolicy string `json:"dnssecPolicy,omitempty"`

	stmt *namedconf.Stmt `json:"-"`
}
