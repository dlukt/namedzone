# namedzone

Typed, JSON-friendly Go API over BIND 9 `named.conf`, built on the lossless parser/writer in `github.com/dlukt/namedconf`.

- **Lossless**: Unmodeled/unknown statements remain byte-for-byte.
- **JSON-first**: All config types carry `json` tags for easy marshalling in GraphQL/REST/gRPC handlers.
- **Modern**: Focuses on non-deprecated statements from the BIND 9 stable reference.

## Install

```bash
go get github.com/dlukt/namedzone@latest
```

> Requires the base module `github.com/dlukt/namedconf`.

## Quickstart

```go
package main

import (
    "encoding/json"
    "fmt"
    nc "github.com/dlukt/namedconf"
    nz "github.com/dlukt/namedzone"
)

func main() {
    // Parse concrete syntax tree (lossless)
    f, err := nc.ParseFile("/etc/named.conf")
    if err != nil { panic(err) }

    // Build typed view
    cfg, err := nz.FromFile(f)
    if err != nil { panic(err) }

    // List zones
    for _, z := range cfg.Zones { fmt.Println(z.Name, z.Type) }

    // Toggle recursion
    cfg.SetRecursion(false)

    // Write changes back (unchanged parts preserved)
    if err := cfg.Save("/etc/named.conf"); err != nil { panic(err) }

    // JSON for web APIs
    b, _ := json.MarshalIndent(cfg, "", "  ")
    fmt.Println(string(b))
}
```

## Example transforms

### 1) Promote a zone to use a DNSSEC policy & inject trust anchors (top-level)

```go
// Assume cfg obtained via nz.FromFile(f)

// Set a DNSSEC policy for an existing zone (create or update)
z := cfg.GetZone("example.com")
if z == nil {
    nz := nz.Zone{Name: "example.com.", Type: nz.ZonePrimary, File: "/var/named/example.com.zone"}
    cfg.UpsertZone(nz)
    z = cfg.GetZone("example.com.")
}
z.DNSSECPolicy = "default"

// Add (or replace) global trust-anchors block
cfg.TrustAnchors = []nz.TrustAnchors{ {
    Items: []nz.TrustAnchorItem{
        {Name: ".", DS: "static-ds 20326 8 2 E06D...."},
    },
}} 

// Apply & save
_ = cfg.Apply(nil)
_ = cfg.Save("/etc/named.conf")
```

### 2) View-scoped edits (e.g., external view)

```go
// Insert/replace a zone inside a specific view
cfg.UpsertZoneInView("external", nz.Zone{
    Name: "example.net.", Type: nz.ZoneSecondary,
    PrimariesRef: "upstream-dns", // references a remote-servers block
})

// Replace trust-anchors in the view
cfg.SetTrustAnchorsInView("external", nz.TrustAnchors{Items: []nz.TrustAnchorItem{
    {Name: ".", DS: "static-ds 20326 8 2 E06D...."},
}})

_ = cfg.Save("/etc/named.conf")
```

### 3) Logging & rrset-order examples

```go
// Ensure a logging channel and category exist
if cfg.Logging == nil { cfg.Logging = &nz.Logging{} }

cfg.Logging.Channels = append(cfg.Logging.Channels, nz.LogChannel{
    Name: "mysyslog", Syslog: &nz.LogSyslogDest{Facility: "daemon"}, Severity: "info",
})

cfg.Logging.Categories = append(cfg.Logging.Categories, nz.LogCategory{
    Name: "queries", Channels: []string{"mysyslog"},
})

// RRset ordering rules under options
if cfg.Options == nil { cfg.Options = &nz.Options{} }
cfg.Options.RRsetOrder = []nz.RRsetOrder{
    {Name: "www.example.com.", Order: "fixed"},
    {Type: "A", Order: "random"},
}

_ = cfg.Save("/etc/named.conf")
```

## Notes

- Deprecated statements are intentionally not modeled; they stay intact in the underlying AST.
- Unknown statements inside known blocks are preserved in `Options.Other`.
- Typed → AST sync replaces only the blocks we model, leaving all other trivia/comments whitespace intact.
