# github.com/dlukt/namedzone

A tiny Go library that adds **view-aware CRUD for `zone` blocks** in `named.conf`, built on top of the [`github.com/dlukt/namedconf`](https://github.com/dlukt/namedconf) parser/AST you provided.

- Library only (no CLI)
- Simple API
- All edits happen through the `namedconf` AST — no regexes
- Zero external deps beyond `namedconf`
- **View-aware**: operate at the top-level *or* inside a specific `view "name" { ... }`

## Install

```bash
go get github.com/dlukt/namedzone
```

## Usage

```go
package main

import (
    "fmt"
    nz "github.com/dlukt/namedzone"
)

func main() {
    cfg, err := nz.Load("/etc/bind/named.conf")
    if err != nil { panic(err) }

    // --- List top-level zones
    for _, z := range cfg.List() {
        fmt.Printf("zone %q type=%q file=%q\n", z.Name, z.Type, z.File)
    }

    // --- View-aware get
    if z := cfg.GetInView("example.com", "internal"); z != nil {
        fmt.Println("internal view file:", z.File)
    }

    // --- Create in a view
    allow := nz.MG(
        nz.Item(false, nz.Ident("localnets")),
        nz.Item(false, nz.CIDR("10.0.0.0/8")),
        nz.Item(true,  nz.IP("192.0.2.66")),
    )
    err = cfg.CreateInView(nz.Zone{
        Name:  "example.org",
        Class: "IN",
        Type:  "master",
        File:  "/var/lib/bind/example.org.zone",
        AllowQuery: &allow,
        Notify: "yes", // yes|no|explicit
    }, "internal")
    if err != nil { panic(err) }

    // --- Update with a function
    _ = cfg.UpdateInView("example.org", "internal", func(z *nz.Zone) error {
        z.AlsoNotify = &nz.MG(
            nz.Item(false, nz.IP("192.0.2.53")),
        )
        z.AllowTransfer = &nz.MG(
            nz.Item(false, nz.Ident("any")),
        )
        b := true
        z.InlineSigning = &b
        z.AutoDNSSEC = "maintain"
        return nil
    })

    // --- Delete a zone
    _ = cfg.DeleteInView("old.example", "external")

    // Persist changes
    if err := cfg.Save(); err != nil { panic(err) }
}
```

### Typed fields on `Zone`

- Address-match lists (`*namedconf.MatchGroup`): `AllowQuery`, `AllowUpdate`, `AllowTransfer`, `AllowNotify`, `AlsoNotify`, `Masters`, `Forwarders`
- Simple tokens: `Forward` (`"only"`/`"first"`), `Notify` (`"yes"`/`"no"`/`"explicit"`)
- Booleans: `InlineSigning`, `IXFRFromDifferences`, `NotifyToSoa`
- Strings: `AutoDNSSEC`, `DNSSECPolicy`, `Journal`, `MaxJournalSize`
- Block preserved as-is: `UpdatePolicy`
- Everything else round-trips via `Extras map[string][][]string`

### Helpers for match-groups

```go
// Build { localnets; 10.0.0.0/8; !192.0.2.66; }
g := nz.MG(
    nz.Item(false, nz.Ident("localnets")),
    nz.Item(false, nz.CIDR("10.0.0.0/8")),
    nz.Item(true,  nz.IP("192.0.2.66")),
)
```

### Notes

- Paths (e.g., `file`, `journal`) are rendered as quoted strings to preserve backslashes and avoid accidental escapes.
- Unknown zone directives are preserved in `Extras` and round-trip back in a stable order.
- All manipulations are done strictly via the provided `namedconf` AST types.
