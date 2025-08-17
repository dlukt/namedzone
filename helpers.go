// File: pkg/namedzone/helpers.go
package namedzone

// BoolPtr returns a pointer to the provided bool.
// Useful for succinctly setting optional fields in the typed API.
func BoolPtr(b bool) *bool { return &b }
