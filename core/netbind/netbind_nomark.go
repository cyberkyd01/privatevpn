//go:build !(linux && !android)

package netbind

// canMark: no socket mark is needed outside Linux (§7.4).
func canMark() bool { return true }
