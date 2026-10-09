// Package harden reduces the ways decrypted secrets can leak out of process memory.
package harden

// Apply disables core dumps and, where supported, blocks other same-user
// processes from attaching a debugger or reading /proc/<pid>/mem.
// It is best-effort: failures are returned but are not fatal.
func Apply() error { return apply() }
