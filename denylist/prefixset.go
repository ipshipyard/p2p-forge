package denylist

import (
	"net/netip"
	"sync/atomic"

	"github.com/gaissmai/bart"
)

// prefixSet is a thread-safe set of IP prefixes optimized for lookup.
// Uses a BART (Balanced Routing Table) for O(log n) lookups and
// copy-on-write semantics for lock-free reads.
type prefixSet struct {
	trie atomic.Pointer[bart.Lite]
}

// newPrefixSet creates an empty prefixSet.
func newPrefixSet() *prefixSet {
	ps := &prefixSet{}
	ps.trie.Store(new(bart.Lite))
	return ps
}

// contains returns true if ip is within any prefix in the set.
// IPv4-mapped IPv6 addresses (::ffff:x.x.x.x) are unmapped before lookup,
// so they match IPv4 prefixes.
func (ps *prefixSet) contains(ip netip.Addr) bool {
	t := ps.trie.Load()
	if t == nil {
		return false
	}
	// Normalize IPv4-mapped IPv6 to IPv4 (bart requires native addresses)
	if ip.Is4In6() {
		ip = netip.AddrFrom4(ip.As4())
	}
	return t.Lookup(ip)
}

// replace atomically replaces all prefixes in the set.
func (ps *prefixSet) replace(prefixes []netip.Prefix) {
	t := new(bart.Lite)
	for _, p := range prefixes {
		if p.IsValid() {
			t.Insert(p)
		}
	}
	ps.trie.Store(t)
}

// size returns the total number of prefixes in the set.
func (ps *prefixSet) size() int {
	t := ps.trie.Load()
	if t == nil {
		return 0
	}
	return t.Size()
}
