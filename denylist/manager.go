package denylist

import (
	"errors"
	"io"
	"net/netip"
	"sync"
)

// Manager combines multiple checker implementations.
// Allowlists are checked first; if an IP matches any allowlist,
// it bypasses all denylist checks.
type Manager struct {
	allowlists []checker
	denylists  []checker
	mu         sync.RWMutex
	closeOnce  sync.Once
}

// NewManager creates an empty Manager.
func NewManager() *Manager {
	return &Manager{}
}

// add adds a checker to the manager.
// Checkers are sorted into allowlists or denylists based on Type().
// Within each category, checkers are evaluated in insertion order (first match wins).
func (m *Manager) add(c checker) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if c.Type() == listTypeAllow {
		m.allowlists = append(m.allowlists, c)
	} else {
		m.denylists = append(m.denylists, c)
	}
}

// Check checks if an IP should be denied.
// Returns (denied, result) where denied is true if the IP should be blocked.
// Allowlists are checked first - if the IP matches any allowlist, it's allowed.
func (m *Manager) Check(ip netip.Addr) (denied bool, result CheckResult) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// 1. Check allowlists first
	for _, checker := range m.allowlists {
		if r := checker.Check(ip); r.Matched {
			incIPAllowed(r.Name)
			return false, r // allowed - skip denylists
		}
	}

	// 2. Check denylists
	for _, checker := range m.denylists {
		if r := checker.Check(ip); r.Matched {
			incIPDenied(r.Name)
			return true, r // denied
		}
	}

	return false, CheckResult{} // not in any list
}

// close closes all checkers that implement io.Closer. Safe to call multiple times.
func (m *Manager) close() error {
	var errs []error
	m.closeOnce.Do(func() {
		m.mu.Lock()
		defer m.mu.Unlock()

		for _, c := range m.allowlists {
			if closer, ok := c.(io.Closer); ok {
				if err := closer.Close(); err != nil {
					errs = append(errs, err)
				}
			}
		}
		for _, c := range m.denylists {
			if closer, ok := c.(io.Closer); ok {
				if err := closer.Close(); err != nil {
					errs = append(errs, err)
				}
			}
		}
	})
	return errors.Join(errs...)
}
