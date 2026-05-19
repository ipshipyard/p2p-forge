package denylist

import (
	"sync"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
)

const pluginName = "denylist"

var (
	sharedManager   *Manager
	sharedManagerMu sync.RWMutex
)

func init() { plugin.Register(pluginName, setup) }

func setup(c *caddy.Controller) error {
	config := dnsserver.GetConfig(c)

	// Get zone name as forgeDomain for URL parsing optimization
	forgeDomain := ""
	if len(config.Zone) > 0 {
		forgeDomain = config.Zone
	}

	c.Next() // consume "denylist" token

	mgr, err := parseConfig(c, config.Root, forgeDomain)
	if err != nil {
		return plugin.Error(pluginName, err)
	}

	if mgr != nil {
		sharedManagerMu.Lock()
		sharedManager = mgr
		sharedManagerMu.Unlock()
		initMetrics()

		// Capture `mgr` in the closure: a graceful reload runs the successor's
		// setup before this instance's OnShutdown, so `sharedManager` may
		// already point at the new instance by the time cleanup runs.
		c.OnShutdown(func() error {
			err := mgr.close()
			sharedManagerMu.Lock()
			if sharedManager == mgr {
				sharedManager = nil
			}
			sharedManagerMu.Unlock()
			return err
		})
	}

	// denylist is a data provider, not a DNS handler
	// Other plugins call GetManager() to access it
	return nil
}

// GetManager returns the shared Manager instance for other plugins.
// Returns nil if denylist plugin is not configured.
func GetManager() *Manager {
	sharedManagerMu.RLock()
	defer sharedManagerMu.RUnlock()
	return sharedManager
}

// ResetManager clears the shared Manager instance.
// Used during shutdown and tests.
func ResetManager() {
	sharedManagerMu.Lock()
	defer sharedManagerMu.Unlock()
	sharedManager = nil
}
