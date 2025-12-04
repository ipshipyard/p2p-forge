package denylist

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"runtime/debug"
	"strings"
	"sync"
	"time"
)

// userAgent returns an identifier for HTTP requests to feed operators.
// This helps feed maintainers identify p2p-forge as a consumer of their data.
func userAgent() string {
	const (
		name       = "p2p-forge"
		importPath = "github.com/ipshipyard/p2p-forge"
	)
	version := "unknown"
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range bi.Deps {
			if dep.Path == importPath {
				version = dep.Version
				break
			}
		}
		// Main module
		if version == "unknown" && bi.Main.Path == importPath && bi.Main.Version != "" {
			version = bi.Main.Version
		}
	}
	return name + "/" + version
}

// feedList is an HTTP feed-based IP list that auto-refreshes.
type feedList struct {
	url         string
	name        string
	listType    listType
	format      feedFormat
	refresh     time.Duration
	forgeSuffix string
	prefixes    *prefixSet

	client       *http.Client
	lastModified string // Last-Modified header value
	lastUpdate   time.Time
	mu           sync.RWMutex

	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
}

// feedConfig holds configuration for an HTTP feed-based list.
type feedConfig struct {
	URL         string        // feed URL
	Name        string        // name for metrics (defaults to URL hostname)
	Type        listType      // allow or deny (default: deny)
	Format      feedFormat    // ip or url
	Refresh     time.Duration // refresh interval
	ForgeSuffix string        // forge domain suffix for URL format (e.g., "libp2p.direct")
}

// newFeedList creates a new HTTP feed-based list.
func newFeedList(cfg feedConfig) (*feedList, error) {
	// Validate URL
	u, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid feed URL: %w", err)
	}

	name := cfg.Name
	if name == "" {
		// Derive name from URL
		name = strings.TrimPrefix(u.Host, "www.")
		if u.Path != "" && u.Path != "/" {
			// Include last path segment for uniqueness
			parts := strings.Split(strings.Trim(u.Path, "/"), "/")
			if len(parts) > 0 {
				name = name + "-" + parts[len(parts)-1]
			}
		}
	}

	lt := cfg.Type
	if lt == "" {
		lt = listTypeDeny
	}

	format := cfg.Format
	if format == "" {
		format = formatIP
	}

	refresh := cfg.Refresh
	if refresh == 0 {
		refresh = defaultFeedRefresh
	}

	ctx, cancel := context.WithCancel(context.Background())

	fl := &feedList{
		url:         cfg.URL,
		name:        name,
		listType:    lt,
		format:      format,
		refresh:     refresh,
		forgeSuffix: cfg.ForgeSuffix,
		prefixes:    newPrefixSet(),
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		ctx:    ctx,
		cancel: cancel,
		done:   make(chan struct{}),
	}

	// Start background refresh (includes initial fetch)
	go fl.refreshLoop()

	return fl, nil
}

// Update fetches the feed and updates the prefix set.
// Returns the number of entries loaded.
func (fl *feedList) Update(ctx context.Context) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fl.url, nil)
	if err != nil {
		return 0, err
	}

	// Use If-Modified-Since for conditional request
	fl.mu.RLock()
	lastMod := fl.lastModified
	fl.mu.RUnlock()

	if lastMod != "" {
		req.Header.Set("If-Modified-Since", lastMod)
	}

	req.Header.Set("User-Agent", userAgent())

	resp, err := fl.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	// Handle 304 Not Modified
	if resp.StatusCode == http.StatusNotModified {
		return fl.prefixes.size(), nil
	}

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Parse content
	prefixes, err := fl.parseBody(resp.Body)
	if err != nil {
		return 0, err
	}

	fl.prefixes.replace(prefixes)

	now := time.Now()
	fl.mu.Lock()
	fl.lastUpdate = now
	if lm := resp.Header.Get("Last-Modified"); lm != "" {
		fl.lastModified = lm
	}
	fl.mu.Unlock()

	// Update metrics
	updateEntries(fl.name, fl.listType, len(prefixes))
	updateLastUpdate(fl.name, now.Unix())

	return len(prefixes), nil
}

func (fl *feedList) parseBody(r io.Reader) ([]netip.Prefix, error) {
	return parse(fl.format, r, fl.forgeSuffix)
}

func (fl *feedList) refreshLoop() {
	defer close(fl.done)

	// Initial fetch (non-blocking startup)
	if n, err := fl.Update(fl.ctx); err != nil {
		log.Warningf("denylist feed %s: initial fetch failed: %v (will retry in %v)", fl.name, err, fl.refresh)
	} else {
		log.Infof("denylist feed %s: loaded %d entries", fl.name, n)
	}

	ticker := time.NewTicker(fl.refresh)
	defer ticker.Stop()

	for {
		select {
		case <-fl.ctx.Done():
			return
		case <-ticker.C:
			if n, err := fl.Update(fl.ctx); err != nil {
				log.Warningf("denylist feed %s: refresh failed: %v", fl.name, err)
			} else {
				log.Infof("denylist feed %s: refreshed, %d entries", fl.name, n)
			}
		}
	}
}

// Check implements checker.
func (fl *feedList) Check(ip netip.Addr) CheckResult {
	if fl.prefixes.contains(ip) {
		return CheckResult{
			Matched: true,
			Name:    fl.name,
		}
	}
	return CheckResult{}
}

// Name implements checker.
func (fl *feedList) Name() string {
	return fl.name
}

// Type implements checker.
func (fl *feedList) Type() listType {
	return fl.listType
}

// Size implements checker.
func (fl *feedList) Size() int {
	return fl.prefixes.size()
}

// LastUpdate implements updatable.
func (fl *feedList) LastUpdate() time.Time {
	fl.mu.RLock()
	defer fl.mu.RUnlock()
	return fl.lastUpdate
}

// Close implements io.Closer.
func (fl *feedList) Close() error {
	fl.cancel()
	<-fl.done
	return nil
}
