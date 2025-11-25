package denylist

import (
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// fileList is a file-based IP list that auto-reloads on changes.
type fileList struct {
	path       string
	name       string
	listType   listType
	prefixes   *prefixSet
	watcher    *fsnotify.Watcher
	lastUpdate time.Time
	mu         sync.RWMutex
	done       chan struct{}
	closeOnce  sync.Once
}

// fileConfig holds configuration for a file-based list.
type fileConfig struct {
	Path    string   // absolute or relative path to file
	Name    string   // name for metrics (defaults to filename)
	Type    listType // allow or deny (default: deny)
	BaseDir string   // base directory for relative paths
}

// newFileList creates a new file-based list.
func newFileList(cfg fileConfig) (*fileList, error) {
	// Resolve relative paths
	path := cfg.Path
	if !filepath.IsAbs(path) && cfg.BaseDir != "" {
		path = filepath.Join(cfg.BaseDir, path)
	}

	name := cfg.Name
	if name == "" {
		name = filepath.Base(path)
	}

	lt := cfg.Type
	if lt == "" {
		lt = listTypeDeny
	}

	fl := &fileList{
		path:     path,
		name:     name,
		listType: lt,
		prefixes: newPrefixSet(),
		done:     make(chan struct{}),
	}

	// Initial load
	if err := fl.load(); err != nil {
		return nil, err
	}
	log.Infof("denylist file %s: loaded %d entries", fl.name, fl.Size())

	// Setup file watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	fl.watcher = watcher

	// Watch the directory (more reliable than watching the file directly)
	if err := watcher.Add(filepath.Dir(path)); err != nil {
		watcher.Close()
		return nil, err
	}

	go fl.watchLoop()

	return fl, nil
}

func (fl *fileList) load() error {
	f, err := os.Open(fl.path)
	if err != nil {
		return err
	}
	defer f.Close()

	return fl.loadFrom(f)
}

func (fl *fileList) loadFrom(r io.Reader) error {
	prefixes, err := parseIP(r)
	if err != nil {
		return err
	}

	fl.prefixes.replace(prefixes)

	now := time.Now()
	fl.mu.Lock()
	fl.lastUpdate = now
	fl.mu.Unlock()

	// Update metrics
	updateEntries(fl.name, fl.listType, len(prefixes))
	updateLastUpdate(fl.name, now.Unix())

	return nil
}

func (fl *fileList) watchLoop() {
	filename := filepath.Base(fl.path)

	for {
		select {
		case <-fl.done:
			return
		case event, ok := <-fl.watcher.Events:
			if !ok {
				return
			}
			// Only reload if our file was modified
			if filepath.Base(event.Name) == filename {
				if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
					// Small delay to let writes complete
					time.Sleep(100 * time.Millisecond)
					if err := fl.load(); err != nil {
						log.Warningf("denylist file %s: reload failed: %v", fl.name, err)
					} else {
						log.Infof("denylist file %s: reloaded, %d entries", fl.name, fl.Size())
					}
				}
			}
		case err, ok := <-fl.watcher.Errors:
			if ok && err != nil {
				log.Warningf("denylist file %s: watcher error: %v", fl.name, err)
			}
		}
	}
}

// Check implements checker.
func (fl *fileList) Check(ip netip.Addr) CheckResult {
	if fl.prefixes.contains(ip) {
		return CheckResult{
			Matched: true,
			Name:    fl.name,
		}
	}
	return CheckResult{}
}

// Name implements checker.
func (fl *fileList) Name() string {
	return fl.name
}

// Type implements checker.
func (fl *fileList) Type() listType {
	return fl.listType
}

// Size implements checker.
func (fl *fileList) Size() int {
	return fl.prefixes.size()
}

// LastUpdate returns when the file was last loaded.
func (fl *fileList) LastUpdate() time.Time {
	fl.mu.RLock()
	defer fl.mu.RUnlock()
	return fl.lastUpdate
}

// Close implements io.Closer. Safe to call multiple times.
func (fl *fileList) Close() error {
	var err error
	fl.closeOnce.Do(func() {
		close(fl.done)
		if fl.watcher != nil {
			err = fl.watcher.Close()
		}
	})
	return err
}
