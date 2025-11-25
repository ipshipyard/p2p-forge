package denylist

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrefixSet(t *testing.T) {
	ps := newPrefixSet()

	// Initially empty
	assert.Equal(t, 0, ps.size())

	// Add some prefixes
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("192.168.1.0/24"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("2001:db8::/32"),
	}
	ps.replace(prefixes)
	assert.Equal(t, 3, ps.size())

	// Test contains - IPv4 in range
	assert.True(t, ps.contains(netip.MustParseAddr("192.168.1.100")))

	// Test contains - IPv4 not in range
	assert.False(t, ps.contains(netip.MustParseAddr("172.16.0.1")))

	// Test contains - IPv6 in range
	assert.True(t, ps.contains(netip.MustParseAddr("2001:db8::1")))

	// Test contains - IPv6 not in range
	assert.False(t, ps.contains(netip.MustParseAddr("2001:db9::1")))

	// Test replace clears old data
	ps.replace([]netip.Prefix{netip.MustParsePrefix("1.2.3.4/32")})
	assert.Equal(t, 1, ps.size())
	assert.False(t, ps.contains(netip.MustParseAddr("192.168.1.100")))
}

func TestParseIP(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name: "single IPs",
			input: `192.168.1.1
10.0.0.1
2001:db8::1`,
			expected: []string{"192.168.1.1/32", "10.0.0.1/32", "2001:db8::1/128"},
		},
		{
			name:     "windows line endings CRLF",
			input:    "192.168.1.1\r\n10.0.0.1\r\n2001:db8::1\r\n",
			expected: []string{"192.168.1.1/32", "10.0.0.1/32", "2001:db8::1/128"},
		},
		{
			name:     "mixed line endings",
			input:    "192.168.1.1\n10.0.0.1\r\n172.16.0.1\n",
			expected: []string{"192.168.1.1/32", "10.0.0.1/32", "172.16.0.1/32"},
		},
		{
			name: "CIDR ranges",
			input: `192.168.0.0/16
10.0.0.0/8`,
			expected: []string{"192.168.0.0/16", "10.0.0.0/8"},
		},
		{
			name: "with comments",
			input: `# This is a comment
192.168.1.1
; Another comment style
10.0.0.1 ; inline comment
172.16.0.0/12 # inline comment`,
			expected: []string{"192.168.1.1/32", "10.0.0.1/32", "172.16.0.0/12"},
		},
		{
			name: "empty lines",
			input: `192.168.1.1

10.0.0.1

`,
			expected: []string{"192.168.1.1/32", "10.0.0.1/32"},
		},
		{
			name:     "empty input",
			input:    "",
			expected: []string{},
		},
		{
			name: "invalid lines skipped",
			input: `192.168.1.1
not-an-ip
10.0.0.1`,
			expected: []string{"192.168.1.1/32", "10.0.0.1/32"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefixes, err := parseIP(strings.NewReader(tt.input))
			require.NoError(t, err)

			got := make([]string, 0, len(prefixes))
			for _, p := range prefixes {
				got = append(got, p.String())
			}
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestParseForgeIP(t *testing.T) {
	tests := []struct {
		name        string
		host        string
		forgeSuffix string
		wantIP      string
		wantOK      bool
	}{
		{
			name:        "IPv4 forge domain",
			host:        "192-168-1-1.k51qzi5uqu5dj094.libp2p.direct",
			forgeSuffix: ".libp2p.direct",
			wantIP:      "192.168.1.1",
			wantOK:      true,
		},
		{
			name:        "IPv6 forge domain",
			host:        "2001-db8-0-0-0-0-0-1.k51qzi5uqu5dj094.libp2p.direct",
			forgeSuffix: ".libp2p.direct",
			wantIP:      "2001:db8::1",
			wantOK:      true,
		},
		{
			name:        "IPv6 with leading zero for RFC 1035",
			host:        "0--1.k51qzi5uqu5dj094.libp2p.direct",
			forgeSuffix: ".libp2p.direct",
			wantIP:      "::1",
			wantOK:      true,
		},
		{
			name:        "invalid IP in forge domain",
			host:        "not-an-ip.k51qzi5uqu5dj094.libp2p.direct",
			forgeSuffix: ".libp2p.direct",
			wantOK:      false,
		},
		{
			name:        "non-matching suffix",
			host:        "192-168-1-1.example.com",
			forgeSuffix: ".libp2p.direct",
			wantOK:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, ok := parseForgeIP(tt.host, tt.forgeSuffix)
			assert.Equal(t, tt.wantOK, ok)
			if tt.wantOK {
				assert.Equal(t, tt.wantIP, ip.String())
			}
		})
	}
}

func TestParseURL(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		forgeSuffix string
		wantCount   int
		wantIPs     []string // subset to check
	}{
		{
			name: "URLs with IP hosts",
			input: `http://192.168.1.1/malware.exe
https://10.0.0.1:8080/bad.js`,
			wantCount: 2,
			wantIPs:   []string{"192.168.1.1", "10.0.0.1"},
		},
		{
			name:      "URLs with CRLF line endings",
			input:     "http://192.168.1.1/file\r\nhttp://10.0.0.1/file\r\n",
			wantCount: 2,
			wantIPs:   []string{"192.168.1.1", "10.0.0.1"},
		},
		{
			name: "forge domain extraction",
			input: `http://192-168-1-1.k51qzi5uqu5dj094.libp2p.direct/file
http://10-0-0-1.k51qzi5uqu5dj094.libp2p.direct/file`,
			forgeSuffix: "libp2p.direct",
			wantCount:   2,
			wantIPs:     []string{"192.168.1.1", "10.0.0.1"},
		},
		{
			name: "with comments",
			input: `# comment
http://192.168.1.1/file`,
			wantCount: 1,
		},
		{
			name:      "empty input",
			input:     "",
			wantCount: 0,
		},
		{
			name: "deduplicate IPs",
			input: `http://192.168.1.1/file1
http://192.168.1.1/file2`,
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefixes, err := parseURL(strings.NewReader(tt.input), parseURLOptions{
				ForgeSuffix: tt.forgeSuffix,
			})
			require.NoError(t, err)
			assert.Equal(t, tt.wantCount, len(prefixes))

			if len(tt.wantIPs) > 0 {
				gotIPs := make([]string, 0, len(prefixes))
				for _, p := range prefixes {
					gotIPs = append(gotIPs, p.Addr().String())
				}
				for _, wantIP := range tt.wantIPs {
					assert.Contains(t, gotIPs, wantIP)
				}
			}
		})
	}
}

func TestFileList(t *testing.T) {
	// Create temp file
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")

	content := `192.168.1.0/24
10.0.0.0/8`
	err := os.WriteFile(path, []byte(content), 0644)
	require.NoError(t, err)

	fl, err := newFileList(fileConfig{
		Path: path,
		Name: "test-list",
		Type: listTypeDeny,
	})
	require.NoError(t, err)
	defer fl.Close()

	assert.Equal(t, "test-list", fl.Name())
	assert.Equal(t, listTypeDeny, fl.Type())
	assert.Equal(t, 2, fl.Size())

	// Test Check
	result := fl.Check(netip.MustParseAddr("192.168.1.100"))
	assert.True(t, result.Matched)
	assert.Equal(t, "test-list", result.Name)

	result = fl.Check(netip.MustParseAddr("172.16.0.1"))
	assert.False(t, result.Matched)
}

func TestFileListReload(t *testing.T) {
	// Create temp file
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")

	err := os.WriteFile(path, []byte("192.168.1.0/24\n"), 0644)
	require.NoError(t, err)

	fl, err := newFileList(fileConfig{Path: path})
	require.NoError(t, err)
	defer fl.Close()

	assert.Equal(t, 1, fl.Size())

	// Modify file
	err = os.WriteFile(path, []byte("192.168.1.0/24\n10.0.0.0/8\n"), 0644)
	require.NoError(t, err)

	// Wait for reload (fsnotify + 100ms delay)
	assert.Eventually(t, func() bool {
		return fl.Size() == 2
	}, time.Second, 50*time.Millisecond, "file should reload with 2 entries")
}

func TestFeedList(t *testing.T) {
	// Create test server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Last-Modified", "Mon, 02 Jan 2006 15:04:05 GMT")
		io.WriteString(w, "192.168.1.0/24\n10.0.0.0/8\n")
	}))
	defer srv.Close()

	fl, err := newFeedList(feedConfig{
		URL:     srv.URL,
		Name:    "test-feed",
		Type:    listTypeDeny,
		Format:  formatIP,
		Refresh: time.Hour,
	})
	require.NoError(t, err)
	defer fl.Close()

	// Wait for async initial fetch
	assert.Eventually(t, func() bool { return fl.Size() == 2 }, time.Second, 10*time.Millisecond)

	assert.Equal(t, "test-feed", fl.Name())
	assert.Equal(t, listTypeDeny, fl.Type())

	// Test Check
	result := fl.Check(netip.MustParseAddr("192.168.1.100"))
	assert.True(t, result.Matched)
}

func TestFeedListNotModified(t *testing.T) {
	var requestCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		if r.Header.Get("If-Modified-Since") != "" {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Last-Modified", "Mon, 02 Jan 2006 15:04:05 GMT")
		io.WriteString(w, "192.168.1.0/24\n")
	}))
	defer srv.Close()

	fl, err := newFeedList(feedConfig{
		URL:     srv.URL,
		Format:  formatIP,
		Refresh: time.Hour,
	})
	require.NoError(t, err)
	defer fl.Close()

	// Wait for async initial fetch
	assert.Eventually(t, func() bool { return requestCount.Load() == 1 }, time.Second, 10*time.Millisecond)

	// Manual update should get 304
	ctx := context.Background()
	count, err := fl.Update(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, count) // Same count, no parse
	assert.Equal(t, int32(2), requestCount.Load())
}

func TestManager(t *testing.T) {
	// Create allowlist
	allowPS := newPrefixSet()
	allowPS.replace([]netip.Prefix{netip.MustParsePrefix("10.0.0.1/32")})

	// Create denylist
	denyPS := newPrefixSet()
	denyPS.replace([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})

	mgr := NewManager()

	// Add mock checkers (using simple struct that implements Checker)
	mgr.add(&mockChecker{
		name:     "allowlist",
		listType: listTypeAllow,
		prefixes: allowPS,
	})
	mgr.add(&mockChecker{
		name:     "denylist",
		listType: listTypeDeny,
		prefixes: denyPS,
	})

	// 10.0.0.1 should be allowed (allowlist takes priority)
	denied, result := mgr.Check(netip.MustParseAddr("10.0.0.1"))
	assert.False(t, denied)
	assert.True(t, result.Matched)

	// 10.0.0.2 should be denied (only on denylist)
	denied, result = mgr.Check(netip.MustParseAddr("10.0.0.2"))
	assert.True(t, denied)
	assert.True(t, result.Matched)

	// 192.168.1.1 should not match anything
	denied, result = mgr.Check(netip.MustParseAddr("192.168.1.1"))
	assert.False(t, denied)
	assert.False(t, result.Matched)
}

type mockChecker struct {
	name     string
	listType listType
	prefixes *prefixSet
}

func (m *mockChecker) Check(ip netip.Addr) CheckResult {
	if m.prefixes.contains(ip) {
		return CheckResult{
			Matched: true,
			Name:    m.name,
		}
	}
	return CheckResult{}
}

func (m *mockChecker) Name() string          { return m.name }
func (m *mockChecker) Type() listType        { return m.listType }
func (m *mockChecker) Size() int             { return m.prefixes.size() }
func (m *mockChecker) Close() error          { return nil }
func (m *mockChecker) LastUpdate() time.Time { return time.Now() }

// TestDenylistIntegration tests the full integration of Manager with real FileList and FeedList.
func TestDenylistIntegration(t *testing.T) {
	testIP := netip.MustParseAddr("192.168.1.100")

	t.Run("IP_blocked_by_file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "denylist.txt")
		err := os.WriteFile(path, []byte("192.168.1.0/24\n"), 0644)
		require.NoError(t, err)

		fl, err := newFileList(fileConfig{Path: path, Type: listTypeDeny})
		require.NoError(t, err)
		defer fl.Close()

		mgr := NewManager()
		mgr.add(fl)

		denied, result := mgr.Check(testIP)
		assert.True(t, denied, "IP should be blocked by file denylist")
		assert.True(t, result.Matched)
	})

	t.Run("IP_blocked_by_feed", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "192.168.1.0/24\n")
		}))
		defer srv.Close()

		fl, err := newFeedList(feedConfig{
			URL:     srv.URL,
			Format:  formatIP,
			Type:    listTypeDeny,
			Refresh: time.Hour,
		})
		require.NoError(t, err)
		defer fl.Close()

		// Wait for async load
		assert.Eventually(t, func() bool { return fl.Size() > 0 }, time.Second, 10*time.Millisecond)

		mgr := NewManager()
		mgr.add(fl)

		denied, result := mgr.Check(testIP)
		assert.True(t, denied, "IP should be blocked by feed denylist")
		assert.True(t, result.Matched)
	})

	t.Run("allowlist_overrides_denylist", func(t *testing.T) {
		dir := t.TempDir()

		// Allowlist file with specific IP
		allowPath := filepath.Join(dir, "allowlist.txt")
		err := os.WriteFile(allowPath, []byte("192.168.1.100/32\n"), 0644)
		require.NoError(t, err)

		allowFL, err := newFileList(fileConfig{Path: allowPath, Type: listTypeAllow, Name: "allowlist"})
		require.NoError(t, err)
		defer allowFL.Close()

		// Feed denylist with broader range
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "192.168.0.0/16\n")
		}))
		defer srv.Close()

		denyFL, err := newFeedList(feedConfig{
			URL:     srv.URL,
			Format:  formatIP,
			Type:    listTypeDeny,
			Name:    "denylist",
			Refresh: time.Hour,
		})
		require.NoError(t, err)
		defer denyFL.Close()

		assert.Eventually(t, func() bool { return denyFL.Size() > 0 }, time.Second, 10*time.Millisecond)

		mgr := NewManager()
		mgr.add(allowFL)
		mgr.add(denyFL)

		// IP is on both lists - allowlist should win
		denied, result := mgr.Check(testIP)
		assert.False(t, denied, "IP should NOT be blocked (allowlist overrides)")
		assert.True(t, result.Matched, "IP should match allowlist")
		assert.Equal(t, "allowlist", result.Name)

		// Different IP in same range should be blocked
		otherIP := netip.MustParseAddr("192.168.1.200")
		denied, result = mgr.Check(otherIP)
		assert.True(t, denied, "Other IP should be blocked by denylist")
	})

	t.Run("feed_update_causes_blocking", func(t *testing.T) {
		// Mutable feed content
		var content atomic.Value
		content.Store("")

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, content.Load().(string))
		}))
		defer srv.Close()

		fl, err := newFeedList(feedConfig{
			URL:     srv.URL,
			Format:  formatIP,
			Type:    listTypeDeny,
			Refresh: 100 * time.Millisecond, // Short refresh for test
		})
		require.NoError(t, err)
		defer fl.Close()

		mgr := NewManager()
		mgr.add(fl)

		// Initially empty - IP should NOT be blocked
		time.Sleep(50 * time.Millisecond) // Let initial fetch complete
		denied, _ := mgr.Check(testIP)
		assert.False(t, denied, "IP should NOT be blocked initially (empty feed)")

		// Update feed content
		content.Store("192.168.1.0/24\n")

		// Wait for refresh and verify blocking
		assert.Eventually(t, func() bool {
			denied, _ := mgr.Check(testIP)
			return denied
		}, 500*time.Millisecond, 20*time.Millisecond, "IP should be blocked after feed update")
	})
}

// BenchmarkManagerCheck benchmarks denylist check with realistic 2025Q1 feed sizes:
// - spamhaus-drop: ~1.4k IPv4 CIDRs (mix of /8 to /24)
// - spamhaus-dropv6: ~84 IPv6 prefixes
// - urlhaus: ~30k IPv4 /32s
func BenchmarkManagerCheck(b *testing.B) {
	// Spamhaus DROP: ~1.4k IPv4 CIDRs
	dropPrefixes := make([]netip.Prefix, 1448)
	for i := range dropPrefixes {
		o1, o2 := byte(1+(i*7)%254), byte((i*13)%256)
		o3, o4 := byte((i*17)%256), byte(0)
		ip := netip.AddrFrom4([4]byte{o1, o2, o3, o4})
		// Real DROP has mix: /8(~2%), /16(~15%), /20(~20%), /24(~63%)
		bits := []int{8, 16, 16, 20, 20, 20, 24, 24, 24, 24}[i%10]
		dropPrefixes[i] = netip.PrefixFrom(ip, bits)
	}

	// Spamhaus DROPv6: ~84 IPv6 prefixes
	dropv6Prefixes := make([]netip.Prefix, 84)
	for i := range dropv6Prefixes {
		ip := netip.MustParseAddr("2001:db8::").As16()
		ip[2] = byte(i)
		dropv6Prefixes[i] = netip.PrefixFrom(netip.AddrFrom16(ip), 32)
	}

	// URLhaus: ~30k IPv4 /32s
	urlhausPrefixes := make([]netip.Prefix, 30000)
	for i := range urlhausPrefixes {
		o1 := byte(1 + (i*7)%254)
		o2 := byte((i * 13) % 256)
		o3 := byte((i * 17) % 256)
		o4 := byte((i * 23) % 256)
		ip := netip.AddrFrom4([4]byte{o1, o2, o3, o4})
		urlhausPrefixes[i] = netip.PrefixFrom(ip, 32)
	}

	dropPS := newPrefixSet()
	dropPS.replace(dropPrefixes)

	dropv6PS := newPrefixSet()
	dropv6PS.replace(dropv6Prefixes)

	urlhausPS := newPrefixSet()
	urlhausPS.replace(urlhausPrefixes)

	mgr := NewManager()
	mgr.add(&mockChecker{name: "spamhaus-drop", listType: listTypeDeny, prefixes: dropPS})
	mgr.add(&mockChecker{name: "spamhaus-dropv6", listType: listTypeDeny, prefixes: dropv6PS})
	mgr.add(&mockChecker{name: "urlhaus", listType: listTypeDeny, prefixes: urlhausPS})

	// Test IPs - common legitimate IPs (should miss all lists)
	testIPv4s := []netip.Addr{
		netip.MustParseAddr("8.8.8.8"),
		netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("192.168.1.1"),
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("172.16.0.1"),
		netip.MustParseAddr("203.0.113.50"),
	}
	testIPv6s := []netip.Addr{
		netip.MustParseAddr("2606:4700:4700::1111"),
		netip.MustParseAddr("2001:4860:4860::8888"),
	}

	b.Run("IPv4", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			mgr.Check(testIPv4s[i%len(testIPv4s)])
		}
	})

	b.Run("IPv6", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			mgr.Check(testIPv6s[i%len(testIPv6s)])
		}
	})
}
