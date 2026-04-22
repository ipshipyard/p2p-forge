// Package denylist provides IP address filtering for the p2p-forge DNS and
// ACME registration services. It supports file-based and HTTP feed-based
// deny/allow lists to prevent misuse such as DNS rebinding attacks.
package denylist

import (
	"net/netip"

	clog "github.com/coredns/coredns/plugin/pkg/log"
)

var log = clog.NewWithPlugin("denylist")

// listType indicates whether a list is an allowlist or denylist.
type listType string

const (
	// listTypeAllow indicates entries that should bypass denylist checks.
	listTypeAllow listType = "allow"
	// listTypeDeny indicates entries that should be blocked (default).
	listTypeDeny listType = "deny"
)

// feedFormat specifies how to parse external feed content.
type feedFormat string

const (
	// formatIP parses one IP or CIDR per line with # or ; comments.
	// Used for Spamhaus DROP, FireHOL, and custom lists.
	formatIP feedFormat = "ip"
	// formatURL parses URLs, extracts hosts, resolves domains to IPs.
	// Used for URLhaus and similar feeds.
	formatURL feedFormat = "url"
)

// CheckResult contains the outcome of checking an IP against a list.
type CheckResult struct {
	Matched bool   // whether the IP matched an entry
	Name    string // source name (e.g., "spamhaus-drop")
}

// checker checks IP addresses against a list.
type checker interface {
	// Check returns whether the IP matches any entry in this list.
	Check(ip netip.Addr) CheckResult
	// Name returns the name of this checker for metrics/logging.
	Name() string
	// Type returns whether this is an allow or deny list.
	Type() listType
	// Size returns the number of entries in the list.
	Size() int
}
