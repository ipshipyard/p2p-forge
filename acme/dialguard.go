package acme

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/ipshipyard/p2p-forge/denylist"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/control"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	madns "github.com/multiformats/go-multiaddr-dns"
	manet "github.com/multiformats/go-multiaddr/net"
)

// probeTimeout bounds a single reachability probe so a slow or blackholed
// target cannot pin a request goroutine and its libp2p host.
const probeTimeout = 15 * time.Second

// maxProbeAddresses bounds how many addresses one registration may ask the
// forge to dial, limiting dial fan-out and reflection. It is enforced only when
// address vetting is on (see acmeWriter.AllowPrivateAddrs).
const maxProbeAddresses = 32

// blockedPrefixes are IP ranges the forge must never dial: they reach internal,
// link-local, IPv4-embedding, or otherwise non-globally-routable targets (cloud
// metadata, RFC1918, CGNAT, NAT64, 6to4, Teredo, IPv4-compatible IPv6, reserved
// space). netip's own predicates cover loopback, unspecified, link-local,
// multicast, RFC1918, and ULA; these are the gaps it does not.
var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),      // "this host on this network" (RFC 6890)
	netip.MustParsePrefix("100.64.0.0/10"),  // CGNAT (RFC 6598)
	netip.MustParsePrefix("198.18.0.0/15"),  // benchmarking (RFC 2544)
	netip.MustParsePrefix("240.0.0.0/4"),    // reserved / Class E
	netip.MustParsePrefix("::/96"),          // IPv4-compatible IPv6 (deprecated, embeds v4)
	netip.MustParsePrefix("64:ff9b::/96"),   // NAT64 well-known (RFC 6052)
	netip.MustParsePrefix("64:ff9b:1::/48"), // NAT64 local-use (RFC 8215)
	netip.MustParsePrefix("2002::/16"),      // 6to4 (RFC 3056)
	netip.MustParsePrefix("2001::/32"),      // Teredo (RFC 4380)
}

// vetDestIP reports whether ip is a public, globally routable unicast address
// the forge may dial. It unmaps IPv4-in-IPv6 first so an embedded private v4
// cannot slip through as a v6 literal.
func vetDestIP(ip netip.Addr) error {
	ip = ip.Unmap()
	if !ip.IsValid() {
		return fmt.Errorf("invalid IP")
	}
	switch {
	case ip.IsLoopback():
		return fmt.Errorf("loopback IP %s", ip)
	case ip.IsUnspecified():
		return fmt.Errorf("unspecified IP %s", ip)
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		return fmt.Errorf("link-local IP %s", ip)
	case ip.IsMulticast(), ip.IsInterfaceLocalMulticast():
		return fmt.Errorf("multicast IP %s", ip)
	case ip.IsPrivate(): // RFC1918 and ULA fc00::/7
		return fmt.Errorf("private IP %s", ip)
	case !ip.IsGlobalUnicast():
		return fmt.Errorf("non-global IP %s", ip)
	}
	for _, p := range blockedPrefixes {
		if p.Contains(ip) {
			return fmt.Errorf("reserved IP %s (%s)", ip, p)
		}
	}
	return nil
}

// multiaddrIP extracts the IP literal from a multiaddr, or false if it carries
// none (e.g. a /dns or relay address).
func multiaddrIP(m multiaddr.Multiaddr) (netip.Addr, bool) {
	ip, err := manet.ToIP(m)
	if err != nil {
		return netip.Addr{}, false
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

// ipGater is a libp2p ConnectionGater that permits dials only to a fixed set of
// pre-vetted IPs. It closes any DNS-rebinding gap left after resolution by
// pinning the exact IPs the forge decided to dial, for TCP and QUIC alike.
type ipGater struct {
	allowed map[netip.Addr]struct{}
}

func newIPGater(ips []netip.Addr) *ipGater {
	allowed := make(map[netip.Addr]struct{}, len(ips))
	for _, ip := range ips {
		allowed[ip] = struct{}{}
	}
	return &ipGater{allowed: allowed}
}

func (g *ipGater) permitted(m multiaddr.Multiaddr) bool {
	ip, ok := multiaddrIP(m)
	if !ok {
		return false
	}
	_, ok = g.allowed[ip]
	return ok
}

func (g *ipGater) InterceptAddrDial(_ peer.ID, m multiaddr.Multiaddr) bool {
	return g.permitted(m)
}

func (g *ipGater) InterceptPeerDial(peer.ID) bool { return true }

func (g *ipGater) InterceptAccept(network.ConnMultiaddrs) bool { return true }

func (g *ipGater) InterceptSecured(network.Direction, peer.ID, network.ConnMultiaddrs) bool {
	return true
}

func (g *ipGater) InterceptUpgraded(network.Conn) (bool, control.DisconnectReason) {
	return true, 0
}

// isCircuit reports whether m contains a /p2p-circuit relay hop.
func isCircuit(m multiaddr.Multiaddr) bool {
	for _, p := range m.Protocols() {
		if p.Code == multiaddr.P_CIRCUIT {
			return true
		}
	}
	return false
}

// resolveAndVet parses the submitted addresses, resolves any /dns* component to
// concrete IPs, drops relay and non-public addresses (unless allowPrivate), and
// returns the concrete multiaddrs to dial plus the deduped IP set to pin. It
// errors if nothing dialable remains.
func resolveAndVet(ctx context.Context, resolver *madns.Resolver, addrStrs []string, allowPrivate bool) ([]multiaddr.Multiaddr, []netip.Addr, error) {
	var (
		dialable []multiaddr.Multiaddr
		ips      []netip.Addr
		seen     = map[netip.Addr]struct{}{}
	)
outer:
	for _, s := range addrStrs {
		m, err := multiaddr.NewMultiaddr(s)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing address %q: %w", s, err)
		}
		if isCircuit(m) {
			continue
		}

		resolved := []multiaddr.Multiaddr{m}
		if madns.Matches(m) {
			resolved, err = resolver.Resolve(ctx, m)
			if err != nil {
				continue
			}
		}
		for _, rm := range resolved {
			ip, ok := multiaddrIP(rm)
			if !ok {
				continue // no IP literal to vet or pin
			}
			if !allowPrivate {
				if err := vetDestIP(ip); err != nil {
					continue // never dial a non-public target
				}
			}
			dialable = append(dialable, rm)
			if _, dup := seen[ip]; !dup {
				seen[ip] = struct{}{}
				ips = append(ips, ip)
			}
			// Bound the dial fan-out after resolution, since one /dns* input
			// can expand to many IPs.
			if !allowPrivate && len(dialable) >= maxProbeAddresses {
				break outer
			}
		}
	}
	if len(dialable) == 0 {
		return nil, nil, fmt.Errorf("no dialable public address")
	}
	return dialable, ips, nil
}

// testAddresses verifies the peer is reachable and authenticates as p by
// dialing its addresses over libp2p. When address vetting is enabled (the
// default) it caps the address count, refuses non-public targets, pins the
// vetted IPs with a connection gater against DNS rebinding, and bounds the dial
// with a timeout.
func (c *acmeWriter) testAddresses(ctx context.Context, p peer.ID, addrStrs []string, httpUserAgent string) error {
	agentVersion := agentType(httpUserAgent)

	if !c.AllowPrivateAddrs && len(addrStrs) > maxProbeAddresses {
		recordPeerProbe("error", agentVersion)
		return fmt.Errorf("too many addresses (%d > %d)", len(addrStrs), maxProbeAddresses)
	}

	dialable, ips, err := resolveAndVet(ctx, madns.DefaultResolver, addrStrs, c.AllowPrivateAddrs)
	if err != nil {
		recordPeerProbe("error", agentVersion)
		return err
	}

	// Close the /dns denylist gap: block on the resolved IPs, which
	// checkDenylist's multiaddrsToIPs never sees behind a name.
	if mgr := denylist.GetManager(); mgr != nil {
		for _, ip := range ips {
			if denied, res := mgr.Check(ip); denied {
				recordPeerProbe("error", agentVersion)
				return fmt.Errorf("address IP %s blocked by %s", ip, res.Name)
			}
		}
	}

	opts := []libp2p.Option{libp2p.NoListenAddrs, libp2p.DisableRelay()}
	dialCtx := ctx
	if !c.AllowPrivateAddrs {
		var cancel context.CancelFunc
		dialCtx, cancel = context.WithTimeout(ctx, probeTimeout)
		defer cancel()
		opts = append(opts, libp2p.ConnectionGater(newIPGater(ips)))
	}

	h, err := libp2p.New(opts...)
	if err != nil {
		recordPeerProbe("error", agentVersion)
		return err
	}
	defer h.Close()

	if err := h.Connect(dialCtx, peer.AddrInfo{ID: p, Addrs: dialable}); err != nil {
		recordPeerProbe("error", agentVersion)
		// Return a generic error: the underlying dial result (refused vs
		// handshake-fail vs timeout) would let a caller port-scan public hosts
		// through the forge. The detail is logged server-side only.
		log.Debugf("probe dial to %s failed: %v", p, err)
		return fmt.Errorf("peer is not reachable at any submitted address")
	}

	log.Debugf("connected to peer %s (agent %q)", p, agentVersion)
	recordPeerProbe("ok", agentVersion)
	return nil
}
