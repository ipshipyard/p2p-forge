package acme

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/ipshipyard/p2p-forge/client"
	"github.com/ipshipyard/p2p-forge/denylist"
	"github.com/ipshipyard/p2p-forge/internal/ownership"
)

const (
	// ownershipFetchTimeout bounds one proof fetch.
	ownershipFetchTimeout = 15 * time.Second
	// ownershipBodyLimit caps the proof response body (a compact JWT).
	ownershipBodyLimit = 8 << 10
	// maxOwnershipURLs caps how many http endpoints one request may present.
	maxOwnershipURLs = 8
	// overallVerifyTimeout bounds all reachability work for one registration,
	// so a request cannot pin the forge on slow endpoints across many fetches.
	overallVerifyTimeout = 45 * time.Second
)

// verifyReachable proves the peer controls a submitted address, trying the
// no-libp2p http-ownership proof first and falling back to the libp2p dialback.
// It returns the verification mode that succeeded.
func (c *acmeWriter) verifyReachable(ctx context.Context, v *v2Verified, addrs []string, userAgent string) (string, error) {
	if !c.AllowPrivateAddrs {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, overallVerifyTimeout)
		defer cancel()
	}

	httpURLs, libp2pAddrs := partitionAddrs(addrs)

	var lastErr error
	if len(httpURLs) > 0 {
		if err := c.verifyHTTPOwnership(ctx, v.pub, v.keyID, httpURLs); err == nil {
			return "http-ownership", nil
		} else {
			lastErr = err
		}
	}
	if len(libp2pAddrs) > 0 {
		if err := c.testAddresses(ctx, v.peerID, libp2pAddrs, userAgent); err == nil {
			return "libp2p-dialback", nil
		} else {
			lastErr = err
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no verifiable address submitted")
	}
	return "", lastErr
}

// partitionAddrs splits submitted addresses into http(s) origin URLs (verified
// by ownership proof) and everything else (verified by libp2p dialback).
// Schemes are case-insensitive (RFC 3986); CanonicalOrigin lowercases later.
func partitionAddrs(addrs []string) (httpURLs, libp2pAddrs []string) {
	for _, a := range addrs {
		lower := strings.ToLower(a)
		if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
			httpURLs = append(httpURLs, a)
		} else {
			libp2pAddrs = append(libp2pAddrs, a)
		}
	}
	return httpURLs, libp2pAddrs
}

// verifyHTTPOwnership tries each submitted http endpoint until one serves a
// valid ownership proof signed by the registration key pub.
func (c *acmeWriter) verifyHTTPOwnership(ctx context.Context, pub ed25519.PublicKey, keyID string, urls []string) error {
	if !c.AllowPrivateAddrs && len(urls) > maxOwnershipURLs {
		return fmt.Errorf("too many http addresses (%d > %d)", len(urls), maxOwnershipURLs)
	}
	var lastErr error
	for _, raw := range urls {
		o, err := client.CanonicalOrigin(raw)
		if err != nil {
			lastErr = err
			continue
		}
		if err := c.fetchAndVerifyOwnership(ctx, pub, keyID, o); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	if lastErr == nil {
		lastErr = errors.New("no http address proved ownership")
	}
	return lastErr
}

// fetchAndVerifyOwnership fetches and checks the proof at o. Any port is
// allowed on purpose: a NATed node forwards an arbitrary port via UPnP or
// router config, and the libp2p dialback accepts arbitrary ports too. Abuse
// control rests on the public-IP vetting and the per-IP denylist, not the
// port.
func (c *acmeWriter) fetchAndVerifyOwnership(ctx context.Context, pub ed25519.PublicKey, keyID string, o client.HTTPOrigin) error {
	ips, err := c.resolvePinnedIPs(ctx, o.Host)
	if err != nil {
		return err
	}
	var lastErr error
	for _, ip := range ips {
		if mgr := denylist.GetManager(); mgr != nil {
			if denied, res := mgr.Check(ip); denied {
				lastErr = fmt.Errorf("endpoint IP %s blocked by %s", ip, res.Name)
				continue
			}
		}
		proof, err := fetchOwnershipProof(ctx, o, ip, keyID)
		if err != nil {
			lastErr = err
			continue
		}
		// A fetched proof is authoritative: verify it under the registration
		// key (never a key the proof itself names) and stop either way.
		return ownership.Verify(string(proof), pub, o.Origin, time.Now())
	}
	return lastErr
}

// resolvePinnedIPs resolves host to at most one vettable public IP per address
// family to pin fetches to, so one stale or unreachable record (say a dead
// AAAA) cannot sink the proof when the other family works. A literal IP is
// used directly. Vetting is skipped when AllowPrivateAddrs.
func (c *acmeWriter) resolvePinnedIPs(ctx context.Context, host string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		if !c.AllowPrivateAddrs {
			if err := vetDestIP(ip); err != nil {
				return nil, err
			}
		}
		return []netip.Addr{ip.Unmap()}, nil
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("resolving %s: %w", host, err)
	}
	var picked []netip.Addr
	var have4, have6 bool
	for _, ip := range ips {
		ip = ip.Unmap()
		if !c.AllowPrivateAddrs && vetDestIP(ip) != nil {
			continue
		}
		if ip.Is4() && !have4 {
			picked = append(picked, ip)
			have4 = true
		}
		if !ip.Is4() && !have6 {
			picked = append(picked, ip)
			have6 = true
		}
	}
	if len(picked) == 0 {
		return nil, fmt.Errorf("no public IP for %s", host)
	}
	return picked, nil
}

// fetchOwnershipProof GETs the well-known proof, pinning the connection to ip so
// a DNS rebind cannot redirect it, following no redirects, and capping the body.
// The fetch never requires a CA-verified certificate: a node registers precisely
// because it has no publicly trusted cert yet, so authenticity rests on the
// proof's signature and host binding on the pinned, vetted IP, not on WebPKI.
func fetchOwnershipProof(ctx context.Context, o client.HTTPOrigin, ip netip.Addr, keyID string) ([]byte, error) {
	proofURL := o.Origin + client.WellKnownProofPath + keyID
	pinned := net.JoinHostPort(ip.String(), o.Port)

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, pinned) // ignore the hostname; connect to the pinned IP
		},
		DisableKeepAlives:      true,
		DisableCompression:     true,
		ResponseHeaderTimeout:  ownershipFetchTimeout,
		MaxResponseHeaderBytes: 16 << 10,
		TLSClientConfig:        &tls.Config{ServerName: o.Host, InsecureSkipVerify: true},
	}
	httpClient := &http.Client{
		Transport:     transport,
		Timeout:       ownershipFetchTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, proofURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ownership endpoint returned %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, ownershipBodyLimit))
	if err != nil {
		return nil, fmt.Errorf("reading ownership proof: %w", err)
	}
	return body, nil
}
