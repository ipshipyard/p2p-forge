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
	"github.com/ipshipyard/p2p-forge/internal/httpsig"
	"github.com/ipshipyard/p2p-forge/internal/ownership"
	"github.com/libp2p/go-libp2p/core/peer"
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
func (c *acmeWriter) verifyReachable(ctx context.Context, keyID string, peerID peer.ID, addrs []string, userAgent string) (string, error) {
	if !c.AllowPrivateAddrs {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, overallVerifyTimeout)
		defer cancel()
	}

	httpURLs, libp2pAddrs := partitionAddrs(addrs)

	var lastErr error
	if len(httpURLs) > 0 {
		if err := c.verifyHTTPOwnership(ctx, keyID, httpURLs); err == nil {
			return "http-ownership", nil
		} else {
			lastErr = err
		}
	}
	if len(libp2pAddrs) > 0 {
		if err := c.testAddresses(ctx, peerID, libp2pAddrs, userAgent); err == nil {
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
func partitionAddrs(addrs []string) (httpURLs, libp2pAddrs []string) {
	for _, a := range addrs {
		if strings.HasPrefix(a, "http://") || strings.HasPrefix(a, "https://") {
			httpURLs = append(httpURLs, a)
		} else {
			libp2pAddrs = append(libp2pAddrs, a)
		}
	}
	return httpURLs, libp2pAddrs
}

// verifyHTTPOwnership tries each submitted http endpoint until one serves a
// valid ownership proof signed by the registration key.
func (c *acmeWriter) verifyHTTPOwnership(ctx context.Context, keyID string, urls []string) error {
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
		if err := c.fetchAndVerifyOwnership(ctx, keyID, o); err != nil {
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

func (c *acmeWriter) fetchAndVerifyOwnership(ctx context.Context, keyID string, o client.HTTPOrigin) error {
	if !c.AllowPrivateAddrs && o.Port != "80" && o.Port != "443" {
		return fmt.Errorf("ownership fetch port %s not allowed", o.Port)
	}

	ip, err := c.resolvePinnedIP(ctx, o.Host)
	if err != nil {
		return err
	}
	if mgr := denylist.GetManager(); mgr != nil {
		if denied, res := mgr.Check(ip); denied {
			return fmt.Errorf("endpoint IP %s blocked by %s", ip, res.Name)
		}
	}

	// The proof must verify under the registration key, never a key the proof
	// itself names.
	regPub, err := httpsig.DecodeDIDKey(keyID)
	if err != nil {
		return err
	}
	raw, err := regPub.Raw()
	if err != nil {
		return fmt.Errorf("reading registration key: %w", err)
	}

	proof, err := fetchOwnershipProof(ctx, o, ip, keyID)
	if err != nil {
		return err
	}
	return ownership.Verify(string(proof), ed25519.PublicKey(raw), o.Origin, time.Now())
}

// resolvePinnedIP resolves host to a single vettable public IP to pin the fetch
// to. A literal IP is used directly. Vetting is skipped when AllowPrivateAddrs.
func (c *acmeWriter) resolvePinnedIP(ctx context.Context, host string) (netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		if !c.AllowPrivateAddrs {
			if err := vetDestIP(ip); err != nil {
				return netip.Addr{}, err
			}
		}
		return ip.Unmap(), nil
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("resolving %s: %w", host, err)
	}
	for _, ip := range ips {
		ip = ip.Unmap()
		if c.AllowPrivateAddrs {
			return ip, nil
		}
		if vetDestIP(ip) == nil {
			return ip, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("no public IP for %s", host)
}

// fetchOwnershipProof GETs the well-known proof, pinning the connection to ip so
// a DNS rebind cannot redirect it, following no redirects, and capping the body.
// For https it first tries WebPKI verification (strong host binding); if that
// fails (e.g. the node has no valid cert yet) it retries without verification,
// where host binding rests on the IP pin and key binding on the signature.
func fetchOwnershipProof(ctx context.Context, o client.HTTPOrigin, ip netip.Addr, keyID string) ([]byte, error) {
	proofURL := o.Origin + client.WellKnownProofPath + keyID
	pinned := net.JoinHostPort(ip.String(), o.Port)

	do := func(insecure bool) ([]byte, error) {
		transport := &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, pinned) // ignore the hostname; connect to the pinned IP
			},
			DisableKeepAlives:      true,
			DisableCompression:     true,
			ResponseHeaderTimeout:  ownershipFetchTimeout,
			MaxResponseHeaderBytes: 16 << 10,
			TLSClientConfig:        &tls.Config{ServerName: o.Host, InsecureSkipVerify: insecure},
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

	if o.Scheme == "https" {
		body, err := do(false)
		if err == nil {
			return body, nil
		}
		// Retry without verification only when the cert itself failed to verify
		// (the node has no valid CA cert yet). Do not retry on a refused
		// connection, timeout, or non-200, which would just double the work.
		var certErr *tls.CertificateVerificationError
		if errors.As(err, &certErr) {
			return do(true)
		}
		return nil, err
	}
	return do(true)
}
