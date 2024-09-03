package client

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	logging "github.com/ipfs/go-log/v2"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	libp2pquic "github.com/libp2p/go-libp2p/p2p/transport/quic"
	"github.com/libp2p/go-libp2p/p2p/transport/tcp"
	libp2pwebrtc "github.com/libp2p/go-libp2p/p2p/transport/webrtc"
	libp2pws "github.com/libp2p/go-libp2p/p2p/transport/websocket"
	libp2pwebtransport "github.com/libp2p/go-libp2p/p2p/transport/webtransport"
	"github.com/mholt/acmez/v2"
	"github.com/mholt/acmez/v2/acme"
	"github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
	"github.com/multiformats/go-multibase"
)

var log = logging.Logger("p2p-forge/client")

type P2PForgeCertMgr struct {
	forgeDomain               string
	forgeRegistrationEndpoint string
	cfg                       *certmagic.Config
	h                         *hostWrapper
}

type hostWrapper struct {
	host.Host
}

type hostCloseWrapper struct {
	host.Host
	closeFn func() error
}

func (h hostCloseWrapper) Close() error {
	return h.closeFn()
}

func NewHostWithP2PForge(forgeDomain string, forgeRegistrationEndpoint string, caEndpoint string, userEmail string, trustedRoots *x509.CertPool, onCertLoaded func(), allowPrivateForgeAddrs bool, opts ...libp2p.Option) (host.Host, error) {
	certMgr := NewP2PForgeCertMgr(forgeDomain, forgeRegistrationEndpoint, caEndpoint, userEmail, trustedRoots)
	tlsCfg := certMgr.cfg.TLSConfig()
	tlsCfg.NextProtos = []string{"h2", "http/1.1"} // remove the ACME ALPN and set the HTTP 1.1 and 2 ALPNs

	var p2pForgeWssComponent = multiaddr.StringCast(fmt.Sprintf("/tls/sni/*.%s/ws", forgeDomain))

	var h host.Host
	var mx sync.RWMutex
	// TODO: Option passing mechanism here isn't respectful of which transports the user wants to support or the addresses they want to listen on
	hTmp, err := libp2p.New(libp2p.ChainOptions(libp2p.ChainOptions(opts...),
		libp2p.DefaultListenAddrs,
		libp2p.ListenAddrStrings([]string{ // TODO: Grab these addresses from a TCP listener and share the ports
			fmt.Sprintf("/ip4/0.0.0.0/tcp/0/tls/sni/*.%s/ws", forgeDomain),
			fmt.Sprintf("/ip6/::/tcp/0/tls/sni/*.%s/ws", forgeDomain),
		}...),
		libp2p.Transport(tcp.NewTCPTransport),
		libp2p.Transport(libp2pquic.NewTransport),
		libp2p.Transport(libp2pws.New, libp2pws.WithTLSConfig(tlsCfg)),
		libp2p.Transport(libp2pwebtransport.New),
		libp2p.Transport(libp2pwebrtc.New),
		libp2p.AddrsFactory(func(multiaddrs []multiaddr.Multiaddr) []multiaddr.Multiaddr {
			mx.RLock()
			if h == nil {
				mx.RUnlock()
				return multiaddrs
			}
			mx.RUnlock()

			retAddrs := make([]multiaddr.Multiaddr, len(multiaddrs))
			for i, a := range multiaddrs {
				if isRelayAddr(a) || (!allowPrivateForgeAddrs && isPublicAddr(a)) {
					retAddrs[i] = a
					continue
				}

				// We expect the address to be of the form: /ipX/<IP address>/tcp/<Port>/tls/sni/*.<forge-domain>/ws
				// We'll then replace the * with the IP address
				withoutForgeWSS := a.Decapsulate(p2pForgeWssComponent)
				if withoutForgeWSS.Equal(a) {
					retAddrs[i] = a
					continue
				}

				index := 0
				var escapedIPStr string
				var ipMaStr string
				var tcpPortStr string
				multiaddr.ForEach(withoutForgeWSS, func(c multiaddr.Component) bool {
					switch index {
					case 0:
						switch c.Protocol().Code {
						case multiaddr.P_IP4:
							ipMaStr = c.String()
							ipAddr := c.Value()
							escapedIPStr = strings.ReplaceAll(ipAddr, ".", "-")
						case multiaddr.P_IP6:
							ipMaStr = c.String()
							ipAddr := c.Value()
							escapedIPStr = strings.ReplaceAll(ipAddr, ":", "-")
							if escapedIPStr[0] == '-' {
								escapedIPStr = "0" + escapedIPStr
							}
							if escapedIPStr[len(escapedIPStr)-1] == '-' {
								escapedIPStr = escapedIPStr + "0"
							}
						default:
							return false
						}
					case 1:
						if c.Protocol().Code != multiaddr.P_TCP {
							return false
						}
						tcpPortStr = c.Value()
					default:
						index++
						return false
					}
					index++
					return true
				})
				if index != 2 || escapedIPStr == "" || tcpPortStr == "" {
					retAddrs[i] = a
					continue
				}

				pidStr := peer.ToCid(h.ID()).Encode(multibase.MustNewEncoder(multibase.Base36))

				newMaStr := fmt.Sprintf("%s/tcp/%s/tls/sni/%s.%s.%s/ws", ipMaStr, tcpPortStr, escapedIPStr, pidStr, forgeDomain)
				newMA, err := multiaddr.NewMultiaddr(newMaStr)
				if err != nil {
					log.Errorf("error creating new multiaddr from %q: %s", newMaStr, err.Error())
					retAddrs[i] = a
					continue
				}
				retAddrs[i] = newMA
			}
			return retAddrs
		}),
	))
	if err != nil {
		return nil, err
	}
	mx.Lock()
	h = hTmp
	mx.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	if err := certMgr.Run(ctx, h); err != nil {
		cancel()
		return nil, err
	}

	w := &hostCloseWrapper{Host: h, closeFn: func() error {
		cancel()
		err := h.Close()
		return err
	}}

	if onCertLoaded != nil {
		pidStr := peer.ToCid(h.ID()).Encode(multibase.MustNewEncoder(multibase.Base36))
		certName := fmt.Sprintf("*.%s.%s", pidStr, forgeDomain)
		_ = certName
		certMgr.cfg.OnEvent = func(ctx context.Context, event string, data map[string]any) error {
			if event == "cached_managed_cert" {
				sans, ok := data["sans"]
				if !ok {
					return nil
				}
				sanList, ok := sans.([]string)
				if !ok {
					return nil
				}
				for _, san := range sanList {
					if san == certName {
						onCertLoaded()
					}
				}
				return nil
			}
			return nil
		}
	}

	return w, nil
}

func isRelayAddr(a multiaddr.Multiaddr) bool {
	found := false
	multiaddr.ForEach(a, func(c multiaddr.Component) bool {
		found = c.Protocol().Code == multiaddr.P_CIRCUIT
		return !found
	})
	return found
}

var publicCIDR6 = "2000::/3"
var public6 *net.IPNet

func init() {
	_, public6, _ = net.ParseCIDR(publicCIDR6)
}

// isPublicAddr follows the logic of manet.IsPublicAddr, except it uses
// a stricter definition of "public" for ipv6: namely "is it in 2000::/3"?
func isPublicAddr(a multiaddr.Multiaddr) bool {
	ip, err := manet.ToIP(a)
	if err != nil {
		return false
	}
	if ip.To4() != nil {
		return !inAddrRange(ip, manet.Private4) && !inAddrRange(ip, manet.Unroutable4)
	}

	return public6.Contains(ip)
}

func inAddrRange(ip net.IP, ipnets []*net.IPNet) bool {
	for _, ipnet := range ipnets {
		if ipnet.Contains(ip) {
			return true
		}
	}

	return false
}

func NewP2PForgeCertMgr(forgeDomain string, forgeRegistrationEndpoint string, caEndpoint string, userEmail string, trustedRoots *x509.CertPool) *P2PForgeCertMgr {
	cfg := certmagic.NewDefault()
	cfg.Storage = &certmagic.FileStorage{Path: "foo"}
	h := &hostWrapper{}
	myACME := certmagic.NewACMEIssuer(cfg, certmagic.ACMEIssuer{ // TODO: UX around user passed emails + agreement
		CA:           caEndpoint, // TODO: Switch to real CA by default
		Email:        userEmail,
		Agreed:       true,
		DNS01Solver:  &dns01P2PForgeSolver{forgeRegistrationEndpoint, h},
		TrustedRoots: trustedRoots,
	})
	cfg.Issuers = []certmagic.Issuer{myACME}
	return &P2PForgeCertMgr{forgeDomain, forgeRegistrationEndpoint, cfg, h}
}

func (m *P2PForgeCertMgr) Run(ctx context.Context, h host.Host) error {
	m.h.Host = h
	pb36 := peer.ToCid(h.ID()).Encode(multibase.MustNewEncoder(multibase.Base36))

	if err := m.cfg.ManageAsync(ctx, []string{fmt.Sprintf("*.%s.%s", pb36, m.forgeDomain)}); err != nil {
		return err
	}
	return nil
}

type dns01P2PForgeSolver struct {
	forge string
	host  host.Host
}

func (d *dns01P2PForgeSolver) Wait(ctx context.Context, challenge acme.Challenge) error {
	// TODO: query the authoritative DNS
	time.Sleep(time.Second * 5)
	return nil
}

func (d *dns01P2PForgeSolver) Present(ctx context.Context, challenge acme.Challenge) error {
	return SendChallenge(ctx, d.forge, d.host.ID(), d.host.Peerstore().PrivKey(d.host.ID()), challenge.DNS01KeyAuthorization(), d.host.Addrs())
}

func (d *dns01P2PForgeSolver) CleanUp(ctx context.Context, challenge acme.Challenge) error {
	//TODO: Should we implement this, or is doing delete and Last-Writer-Wins enough?
	return nil
}

var _ acmez.Solver = (*dns01P2PForgeSolver)(nil)
var _ acmez.Waiter = (*dns01P2PForgeSolver)(nil)
