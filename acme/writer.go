package acme

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/plugin/pkg/reuseport"
	"github.com/felixge/httpsnoop"
	"github.com/ipshipyard/p2p-forge/client"
	"github.com/ipshipyard/p2p-forge/denylist"
	"github.com/prometheus/client_golang/prometheus"

	metrics "github.com/slok/go-http-metrics/metrics/prometheus"
	"github.com/slok/go-http-metrics/middleware"
	"github.com/slok/go-http-metrics/middleware/std"

	"github.com/caddyserver/certmagic"

	"github.com/ipfs/go-datastore"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	httppeeridauth "github.com/libp2p/go-libp2p/p2p/http/auth"
)

var log = clog.NewWithPlugin(pluginName)

const registrationApiPath = "/v1/_acme-challenge"
const healthcheckApiPath = "/v1/health"

// acmeWriter implements writing of ACME Challenge DNS records by exporting an HTTP endpoint.
type acmeWriter struct {
	Addr        string
	Domain      string
	ForgeDomain string
	ExternalTLS bool

	// AllowPrivateAddrs disables every reachability safeguard: destination-IP
	// vetting, the address caps, the dialback IP pinning, and the probe and
	// overall verification timeouts. Off by default; intended for tests and
	// private deployments that trust the submitted addresses.
	AllowPrivateAddrs bool

	// ClientIPHeader, when set, names the request header the fronting proxy
	// populates with the real client IP (e.g. CF-Connecting-IP). Empty means
	// only the direct connection address is trusted.
	ClientIPHeader string

	Datastore datastore.TTLDatastore

	ln           net.Listener
	nlSetup      bool
	closeCertMgr func()

	handler http.Handler

	forgeAuthKey string
}

func (c *acmeWriter) OnStartup() error {
	ln, err := reuseport.Listen("tcp", c.Addr)
	if err != nil {
		return err
	}

	if !c.ExternalTLS {
		certCfg := certmagic.NewDefault()
		certCfg.Storage = &certmagic.FileStorage{Path: fmt.Sprintf("%s-certs", strings.Replace(c.Domain, ".", "_", -1))}
		myACME := certmagic.NewACMEIssuer(certCfg, certmagic.ACMEIssuer{
			CA:     certmagic.LetsEncryptProductionCA, // TODO: Add a way to set the email and/or CA
			Agreed: true,
		})
		certCfg.Issuers = []certmagic.Issuer{myACME}

		tlsConfig := certCfg.TLSConfig()
		tlsConfig.NextProtos = append([]string{"h2", "http/1.1"}, tlsConfig.NextProtos...)

		ctx, cancel := context.WithCancel(context.Background())
		if err := certCfg.ManageAsync(ctx, []string{c.Domain}); err != nil {
			cancel()
			return err
		}
		c.closeCertMgr = cancel

		ln = tls.NewListener(ln, tlsConfig)
	}

	authKey, found := os.LookupEnv(client.ForgeAuthEnv)
	if found {
		c.forgeAuthKey = authKey
	} else {
		fmt.Printf("NOTE: environment variable %s not set, registration is open to all peers\n", client.ForgeAuthEnv)
	}

	c.ln = ln
	c.nlSetup = true

	// server side secret key and peerID not particularly relevant, so we can generate new ones as needed
	sk, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		return err
	}

	authPeer := &httppeeridauth.ServerPeerIDAuth{
		PrivKey:  sk,
		TokenTTL: time.Hour,
		Next: func(peerID peer.ID, w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintln(w, "400 Bad Request: Only POST method is allowed.")
				return
			}
			if c.forgeAuthKey != "" {
				auth := r.Header.Get(client.ForgeAuthHeader)
				if !constantTimeEqual(auth, c.forgeAuthKey) {
					w.WriteHeader(http.StatusForbidden)
					fmt.Fprintf(w, "403 Forbidden: Missing %s header.", client.ForgeAuthHeader)
					return
				}
			}

			body, err := io.ReadAll(r.Body)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(fmt.Sprintf("error reading body: %s", err)))
				return
			}

			typedBody := &requestBody{}
			decoder := json.NewDecoder(bytes.NewReader(body))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(typedBody); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(fmt.Sprintf("error decoding body: %s", err)))
				return
			}

			// Value must be a base64url encoding of a SHA256 digest per https://datatracker.ietf.org/doc/html/rfc8555/#section-8.4
			// It MUST NOT contain any characters outside the base64url alphabet, including padding characters ("=").
			decodedValue, err := base64.RawURLEncoding.DecodeString(typedBody.Value)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(fmt.Sprintf("error decoding value as base64url: %s", err)))
				return
			}

			if len(decodedValue) != 32 {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte("value is not a base64url of a SHA256 digest"))
				return
			}

			// Check denylist before attempting to connect
			if blocked, reason := checkDenylist(clientIPs(r, c.ClientIPHeader), typedBody.Addresses); blocked {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(fmt.Sprintf("403 Forbidden: %s", reason)))
				return
			}

			httpUserAgent := r.Header.Get("User-Agent")
			if err := c.testAddresses(r.Context(), peerID, typedBody.Addresses, httpUserAgent); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(fmt.Sprintf("error testing addresses: %s", err)))
				return
			}

			const ttl = time.Hour
			err = c.Datastore.PutWithTTL(r.Context(), datastore.NewKey(peerID.String()), []byte(typedBody.Value), ttl)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(fmt.Sprintf("error storing value: %s", err)))
				return
			}
			w.WriteHeader(http.StatusOK)
		},
	}

	if c.ExternalTLS {
		authPeer.NoTLS = true
		authPeer.ValidHostnameFn = func(s string) bool {
			return s == c.Domain
		}
	}

	// Use appropriate registry for HTTP metrics
	var reg *prometheus.Registry
	if testing.Testing() {
		reg = prometheus.NewRegistry()
	} else {
		reg = prometheus.DefaultRegisterer.(*prometheus.Registry)
	}

	// middleware with prometheus recorder
	httpMetricsMiddleware := middleware.New(middleware.Config{
		Recorder: metrics.NewRecorder(metrics.Config{
			Registry:        reg,
			Prefix:          "coredns_forge_" + pluginName,
			DurationBuckets: []float64{0.1, 0.5, 1, 2, 5, 8, 10, 20, 30}, // TODO: remove this comment if we are ok with these buckets
		}),
		DisableMeasureSize: true, // not meaningful for the registration api
	})

	// register handlers
	mux := http.NewServeMux()
	mux.Handle(registrationApiPath, std.Handler(registrationApiPath, httpMetricsMiddleware, authPeer))
	mux.HandleFunc(healthcheckApiPath, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	// v2 registration API: RFC 9421-signed, no libp2p PeerID-auth handshake.
	mux.Handle("POST "+registrationV2ApiPath, std.Handler(registrationV2ApiPath, httpMetricsMiddleware, http.HandlerFunc(c.handleV2Challenge)))
	mux.HandleFunc("GET "+healthV2ApiPath, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	c.handler = withRequestLogger(mux)

	go func() {
		log.Infof("Registration HTTP API (%s) listener at %s", registrationApiPath, c.ln.Addr().String())
		http.Serve(c.ln, c.handler)
	}()

	return nil
}

func withRequestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, healthcheckApiPath) {
			// skip logging requests to  healthcheck endpoint because its spammed by loadbalancer
			next.ServeHTTP(w, r)
		} else {
			// TODO: decide if we want to keep this logger enabled by default, or move it to debug
			m := httpsnoop.CaptureMetrics(next, w, r)
			log.Infof("%s %s (status=%d dt=%s ua=%q)", r.Method, r.URL, m.Code, m.Duration, r.UserAgent())
		}
	})
}

// agentType returns bound cardinality agent label for metrics.
// libp2p clients can set agent version to arbitrary strings,
// and the metric labels have to have a bound cardinality
func agentType(agentVersion string) string {
	switch {
	case strings.HasPrefix(agentVersion, "kubo/"):
		return "kubo"
	case strings.HasPrefix(agentVersion, "go-ipfs/"): // not kubo, but maybe storm ;)
		return "go-ipfs"
	case strings.HasPrefix(agentVersion, "helia/"):
		return "helia"
	case strings.HasPrefix(agentVersion, "libp2p/") || strings.Contains(agentVersion, "js-libp2p/"):
		return "js-libp2p"
	case strings.Contains(agentVersion, "go-libp2p"):
		return "go-libp2p"
	case strings.Contains(agentVersion, "Go-http-client"):
		return "go-http-client"
	case strings.Contains(agentVersion, "python-requests"):
		return "python-requests"
	case strings.HasPrefix(agentVersion, "curl/"):
		return "curl"
	case agentVersion == "node": // sent when running via 'node poc.js' (not matching prefix as it is too generic, could match node-foo)
		return "node"
	case strings.HasPrefix(agentVersion, "Mozilla/"): // most of browsers make requests with user-agent  header value starting with
		return "browser"
	}
	return "other"
}

// constantTimeEqual compares two secrets without leaking where they differ,
// hashing first so a length difference leaks nothing either.
func constantTimeEqual(a, b string) bool {
	ha := sha256.Sum256([]byte(a))
	hb := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ha[:], hb[:]) == 1
}

type requestBody struct {
	Value     string   `json:"value"`
	Addresses []string `json:"addresses"`
}

// checkDenylist checks the client IPs and the submitted multiaddr IPs against
// the denylist, blocking if any is denied. Returns (blocked, reason).
func checkDenylist(clientIPs []netip.Addr, multiaddrs []string) (bool, string) {
	if blocked, reason := denylistClientIPs(clientIPs); blocked {
		return true, reason
	}
	return denylistAddresses(multiaddrs)
}

// denylistClientIPs checks only the client IPs (the trusted header and the
// direct connection address), so a denylisted caller can be rejected before
// any signature or dialback work.
func denylistClientIPs(clientIPs []netip.Addr) (bool, string) {
	mgr := denylist.GetManager()
	if mgr == nil {
		return false, ""
	}
	for _, client := range clientIPs {
		if !client.IsValid() {
			continue
		}
		if denied, result := mgr.Check(client); denied {
			return true, fmt.Sprintf("client IP %s blocked by %s", client, result.Name)
		}
	}
	return false, ""
}

// denylistAddresses checks the IPs carried in the submitted multiaddrs. It does
// not see behind a /dns name; testAddresses re-checks resolved IPs.
func denylistAddresses(multiaddrs []string) (bool, string) {
	mgr := denylist.GetManager()
	if mgr == nil {
		return false, ""
	}
	for _, ip := range multiaddrsToIPs(multiaddrs) {
		if denied, result := mgr.Check(ip); denied {
			return true, fmt.Sprintf("multiaddr IP %s blocked by %s", ip, result.Name)
		}
	}
	return false, ""
}

func (c *acmeWriter) OnFinalShutdown() error {
	if !c.nlSetup {
		return nil
	}

	c.ln.Close()
	if c.closeCertMgr != nil {
		c.closeCertMgr()
	}

	// Close datastore to release file handles (critical on Windows).
	// Shared with acmeReader but closed here to avoid double-close.
	if c.Datastore != nil {
		if err := c.Datastore.Close(); err != nil {
			log.Warningf("failed to close datastore: %v", err)
		}
	}

	c.nlSetup = false
	return nil
}

func (c *acmeWriter) OnReload() error {
	if !c.nlSetup {
		return nil
	}

	c.ln.Close()
	if c.closeCertMgr != nil {
		c.closeCertMgr()
	}
	c.nlSetup = false
	return nil
}
