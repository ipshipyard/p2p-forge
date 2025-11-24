package acme

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/plugin/pkg/reuseport"
	"github.com/felixge/httpsnoop"
	"github.com/ipshipyard/p2p-forge/client"
	"github.com/prometheus/client_golang/prometheus"

	metrics "github.com/slok/go-http-metrics/metrics/prometheus"
	"github.com/slok/go-http-metrics/middleware"
	"github.com/slok/go-http-metrics/middleware/std"

	"github.com/caddyserver/certmagic"

	"github.com/ipfs/go-datastore"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	httppeeridauth "github.com/libp2p/go-libp2p/p2p/http/auth"
	"github.com/multiformats/go-multiaddr"
)

var log = clog.NewWithPlugin(pluginName)

const registrationApiPath = "/v1/_acme-challenge"
const healthcheckApiPath = "/v1/health"

// acmeWriter implements writing of ACME Challenge DNS records by exporting an HTTP endpoint.
type acmeWriter struct {
	Addr        string
	Domain      string
	ExternalTLS bool

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
				if c.forgeAuthKey != auth {
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

			httpUserAgent := r.Header.Get("User-Agent")
			if err := testAddresses(r.Context(), peerID, typedBody.Addresses, httpUserAgent); err != nil {
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

func testAddresses(ctx context.Context, p peer.ID, addrs []string, httpUserAgent string) error {
	agentVersion := agentType(httpUserAgent)
	h, err := libp2p.New(libp2p.NoListenAddrs, libp2p.DisableRelay())
	if err != nil {
		recordPeerProbe("error", agentVersion)
		return err
	}
	defer h.Close()

	var mas []multiaddr.Multiaddr
	for _, addr := range addrs {
		ma, err := multiaddr.NewMultiaddr(addr)
		if err != nil {
			recordPeerProbe("error", agentVersion)
			return err
		}
		mas = append(mas, ma)
	}

	err = h.Connect(ctx, peer.AddrInfo{ID: p, Addrs: mas})
	if err != nil {
		recordPeerProbe("error", agentVersion)
		return err
	}

	// TODO: Do we need to listen on the identify event instead?
	if v, err := h.Peerstore().Get(p, "AgentVersion"); err == nil {
		if vs, ok := v.(string); ok {
			// if we had successful libp2p identify we prefer agentVersion from it
			agentVersion = vs
		}
	}
	log.Debugf("connected to peer %s - UserAgent: %q", p, agentVersion)
	recordPeerProbe("ok", agentType(agentVersion))
	return nil
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

type requestBody struct {
	Value     string   `json:"value"`
	Addresses []string `json:"addresses"`
}

func (c *acmeWriter) OnFinalShutdown() error {
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
