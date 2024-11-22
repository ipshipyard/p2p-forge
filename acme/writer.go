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

			if err := testAddresses(r.Context(), peerID, typedBody.Addresses); err != nil {
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

	// middleware with prometheus recorder
	httpMetricsMiddleware := middleware.New(middleware.Config{
		Recorder: metrics.NewRecorder(metrics.Config{
			Registry:        prometheus.DefaultRegisterer.(*prometheus.Registry),
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
		// we skip healthcheck endpoint because its spammed
		if !strings.HasPrefix(r.URL.Path, healthcheckApiPath) {
			// TODO: decide if we want to keep this logger enabled by default, or move it to debug
			m := httpsnoop.CaptureMetrics(next, w, r)
			log.Infof("%s %s (status=%d dt=%s ua=%q)", r.Method, r.URL, m.Code, m.Duration, r.UserAgent())
		}
	})
}

func testAddresses(ctx context.Context, p peer.ID, addrs []string) error {
	h, err := libp2p.New(libp2p.NoListenAddrs, libp2p.DisableRelay())
	if err != nil {
		peerProbeCount.WithLabelValues("error", "unknown").Add(1)
		return err
	}
	defer h.Close()

	var mas []multiaddr.Multiaddr
	for _, addr := range addrs {
		ma, err := multiaddr.NewMultiaddr(addr)
		if err != nil {
			peerProbeCount.WithLabelValues("error", "unknown").Add(1)
			return err
		}
		mas = append(mas, ma)
	}

	err = h.Connect(ctx, peer.AddrInfo{ID: p, Addrs: mas})
	if err != nil {
		peerProbeCount.WithLabelValues("error", "unknown").Add(1)
		return err
	}

	// TODO: Do we need to listen on the identify event instead?
	// TODO: Where do we want to record this information if anywhere?
	var agentVersion string
	if v, err := h.Peerstore().Get(p, "AgentVersion"); err == nil {
		if vs, ok := v.(string); ok {
			agentVersion = vs
		}
	}
	log.Debugf("connected to peer %s - UserAgent: %q", p, agentVersion)
	peerProbeCount.WithLabelValues("ok", agentType(agentVersion)).Add(1)
	return nil
}

// agentType returns bound cardinality agent label for metrics.
// libp2p clients can set agent version to arbitrary strings,
// and the metric labels have to have a bound cardinality
func agentType(agentVersion string) string {
	if strings.HasPrefix(agentVersion, "kubo/") {
		return "kubo"
	}
	if strings.HasPrefix(agentVersion, "helia/") {
		return "helia"
	}
	// TODO:  revisit once js0libp2p cleans up default user agents to something unique and not "libp2p/"
	if strings.HasPrefix(agentVersion, "libp2p/") || strings.HasPrefix(agentVersion, "js-libp2p/") {
		return "js-libp2p"
	}
	if strings.Contains(agentVersion, "go-libp2p") {
		return "go-libp2p"
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
