package acme

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/plugin/pkg/reuseport"

	"github.com/gorilla/mux"

	"github.com/ipfs/go-datastore"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	httppeeridauth "github.com/libp2p/go-libp2p/p2p/http/auth"
	"github.com/multiformats/go-multiaddr"
)

var log = clog.NewWithPlugin(pluginName)

// acmeWriter implements writing of ACME Challenge DNS records by exporting an HTTP endpoint.
type acmeWriter struct {
	Addr string

	Datastore datastore.TTLDatastore

	ln      net.Listener
	nlSetup bool
	mux     *mux.Router
}

func (c *acmeWriter) OnStartup() error {
	if c.Addr == "" {
		c.Addr = ":8080"
	}

	var err error

	ln, err := reuseport.Listen("tcp", c.Addr)
	if err != nil {
		return err
	}

	c.ln = ln

	c.mux = mux.NewRouter()
	c.nlSetup = true

	// server side secret key and peerID not particularly relevant, so we can generate new ones as needed
	sk, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		return err
	}
	authPeer := &httppeeridauth.ServerPeerIDAuth{
		PrivKey:       sk,
		TokenTTL:      time.Hour,
		InsecureNoTLS: true, // TODO: figure out how we want to handle TLS termination for this service
		ValidHostnameFn: func(s string) bool {
			return true
		},
		Next: func(peerID peer.ID, w http.ResponseWriter, r *http.Request) {
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

	c.mux.Handle("/v1/_acme-challenge", authPeer).Methods("POST")

	go func() { http.Serve(c.ln, c.mux) }()

	return nil
}

func testAddresses(ctx context.Context, p peer.ID, addrs []string) error {
	h, err := libp2p.New(libp2p.NoListenAddrs, libp2p.DisableRelay())
	if err != nil {
		return err
	}
	defer h.Close()

	var mas []multiaddr.Multiaddr
	for _, addr := range addrs {
		ma, err := multiaddr.NewMultiaddr(addr)
		if err != nil {
			return err
		}
		mas = append(mas, ma)
	}

	err = h.Connect(ctx, peer.AddrInfo{ID: p, Addrs: mas})
	if err != nil {
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
	log.Debugf("connected to peer %s - UserAgent: %s", p, agentVersion)
	return nil
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
	c.nlSetup = false
	return nil
}

func (c *acmeWriter) OnReload() error {
	if !c.nlSetup {
		return nil
	}

	c.ln.Close()
	c.nlSetup = false
	return nil
}
