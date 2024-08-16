package acme

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/plugin/pkg/reuseport"

	"github.com/gorilla/mux"

	"github.com/ipfs/go-datastore"
	pool "github.com/libp2p/go-buffer-pool"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	"github.com/multiformats/go-varint"
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

	c.mux.HandleFunc("/v1/{peerID}/_acme-challenge", func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("must pass an authorization header"))
			return
		}

		vars := mux.Vars(r)
		peerIDStr, peerIDFound := vars["peerID"]
		if !peerIDFound {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("peerID not found in request URL"))
			return
		}
		peerID, err := peer.Decode(peerIDStr)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("invalid peer ID"))
			return
		}

		pk, err := peerID.ExtractPublicKey()
		if err != nil && errors.Is(err, peer.ErrNoPublicKey) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(fmt.Sprintf("unable to extract public key from peer ID: %s", err.Error())))
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(fmt.Sprintf("error reading body: %s", err)))
			return
		}

		authComponents := strings.Split(authHeader, ".")
		if pk == nil {
			if len(authComponents) != 2 {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte("must pass both a signature and public key if the public key cannot be extracted from the peerID"))
				return
			}
			base64EncodedPubKey := authComponents[1]
			encodedPubKey, err := base64.StdEncoding.DecodeString(base64EncodedPubKey)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte("could not decode public key"))
				return
			}
			pk, err = crypto.UnmarshalPublicKey(encodedPubKey)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte("could not unmarshal public key"))
				return
			}

			calculatedID, err := peer.IDFromPublicKey(pk)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte("could not calculate peerID from public key"))
				return
			}

			if calculatedID != peerID {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte("calculated peer ID does not match the passed peerID"))
				return
			}
		} else {
			if len(authComponents) != 1 {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte("when the peerID can be extracted from the public key only the signature should be in the authorization header"))
				return
			}
		}

		base64EncodedSignature := authComponents[0]
		signature, err := base64.StdEncoding.DecodeString(base64EncodedSignature)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(fmt.Sprintf("error decoding signature: %s", err)))
		}

		unsigned := makeUnsigned(signatureDomainString, signaturePayloadType, body)
		defer pool.Put(unsigned)

		verified, err := pk.Verify(unsigned, signature)
		if !verified {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("invalid signature"))
			return
		}

		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(fmt.Sprintf("error verifying signature: %s", err)))
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
	}).Methods("POST")

	go func() { http.Serve(c.ln, c.mux) }()

	return nil
}

func testAddresses(ctx context.Context, p peer.ID, addrs []string) error {
	h, err := libp2p.New(libp2p.NoListenAddrs, libp2p.DisableRelay())
	if err != nil {
		return err
	}

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

const signatureDomainString = "peer-forge-domain-challenge"

var signaturePayloadType []byte = []byte("/peer-forge-domain-challenge")

// makeUnsigned is a helper function that prepares a buffer to sign or verify.
// It returns a byte slice from a pool. The caller MUST return this slice to the
// pool.
func makeUnsigned(domain string, payloadType []byte, payload []byte) []byte {
	var (
		fields = [][]byte{[]byte(domain), payloadType, payload}

		// fields are prefixed with their length as an unsigned varint. we
		// compute the lengths before allocating the sig buffer, so we know how
		// much space to add for the lengths
		flen = make([][]byte, len(fields))
		size = 0
	)

	for i, f := range fields {
		l := len(f)
		flen[i] = varint.ToUvarint(uint64(l))
		size += l + len(flen[i])
	}

	b := pool.Get(size)

	var s int
	for i, f := range fields {
		s += copy(b[s:], flen[i])
		s += copy(b[s:], f)
	}

	return b[:s]
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
