package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/record"
	"github.com/libp2p/go-libp2p/core/record/pb"
	"github.com/multiformats/go-multiaddr"
	"google.golang.org/protobuf/proto"
)

// SendChallenge submits a challenge to the DNS server for the given peerID.
// It requires the corresponding private key and a list of multiaddresses that the peerID is listening on using
// publicly reachable IP addresses.
func SendChallenge(ctx context.Context, baseURL string, peerID peer.ID, privKey crypto.PrivKey, challenge string, addrs []multiaddr.Multiaddr) error {
	maStrs := make([]string, len(addrs))
	for i, addr := range addrs {
		maStrs[i] = addr.String()
	}
	var requestBody = &requestRecord{
		Value:     challenge,
		Addresses: maStrs,
	}

	env, err := record.Seal(requestBody, privKey)
	if err != nil {
		return err
	}
	envBytes, err := env.Marshal()
	if err != nil {
		return err
	}

	var pbEnv pb.Envelope
	if err := proto.Unmarshal(envBytes, &pbEnv); err != nil {
		return err
	}
	authHeader := base64.StdEncoding.EncodeToString(pbEnv.Signature)
	pk, err := peerID.ExtractPublicKey()
	if err != nil && errors.Is(err, peer.ErrNoPublicKey) {
		return err
	}
	if pk == nil {
		pk = env.PublicKey
		pkBytes, err := crypto.MarshalPublicKey(pk)
		if err != nil {
			return err
		}
		base64EncodedPk := base64.StdEncoding.EncodeToString(pkBytes)
		authHeader += "." + base64EncodedPk
	}

	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/v1/%s/_acme-challenge", baseURL, peerID), bytes.NewReader(pbEnv.Payload))
	if err != nil {
		return err
	}
	req.Header.Add("Authorization", authHeader)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%s : %s", resp.Status, respBody)
	}
	return nil
}

type requestRecord struct {
	Value     string   `json:"value"`
	Addresses []string `json:"addresses"`
}

func (r *requestRecord) Domain() string {
	return "peer-forge-domain-challenge"
}

func (r *requestRecord) Codec() []byte {
	return []byte("/peer-forge-domain-challenge")
}

func (r *requestRecord) MarshalRecord() ([]byte, error) {
	out, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (r *requestRecord) UnmarshalRecord(bytes []byte) error {
	return json.Unmarshal(bytes, r)
}

var _ record.Record = (*requestRecord)(nil)
