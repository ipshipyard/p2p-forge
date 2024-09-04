# p2p-forge

> An Authoritative DNS server for distributing DNS subdomains to libp2p peers

## Build

`go build` will build the binary in your local directory

## Install

```console
$ go install github.com/ipshipyard/p2p-forge@latest
```

Will download using go mod, build and install the binary in your global Go binary directory (e.g. `~/go/bin`)

### From source
`go install` will build and install the binary in your global Go binary directory (e.g. `~/go/bin`)

## Usage

### Handled DNS records

There are 3 types of records handled for a given peer and forge (e.g. `<peerID>.libp2p.direct`):
- ACME Challenges for a given peerID `_acme-challenge.<peerID>.libp2p.direct`
- A records for an IPv4 prefixed subdomain like `1-2-3-4.<peerID>.libp2p.direct`
- AAAA records for an IPv6 prefixed subdomain like `2001-db8--.<peerID>.libp2p.direct`

#### IPv4 subdomain handling

IPv4 handling is fairly straightforward, for a given IPv4 address `1.2.3.4` convert the `.`s into `-`s and the result
will be valid.

#### IPv6 subdomain handling

Due to the length of IPv6 addresses there are a number of different formats for describing IPv6 addresses.

The addresses handled here are:
- For an address `A:B:C:D:1:2:3:4` convert the `:`s into `-`s and the result will be valid.
- Addresses of the form `A::C:D` can be converted either into their expanded form or into a condensed form by replacing
the `:`s with `-`s, like `A--C-D`
- When there is a `:` as the first or last character it must be converted to a 0 to comply with [rfc1123](https://datatracker.ietf.org/doc/html/rfc1123#section-2)
, so `::B:C:D` would become `0--B-C-D` and `1::` would become `1--0`

Other address formats (e.g. the dual IPv6/IPv4 format) are not supported

### Submitting Challenge Records

To claim a domain name like `<peerID>.libp2p.direct` requires:
1. The private key corresponding to the given peerID
2. A publicly reachable libp2p endpoint with one of the following libp2p transport configurations:
   - QUIC-v1
   - TCP or WS or WSS, Yamux, TLS or Noise
   - WebTransport
   - Note: The [Identify protocol](https://github.com/libp2p/specs/tree/master/identify) (`/ipfs/id/1.0.0`)
   - Other transports are under consideration (e.g. HTTP), if they are of interest please file an issue

To set an ACME challenge send an HTTP request to the server (for libp2p.direct this is registration.libp2p.direct)
```shell
curl -X POST "https://registration.libp2p.direct/v1/<peerID>/_acme-challenge" \
-H "Authorization: libp2p-PeerID bearer=\"<base64-encoded-opaque-blob>\""
-H "Content-Type: application/json" \
-d '{
  "value": "your_acme_challenge_token",
  "addresses": "[your_multiaddrs, comma_separated]"
}'
```

Where the bearer token is derived via the [libp2p HTTP PeerID Auth Specification](https://github.com/libp2p/specs/pull/564).