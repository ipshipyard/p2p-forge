## p2p-forge metrics

Prometheus endpoint is exposed at `http://localhost:9253/metrics`

It includes default [Prometheus Go client metrics](https://prometheus.io/docs/guides/go-application/) + [CoreDNS](#coredns-metrics) + [p2p-forge](#forge-metrics)-specific metrics listed below.

### Forge metrics

- `coredns_forge_info{version}` - p2p-forge version, useful for tracking deployments

#### `ipparser` plugin (DNS A/AAAA)

- `coredns_forge_ipparser_responses_total{type}` - dynamic DNS responses for `ip.peerid.domain` queries
  - `type=A` - successful IPv4 response
  - `type=AAAA` - successful IPv6 response
  - `type=NODATA-{qtype}` - query type not supported for this domain (e.g., TXT, MX)
  - `type=NODATA-PEERID-{qtype}` - query to bare `peerid.domain` (no IP prefix)

#### `acme` plugin (HTTP registration + DNS-01)

- `coredns_forge_acme_dns01_responses_total{type}` - DNS responses for `_acme-challenge.peerid.domain`
  - `type=TXT` - challenge value present
  - `type=TXT-EMPTY` - no challenge registered yet (returns placeholder)
  - `type=NODATA-{qtype}` - non-TXT query type

- `coredns_forge_acme_libp2p_probe_total{result, agent}` - libp2p connectivity probes before accepting registration
  - `result`: `ok` or `error`
  - `agent`: `kubo`, `go-ipfs`, `helia`, `js-libp2p`, `go-libp2p`, `go-http-client`, `python-requests`, `curl`, `node`, `browser`, or `other`

- `coredns_forge_acme_http_request_duration_seconds{code, handler}` - HTTP request latency histogram
- `coredns_forge_acme_http_requests_inflight{handler}` - current in-flight HTTP requests

### CoreDNS metrics

In addition to the default Go metrics exported by the [Prometheus Go client](https://prometheus.io/docs/guides/go-application/), the following metrics are exported:

- `coredns_build_info{version, revision, goversion}` - info about CoreDNS itself.
- `coredns_panics_total{}` - total number of panics.
- `coredns_dns_requests_total{server, zone, view, proto, family, type}` - total query count.
- `coredns_dns_request_duration_seconds{server, zone, view, type}` - duration to process each query.
- `coredns_dns_request_size_bytes{server, zone, view, proto}` - size of the request in bytes.
- `coredns_dns_do_requests_total{server, view, zone}` - queries that have the DO bit set
- `coredns_dns_response_size_bytes{server, zone, view, proto}` - response size in bytes.
- `coredns_dns_responses_total{server, zone, view, rcode, plugin}` - response per zone, rcode and plugin.
- `coredns_dns_https_responses_total{server, status}` - responses per server and http status code.
- `coredns_dns_quic_responses_total{server, status}` - responses per server and QUIC application code.
- `coredns_plugin_enabled{server, zone, view, name}` - indicates whether a plugin is enabled on per server, zone and view basis.
