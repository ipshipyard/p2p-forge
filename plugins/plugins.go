package plugins

import (
	// CoreDNS: only load plugins we use
	_ "github.com/coredns/caddy/onevent"
	_ "github.com/coredns/coredns/plugin/any"
	_ "github.com/coredns/coredns/plugin/bind"
	_ "github.com/coredns/coredns/plugin/errors"
	_ "github.com/coredns/coredns/plugin/file"
	_ "github.com/coredns/coredns/plugin/log"
	_ "github.com/coredns/coredns/plugin/metadata"
	_ "github.com/coredns/coredns/plugin/metrics"
	_ "github.com/coredns/coredns/plugin/pprof"
	_ "github.com/coredns/coredns/plugin/reload"
	_ "github.com/coredns/coredns/plugin/root"

	// Load p2p-forge plugins
	_ "github.com/ipshipyard/p2p-forge/acme"
	_ "github.com/ipshipyard/p2p-forge/ipparser"
)
