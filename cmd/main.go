package main

import (
	_ "github.com/coredns/coredns/core/plugin" // Load all managed plugins in github.com/coredns/coredns.
	_ "github.com/ipshipyard/p2p-forge/acme"
	_ "github.com/ipshipyard/p2p-forge/ipparser"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/coremain"
)

var customDirectives = []string{
	"ipparser",
	"acme",
}

func init() {
	dnsserver.Directives = append(dnsserver.Directives, customDirectives...)
}

func main() {
	coremain.Run()
}
