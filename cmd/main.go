package main

import (
	_ "github.com/coredns/coredns/core/plugin" // Load all managed plugins in github.com/coredns/coredns.
	_ "github.com/ipshipyard/p2p-forge/acme"
	_ "github.com/ipshipyard/p2p-forge/ipparser"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/coremain"
)

var directives = []string{
	"log",
	"whoami",
	"startup",
	"shutdown",
	"ipparser",
	"acme",
}

func init() {
	dnsserver.Directives = directives
}

func main() {
	coremain.Run()
}
