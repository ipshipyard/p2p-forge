package main

import (
	"fmt"

	// Load CoreDNS + p2p-forge plugins
	_ "github.com/ipshipyard/p2p-forge/plugins"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/coremain"
	clog "github.com/coredns/coredns/plugin/pkg/log"

	"github.com/joho/godotenv"
)

var p2pForgeDirectives = []string{
	"ipparser",
	"acme",
}

func init() {
	// Add custom plugins before 'file' to ensure our dynamic
	// code is executed before static records loaded via 'file' which does not
	// support fallthrough
	// https://github.com/coredns/coredns/blob/v1.11.3/plugin.cfg
	// https://github.com/coredns/coredns/issues/3601
	for i, d := range dnsserver.Directives {
		if d == "file" {
			ds := make([]string, 0, len(dnsserver.Directives)+len(p2pForgeDirectives))
			ds = append(ds, dnsserver.Directives[:i]...)
			ds = append(ds, p2pForgeDirectives...)
			ds = append(ds, dnsserver.Directives[i:]...)
			dnsserver.Directives = ds
			break
		}
	}
	clog.Debugf("updated directives: %v", dnsserver.Directives)
}

func main() {
	fmt.Printf("%s %s\n", name, version) // always print version
	err := godotenv.Load()
	if err == nil {
		fmt.Println(".env found and loaded")
	}
	coremain.Run()
}
