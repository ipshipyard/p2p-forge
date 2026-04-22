package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	// Load CoreDNS + p2p-forge plugins
	_ "github.com/ipshipyard/p2p-forge/plugins"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/coremain"
	clog "github.com/coredns/coredns/plugin/pkg/log"

	golog "github.com/ipfs/go-log/v2"
	"github.com/libp2p/go-libp2p/gologshim"

	"github.com/joho/godotenv"
)

func init() {
	// Route stdlib slog and go-libp2p's gologshim through go-log so
	// libp2p subsystem logs share formatting and level control
	// (golog.SetLogLevel) with the rest of go-log output.
	// Required since go-log v2.9 + go-libp2p v0.45; see
	// https://github.com/ipfs/go-log/releases/tag/v2.9.0
	slog.SetDefault(slog.New(golog.SlogHandler()))
	gologshim.SetDefaultHandler(golog.SlogHandler())
}

var p2pForgeDirectives = []string{
	"denylist", // must be first - provides Manager for ipparser and acme
	"ipparser",
	"acme",
}

const usageGuidance = `
Error: Corefile is missing required p2p-forge plugins (acme, ipparser).

Start p2p-forge with a Corefile that loads both plugins. See
https://github.com/ipshipyard/p2p-forge#usage

Local development:
  ./p2p-forge -conf Corefile.local-dev -dns.port 5354

Local Docker development:
  docker build -t p2p-forge-dev . && docker run --rm -it --net=host p2p-forge-dev
  docker run --rm -it --net=host -v ./Corefile.local-dev:/p2p-forge/Corefile.local-dev p2p-forge-dev -conf /p2p-forge/Corefile.local-dev -dns.port 5354

Production deployment (do not use Corefile.local-dev):
  ./p2p-forge -conf Corefile

`

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
	registerVersionMetric()
	err := godotenv.Load()
	if err == nil {
		fmt.Println(".env found and loaded")
	}

	if shouldShowUsageGuidance() {
		fmt.Fprint(os.Stderr, usageGuidance)
		os.Exit(1)
	}

	coremain.Run()
}

// shouldShowUsageGuidance reports whether the resolved Corefile is missing p2p-forge plugins.
func shouldShowUsageGuidance() bool {
	return shouldShowUsageGuidanceWithOptions(os.Args[1:], ".")
}

// shouldShowUsageGuidanceWithOptions accepts args and workDir for testing.
func shouldShowUsageGuidanceWithOptions(args []string, workDir string) bool {
	confFile := getConfigFileFromArgs(args)
	if confFile == "" {
		defaultCorefile := filepath.Join(workDir, "Corefile")
		if _, err := os.Stat(defaultCorefile); errors.Is(err, os.ErrNotExist) {
			// No Corefile at all - show guidance.
			return true
		}
		confFile = defaultCorefile
	} else if !filepath.IsAbs(confFile) {
		confFile = filepath.Join(workDir, confFile)
	}

	return isMissingP2PForgePlugins(confFile)
}

func getConfigFileFromArgs(args []string) string {
	for i, arg := range args {
		if arg == "-conf" && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

// isMissingP2PForgePlugins reports whether the Corefile lacks acme or ipparser
// directives. The check is a substring match on non-comment lines, so tokens
// like "acmeish" would register as a false positive; acceptable since this
// only gates a usage hint, not CoreDNS startup.
func isMissingP2PForgePlugins(filename string) bool {
	content, err := os.ReadFile(filename)
	if err != nil {
		// If we can't read the file, let CoreDNS handle the error.
		return false
	}

	hasAcme := false
	hasIPParser := false

	for line := range strings.SplitSeq(string(content), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, "acme") {
			hasAcme = true
		}
		if strings.Contains(line, "ipparser") {
			hasIPParser = true
		}
	}

	return !hasAcme || !hasIPParser
}

func registerVersionMetric() {
	m := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace:   "coredns",
		Subsystem:   "forge",
		Name:        "info",
		Help:        "Information about p2p-forge instance.",
		ConstLabels: prometheus.Labels{"version": version},
	})
	prometheus.MustRegister(m)
	m.Set(1)
}
