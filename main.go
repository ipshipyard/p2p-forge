package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	// Load CoreDNS + p2p-forge plugins
	_ "github.com/ipshipyard/p2p-forge/plugins"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/coremain"
	clog "github.com/coredns/coredns/plugin/pkg/log"

	"github.com/joho/godotenv"
)

var p2pForgeDirectives = []string{
	"denylist", // must be first - provides Manager for ipparser and acme
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

// shouldShowUsageGuidance detects when Corefile is missing p2p-forge plugins
func shouldShowUsageGuidance() bool {
	return shouldShowUsageGuidanceWithOptions(os.Args[1:], ".")
}

// shouldShowUsageGuidanceWithOptions is a testable version that accepts custom args and working directory
func shouldShowUsageGuidanceWithOptions(args []string, workDir string) bool {
	// Check if -conf flag is explicitly provided
	confFile := getConfigFileFromArgs(args)
	if confFile == "" {
		// No explicit config, check if default Corefile exists
		defaultCorefile := filepath.Join(workDir, "Corefile")
		if _, err := os.Stat(defaultCorefile); os.IsNotExist(err) {
			// No Corefile at all - show guidance
			return true
		}
		confFile = defaultCorefile
	} else if !filepath.IsAbs(confFile) {
		// Make relative path absolute based on working directory
		confFile = filepath.Join(workDir, confFile)
	}

	// Check if the config file is missing required p2p-forge plugins
	return isMissingP2PForgePlugins(confFile)
}

// getConfigFile returns the config file path from command line args
func getConfigFile() string {
	return getConfigFileFromArgs(os.Args[1:])
}

// getConfigFileFromArgs is a testable version that accepts custom args
func getConfigFileFromArgs(args []string) string {
	for i, arg := range args {
		if arg == "-conf" && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

// isMissingP2PForgePlugins checks if the config file is missing acme or ipparser plugins
func isMissingP2PForgePlugins(filename string) bool {
	content, err := os.ReadFile(filename)
	if err != nil {
		// If we can't read the file, let CoreDNS handle the error
		return false
	}

	configStr := string(content)

	// Simple check for plugins not in comments
	// Split by lines and check each line for plugins not preceded by #
	hasAcme := false
	hasIPParser := false

	lines := strings.Split(configStr, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Skip comment lines
		if strings.HasPrefix(line, "#") {
			continue
		}
		// Check for plugins (look for word boundaries to avoid partial matches)
		if strings.Contains(line, "acme") {
			hasAcme = true
		}
		if strings.Contains(line, "ipparser") {
			hasIPParser = true
		}
	}

	// Show guidance if missing either essential plugin
	return !hasAcme || !hasIPParser
}

func main() {
	fmt.Printf("%s %s\n", name, version) // always print version
	registerVersionMetric()
	err := godotenv.Load()
	if err == nil {
		fmt.Println(".env found and loaded")
	}

	// Check for common misconfiguration before running CoreDNS
	if shouldShowUsageGuidance() {
		fmt.Fprintf(os.Stderr, "\nError: Configuration issue detected.\n\n")
		fmt.Fprintf(os.Stderr, "p2p-forge requires a Corefile with 'acme' and 'ipparser' plugins.\n")
		fmt.Fprintf(os.Stderr, "This error occurs when running without a proper Corefile or with\n")
		fmt.Fprintf(os.Stderr, "a generic CoreDNS config missing p2p-forge-specific plugins.\n\n")
		fmt.Fprintf(os.Stderr, "For detailed usage instructions, see: https://github.com/ipshipyard/p2p-forge#usage\n\n")
		fmt.Fprintf(os.Stderr, "Local development:\n")
		fmt.Fprintf(os.Stderr, "  ./p2p-forge -conf Corefile.local-dev -dns.port 5354\n\n")
		fmt.Fprintf(os.Stderr, "Local Docker development:\n")
		fmt.Fprintf(os.Stderr, "  docker build -t p2p-forge-dev . && docker run --rm -it --net=host p2p-forge-dev\n")
		fmt.Fprintf(os.Stderr, "  docker run --rm -it --net=host -v ./Corefile.local-dev:/p2p-forge/Corefile.local-dev p2p-forge-dev -conf /p2p-forge/Corefile.local-dev -dns.port 5354\n\n")
		fmt.Fprintf(os.Stderr, "Production deployment:\n")
		fmt.Fprintf(os.Stderr, "  ./p2p-forge -conf Corefile\n")
		fmt.Fprintf(os.Stderr, "  (Note: Use production-appropriate Corefile, not Corefile.local-dev)\n\n")
		os.Exit(1)
	}

	coremain.Run()
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
