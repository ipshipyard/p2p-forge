package denylist

import (
	"fmt"
	"strings"
	"time"

	"github.com/coredns/caddy"
)

const defaultFeedRefresh = time.Hour

// parseListTypeValue parses a list type value from configuration.
func parseListTypeValue(v string) (listType, error) {
	switch v {
	case "allow":
		return listTypeAllow, nil
	case "deny":
		return listTypeDeny, nil
	default:
		return "", fmt.Errorf("invalid type: %s (expected allow or deny)", v)
	}
}

// parseConfig parses a denylist configuration block from the Corefile.
// Returns nil if there is no denylist block.
//
// Syntax:
//
//	denylist {
//	    file <path> [type=allow|deny] [name=<name>]
//	    feed <url> format=ip|url [type=allow|deny] [refresh=<duration>] [name=<name>]
//	}
//
// forgeDomain is used to optimize URL format feeds by extracting IPs directly
// from forge subdomains (e.g., "192-168-1-1.peerid.libp2p.direct") instead of
// doing DNS resolution.
func parseConfig(c *caddy.Controller, baseDir, forgeDomain string) (*Manager, error) {
	if !c.NextBlock() {
		return nil, nil // no denylist block
	}

	mgr := NewManager()
	var checkers []checker

parseLoop:
	for {
		switch c.Val() {
		case "file":
			cfg, err := parseFileDirective(c, baseDir)
			if err != nil {
				return nil, err
			}
			fl, err := newFileList(cfg)
			if err != nil {
				return nil, fmt.Errorf("file %s: %w", cfg.Path, err)
			}
			checkers = append(checkers, fl)

		case "feed":
			cfg, err := parseFeedDirective(c, forgeDomain)
			if err != nil {
				return nil, err
			}
			fl, err := newFeedList(cfg)
			if err != nil {
				return nil, fmt.Errorf("feed %s: %w", cfg.URL, err)
			}
			checkers = append(checkers, fl)

		default:
			if c.Val() == "}" {
				break parseLoop
			}
			return nil, fmt.Errorf("unknown directive: %s", c.Val())
		}

		if !c.Next() {
			break
		}
	}

	if len(checkers) == 0 {
		return nil, nil // no lists configured
	}

	for _, chk := range checkers {
		mgr.add(chk)
	}

	return mgr, nil
}

func parseFileDirective(c *caddy.Controller, baseDir string) (fileConfig, error) {
	cfg := fileConfig{
		BaseDir: baseDir,
		Type:    listTypeDeny,
	}

	args := c.RemainingArgs()
	if len(args) == 0 {
		return cfg, c.ArgErr()
	}

	cfg.Path = args[0]

	// Parse key=value options
	for _, arg := range args[1:] {
		kv := strings.SplitN(arg, "=", 2)
		if len(kv) != 2 {
			return cfg, fmt.Errorf("invalid option: %s (expected key=value)", arg)
		}
		k, v := kv[0], kv[1]
		switch k {
		case "type":
			t, err := parseListTypeValue(v)
			if err != nil {
				return cfg, err
			}
			cfg.Type = t
		case "name":
			cfg.Name = v
		default:
			return cfg, fmt.Errorf("unknown file option: %s", k)
		}
	}

	return cfg, nil
}

func parseFeedDirective(c *caddy.Controller, forgeDomain string) (feedConfig, error) {
	cfg := feedConfig{
		Type:        listTypeDeny,
		Refresh:     defaultFeedRefresh,
		ForgeSuffix: forgeDomain,
	}

	args := c.RemainingArgs()
	if len(args) == 0 {
		return cfg, c.ArgErr()
	}

	cfg.URL = args[0]

	// Parse key=value options
	var hasFormat bool
	for _, arg := range args[1:] {
		kv := strings.SplitN(arg, "=", 2)
		if len(kv) != 2 {
			return cfg, fmt.Errorf("invalid option: %s (expected key=value)", arg)
		}
		k, v := kv[0], kv[1]
		switch k {
		case "format":
			switch v {
			case "ip":
				cfg.Format = formatIP
			case "url":
				cfg.Format = formatURL
			default:
				return cfg, fmt.Errorf("invalid format: %s (expected ip or url)", v)
			}
			hasFormat = true
		case "type":
			t, err := parseListTypeValue(v)
			if err != nil {
				return cfg, err
			}
			cfg.Type = t
		case "refresh":
			d, err := time.ParseDuration(v)
			if err != nil {
				return cfg, fmt.Errorf("invalid refresh duration: %w", err)
			}
			cfg.Refresh = d
		case "name":
			cfg.Name = v
		default:
			return cfg, fmt.Errorf("unknown feed option: %s", k)
		}
	}

	if !hasFormat {
		return cfg, fmt.Errorf("feed directive requires format=ip|url")
	}

	return cfg, nil
}
