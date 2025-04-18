package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"runtime/debug"
	"time"
)

//go:embed version.json
var versionJSON []byte

var name = "p2p-forge"
var version = buildVersion()

//var userAgent = name + "/" + version

func buildVersion() string {
	// Read version from embedded JSON file.
	var verMap map[string]string
	json.Unmarshal(versionJSON, &verMap)
	release := verMap["version"]

	var revision string
	var day string
	var dirty bool

	info, ok := debug.ReadBuildInfo()
	if !ok {
		return release + " dev-build"
	}
	for _, kv := range info.Settings {
		switch kv.Key {
		case "vcs.revision":
			revision = kv.Value[:7]
		case "vcs.time":
			t, _ := time.Parse(time.RFC3339, kv.Value)
			day = t.UTC().Format("2006-01-02")
		case "vcs.modified":
			dirty = kv.Value == "true"
		}
	}
	if dirty {
		revision += "-dirty"
	}
	if revision != "" {
		return fmt.Sprintf("%s %s-%s", release, day, revision)
	}
	return release + " dev-build"
}
