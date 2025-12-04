package denylist

import (
	"sync"
	"testing"

	"github.com/coredns/coredns/plugin"
	"github.com/prometheus/client_golang/prometheus"
)

const subsystem = "forge_denylist"

var (
	deniedTotal     *prometheus.CounterVec
	allowedTotal    *prometheus.CounterVec
	entriesGauge    *prometheus.GaugeVec
	lastUpdateGauge *prometheus.GaugeVec
	metricsOnce     sync.Once
)

// initMetrics initializes and registers denylist metrics with appropriate registry.
// Uses sync.Once to ensure single initialization across parallel tests.
func initMetrics() {
	metricsOnce.Do(func() {
		var registry prometheus.Registerer = prometheus.DefaultRegisterer

		if testing.Testing() {
			// Use isolated registry in tests to avoid metric collisions
			registry = prometheus.NewRegistry()
		}

		deniedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: plugin.Namespace,
			Subsystem: subsystem,
			Name:      "denied_total",
			Help:      "Total number of IPs denied by denylist.",
		}, []string{"name"})

		allowedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: plugin.Namespace,
			Subsystem: subsystem,
			Name:      "allowed_total",
			Help:      "Total number of IPs allowed by allowlist override.",
		}, []string{"name"})

		entriesGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: plugin.Namespace,
			Subsystem: subsystem,
			Name:      "entries",
			Help:      "Number of entries in each denylist source.",
		}, []string{"name", "type"})

		lastUpdateGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: plugin.Namespace,
			Subsystem: subsystem,
			Name:      "last_update_timestamp",
			Help:      "Unix timestamp of last successful update.",
		}, []string{"name"})

		registry.MustRegister(deniedTotal, allowedTotal, entriesGauge, lastUpdateGauge)
	})
}

// incIPDenied increments the denied IP counter for a denylist.
func incIPDenied(name string) {
	if deniedTotal != nil {
		deniedTotal.WithLabelValues(name).Inc()
	}
}

// incIPAllowed increments the allowed IP counter (allowlist override).
func incIPAllowed(name string) {
	if allowedTotal != nil {
		allowedTotal.WithLabelValues(name).Inc()
	}
}

// updateEntries updates the entry count for a list.
func updateEntries(name string, lt listType, count int) {
	if entriesGauge != nil {
		entriesGauge.WithLabelValues(name, string(lt)).Set(float64(count))
	}
}

// updateLastUpdate updates the last update timestamp for a list.
func updateLastUpdate(name string, unixTimestamp int64) {
	if lastUpdateGauge != nil {
		lastUpdateGauge.WithLabelValues(name).Set(float64(unixTimestamp))
	}
}
