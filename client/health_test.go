package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestParseRetryAfter(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		in   string
		want time.Duration
	}{
		{"absent", "", 0},
		{"delay-seconds", "7200", 2 * time.Hour},
		{"negative seconds", "-5", 0},
		{"garbage", "not-a-date", 0},
		{"http-date in the past", "Mon, 02 Jan 2006 15:04:05 GMT", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := parseRetryAfter(tc.in); got != tc.want {
				t.Fatalf("parseRetryAfter(%q) = %s, want %s", tc.in, got, tc.want)
			}
		})
	}

	t.Run("http-date in the future", func(t *testing.T) {
		t.Parallel()
		in := time.Now().Add(90 * time.Minute).UTC().Format(http.TimeFormat)
		got := parseRetryAfter(in)
		if got < 89*time.Minute || got > 90*time.Minute {
			t.Fatalf("parseRetryAfter(%q) = %s, want ~90m", in, got)
		}
	})
}

func TestNextHealthCheckDelay(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		retryAfter time.Duration
		want       time.Duration
	}{
		{"no Retry-After keeps the default interval", 0, healthCheckRetryInterval},
		{"shorter Retry-After does not shrink the interval", 30 * time.Minute, healthCheckRetryInterval},
		{"longer Retry-After stretches the interval", 2 * time.Hour, 2 * time.Hour},
		{"excessive Retry-After is capped", 100 * time.Hour, healthCheckRetryIntervalMax},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := nextHealthCheckDelay(tc.retryAfter); got != tc.want {
				t.Fatalf("nextHealthCheckDelay(%s) = %s, want %s", tc.retryAfter, got, tc.want)
			}
		})
	}
}

func TestCheckBrokerHealth(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		status  int
		healthy bool
	}{
		{"204 is healthy", http.StatusNoContent, true},
		{"200 is not healthy", http.StatusOK, false},
		{"404 is not healthy", http.StatusNotFound, false},
		{"503 is not healthy", http.StatusServiceUnavailable, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gotPath := make(chan string, 1)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				select {
				case gotPath <- r.URL.Path:
				default:
				}
				w.WriteHeader(tc.status)
			}))
			defer srv.Close()

			err := CheckBrokerHealth(context.Background(), srv.URL, "", nil)
			if tc.healthy && err != nil {
				t.Fatalf("expected healthy broker, got error: %v", err)
			}
			if !tc.healthy && err == nil {
				t.Fatal("expected error for unhealthy broker")
			}
			if path := <-gotPath; path != HealthCheckPath {
				t.Fatalf("expected probe of %q, got %q", HealthCheckPath, path)
			}
		})
	}

	t.Run("trailing slash in endpoint", func(t *testing.T) {
		t.Parallel()
		gotPath := make(chan string, 1)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case gotPath <- r.URL.Path:
			default:
			}
			w.WriteHeader(http.StatusNoContent)
		}))
		defer srv.Close()

		if err := CheckBrokerHealth(context.Background(), srv.URL+"/", "", nil); err != nil {
			t.Fatalf("expected healthy broker, got error: %v", err)
		}
		if path := <-gotPath; path != HealthCheckPath {
			t.Fatalf("expected probe of %q, got %q", HealthCheckPath, path)
		}
	})

	t.Run("unreachable broker", func(t *testing.T) {
		t.Parallel()
		// port 0 is never connectable, no dependency on real port state
		if err := CheckBrokerHealth(context.Background(), "http://127.0.0.1:0", "", nil); err == nil {
			t.Fatal("expected error for unreachable broker")
		}
	})

	t.Run("Retry-After header is surfaced on failure", func(t *testing.T) {
		t.Parallel()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Retry-After", "7200")
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer srv.Close()

		retryAfter, err := checkBrokerHealth(context.Background(), srv.URL, "", nil)
		if err == nil {
			t.Fatal("expected error for unhealthy broker")
		}
		if retryAfter != 2*time.Hour {
			t.Fatalf("expected Retry-After of 2h, got %s", retryAfter)
		}
	})

	t.Run("custom user agent is sent", func(t *testing.T) {
		t.Parallel()
		gotUA := make(chan string, 1)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case gotUA <- r.UserAgent():
			default:
			}
			w.WriteHeader(http.StatusNoContent)
		}))
		defer srv.Close()

		if err := CheckBrokerHealth(context.Background(), srv.URL, "test-agent/1.0", nil); err != nil {
			t.Fatalf("expected healthy broker, got error: %v", err)
		}
		if ua := <-gotUA; ua != "test-agent/1.0" {
			t.Fatalf("expected User-Agent %q, got %q", "test-agent/1.0", ua)
		}
	})
}
