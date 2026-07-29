package acme

import (
	"testing"

	"github.com/coredns/caddy"
	"github.com/stretchr/testify/require"
)

func TestParseClientIPHeader(t *testing.T) {
	t.Run("a single-value header is accepted", func(t *testing.T) {
		c := caddy.NewTestController("dns", `acme libp2p.direct {
			registration-domain registration.libp2p.direct
			client-ip-header CF-Connecting-IP
		}`)
		_, w, err := parse(c)
		require.NoError(t, err)
		require.Equal(t, "CF-Connecting-IP", w.ClientIPHeader)
	})

	t.Run("X-Forwarded-For is rejected", func(t *testing.T) {
		c := caddy.NewTestController("dns", `acme libp2p.direct {
			registration-domain registration.libp2p.direct
			client-ip-header X-Forwarded-For
		}`)
		_, _, err := parse(c)
		require.ErrorContains(t, err, "X-Forwarded-For")
	})

	t.Run("X-Forwarded-For is rejected regardless of case", func(t *testing.T) {
		c := caddy.NewTestController("dns", `acme libp2p.direct {
			registration-domain registration.libp2p.direct
			client-ip-header x-forwarded-for
		}`)
		_, _, err := parse(c)
		require.Error(t, err)
	})
}
