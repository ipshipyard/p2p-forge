package client

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

// newTestCertmagic returns a certmagic config with file storage in a temp dir
// and a single Let's Encrypt ACME issuer, mirroring the setup wired by
// NewP2PForgeCertMgr.
func newTestCertmagic(t *testing.T) *certmagic.Config {
	t.Helper()
	var cfg *certmagic.Config
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) {
			return cfg, nil
		},
		Logger: zaptest.NewLogger(t),
	})
	t.Cleanup(cache.Stop)
	cfg = certmagic.New(cache, certmagic.Config{
		Storage: &certmagic.FileStorage{Path: t.TempDir()},
		Logger:  zaptest.NewLogger(t),
	})
	issuer := certmagic.NewACMEIssuer(cfg, certmagic.ACMEIssuer{
		CA:     certmagic.LetsEncryptProductionCA,
		Agreed: true,
		Logger: zaptest.NewLogger(t),
	})
	cfg.Issuers = []certmagic.Issuer{issuer}
	return cfg
}

// storeTestCert generates a self-signed certificate for name with the passed
// NotAfter and stores it in cfg.Storage under the same keys certmagic uses
// for managed certificates.
func storeTestCert(t *testing.T, cfg *certmagic.Config, name string, notAfter time.Time) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{name},
		NotBefore:    notAfter.Add(-90 * 24 * time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)

	issuerKey := cfg.Issuers[0].(*certmagic.ACMEIssuer).IssuerKey()
	ctx := t.Context()
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	require.NoError(t, cfg.Storage.Store(ctx, certmagic.StorageKeys.SiteCert(issuerKey, name), certPEM))
	require.NoError(t, cfg.Storage.Store(ctx, certmagic.StorageKeys.SitePrivateKey(issuerKey, name), keyPEM))
	require.NoError(t, cfg.Storage.Store(ctx, certmagic.StorageKeys.SiteMeta(issuerKey, name), []byte(`{}`)))
}

func TestDropLocalCertIfExpired(t *testing.T) {
	name := "*.k51qzi5uqu5dtest." + testForgeDomain
	log := zaptest.NewLogger(t).Sugar()

	t.Run("expired cert is discarded so issuance starts fresh", func(t *testing.T) {
		cfg := newTestCertmagic(t)
		storeTestCert(t, cfg, name, time.Now().Add(-24*time.Hour))
		require.True(t, localCertExists(t.Context(), cfg, name))

		require.True(t, dropLocalCertIfExpired(t.Context(), log, cfg, name))

		require.False(t, localCertExists(t.Context(), cfg, name))
		issuerKey := cfg.Issuers[0].(*certmagic.ACMEIssuer).IssuerKey()
		require.False(t, cfg.Storage.Exists(t.Context(), certmagic.StorageKeys.SitePrivateKey(issuerKey, name)))
		require.False(t, cfg.Storage.Exists(t.Context(), certmagic.StorageKeys.SiteMeta(issuerKey, name)))
	})

	t.Run("valid cert is kept", func(t *testing.T) {
		cfg := newTestCertmagic(t)
		storeTestCert(t, cfg, name, time.Now().Add(24*time.Hour))

		require.False(t, dropLocalCertIfExpired(t.Context(), log, cfg, name))

		require.True(t, localCertExists(t.Context(), cfg, name))
	})

	t.Run("missing cert is a no-op", func(t *testing.T) {
		cfg := newTestCertmagic(t)

		require.False(t, dropLocalCertIfExpired(t.Context(), log, cfg, name))
	})
}
