package client

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// TestSolverRegisterDispatch covers the version selection and the auto-mode
// v2->v1 fallback rule without any network: sendV1/sendV2 just record calls.
func TestSolverRegisterDispatch(t *testing.T) {
	verifyFailed := errors.New("no address verified")

	type call struct{ v1, v2 bool }
	run := func(version RegistrationAPIVersion, isEd bool, v2err error) (call, error) {
		var c call
		s := &dns01P2PForgeSolver{apiVersion: version, log: zap.NewNop().Sugar()}
		err := s.register(isEd,
			func() error { c.v1 = true; return nil },
			func() error { c.v2 = true; return v2err },
		)
		return c, err
	}

	t.Run("explicit v1 uses v1", func(t *testing.T) {
		c, err := run(RegistrationV1, true, nil)
		require.NoError(t, err)
		require.Equal(t, call{v1: true}, c)
	})

	t.Run("explicit v2 uses v2, no fallback", func(t *testing.T) {
		c, err := run(RegistrationV2, true, ErrV2Unsupported)
		require.ErrorIs(t, err, ErrV2Unsupported)
		require.Equal(t, call{v2: true}, c)
	})

	t.Run("auto with Ed25519 uses v2", func(t *testing.T) {
		c, err := run(RegistrationAuto, true, nil)
		require.NoError(t, err)
		require.Equal(t, call{v2: true}, c)
	})

	t.Run("auto falls back to v1 when v2 is unsupported", func(t *testing.T) {
		c, err := run(RegistrationAuto, true, ErrV2Unsupported)
		require.NoError(t, err)
		require.Equal(t, call{v1: true, v2: true}, c)
	})

	t.Run("auto does not fall back on a verification failure", func(t *testing.T) {
		c, err := run(RegistrationAuto, true, verifyFailed)
		require.ErrorIs(t, err, verifyFailed)
		require.Equal(t, call{v2: true}, c, "a non-unsupported v2 error must not retry v1")
	})

	t.Run("auto with a non-Ed25519 key uses v1", func(t *testing.T) {
		c, err := run(RegistrationAuto, false, nil)
		require.NoError(t, err)
		require.Equal(t, call{v1: true}, c)
	})
}
