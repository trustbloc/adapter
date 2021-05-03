/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package healthcheck

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestController_New(t *testing.T) {
	t.Parallel()

	t.Run("test success", func(t *testing.T) {
		t.Parallel()

		controller := New()
		require.NotNil(t, controller)
		ops := controller.GetOperations()

		require.Equal(t, 1, len(ops))
	})
}
