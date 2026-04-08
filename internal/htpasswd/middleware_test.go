package htpasswd

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthenticateAPIKeyHeader(t *testing.T) {
	ht, err := NewFromFile("./testdata/test.htpasswd")
	require.NoError(t, err)

	t.Run("valid base64 user:pass", func(t *testing.T) {
		key := base64.StdEncoding.EncodeToString([]byte("test:test"))
		assert.True(t, AuthenticateAPIKeyHeader(ht, key))
	})

	t.Run("valid base64 user:pass with trailing newline in decoded payload", func(t *testing.T) {
		key := base64.StdEncoding.EncodeToString([]byte("test:test\n"))
		assert.True(t, AuthenticateAPIKeyHeader(ht, key))
	})

	t.Run("valid base64 user:pass with trailing crlf in decoded payload", func(t *testing.T) {
		key := base64.StdEncoding.EncodeToString([]byte("test:test\r\n"))
		assert.True(t, AuthenticateAPIKeyHeader(ht, key))
	})

	t.Run("invalid base64", func(t *testing.T) {
		assert.False(t, AuthenticateAPIKeyHeader(ht, "not-base64"))
	})

	t.Run("missing colon", func(t *testing.T) {
		key := base64.StdEncoding.EncodeToString([]byte("test"))
		assert.False(t, AuthenticateAPIKeyHeader(ht, key))
	})
}
