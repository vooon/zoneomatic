package htpasswd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTPasswdFile(t *testing.T) {

	testCases := []struct {
		name            string
		user            string
		password        string
		expectedOk      bool
		expectedPresent bool
	}{
		{"ok", "test", "test", true, true},
		{"wrong-pass", "test", "foobar", false, true},
		{"no-user", "test2", "test", false, false},
		{"apr1", "test-md5", "test", false, true},
	}

	ht, err := NewFromFile("./testdata/test.htpasswd")
	require.NoError(t, err)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ok, present := ht.Authenticate(tc.user, tc.password)
			assert.Equal(t, tc.expectedOk, ok, "ok")
			assert.Equal(t, tc.expectedPresent, present, "present")
		})
	}
}
