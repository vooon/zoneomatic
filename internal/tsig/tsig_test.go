package tsig

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParse_SingleKey(t *testing.T) {
	keys, err := Parse([]byte(`
key "certmanager.example.com" {
	algorithm hmac-sha256;
	secret "YlZQY3QDIVu4vaD+7ZXhCQJ0NOn35EIvPrR52PP14kQ=";
};
`))
	require.NoError(t, err)
	require.Len(t, keys, 1)

	key, ok := keys["certmanager.example.com."]
	require.True(t, ok)
	assert.Equal(t, dns.HmacSHA256, key.Algorithm)
	assert.Equal(t, "YlZQY3QDIVu4vaD+7ZXhCQJ0NOn35EIvPrR52PP14kQ=", key.Secret)
}

func TestParse_MultipleKeysAndCanonicalization(t *testing.T) {
	keys, err := Parse([]byte(`
key "CM.Example.COM" {
	algorithm hmac-sha512;
	secret "yGSQC9QNxxKCvd6P1Wx2+q+rCpTO7V1JnHBxN6nIcwo7guMT1OZuEXAMNl+3QE4v0MGxzZYFED6OBKAShsxgxw==";
};
key admin-key {
	algorithm hmac-sha256;
	secret "32pD8A6DfOgRA78uPNzvC4SFhqwEaKySaVEQfQWHZIo=";
};
`))
	require.NoError(t, err)
	require.Len(t, keys, 2)

	cm, ok := keys["cm.example.com."]
	require.True(t, ok)
	assert.Equal(t, dns.HmacSHA512, cm.Algorithm)

	admin, ok := keys["admin-key."]
	require.True(t, ok)
	assert.Equal(t, dns.HmacSHA256, admin.Algorithm)
}

func TestParse_CommentsAndParens(t *testing.T) {
	keys, err := Parse([]byte(`
# leading comment
// line comment
/* block
   comment */
key "k1" { algorithm hmac-sha256; secret "32pD8A6DfOgRA78uPNzvC4SFhqwEaKySaVEQfQWHZIo="; }; // trailing
`))
	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.Contains(t, keys, "k1.")
}

func TestParse_Errors(t *testing.T) {
	testCases := []struct {
		name string
		data string
		want string
	}{
		{
			name: "empty",
			data: "; just a comment\n",
			want: "no TSIG keys found",
		},
		{
			name: "bad algorithm",
			data: `key "k" { algorithm hmac-banana; secret "AAAA"; };`,
			want: "unsupported algorithm",
		},
		{
			name: "bad base64",
			data: `key "k" { algorithm hmac-sha256; secret "not base64!!"; };`,
			want: "invalid base64 secret",
		},
		{
			name: "missing secret",
			data: `key "k" { algorithm hmac-sha256; };`,
			want: "missing secret",
		},
		{
			name: "missing algorithm",
			data: `key "k" { secret "AAAA"; };`,
			want: "missing algorithm",
		},
		{
			name: "duplicate key",
			data: `
key "k" { algorithm hmac-sha256; secret "AAAA"; };
key "k" { algorithm hmac-sha256; secret "BBBB"; };`,
			want: "duplicate TSIG key",
		},
		{
			name: "unterminated",
			data: `key "k" { algorithm hmac-sha256; secret "AAAA"; `,
			want: "unterminated stanza",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.data))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestKeys_VerifyAndGenerate(t *testing.T) {
	secret := "32pD8A6DfOgRA78uPNzvC4SFhqwEaKySaVEQfQWHZIo="
	keys := Keys{
		"k1.": {Name: "k1.", Algorithm: dns.HmacSHA256, Secret: secret},
	}

	msg := []byte("hello world")

	tsig := &dns.TSIG{Hdr: dns.RR_Header{Name: "k1."}, Algorithm: dns.HmacSHA256}
	mac, err := keys.Generate(msg, tsig)
	require.NoError(t, err)
	tsig.MAC = strings.ToUpper(hexEncode(mac))

	assert.NoError(t, keys.Verify(msg, tsig))
}

func TestKeys_GenerateWrongAlgorithm(t *testing.T) {
	keys := Keys{
		"k1.": {Name: "k1.", Algorithm: dns.HmacSHA256, Secret: "32pD8A6DfOgRA78uPNzvC4SFhqwEaKySaVEQfQWHZIo="},
	}

	_, err := keys.Generate([]byte("x"), &dns.TSIG{Hdr: dns.RR_Header{Name: "k1."}, Algorithm: dns.HmacSHA512})
	assert.ErrorIs(t, err, dns.ErrKeyAlg)
}

func TestKeys_GenerateUnknownKey(t *testing.T) {
	keys := Keys{
		"k1.": {Name: "k1.", Algorithm: dns.HmacSHA256, Secret: "32pD8A6DfOgRA78uPNzvC4SFhqwEaKySaVEQfQWHZIo="},
	}

	_, err := keys.Generate([]byte("x"), &dns.TSIG{Hdr: dns.RR_Header{Name: "nope."}, Algorithm: dns.HmacSHA256})
	assert.ErrorIs(t, err, dns.ErrSecret)
}

func hexEncode(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = digits[c>>4]
		out[i*2+1] = digits[c&0x0f]
	}
	return string(out)
}
