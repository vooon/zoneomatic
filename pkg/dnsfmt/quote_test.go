package dnsfmt

import "testing"

func TestQuote(t *testing.T) {
	tests := []struct{ in, out string }{
		{"plain", `"plain"`},
		{`a"b`, `"a\"b"`},
		{`back\`, `"back\\"`},
		{"nl\nx", `"nl\010x"`},
		{"del\x7f", `"del\127"`},
		{"tab\t", `"tab\009"`},
		{"\x00", `"\000"`},
		{"héllo", `"héllo"`},
	}
	for _, tc := range tests {
		if got := Quote([]byte(tc.in)); got != tc.out {
			t.Errorf("Quote(%q) = %s, want %s", tc.in, got, tc.out)
		}
	}
}
