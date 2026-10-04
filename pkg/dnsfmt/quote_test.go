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

func TestStripOrigin(t *testing.T) {
	tests := []struct{ origin, name, out string }{
		{"example.com.", "example.com.", "@"},
		{"example.com.", "www.example.com.", "www"},
		{"example.com.", "WWW.Example.COM.", "WWW"},
		{"example.com.", "myexample.com.", "myexample.com."},
		{"x.example.com.", "00x.example.com.", "00x.example.com."},
		{"example.com.", `a\.example.com.`, `a\.example.com.`},
		{"example.com.", "other.org.", "other.org."},
		{"", "www", "www"},
	}
	for _, tc := range tests {
		if got := string(StripOrigin([]byte(tc.origin), []byte(tc.name))); got != tc.out {
			t.Errorf("StripOrigin(%q, %q) = %q, want %q", tc.origin, tc.name, got, tc.out)
		}
	}
}

func TestNameEqual(t *testing.T) {
	if !NameEqual([]byte("WWW.Example.COM."), []byte("www.example.com.")) {
		t.Error("ASCII case must be ignored")
	}
	if NameEqual([]byte("\xcd."), []byte("\xf0.")) {
		t.Error("different non-ASCII bytes must not be equal")
	}
	if NameEqual([]byte("Ä."), []byte("ä.")) {
		t.Error("non-ASCII letters are compared exactly")
	}
}
