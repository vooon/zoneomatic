package zonefile

import (
	"runtime"
	"testing"
	"time"
)

func TestLoad_UnterminatedQuote(t *testing.T) {
	for _, in := range []string{
		`a IN TXT "unterminated`,
		`a IN TXT "ends with backslash\`,
		// A value ending in a backslash written without escaping it; the
		// closing quote is escaped, which used to crash the lexer with an
		// index out of range.
		"_acme-challenge IN TXT \"x\\\"\n",
	} {
		if _, err := Load([]byte(in)); err == nil {
			t.Errorf("expected parsing error for %q", in)
		}
	}
}

func TestLoad_QuotedEscapes(t *testing.T) {
	zf, err := Load([]byte("a IN TXT \"x\\\"y\\\\\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	ents := zf.Entries()
	if len(ents) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(ents))
	}
	// Values are returned unescaped.
	if got := string(ents[0].Values()[0]); got != `x"y\` {
		t.Errorf("unexpected value %s", got)
	}
}

func TestLoad_ErrorsDoNotLeakLexer(t *testing.T) {
	before := runtime.NumGoroutine()
	for range 100 {
		_, _ = Load([]byte("a IN TXT \"bad\nb IN A 192.0.2.1\nc IN A 192.0.2.2\n"))
		_, _ = Load([]byte(")\nb IN A 192.0.2.1\n"))
	}

	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > before+5 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > before+5 {
		t.Errorf("lexer goroutines leaked: %d before, %d after", before, n)
	}
}

func TestValue_MalformedDecimalEscape(t *testing.T) {
	// Used to panic("malformed value") in the caller's goroutine.
	zf, err := Load([]byte("a IN TXT \"\\1x\" \"\\999\" \"\\0650\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	got := zf.Entries()[0].ValuesStrings()
	want := []string{"1x", "999", "A0"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("value %d: got %q, want %q", i, got[i], want[i])
		}
	}
}
