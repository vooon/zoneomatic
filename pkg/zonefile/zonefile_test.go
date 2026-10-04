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

func TestLoad_ControlWithoutValue(t *testing.T) {
	for _, in := range []string{"$ORIGIN", "$TTL\n", "$INCLUDE ; comment\n"} {
		if _, err := Load([]byte(in)); err == nil {
			t.Errorf("expected parsing error for %q", in)
		}
	}
}

func TestLoad_RejectsNUL(t *testing.T) {
	if _, err := Load([]byte("a IN NS b\x00c\n")); err == nil {
		t.Error("expected parsing error for NUL byte")
	}
}

func TestSetDomain_DoesNotAliasCopies(t *testing.T) {
	// No trailing newline: the comment is the entry's last token.
	zf, err := Load([]byte("a IN A 192.0.2.1\n IN AAAA 2001:db8::1 ;note"))
	if err != nil {
		t.Fatal(err)
	}
	orig := zf.Entries()[1]
	cp := orig
	if err := cp.SetDomain([]byte("a")); err != nil {
		t.Fatal(err)
	}
	if len(orig.Domain()) != 0 {
		t.Errorf("original changed: domain %q", orig.Domain())
	}
	for name, e := range map[string]Entry{"original": orig, "copy": cp} {
		if c := e.Comments(); len(c) != 1 || string(c[0]) != ";note" {
			t.Errorf("%s lost its comment: %q", name, c)
		}
	}
}

func TestLoad_UnclosedParen(t *testing.T) {
	if _, err := Load([]byte("@ IN SOA a b (1 2 3 4 5\n")); err == nil {
		t.Error("expected parsing error for unclosed (")
	}
}

func TestLoad_LineEndings(t *testing.T) {
	if _, err := Load([]byte("a IN A 192.0.2.1\r\nb IN A 192.0.2.2\r\n")); err != nil {
		t.Errorf("CRLF must be accepted: %v", err)
	}
	if _, err := Load([]byte("a IN A 192.0.2.1\rb IN A 192.0.2.2\n")); err == nil {
		t.Error("expected parsing error for a lone CR")
	}
}
