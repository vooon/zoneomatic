package dnsfmt

import (
	"bytes"
	"testing"
)

func TestFormat(t *testing.T) {
	// *flagInc = false
	const mess = `$TTL    6H
$ORIGIN example.org.
@       IN      SOA     ns miek.miek.nl. 1282630067  4H 1H 7D 7200
                IN      NS  ns
example.org.		IN	NS  ns.example.org.
`
	out := &bytes.Buffer{}
	if err := Reformat([]byte(mess), nil, out, false); err != nil {
		t.Fatalf("unexpected reformat error: %v", err)
	}
	if out.String() != `$TTL 6H
$ORIGIN example.org.
@               IN   SOA        ns miek.miek.nl. (
                                   1282630067   ; serial  Tue, 24 Aug 2010 06:07:47 UTC
                                   4H           ; refresh
                                   1H           ; retry
                                   1W           ; expire
                                   2H           ; minimum
                                   )
                IN   NS         ns
                IN   NS         ns
` {
		t.Fatalf("failed to properly reformat\n%s\n", out.String())
	}
}

func TestFormatCommentStart(t *testing.T) {
	const mess = `; example.nl,v 1.00 2015/03/19 14:31:47 root Exp
$ORIGIN example.nl.
`
	out := &bytes.Buffer{}
	if err := Reformat([]byte(mess), nil, out, false); err != nil {
		t.Fatalf("unexpected reformat error: %v", err)
	}
	if out.String() != `; example.nl,v 1.00 2015/03/19 14:31:47 root Exp
$ORIGIN example.nl.
` {
		t.Fatalf("failed to properly reformat\n%s\n", out.String())
	}
}

func TestFormatKeepTogether(t *testing.T) {
	// *flagInc = false
	const mess = `$ORIGIN miek.nl.
@       IN      SOA     linode.miek.nl. miek.miek.nl. (
			     1282630063 ; Serial
                             4H         ; Refresh
                             1H         ; Retry
                             7D         ; Expire
                             4H )       ; Negative Cache TTL
                IN      NS      linode.atoom.net.

                IN      MX      10 aspmx3.googlemail.com.

                IN      A       127.0.0.1

a               IN      A       127.0.0.1
                IN      AAAA    1::53

mmark           IN      CNAME   a

bot             IN      CNAME   a

www             IN      CNAME   a
go.dns          IN      TXT     "Hello DNS developer!"
x               IN      CNAME   a

nlgids          IN      CNAME   a
`
	out := &bytes.Buffer{}
	if err := Reformat([]byte(mess), nil, out, false); err != nil {
		t.Fatalf("unexpected reformat error: %v", err)
	}
	if out.String() != `$ORIGIN miek.nl.
@                    IN   SOA        linode miek (
                                        1282630063   ; serial  Tue, 24 Aug 2010 06:07:43 UTC
                                        4H           ; refresh
                                        1H           ; retry
                                        1W           ; expire
                                        4H           ; minimum
                                        )
                     IN   NS         linode.atoom.net.
                     IN   MX         10 aspmx3.googlemail.com.
                     IN   A          127.0.0.1

a                    IN   A          127.0.0.1
                     IN   AAAA       1::53

mmark                IN   CNAME      a
bot                  IN   CNAME      a
www                  IN   CNAME      a

go.dns               IN   TXT        "Hello DNS developer!"

x                    IN   CNAME      a
nlgids               IN   CNAME      a
` {
		t.Fatalf("failed to properly reformat\n%s\n", out.String())
	}
}

func TestFormatInvalidInputReturnsError(t *testing.T) {
	const mess = `$ORIGIN example.org.
@ IN SOA`
	out := &bytes.Buffer{}

	if err := Reformat([]byte(mess), nil, out, false); err == nil {
		t.Fatal("expected reformat error for invalid zone input")
	}
}

func TestFormatTXTMultiKeepsParenthesizedForm(t *testing.T) {
	const mess = `$ORIGIN example.org.
@ IN TXT ("abc" "def")
`
	out := &bytes.Buffer{}
	if err := Reformat([]byte(mess), nil, out, false); err != nil {
		t.Fatalf("unexpected reformat error: %v", err)
	}

	got := out.String()
	if !bytes.Contains([]byte(got), []byte("TXT        (\n")) {
		t.Fatalf("expected parenthesized TXT form, got:\n%s", got)
	}
	if !bytes.Contains([]byte(got), []byte(`"abc"`)) || !bytes.Contains([]byte(got), []byte(`"def"`)) {
		t.Fatalf("expected both TXT chunks, got:\n%s", got)
	}
}

func TestFormatTLSAStaysOneLine(t *testing.T) {
	const mess = `$ORIGIN example.org.
_25._tcp.example.org. TLSA 3 1 1 bbe71be3a546c68e3b802ab0d5e2417ae6c4c795b76250a7c6965914f57d5059
`
	out := &bytes.Buffer{}
	if err := Reformat([]byte(mess), nil, out, false); err != nil {
		t.Fatalf("unexpected reformat error: %v", err)
	}

	got := out.String()
	if bytes.Contains([]byte(got), []byte("TLSA       3 1 1 (\n")) {
		t.Fatalf("expected one-line TLSA form, got:\n%s", got)
	}
	if !bytes.Contains([]byte(got), []byte("TLSA       3 1 1 bbe71be3a546c68e3b802ab0d5e2417ae6c4c795b76250a7c6965914f57d5059")) {
		t.Fatalf("expected full one-line TLSA value, got:\n%s", got)
	}
}
