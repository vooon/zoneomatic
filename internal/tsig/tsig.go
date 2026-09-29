// Package tsig parses BIND-style TSIG key files (as produced by tsig-keygen)
// and provides a dns.TsigProvider that authenticates dynamic DNS updates.
package tsig

import (
	"crypto/hmac"
	"crypto/md5"  // nolint:gosec // HMAC-MD5 is kept for compatibility with legacy keys.
	"crypto/sha1" // nolint:gosec // HMAC-SHA1 is kept for compatibility with legacy keys.
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"os"
	"strings"

	"github.com/miekg/dns"
)

// Key is a single parsed TSIG key.
type Key struct {
	// Name is the canonical key name (lowercase, fully qualified).
	Name string
	// Algorithm is the canonical miekg/dns algorithm name (e.g. "hmac-sha256.").
	Algorithm string
	// Secret is the base64-encoded shared secret as written in the key file.
	Secret string
}

// Keys maps a canonical key name to its key material.
type Keys map[string]Key

var _ dns.TsigProvider = Keys{}

// hmacAlgorithms is the single source of truth for the supported TSIG
// algorithms: canonical miekg/dns name -> hash constructor. It is used both to
// validate parsed key files and to build the HMAC used for signing/verifying.
var hmacAlgorithms = map[string]func() hash.Hash{
	dns.HmacMD5:    md5.New,  // nolint:gosec // legacy compatibility
	dns.HmacSHA1:   sha1.New, // nolint:gosec // legacy compatibility
	dns.HmacSHA224: sha256.New224,
	dns.HmacSHA256: sha256.New,
	dns.HmacSHA384: sha512.New384,
	dns.HmacSHA512: sha512.New,
}

// NewFromFile parses a BIND-format TSIG key file (the output of tsig-keygen or
// ddns-confgen -q). Multiple `key` stanzas are allowed.
func NewFromFile(filename string) (Keys, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	return Parse(data)
}

// Parse parses BIND-format `key "name" { ... };` stanzas. It tolerates
// comments (#, //, /* */), optional parentheses and arbitrary whitespace, and
// ignores unrelated top-level statements.
func Parse(data []byte) (Keys, error) {
	tokens, err := tokenize(data)
	if err != nil {
		return nil, err
	}

	keys := make(Keys)
	for i := 0; i < len(tokens); {
		if tokens[i].kind != tokWord || tokens[i].val != "key" {
			i++
			continue
		}

		key, next, err := parseKey(tokens, i)
		if err != nil {
			return nil, err
		}
		if _, exists := keys[key.Name]; exists {
			return nil, fmt.Errorf("duplicate TSIG key: %q", key.Name)
		}
		keys[key.Name] = key
		i = next
	}

	if len(keys) == 0 {
		return nil, errors.New("no TSIG keys found")
	}

	return keys, nil
}

func parseKey(tokens []token, start int) (Key, int, error) {
	i := start + 1

	if i >= len(tokens) || (tokens[i].kind != tokString && tokens[i].kind != tokWord) {
		return Key{}, 0, fmt.Errorf("expected key name after %q", "key")
	}
	rawName := tokens[i].val
	i++

	if i >= len(tokens) || tokens[i].kind != tokLBrace {
		return Key{}, 0, fmt.Errorf("expected '{' after key name %q", rawName)
	}
	i++

	key := Key{Name: dns.CanonicalName(rawName)}

	for i < len(tokens) && tokens[i].kind != tokRBrace {
		word := tokens[i]
		if word.kind != tokWord {
			i++
			continue
		}

		switch word.val {
		case "algorithm":
			i++
			if i >= len(tokens) || tokens[i].kind != tokWord {
				return Key{}, 0, fmt.Errorf("key %q: expected algorithm value", rawName)
			}
			algorithm := dns.CanonicalName(tokens[i].val)
			if _, ok := hmacAlgorithms[algorithm]; !ok {
				return Key{}, 0, fmt.Errorf("key %q: unsupported algorithm %q", rawName, tokens[i].val)
			}
			key.Algorithm = algorithm
			i++
		case "secret":
			i++
			if i >= len(tokens) || tokens[i].kind != tokString {
				return Key{}, 0, fmt.Errorf("key %q: expected secret value", rawName)
			}
			if _, err := base64.StdEncoding.DecodeString(tokens[i].val); err != nil {
				return Key{}, 0, fmt.Errorf("key %q: invalid base64 secret: %w", rawName, err)
			}
			key.Secret = tokens[i].val
			i++
		default:
			// Skip unknown statement up to the next ';'.
			for i < len(tokens) && tokens[i].kind != tokSemicolon && tokens[i].kind != tokRBrace {
				i++
			}
		}

		if i < len(tokens) && tokens[i].kind == tokSemicolon {
			i++
		}
	}

	if i >= len(tokens) {
		return Key{}, 0, fmt.Errorf("key %q: unterminated stanza", rawName)
	}
	i++ // consume '}'

	// Optional trailing ';'.
	if i < len(tokens) && tokens[i].kind == tokSemicolon {
		i++
	}

	if key.Algorithm == "" {
		return Key{}, 0, fmt.Errorf("key %q: missing algorithm", rawName)
	}
	if key.Secret == "" {
		return Key{}, 0, fmt.Errorf("key %q: missing secret", rawName)
	}

	return key, i, nil
}

type tokenKind int

const (
	tokWord tokenKind = iota
	tokString
	tokLBrace
	tokRBrace
	tokSemicolon
)

type token struct {
	kind tokenKind
	val  string
}

func tokenize(data []byte) ([]token, error) {
	var tokens []token

	for i := 0; i < len(data); {
		c := data[i]

		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '(' || c == ')':
			i++
		case c == '#':
			i = skipLine(data, i)
		case c == '/' && i+1 < len(data) && data[i+1] == '/':
			i = skipLine(data, i)
		case c == '/' && i+1 < len(data) && data[i+1] == '*':
			end := indexSeq(data, i+2, "*/")
			if end < 0 {
				return nil, errors.New("unterminated block comment")
			}
			i = end + 2
		case c == '{':
			tokens = append(tokens, token{kind: tokLBrace, val: "{"})
			i++
		case c == '}':
			tokens = append(tokens, token{kind: tokRBrace, val: "}"})
			i++
		case c == ';':
			tokens = append(tokens, token{kind: tokSemicolon, val: ";"})
			i++
		case c == '"':
			str, next, err := readString(data, i)
			if err != nil {
				return nil, err
			}
			tokens = append(tokens, token{kind: tokString, val: str})
			i = next
		default:
			start := i
			for i < len(data) && !isDelimiter(data[i]) {
				i++
			}
			tokens = append(tokens, token{kind: tokWord, val: string(data[start:i])})
		}
	}

	return tokens, nil
}

func readString(data []byte, start int) (string, int, error) {
	var b strings.Builder

	for i := start + 1; i < len(data); i++ {
		switch data[i] {
		case '\\':
			if i+1 < len(data) {
				b.WriteByte(data[i+1])
				i++
			}
		case '"':
			return b.String(), i + 1, nil
		default:
			b.WriteByte(data[i])
		}
	}

	return "", 0, errors.New("unterminated quoted string")
}

func isDelimiter(c byte) bool {
	switch c {
	case ' ', '\t', '\r', '\n', '(', ')', '{', '}', ';', '"', '#':
		return true
	default:
		return false
	}
}

func skipLine(data []byte, i int) int {
	for i < len(data) && data[i] != '\n' {
		i++
	}
	return i
}

func indexSeq(data []byte, from int, seq string) int {
	for i := from; i+len(seq) <= len(data); i++ {
		if string(data[i:i+len(seq)]) == seq {
			return i
		}
	}
	return -1
}

// Generate signs a message using the key named in t.
func (keys Keys) Generate(msg []byte, t *dns.TSIG) ([]byte, error) {
	k, ok := keys[dns.CanonicalName(t.Hdr.Name)]
	if !ok {
		return nil, dns.ErrSecret
	}
	if dns.CanonicalName(t.Algorithm) != k.Algorithm {
		return nil, dns.ErrKeyAlg
	}

	raw, err := base64.StdEncoding.DecodeString(k.Secret)
	if err != nil {
		return nil, err
	}

	mac, err := newHMAC(k.Algorithm, raw)
	if err != nil {
		return nil, err
	}
	mac.Write(msg)

	return mac.Sum(nil), nil
}

// Verify checks the HMAC in t against the configured key.
func (keys Keys) Verify(msg []byte, t *dns.TSIG) error {
	k, ok := keys[dns.CanonicalName(t.Hdr.Name)]
	if !ok {
		return dns.ErrSecret
	}
	if dns.CanonicalName(t.Algorithm) != k.Algorithm {
		return dns.ErrKeyAlg
	}

	raw, err := base64.StdEncoding.DecodeString(k.Secret)
	if err != nil {
		return err
	}

	mac, err := newHMAC(k.Algorithm, raw)
	if err != nil {
		return err
	}
	mac.Write(msg)

	want, err := hex.DecodeString(t.MAC)
	if err != nil {
		return err
	}

	if !hmac.Equal(mac.Sum(nil), want) {
		return dns.ErrSig
	}

	return nil
}

func newHMAC(algorithm string, key []byte) (hash.Hash, error) {
	newHash, ok := hmacAlgorithms[algorithm]
	if !ok {
		return nil, dns.ErrKeyAlg
	}

	return hmac.New(newHash, key), nil
}
