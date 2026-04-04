package htpasswd

import (
	"bufio"
	"errors"
	"log/slog"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

type HTPasswd interface {
	Authenticate(user, password string) (ok, present bool)
}

type HTPasswdFile map[string]string

func NewFromFile(filename string) (HTPasswd, error) {

	ret := make(HTPasswdFile)

	fd, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer fd.Close() // nolint:errcheck

	scanner := bufio.NewScanner(fd)
	for scanner.Scan() {
		user, hash, ok := strings.Cut(scanner.Text(), ":")
		if ok {
			ret[user] = hash
		}
	}

	return ret, nil
}

func (s HTPasswdFile) Authenticate(user, password string) (ok bool, present bool) {
	hash, present := s[user]
	if !present {
		return false, false
	}

	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	ok = err == nil

	if err != nil && !errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		// Log that user's hash has unsupported format. Better than silently return 401.
		slog.Warn("htpasswd bcrypt compare failed", "user", user)
	}

	return
}
