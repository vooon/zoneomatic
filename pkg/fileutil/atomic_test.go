package fileutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicWriteFile_PreservesMode(t *testing.T) {
	tmpDir := t.TempDir()
	filename := filepath.Join(tmpDir, "zonefile.zone")

	err := os.WriteFile(filename, []byte("old"), 0600)
	if err != nil {
		t.Fatalf("write initial file: %v", err)
	}

	err = AtomicWriteFile(filename, []byte("new"))
	if err != nil {
		t.Fatalf("atomic write: %v", err)
	}

	buf, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("read output file: %v", err)
	}
	if string(buf) != "new" {
		t.Fatalf("unexpected file content: %q", string(buf))
	}

	st, err := os.Stat(filename)
	if err != nil {
		t.Fatalf("stat output file: %v", err)
	}
	if got, want := st.Mode().Perm(), os.FileMode(0600); got != want {
		t.Fatalf("unexpected mode: got %o want %o", got, want)
	}
}
