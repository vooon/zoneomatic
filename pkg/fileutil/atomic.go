package fileutil

import (
	"os"
	"path/filepath"
)

// AtomicWriteFile writes data to filename using a temp file + rename.
// If filename exists, its permission bits are preserved.
func AtomicWriteFile(filename string, data []byte) error {
	mode := os.FileMode(0644)
	if st, err := os.Stat(filename); err == nil {
		mode = st.Mode().Perm()
	}

	dir := filepath.Dir(filename)
	tmp, err := os.CreateTemp(dir, filepath.Base(filename)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // nolint:errcheck

	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	return os.Rename(tmpName, filename)
}
