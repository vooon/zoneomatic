package zone

import (
	"context"
	"net/netip"
	"os"
	"path"
	"testing"
	"testing/synctest"

	fcopy "github.com/otiai10/copy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew_Ok(t *testing.T) {
	assert := assert.New(t)

	ctrl, err := New("./testdata/at.example.com.zone", "./testdata/mx.example.com.zone")
	if assert.NoError(err) {
		assert.Len(ctrl.(*DomainCtrl).files, 2)
	}
}

func TestNew_Bad(t *testing.T) {
	assert := assert.New(t)

	_, err := New("testdata/not_existing_file.zone")
	assert.ErrorIs(err, os.ErrNotExist)

	_, err = New("./testdata/bad_no_soa.zone")
	assert.ErrorIs(err, ErrSoaNotFound)
}

func TestFile_UpdateDDNSAddress(t *testing.T) {

	testv4, _ := netip.ParseAddr("1.2.3.4")
	testv6, _ := netip.ParseAddr("2001:dead:beef::1")
	// loopv4, _ := netip.ParseAddr("127.0.0.1")
	// loopv6, _ := netip.ParseAddr("::1")

	testCases := []struct {
		name         string
		file         string
		domain       string
		addrs        []netip.Addr
		expectedFile string
	}{
		{"new-v4", "./testdata/at.example.com.zone", "new-entry", []netip.Addr{testv4}, "./testdata/expected-new-v4.zone"},
		{"new-v6", "./testdata/at.example.com.zone", "new-entry", []netip.Addr{testv6}, "./testdata/expected-new-v6.zone"},
		{"new-v4v6", "./testdata/at.example.com.zone", "new-entry", []netip.Addr{testv4, testv6}, "./testdata/expected-new-v4v6.zone"},
		{"loop-v4", "./testdata/at.example.com.zone", "loop", []netip.Addr{testv4}, "./testdata/expected-loop-v4.zone"},
		{"loop-v6", "./testdata/at.example.com.zone", "loop", []netip.Addr{testv6}, "./testdata/expected-loop-v6.zone"},
		{"loop-v4v6", "./testdata/at.example.com.zone", "loop", []netip.Addr{testv4, testv6}, "./testdata/expected-loop-v4v6.zone"},
		// XXX: not really working! but it's unlikely condition for a DDNS
		// {"many-loop", "./testdata/at.example.com.zone", "loop", []netip.Addr{loopv4, loopv6, testv4, testv6}, "./testdata/expected-many-loop.zone"},
		{"new-mx", "./testdata/mx.example.com.zone", "mx.example.com.", []netip.Addr{testv4, testv6}, "./testdata/expected-new-mx.zone"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// NOTE: use synctest to have predictable time.New()
			synctest.Test(t, func(t *testing.T) {
				assert := assert.New(t)
				ctx := context.TODO()
				f := newZoneTemp(t, tc.file)

				err := f.UpdateDDNSAddress(ctx, tc.domain, tc.addrs)
				assert.NoError(err)
				assertFiles(t, tc.expectedFile, f.path)
			})
		})
	}
}

func TestFile_UpdateACMEChallenge(t *testing.T) {

	token := "fake/XKo9kaBlVnj9q0XWAWdoSYEPCOrhiZk3ztoBHx5c3O6X"

	testCases := []struct {
		name         string
		file         string
		domain       string
		token        string
		expectedFile string
	}{
		{"new-at", "./testdata/at.example.com.zone", "_acme-challenge", token, "./testdata/expected-acme-new-at.zone"},
		{"zot-at", "./testdata/at.example.com.zone", "_acme-challenge.zot", token, "./testdata/expected-acme-new-zot.zone"},
		{"clean-at", "./testdata/at.example.com.zone", "_acme-challenge.zot", "", "./testdata/expected-acme-clean-at.zone"},
		{"new-mx", "./testdata/mx.example.com.zone", "_acme-challenge", token, "./testdata/expected-acme-new-mx.zone"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// NOTE: use synctest to have predictable time.New()
			synctest.Test(t, func(t *testing.T) {
				assert := assert.New(t)
				ctx := context.TODO()
				f := newZoneTemp(t, tc.file)

				err := f.UpdateACMEChallenge(ctx, tc.domain, tc.token, "")
				assert.NoError(err)
				assertFiles(t, tc.expectedFile, f.path)
			})
		})
	}
}

func newZoneTemp(t *testing.T, file string) *File {
	t.Helper()
	require := require.New(t)

	tmp := t.TempDir()
	dest := path.Join(tmp, path.Base(file))

	err := fcopy.Copy(file, dest)
	require.NoError(err)

	ctrl, err := New(dest)
	require.NoError(err)

	dct := ctrl.(*DomainCtrl)
	require.Len(dct.files, 1)

	return dct.files[0]
}

func assertFiles(t *testing.T, expectedFile, obtainedFile string, msgAndArgs ...any) bool {
	t.Helper()
	require := require.New(t)

	b1, err := os.ReadFile(expectedFile)
	require.NoError(err)

	b2, err := os.ReadFile(obtainedFile)
	require.NoError(err)

	return assert.Equal(t, string(b1), string(b2), msgAndArgs...)
}
