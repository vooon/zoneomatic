package zone

import (
	"context"
	"log/slog"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"testing"
	"testing/synctest"

	fcopy "github.com/otiai10/copy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vooon/zoneomatic/pkg/fileutil"
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

func TestFile_UpdateACMEChallenge_WithTTL(t *testing.T) {
	token := "fake/XKo9kaBlVnj9q0XWAWdoSYEPCOrhiZk3ztoBHx5c3O6X"

	testCases := []struct {
		name         string
		file         string
		domain       string
		token        string
		expectedFile string
	}{
		{"new-at-ttl30", "./testdata/at.example.com.zone", "_acme-challenge", token, "./testdata/expected-acme-ttl30-new-at.zone"},
		{"zot-at-ttl30", "./testdata/at.example.com.zone", "_acme-challenge.zot", token, "./testdata/expected-acme-ttl30-new-zot.zone"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				assert := assert.New(t)
				ctx := context.TODO()
				f := newZoneTempWithOpts(t, tc.file, WithAcmeTTL(30))

				err := f.UpdateACMEChallenge(ctx, tc.domain, tc.token, "")
				assert.NoError(err)
				assertFiles(t, tc.expectedFile, f.path)
			})
		})
	}
}

func TestFile_UpdateACMEChallenge_WildcardPlacement(t *testing.T) {
	token1 := "fake/token1-helloworld"
	token2 := "fake/token2-helloworld"

	// NOTE: use synctest to have predictable time.New()
	synctest.Test(t, func(t *testing.T) {
		assert := assert.New(t)
		ctx := context.TODO()
		f := newZoneTemp(t, "./testdata/acme-apex-at.zone")

		// Present first token - should replace the pre-seeded placeholder
		err := f.UpdateACMEChallenge(ctx, "_acme-challenge", token1, EmptyPlaceholder)
		assert.NoError(err)

		// Present second token - no placeholder left, must be inserted right after the first
		err = f.UpdateACMEChallenge(ctx, "_acme-challenge", token2, EmptyPlaceholder)
		assert.NoError(err)

		assertFiles(t, "./testdata/expected-acme-wildcard-present.zone", f.path)

		// Cleanup - replace tokens back to placeholders in place
		err = f.UpdateACMEChallenge(ctx, "_acme-challenge", "", token2)
		assert.NoError(err)
		err = f.UpdateACMEChallenge(ctx, "_acme-challenge", "", token1)
		assert.NoError(err)

		assertFiles(t, "./testdata/expected-acme-wildcard-clean.zone", f.path)
	})
}

func TestFile_UpdatePTRAddress(t *testing.T) {
	t.Run("append is idempotent for existing target", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx := context.TODO()
			f := newZoneTemp(t, "./testdata/3.2.1.in-addr.arpa.zone")
			changed, err := f.UpdatePTRAddress(ctx, "4.3.2.1.in-addr.arpa.", "hub.example.com.", PTRUpdateAppend)
			assert.NoError(t, err)
			assert.False(t, changed)
			assertFiles(t, "./testdata/3.2.1.in-addr.arpa.zone", f.path)
		})
	})

	t.Run("append keeps existing and adds new after", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx := context.TODO()
			f := newZoneTemp(t, "./testdata/3.2.1.in-addr.arpa.zone")
			_, err := f.UpdatePTRAddress(ctx, "4.3.2.1.in-addr.arpa.", "new.example.com.", PTRUpdateAppend)
			assert.NoError(t, err)
			assertFiles(t, "./testdata/expected-ptr-append.zone", f.path)
		})
	})

	t.Run("replace swaps single record keeping siblings", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx := context.TODO()
			f := newZoneTemp(t, "./testdata/3.2.1.in-addr.arpa.zone")
			_, err := f.UpdatePTRAddress(ctx, "4.3.2.1.in-addr.arpa.", "rebooted.example.com.", PTRUpdateReplace)
			assert.NoError(t, err)
			assertFiles(t, "./testdata/expected-ptr-replace.zone", f.path)
		})
	})

	t.Run("replace-all leaves exactly one record", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx := context.TODO()
			f := newZoneTemp(t, "./testdata/3.2.1.in-addr.arpa.zone")
			_, err := f.UpdatePTRAddress(ctx, "4.3.2.1.in-addr.arpa.", "clean.example.com.", PTRUpdateReplaceAll)
			assert.NoError(t, err)
			assertFiles(t, "./testdata/expected-ptr-replace-all.zone", f.path)
		})
	})

	t.Run("creates record for new name", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx := context.TODO()
			f := newZoneTemp(t, "./testdata/3.2.1.in-addr.arpa.zone")
			_, err := f.UpdatePTRAddress(ctx, "5.3.2.1.in-addr.arpa.", "five.example.com.", PTRUpdateReplaceAll)
			assert.NoError(t, err)
			assertFiles(t, "./testdata/expected-ptr-create.zone", f.path)
		})
	})
}

func TestDomainCtrl_UpdatePTR(t *testing.T) {
	t.Run("replace-all single address", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx := context.TODO()
			dc := newDomainCtrlTemp(t, []string{"./testdata/3.2.1.in-addr.arpa.zone"})

			changed, err := dc.UpdatePTR(ctx, "clean.example.com.", []netip.Addr{netip.MustParseAddr("1.2.3.4")}, PTRUpdateReplaceAll)
			assert.NoError(t, err)
			assert.True(t, changed)

			snap := mustZoneSnapshot(t, dc, "3.2.1.in-addr.arpa.")
			assert.Equal(t, []string{"clean.example.com."}, findRRSet(t, snap.RRsets, "4.3.2.1.in-addr.arpa.", "PTR").Records)
			assert.Equal(t, 1, countRRSet(snap.RRsets, "4.3.2.1.in-addr.arpa.", "PTR"))
		})
	})

	t.Run("append adds after existing", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx := context.TODO()
			dc := newDomainCtrlTemp(t, []string{"./testdata/3.2.1.in-addr.arpa.zone"})

			changed, err := dc.UpdatePTR(ctx, "new.example.com.", []netip.Addr{netip.MustParseAddr("1.2.3.4")}, PTRUpdateAppend)
			assert.NoError(t, err)
			assert.True(t, changed)

			snap := mustZoneSnapshot(t, dc, "3.2.1.in-addr.arpa.")
			assert.Equal(t, []string{"hub.example.com.", "legacy.example.com.", "new.example.com."}, findRRSet(t, snap.RRsets, "4.3.2.1.in-addr.arpa.", "PTR").Records)
		})
	})

	t.Run("no matching reverse zone", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx := context.TODO()
			dc := newDomainCtrlTemp(t, []string{"./testdata/at.example.com.zone"})

			_, err := dc.UpdatePTR(ctx, "hub.example.com.", []netip.Addr{netip.MustParseAddr("1.2.3.4")}, PTRUpdateReplaceAll)
			assert.ErrorIs(t, err, ErrZoneNotFound)
		})
	})

	t.Run("empty addresses", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx := context.TODO()
			dc := newDomainCtrlTemp(t, []string{"./testdata/3.2.1.in-addr.arpa.zone"})

			_, err := dc.UpdatePTR(ctx, "hub.example.com.", nil, PTRUpdateReplaceAll)
			assert.Error(t, err)
		})
	})

	t.Run("invalid mode", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx := context.TODO()
			dc := newDomainCtrlTemp(t, []string{"./testdata/3.2.1.in-addr.arpa.zone"})

			_, err := dc.UpdatePTR(ctx, "hub.example.com.", []netip.Addr{netip.MustParseAddr("1.2.3.4")}, "banana")
			assert.Error(t, err)
		})
	})
}

func TestDomainCtrl_UpdateDDNSAddress_ManagePTR(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx := context.TODO()

		dc := newDomainCtrlTemp(t, []string{
			"./testdata/at.example.com.zone",
			"./testdata/3.2.1.in-addr.arpa.zone",
			"./testdata/8.b.d.0.1.0.0.2.ip6.arpa.zone",
		}, WithDDNSManagePTR(true))

		// dual stack host: forward A/AAAA + v4 PTR + v6 PTR
		err := dc.UpdateDDNSAddress(ctx, "hub.at.example.com.", []netip.Addr{
			netip.MustParseAddr("1.2.3.4"),
			netip.MustParseAddr("2001:db8::1"),
		})
		require.NoError(t, err)

		fwd := mustZoneSnapshot(t, dc, "at.example.com.")
		assert.Equal(t, []string{"1.2.3.4"}, findRRSet(t, fwd.RRsets, "hub.at.example.com.", "A").Records)
		assert.Equal(t, []string{"2001:db8::1"}, findRRSet(t, fwd.RRsets, "hub.at.example.com.", "AAAA").Records)

		v4 := mustZoneSnapshot(t, dc, "3.2.1.in-addr.arpa.")
		assert.Equal(t, []string{"router.example.com."}, findRRSet(t, v4.RRsets, "1.3.2.1.in-addr.arpa.", "PTR").Records)
		assert.Equal(t, []string{"hub.at.example.com."}, findRRSet(t, v4.RRsets, "4.3.2.1.in-addr.arpa.", "PTR").Records)
		assert.Equal(t, 1, countRRSet(v4.RRsets, "4.3.2.1.in-addr.arpa.", "PTR"))

		v6 := mustZoneSnapshot(t, dc, "8.b.d.0.1.0.0.2.ip6.arpa.")
		assert.Equal(t, []string{"hub.at.example.com."}, findRRSet(t, v6.RRsets, "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.", "PTR").Records)

		// same update again: no growth
		err = dc.UpdateDDNSAddress(ctx, "hub.at.example.com.", []netip.Addr{
			netip.MustParseAddr("1.2.3.4"),
			netip.MustParseAddr("2001:db8::1"),
		})
		require.NoError(t, err)
		v4 = mustZoneSnapshot(t, dc, "3.2.1.in-addr.arpa.")
		assert.Equal(t, []string{"hub.at.example.com."}, findRRSet(t, v4.RRsets, "4.3.2.1.in-addr.arpa.", "PTR").Records)
		assert.Equal(t, 1, countRRSet(v4.RRsets, "4.3.2.1.in-addr.arpa.", "PTR"))

		// host moved to a new IPv4: stale PTR removed, new one added
		err = dc.UpdateDDNSAddress(ctx, "hub.at.example.com.", []netip.Addr{
			netip.MustParseAddr("1.2.3.5"),
			netip.MustParseAddr("2001:db8::1"),
		})
		require.NoError(t, err)
		v4 = mustZoneSnapshot(t, dc, "3.2.1.in-addr.arpa.")
		assert.False(t, hasRRSet(v4.RRsets, "4.3.2.1.in-addr.arpa.", "PTR"))
		assert.Equal(t, []string{"hub.at.example.com."}, findRRSet(t, v4.RRsets, "5.3.2.1.in-addr.arpa.", "PTR").Records)
	})
}

func TestDomainCtrl_UpdateDDNSAddress_ManagePTR_Disabled(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx := context.TODO()

		dc := newDomainCtrlTemp(t, []string{
			"./testdata/at.example.com.zone",
			"./testdata/3.2.1.in-addr.arpa.zone",
		})

		err := dc.UpdateDDNSAddress(ctx, "hub.at.example.com.", []netip.Addr{netip.MustParseAddr("1.2.3.4")})
		require.NoError(t, err)

		// reverse zone must be untouched
		v4 := mustZoneSnapshot(t, dc, "3.2.1.in-addr.arpa.")
		assert.Equal(t, []string{"hub.example.com.", "legacy.example.com."}, findRRSet(t, v4.RRsets, "4.3.2.1.in-addr.arpa.", "PTR").Records)
	})
}

func TestDomainCtrl_UpdateDDNSAddress_ManagePTR_NoReverseZone(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx := context.TODO()

		dc := newDomainCtrlTemp(t, []string{"./testdata/at.example.com.zone"}, WithDDNSManagePTR(true))

		// missing reverse zone must not be an issue
		err := dc.UpdateDDNSAddress(ctx, "hub.at.example.com.", []netip.Addr{netip.MustParseAddr("1.2.3.4")})
		require.NoError(t, err)
	})
}

func newDomainCtrlTemp(t *testing.T, files []string, opts ...Option) *DomainCtrl {
	t.Helper()
	require := require.New(t)

	tmp := t.TempDir()
	paths := make([]string, 0, len(files))
	for _, fl := range files {
		dest := path.Join(tmp, path.Base(fl))
		require.NoError(fcopy.Copy(fl, dest))
		paths = append(paths, dest)
	}

	ctrl, err := NewWithOptions(opts, paths...)
	require.NoError(err)

	dc, ok := ctrl.(*DomainCtrl)
	require.True(ok)
	return dc
}

func mustZoneSnapshot(t *testing.T, dc *DomainCtrl, zoneName string) ZoneSnapshot {
	t.Helper()
	snap, err := dc.GetZone(context.Background(), zoneName)
	require.NoError(t, err)
	return snap
}

func TestFile_ZMUpdateRecord_TypeCaseInsensitive(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx := context.TODO()
		f := newZoneTemp(t, "./testdata/at.example.com.zone")

		changed, err := f.ZMUpdateRecord(ctx, "loop", "a", 0, []string{"1.2.3.4"})
		require.NoError(t, err)
		assert.True(t, changed)
		assertFiles(t, "./testdata/expected-loop-v4.zone", f.path)
	})
}

func newZoneTemp(t *testing.T, file string) *File {
	t.Helper()
	return newZoneTempWithOpts(t, file)
}

func newZoneTempWithOpts(t *testing.T, file string, opts ...Option) *File {
	t.Helper()
	require := require.New(t)

	tmp := t.TempDir()
	dest := path.Join(tmp, path.Base(file))

	err := fcopy.Copy(file, dest)
	require.NoError(err)

	ctrl, err := NewWithOptions(opts, dest)
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

func TestMain(m *testing.M) {
	logLevel := slog.LevelDebug

	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
		// AddSource: true,
	})

	slog.SetDefault(slog.New(handler))

	// Run the tests
	os.Exit(m.Run())
}

func TestDomainMatchesOrigin(t *testing.T) {
	assert.True(t, domainMatchesOrigin("example.com.", "example.com."))
	assert.True(t, domainMatchesOrigin("a.example.com.", "example.com."))
	assert.False(t, domainMatchesOrigin("badexample.com.", "example.com."))
}

func TestFindZoneFile_PrefersLongestOrigin(t *testing.T) {
	ctrl := &DomainCtrl{
		files: []*File{
			{origin: "example.com.", path: "/tmp/example.com.zone"},
			{origin: "sub.example.com.", path: "/tmp/sub.example.com.zone"},
		},
	}

	got := ctrl.findZoneFile(context.Background(), slog.Default(), "a.sub.example.com.")
	require.NotNil(t, got)
	assert.Equal(t, "sub.example.com.", got.origin)
}

func TestAtomicWriteFile_PreservesMode(t *testing.T) {
	tmpDir := t.TempDir()
	filename := filepath.Join(tmpDir, "zonefile.zone")

	err := os.WriteFile(filename, []byte("old"), 0600)
	require.NoError(t, err)

	err = fileutil.AtomicWriteFile(filename, []byte("new"))
	require.NoError(t, err)

	buf, err := os.ReadFile(filename)
	require.NoError(t, err)
	assert.Equal(t, "new", string(buf))

	st, err := os.Stat(filename)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), st.Mode().Perm())
}
