package zone

import (
	"context"
	"os"
	"testing"
	"testing/synctest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFile_UpdateACMEChallenge_TTLEqualToDefaultIsDropped(t *testing.T) {
	// The zone has $TTL 60. With --acme-ttl 60 the written record carries
	// no TTL column: the file must look exactly like the one written
	// without --acme-ttl.
	synctest.Test(t, func(t *testing.T) {
		f := newZoneTempWithOpts(t, "./testdata/at.example.com.zone", WithAcmeTTL(60))
		require.NoError(t, f.UpdateACMEChallenge(context.TODO(), "_acme-challenge", "fake/XKo9kaBlVnj9q0XWAWdoSYEPCOrhiZk3ztoBHx5c3O6X", ""))
		assertFiles(t, "./testdata/expected-acme-new-at.zone", f.path)
	})
}

func TestFile_RejectsInjectedRecords(t *testing.T) {
	ctx := context.TODO()
	f := newZoneTemp(t, "./testdata/at.example.com.zone")
	before, err := os.ReadFile(f.path)
	require.NoError(t, err)

	cases := map[string]func() error{
		"zm/update newline": func() error {
			_, err := f.ZMUpdateRecord(ctx, "loop.at.example.com.", "A", 0, []string{"1.2.3.4\nevil IN A 6.6.6.6"})
			return err
		},
		"zm/update comment": func() error {
			_, err := f.ZMUpdateRecord(ctx, "loop.at.example.com.", "A", 0, []string{"1.2.3.4 ; note"})
			return err
		},
		"zm/update directive": func() error {
			_, err := f.ZMUpdateRecord(ctx, "loop.at.example.com.", "A", 0, []string{"1.2.3.4\n$INCLUDE /etc/passwd"})
			return err
		},
		"pdns replace": func() error {
			_, err := f.ReplaceRRSet(ctx, "loop.at.example.com.", "A", 60, []string{"1.2.3.4\nevil IN A 6.6.6.6"})
			return err
		},
		"rfc2136 add": func() error {
			_, err := f.ApplyRecordUpdate(ctx, "loop.at.example.com.", "A", 0, []string{"1.2.3.4\nevil IN A 6.6.6.6"}, nil)
			return err
		},
		"ptr target": func() error {
			_, err := f.UpdatePTRAddress(ctx, "9.at.example.com.", "host.example.com.\nevil IN A 6.6.6.6", PTRUpdateAppend)
			return err
		},
		"owner with newline": func() error {
			_, err := f.ZMUpdateRecord(ctx, "evil IN A 6.6.6.6\nloop.at.example.com.", "A", 0, []string{"1.2.3.4"})
			return err
		},
	}
	for name, run := range cases {
		t.Run(name, func(t *testing.T) {
			assert.ErrorIs(t, run(), ErrInvalidRecord)
		})
	}

	after, err := os.ReadFile(f.path)
	require.NoError(t, err)
	assert.Equal(t, string(before), string(after), "zone file must be untouched")
}

func TestFile_ReplaceRRSet_QuotedRdataIsKept(t *testing.T) {
	ctx := context.TODO()
	f := newZoneTemp(t, "./testdata/at.example.com.zone")

	_, err := f.ReplaceRRSet(ctx, "at.example.com.", "CAA", 60, []string{`0 issue "letsencrypt.org; validationmethods=dns-01"`})
	require.NoError(t, err)

	snap, err := f.Snapshot(ctx)
	require.NoError(t, err)
	assert.Equal(t, []string{"0 issue letsencrypt.org; validationmethods=dns-01"}, findRRSet(t, snap.RRsets, "at.example.com.", "CAA").Records)
}

func TestFile_ApplyRecordUpdate_MultiFieldValues(t *testing.T) {
	// MX rdata has two fields; add and remove must match it however it is
	// spaced, and must not duplicate an existing value.
	ctx := context.TODO()
	f := newZoneTemp(t, "./testdata/at.example.com.zone")

	changed, err := f.ApplyRecordUpdate(ctx, "at.example.com.", "MX", 0, []string{"10 mx1.example.com."}, nil)
	require.NoError(t, err)
	assert.True(t, changed)

	changed, err = f.ApplyRecordUpdate(ctx, "at.example.com.", "MX", 0, []string{"10   mx1.example.com.", "20 mx2.example.com."}, nil)
	require.NoError(t, err)
	assert.True(t, changed)

	snap, err := f.Snapshot(ctx)
	require.NoError(t, err)
	assert.Equal(t, []string{"10 mx1.example.com.", "20 mx2.example.com."}, findRRSet(t, snap.RRsets, "at.example.com.", "MX").Records)

	changed, err = f.ApplyRecordUpdate(ctx, "at.example.com.", "MX", 0, nil, []string{"10 mx1.example.com."})
	require.NoError(t, err)
	assert.True(t, changed)

	snap, err = f.Snapshot(ctx)
	require.NoError(t, err)
	assert.Equal(t, []string{"20 mx2.example.com."}, findRRSet(t, snap.RRsets, "at.example.com.", "MX").Records)
}
