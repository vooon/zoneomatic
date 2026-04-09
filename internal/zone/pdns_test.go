package zone

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFile_Snapshot(t *testing.T) {
	f := newZoneTemp(t, "./testdata/at.example.com.zone")

	snapshot, err := f.Snapshot(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "at.example.com.", snapshot.ID)
	assert.Equal(t, uint32(1763822925), snapshot.Serial)
	assert.Contains(t, snapshot.Nameservers, "ns1.example.com.")
	assert.Contains(t, snapshot.Nameservers, "ns2.example.com.")

	loopA := findRRSet(t, snapshot.RRsets, "loop.at.example.com.", "A")
	assert.Equal(t, 60, loopA.TTL)
	assert.Equal(t, []string{"127.0.0.1"}, loopA.Records)

	acmeTXT := findRRSet(t, snapshot.RRsets, "_acme-challenge.zot.at.example.com.", "TXT")
	assert.Equal(t, []string{"8NwtedqEdkceTHTZILXsMU2UWEeEon24tXw0dSSDkrs"}, acmeTXT.Records)
}

func TestFile_ReplaceRRSet(t *testing.T) {
	f := newZoneTemp(t, "./testdata/at.example.com.zone")

	changed, err := f.ReplaceRRSet(context.Background(), "new-entry.at.example.com.", "A", 120, []string{"1.2.3.4"})
	require.NoError(t, err)
	assert.True(t, changed)

	snapshot, err := f.Snapshot(context.Background())
	require.NoError(t, err)
	rrset := findRRSet(t, snapshot.RRsets, "new-entry.at.example.com.", "A")
	assert.Equal(t, 120, rrset.TTL)
	assert.Equal(t, []string{"1.2.3.4"}, rrset.Records)
}

func TestFile_ReplaceRRSet_CaseInsensitiveName(t *testing.T) {
	f := newZoneTemp(t, "./testdata/at.example.com.zone")

	changed, err := f.ReplaceRRSet(context.Background(), "LOOP.at.example.com.", "A", 60, []string{"127.0.0.1"})
	require.NoError(t, err)
	assert.True(t, changed)

	snapshot, err := f.Snapshot(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, countRRSet(snapshot.RRsets, "loop.at.example.com.", "A"))
}

func TestFile_DeleteRRSet(t *testing.T) {
	f := newZoneTemp(t, "./testdata/at.example.com.zone")

	changed, err := f.DeleteRRSet(context.Background(), "loop.at.example.com.", "AAAA")
	require.NoError(t, err)
	assert.True(t, changed)

	snapshot, err := f.Snapshot(context.Background())
	require.NoError(t, err)
	assert.False(t, hasRRSet(snapshot.RRsets, "loop.at.example.com.", "AAAA"))

	changed, err = f.DeleteRRSet(context.Background(), "missing.at.example.com.", "A")
	require.NoError(t, err)
	assert.False(t, changed)
}

func TestFile_DeleteRRSet_CaseInsensitiveName(t *testing.T) {
	f := newZoneTemp(t, "./testdata/at.example.com.zone")

	changed, err := f.DeleteRRSet(context.Background(), "LOOP.at.example.com.", "AAAA")
	require.NoError(t, err)
	assert.True(t, changed)

	snapshot, err := f.Snapshot(context.Background())
	require.NoError(t, err)
	assert.False(t, hasRRSet(snapshot.RRsets, "loop.at.example.com.", "AAAA"))
}

func findRRSet(t *testing.T, rrsets []RRSet, name, typ string) RRSet {
	t.Helper()
	for _, rrset := range rrsets {
		if rrset.Name == name && rrset.Type == typ {
			return rrset
		}
	}

	t.Fatalf("rrset not found: %s %s", name, typ)
	return RRSet{}
}

func hasRRSet(rrsets []RRSet, name, typ string) bool {
	for _, rrset := range rrsets {
		if rrset.Name == name && rrset.Type == typ {
			return true
		}
	}

	return false
}

func countRRSet(rrsets []RRSet, name, typ string) int {
	var count int
	for _, rrset := range rrsets {
		if rrset.Name == name && rrset.Type == typ {
			count++
		}
	}

	return count
}
