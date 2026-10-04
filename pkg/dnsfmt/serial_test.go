package dnsfmt

import (
	"strconv"
	"testing"
	"time"
)

func TestSerialToHuman(t *testing.T) {
	tests := []struct {
		in  string
		out string
	}{
		{"1282630063", "Tue, 24 Aug 2010 06:07:43 UTC"},
		{"2024041300", "Sat, 13 Apr 2024 00:00:00 UTC"},
		{"2024041301", "Sat, 13 Apr 2024 00:14:00 UTC"},
		{"2024041399", "Sat, 13 Apr 2024 23:06:00 UTC"},
	}
	for i, ts := range tests {
		if x := SerialToHuman([]byte(ts.in)); x != "  "+ts.out {
			t.Errorf("test %d, expected %s, got %s for %s", i, ts.out, x, ts.in)
		}
	}
}

func TestIncreaseEpoch(t *testing.T) {
	now := time.Now().Unix()

	// An old epoch serial jumps to the current time.
	old := strconv.FormatInt(now-3600, 10)
	if got, _ := strconv.ParseInt(string(Increase([]byte(old))), 10, 64); got < now {
		t.Errorf("expected serial >= %d, got %d", now, got)
	}

	// Two changes within the same second must still produce a newer serial.
	cur := strconv.FormatInt(now+10, 10)
	if got := string(Increase([]byte(cur))); got != strconv.FormatInt(now+11, 10) {
		t.Errorf("expected %d, got %s", now+11, got)
	}
}
