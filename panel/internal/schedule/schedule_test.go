package schedule

import (
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	for _, ok := range []string{"0 * * * *", "0 3 * * *", "30 2 * * 0", "0 */6 * * *", "  0   4 1 * * "} {
		if _, err := Parse(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "* * * * *", "*/30 * * * *", "0,30 * * * *", "0 3 * *", "@hourly", "CRON_TZ=UTC 0 3 * * *", "0 3 * * * *", "61 * * * *", "0 3 31 2 *"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("%q: expected error", bad)
		}
	}
}

func TestNextIsUTC(t *testing.T) {
	s, err := Parse("0 3 * * *")
	if err != nil {
		t.Fatal(err)
	}
	berlin := time.FixedZone("CEST", 2*3600)
	got := s.Next(time.Date(2026, 10, 16, 4, 0, 0, 0, berlin)) // 02:00 UTC
	want := time.Date(2026, 10, 16, 3, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("got %s want %s", got, want)
	}
}
