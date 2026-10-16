// Package schedule parses the cron expressions of automatic snapshots. All
// times are UTC.
package schedule

import (
	"fmt"
	"strings"
	"time"

	"github.com/robfig/cron/v3"
)

// MinInterval keeps a single tenant from filling the disk and the worker queue.
const MinInterval = time.Hour

var parser = cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)

type Schedule struct {
	expr  string
	sched cron.Schedule
}

// Parse accepts a standard 5 field cron expression and rejects schedules that
// run more often than MinInterval.
func Parse(expr string) (*Schedule, error) {
	expr = strings.Join(strings.Fields(expr), " ")
	if strings.HasPrefix(expr, "@") || strings.Contains(expr, "TZ=") {
		return nil, fmt.Errorf("use a 5 field cron expression like \"0 3 * * *\"")
	}
	s, err := parser.Parse(expr)
	if err != nil {
		return nil, fmt.Errorf("invalid cron expression: %v", err)
	}
	// check the gaps between all runs of one year
	t := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	prev := s.Next(t)
	if prev.IsZero() {
		return nil, fmt.Errorf("this schedule never runs")
	}
	for i := 0; i < 1000; i++ {
		next := s.Next(prev)
		if next.IsZero() || next.Sub(t) > 366*24*time.Hour {
			break
		}
		if next.Sub(prev) < MinInterval {
			return nil, fmt.Errorf("snapshots can run at most once per hour")
		}
		prev = next
	}
	return &Schedule{expr: expr, sched: s}, nil
}

func (s *Schedule) String() string { return s.expr }

func (s *Schedule) Next(after time.Time) time.Time { return s.sched.Next(after.UTC()) }
