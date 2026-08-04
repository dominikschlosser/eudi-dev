package cmd

import (
	"testing"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/wallet"
)

func TestParseDemoResetForms(t *testing.T) {
	opts, err := parseDemoReset("24h")
	if err != nil || opts.ResetInterval != 24*time.Hour || opts.ResetDaily != nil {
		t.Fatalf("duration form: %+v %v", opts, err)
	}
	opts, err = parseDemoReset("00:00 Europe/Berlin")
	if err != nil || opts.ResetDaily == nil {
		t.Fatalf("daily form: %+v %v", opts, err)
	}
	if opts.ResetDaily.Hour != 0 || opts.ResetDaily.Location.String() != "Europe/Berlin" {
		t.Fatalf("parsed wrong: %+v", opts.ResetDaily)
	}
	if _, err := parseDemoReset("25:00"); err == nil {
		t.Fatal("expected out of range error")
	}
	if _, err := parseDemoReset("00:00 Mars/Olympus"); err == nil {
		t.Fatal("expected unknown timezone error")
	}
}

func TestDailyScheduleNext(t *testing.T) {
	berlin, err := time.LoadLocation("Europe/Berlin")
	if err != nil {
		t.Fatalf("loading zone (tzdata embedded?): %v", err)
	}
	s := wallet.DailySchedule{Hour: 0, Minute: 0, Location: berlin}

	// Just before midnight: next reset is minutes away, same night.
	now := time.Date(2026, 8, 4, 23, 30, 0, 0, berlin)
	if got := s.Next(now); !got.Equal(time.Date(2026, 8, 5, 0, 0, 0, 0, berlin)) {
		t.Errorf("before midnight: %v", got)
	}
	// Exactly at midnight: must move to the next day, never fire in a loop.
	now = time.Date(2026, 8, 4, 0, 0, 0, 0, berlin)
	if got := s.Next(now); !got.Equal(time.Date(2026, 8, 5, 0, 0, 0, 0, berlin)) {
		t.Errorf("at midnight: %v", got)
	}
	// Across the spring DST switch the local time stays 00:00, so the gap is
	// 23 hours rather than 24.
	now = time.Date(2026, 3, 28, 12, 0, 0, 0, berlin)
	next := s.Next(now)
	if next.Hour() != 0 || next.Day() != 29 {
		t.Errorf("dst: %v", next)
	}
	// A UTC "now" must still resolve to Berlin midnight.
	utcNow := time.Date(2026, 8, 4, 21, 0, 0, 0, time.UTC)
	if got := s.Next(utcNow); !got.Equal(time.Date(2026, 8, 5, 0, 0, 0, 0, berlin)) {
		t.Errorf("from utc: %v", got)
	}
}
