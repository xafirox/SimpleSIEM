package sieg

import (
	"testing"
)

func TestParseStorageThreshold(t *testing.T) {
	cases := []struct {
		in        string
		wantPct   float64
		wantBytes uint64
		wantErr   bool
	}{
		{"", 0, 0, false}, // empty -> zero, no error
		{"80%", 80, 0, false},
		{"100%", 100, 0, false},
		{" 75 % ", 75, 0, false},
		{"0%", 0, 0, true},
		{"101%", 0, 0, true},
		{"-10%", 0, 0, true},
		{"abc%", 0, 0, true},
		{"1024", 0, 1024, false},
		{"1KB", 0, 1000, false},
		{"1 KiB", 0, 1024, false},
		{"512MiB", 0, 512 * 1024 * 1024, false},
		{"2GB", 0, 2 * 1000 * 1000 * 1000, false},
		{"1TB", 0, 1000 * 1000 * 1000 * 1000, false},
		{"1.5GB", 0, 1_500_000_000, false},
		{"0GB", 0, 0, true},
		{"abc", 0, 0, true},
		{"1XYZ", 0, 0, true},
	}
	for _, c := range cases {
		got, err := parseStorageThreshold(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("parseStorageThreshold(%q): err=%v want_err=%v", c.in, err, c.wantErr)
			continue
		}
		if c.wantErr {
			continue
		}
		if got.UsedPercent != c.wantPct {
			t.Errorf("parseStorageThreshold(%q): pct=%v want %v", c.in, got.UsedPercent, c.wantPct)
		}
		if got.FreeBytes != c.wantBytes {
			t.Errorf("parseStorageThreshold(%q): bytes=%v want %v", c.in, got.FreeBytes, c.wantBytes)
		}
	}
}

func TestClassifyVolume(t *testing.T) {
	warn, _ := parseStorageThreshold("80%")
	halt, _ := parseStorageThreshold("90%")
	cases := []struct {
		used float64
		free uint64
		want storageState
	}{
		{50, 50_000_000_000, storageOK},
		{79.9, 50_000_000_000, storageOK},
		{80, 50_000_000_000, storageWarn},
		{85, 50_000_000_000, storageWarn},
		{90, 50_000_000_000, storageHalt},
		{95, 50_000_000_000, storageHalt},
		{100, 0, storageHalt},
	}
	for _, c := range cases {
		v := volumeUsage{Used: 0, Free: c.free, Total: 100, UsedPercent: c.used}
		got := classifyVolume(v, warn, halt)
		if got != c.want {
			t.Errorf("classifyVolume(used=%.1f%%): got=%v want=%v", c.used, got, c.want)
		}
	}
}

func TestClassifyVolume_FreeBytesThreshold(t *testing.T) {
	warn, _ := parseStorageThreshold("10GB")
	halt, _ := parseStorageThreshold("1GB")
	const gb = uint64(1_000_000_000)
	cases := []struct {
		free uint64
		want storageState
	}{
		{20 * gb, storageOK},
		{10 * gb, storageWarn}, // free <= warn threshold = WARN
		{5 * gb, storageWarn},
		{1 * gb, storageHalt},
		{500 * 1_000_000, storageHalt},
		{0, storageHalt},
	}
	for _, c := range cases {
		v := volumeUsage{Free: c.free, Total: 100 * gb}
		got := classifyVolume(v, warn, halt)
		if got != c.want {
			t.Errorf("classifyVolume(free=%d): got=%v want=%v", c.free, got, c.want)
		}
	}
}

func TestResolveQuotas_Defaults(t *testing.T) {
	cfg := Config{}
	q := resolveQuotas(cfg)
	if q.Warn.UsedPercent != 80 {
		t.Errorf("default warn: got %v want 80", q.Warn.UsedPercent)
	}
	if q.Halt.UsedPercent != 90 {
		t.Errorf("default halt: got %v want 90", q.Halt.UsedPercent)
	}
}

func TestAllStorageLocations(t *testing.T) {
	cfg := Config{
		LogDir: "/var/log/simplesiem",
		Storage: StorageConfig{
			FailoverLocations: []string{"/mnt/b/simplesiem", "  ", "/mnt/c/simplesiem", "/var/log/simplesiem"},
		},
	}
	got := allStorageLocations(cfg)
	want := []string{"/var/log/simplesiem", "/mnt/b/simplesiem", "/mnt/c/simplesiem"}
	if len(got) != len(want) {
		t.Fatalf("len: got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("[%d]: got %q want %q", i, got[i], want[i])
		}
	}
}
