//go:build linux

package sieg

import "testing"

func TestParseAuthLine_SSH(t *testing.T) {
	tests := []struct {
		line    string
		wantEv  string
		wantRes string
		wantU   string
		wantR   string
	}{
		{
			"Apr 25 10:00:00 host sshd[1234]: Accepted password for alice from 10.0.0.5 port 54321 ssh2",
			"ssh_login", "success", "alice", "10.0.0.5",
		},
		{
			"Apr 25 10:00:00 host sshd[1234]: Failed password for alice from 10.0.0.5 port 54321 ssh2",
			"ssh_login", "failed", "alice", "10.0.0.5",
		},
		{
			"Apr 25 10:00:00 host sshd[1234]: Failed password for invalid user bob from 10.0.0.5 port 54321 ssh2",
			"ssh_login", "failed", "bob", "10.0.0.5",
		},
		{
			"Apr 25 10:00:00 host sshd[1234]: Invalid user bob from 10.0.0.5 port 54321",
			"ssh_login", "invalid_user", "bob", "10.0.0.5",
		},
	}
	for _, tc := range tests {
		got := parseAuthLine(tc.line)
		if got == nil {
			t.Errorf("parseAuthLine(%q) returned nil", tc.line)
			continue
		}
		if got["event"] != tc.wantEv {
			t.Errorf("event=%v want %v for %q", got["event"], tc.wantEv, tc.line)
		}
		if got["result"] != tc.wantRes {
			t.Errorf("result=%v want %v for %q", got["result"], tc.wantRes, tc.line)
		}
		if got["user"] != tc.wantU {
			t.Errorf("user=%v want %v for %q", got["user"], tc.wantU, tc.line)
		}
		if got["remote"] != tc.wantR {
			t.Errorf("remote=%v want %v for %q", got["remote"], tc.wantR, tc.line)
		}
	}
}

func TestParseAuthLine_Sudo(t *testing.T) {
	line := "Apr 25 10:00:00 host sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash -i"
	got := parseAuthLine(line)
	if got == nil {
		t.Fatal("expected sudo to parse")
	}
	if got["event"] != "sudo" || got["user"] != "alice" || got["target"] != "root" {
		t.Errorf("parsed wrong fields: %+v", got)
	}
	if got["command"] != "/bin/bash -i" {
		t.Errorf("command=%v want /bin/bash -i", got["command"])
	}
}

func TestParseAuthLine_Su(t *testing.T) {
	line := "Apr 25 10:00:00 host su[1234]: pam_unix(su:session): session opened for user root by alice(uid=1000)"
	got := parseAuthLine(line)
	if got == nil {
		t.Fatal("expected su to parse")
	}
	if got["event"] != "su" || got["target"] != "root" || got["user"] != "alice" {
		t.Errorf("parsed wrong fields: %+v", got)
	}
}

func TestParseAuthLine_UserLifecycle(t *testing.T) {
	tests := []struct {
		line   string
		wantEv string
		check  func(t *testing.T, ev map[string]any)
	}{
		{
			"May  7 12:34:56 host useradd[12345]: new user: name=alice, UID=1001, GID=1001, home=/home/alice, shell=/bin/bash",
			"user_added",
			func(t *testing.T, ev map[string]any) {
				if ev["user"] != "alice" || ev["uid"] != "1001" || ev["home"] != "/home/alice" || ev["shell"] != "/bin/bash" {
					t.Errorf("user_added fields wrong: %+v", ev)
				}
			},
		},
		{
			"May  7 12:34:56 host useradd[12345]: add 'alice' to group 'sudo'",
			"user_added_to_group",
			func(t *testing.T, ev map[string]any) {
				if ev["user"] != "alice" || ev["group"] != "sudo" {
					t.Errorf("user_added_to_group fields wrong: %+v", ev)
				}
			},
		},
		{
			"May  7 12:34:56 host userdel[12345]: delete user 'alice'",
			"user_deleted",
			func(t *testing.T, ev map[string]any) {
				if ev["user"] != "alice" {
					t.Errorf("user_deleted user wrong: %+v", ev)
				}
			},
		},
		{
			"May  7 12:34:56 host groupadd[12345]: new group: name=eng, GID=2001",
			"group_added",
			func(t *testing.T, ev map[string]any) {
				if ev["group"] != "eng" || ev["gid"] != "2001" {
					t.Errorf("group_added fields wrong: %+v", ev)
				}
			},
		},
		{
			"May  7 12:34:56 host passwd[12345]: pam_unix(passwd:chauthtok): password changed for alice",
			"password_changed",
			func(t *testing.T, ev map[string]any) {
				if ev["user"] != "alice" {
					t.Errorf("password_changed user wrong: %+v", ev)
				}
			},
		},
	}
	for _, tc := range tests {
		got := parseAuthLine(tc.line)
		if got == nil {
			t.Errorf("parseAuthLine(%q) returned nil; want event=%s", tc.line, tc.wantEv)
			continue
		}
		if got["event"] != tc.wantEv {
			t.Errorf("event=%v want %s for %q", got["event"], tc.wantEv, tc.line)
		}
		tc.check(t, got)
	}
}

func TestParseAuthLine_Noise(t *testing.T) {
	noisy := []string{
		"",
		"Apr 25 10:00:00 host CRON[123]: pam_unix(cron:session): session closed for user root",
		"random non-matching line",
	}
	for _, line := range noisy {
		if got := parseAuthLine(line); got != nil {
			t.Errorf("expected nil for %q, got %+v", line, got)
		}
	}
}
