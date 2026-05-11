package sieg

import (
	"reflect"
	"testing"
)

// TestParseUserMgmtCmdline_Linux exercises every Linux user/group
// management command shape we synthesize. Each row asserts the
// emitted event(s) match the AuthLogCollector schema (event +
// user/group as appropriate) — that's how triage's eventSummary
// and the existing rule library remain uniform.
func TestParseUserMgmtCmdline_Linux(t *testing.T) {
	tests := []struct {
		name    string
		cmdline []string
		want    []map[string]any
	}{
		{
			name:    "useradd",
			cmdline: []string{"useradd", "-m", "-s", "/bin/bash", "alice"},
			want:    []map[string]any{{"event": "user_added", "user": "alice"}},
		},
		{
			name:    "adduser",
			cmdline: []string{"adduser", "--disabled-password", "alice"},
			want:    []map[string]any{{"event": "user_added", "user": "alice"}},
		},
		{
			name:    "userdel",
			cmdline: []string{"userdel", "-r", "alice"},
			want:    []map[string]any{{"event": "user_deleted", "user": "alice"}},
		},
		{
			name:    "deluser",
			cmdline: []string{"deluser", "alice"},
			want:    []map[string]any{{"event": "user_deleted", "user": "alice"}},
		},
		{
			name:    "usermod with -aG (single group)",
			cmdline: []string{"usermod", "-aG", "sudo", "alice"},
			want: []map[string]any{
				{"event": "user_modified", "user": "alice"},
				{"event": "user_added_to_group", "user": "alice", "group": "sudo"},
			},
		},
		{
			name:    "usermod with -aG (multi)",
			cmdline: []string{"usermod", "-aG", "sudo,wheel,docker", "alice"},
			want: []map[string]any{
				{"event": "user_modified", "user": "alice"},
				{"event": "user_added_to_group", "user": "alice", "group": "sudo"},
				{"event": "user_added_to_group", "user": "alice", "group": "wheel"},
				{"event": "user_added_to_group", "user": "alice", "group": "docker"},
			},
		},
		{
			name:    "passwd alice",
			cmdline: []string{"passwd", "alice"},
			want:    []map[string]any{{"event": "password_changed", "user": "alice"}},
		},
		{
			name:    "groupadd dev",
			cmdline: []string{"groupadd", "dev"},
			want:    []map[string]any{{"event": "group_added", "group": "dev"}},
		},
		{
			name:    "groupdel dev",
			cmdline: []string{"groupdel", "dev"},
			want:    []map[string]any{{"event": "group_deleted", "group": "dev"}},
		},
		{
			name:    "gpasswd add member",
			cmdline: []string{"gpasswd", "-a", "alice", "dev"},
			want:    []map[string]any{{"event": "user_added_to_group", "user": "alice", "group": "dev"}},
		},
		{
			name:    "gpasswd remove member",
			cmdline: []string{"gpasswd", "-d", "alice", "dev"},
			want:    []map[string]any{{"event": "user_removed_from_group", "user": "alice", "group": "dev"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseUserMgmtCmdline(tt.cmdline[0], tt.cmdline)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v\nwant %v", got, tt.want)
			}
		})
	}
}

// TestParseUserMgmtCmdline_Mac covers sysadminctl/dscl/dseditgroup
// — the macOS user-management entry points the AuthLogCollector
// also recognises via unified-log when log stream is available.
// The cmdline path is the fallback for stripped Macs.
func TestParseUserMgmtCmdline_Mac(t *testing.T) {
	tests := []struct {
		name    string
		cmdline []string
		want    []map[string]any
	}{
		{
			name:    "sysadminctl addUser",
			cmdline: []string{"sysadminctl", "-addUser", "alice", "-password", "secret"},
			want:    []map[string]any{{"event": "user_added", "user": "alice"}},
		},
		{
			name:    "sysadminctl deleteUser",
			cmdline: []string{"sysadminctl", "-deleteUser", "alice"},
			want:    []map[string]any{{"event": "user_deleted", "user": "alice"}},
		},
		{
			name:    "sysadminctl resetPassword",
			cmdline: []string{"sysadminctl", "-resetPasswordFor", "alice", "-newPassword", "x"},
			want:    []map[string]any{{"event": "password_changed", "user": "alice"}},
		},
		{
			name:    "dscl create user",
			cmdline: []string{"dscl", ".", "-create", "/Users/alice"},
			want:    []map[string]any{{"event": "user_added", "user": "alice"}},
		},
		{
			name:    "dscl delete user",
			cmdline: []string{"dscl", ".", "-delete", "/Users/alice"},
			want:    []map[string]any{{"event": "user_deleted", "user": "alice"}},
		},
		{
			name:    "dscl create group",
			cmdline: []string{"dscl", ".", "-create", "/Groups/dev"},
			want:    []map[string]any{{"event": "group_added", "group": "dev"}},
		},
		{
			name:    "dseditgroup add member",
			cmdline: []string{"dseditgroup", "-o", "edit", "-a", "alice", "-t", "user", "admin"},
			want:    []map[string]any{{"event": "user_added_to_group", "user": "alice", "group": "admin"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseUserMgmtCmdline(tt.cmdline[0], tt.cmdline)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v\nwant %v", got, tt.want)
			}
		})
	}
}

// TestParseUserMgmtCmdline_Windows covers `net user` / `net localgroup`
// (the classic CMD path) and PowerShell *-LocalUser/*-LocalGroupMember
// cmdlets. Windows hosts with audit policy enabled would also fire
// EventID 4720/4726 through the existing wevtutil path; this is the
// fallback for hosts where audit isn't on.
func TestParseUserMgmtCmdline_Windows(t *testing.T) {
	tests := []struct {
		name    string
		cmdline []string
		want    []map[string]any
	}{
		{
			name:    "net user add",
			cmdline: []string{"net", "user", "alice", "secret123", "/add"},
			want:    []map[string]any{{"event": "user_added", "user": "alice"}},
		},
		{
			name:    "net user delete",
			cmdline: []string{"net", "user", "alice", "/delete"},
			want:    []map[string]any{{"event": "user_deleted", "user": "alice"}},
		},
		{
			name:    "net localgroup add",
			cmdline: []string{"net", "localgroup", "Administrators", "alice", "/add"},
			want:    []map[string]any{{"event": "user_added_to_group", "user": "alice", "group": "Administrators"}},
		},
		{
			name:    "powershell New-LocalUser",
			cmdline: []string{"powershell", "-Command", "New-LocalUser alice -Password (ConvertTo-SecureString 'x' -AsPlainText -Force)"},
			want:    []map[string]any{{"event": "user_added", "user": "alice"}},
		},
		{
			name:    "powershell Remove-LocalUser",
			cmdline: []string{"powershell", "-Command", "Remove-LocalUser alice"},
			want:    []map[string]any{{"event": "user_deleted", "user": "alice"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Process name may have .exe suffix on Windows — emit
			// path checks both raw and lower-cased TrimSuffix-".exe"
			// already, which is what the production code does.
			name := tt.cmdline[0]
			got := parseUserMgmtCmdline(name, tt.cmdline)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v\nwant %v", got, tt.want)
			}
		})
	}
}

// TestClassifySecurityCriticalPath verifies the path-classifier
// triggers on every credential / persistence path in the threat
// model AND nothing else. Negative case ("/var/log/messages") is
// the regression guard that makes sure we don't accidentally tag
// every modified file.
func TestClassifySecurityCriticalPath(t *testing.T) {
	tests := []struct {
		path     string
		category string
		severity string
	}{
		// Credential stores: high
		{"/etc/passwd", "credential_store", "high"},
		{"/etc/shadow", "credential_store", "high"},
		{"/etc/gshadow", "credential_store", "high"},
		{"/etc/group", "credential_store", "high"},
		{"/etc/master.passwd", "credential_store", "high"},
		{"/etc/sudoers", "credential_store", "high"},
		{"/etc/sudoers.d/zz-temporary", "sudoers_drop_in", "high"},
		{`C:\Windows\System32\config\SAM`, "windows_registry_hive", "high"},
		{`C:\Windows\System32\config\SECURITY`, "windows_registry_hive", "high"},
		// SSH
		{"/home/alice/.ssh/authorized_keys", "ssh_keystore", "high"},
		{"/etc/ssh/sshd_config", "ssh_server_config", "high"},
		// Persistence (medium)
		{"/etc/cron.d/runme", "cron_persistence", "medium"},
		{"/etc/crontab", "cron_persistence", "medium"},
		{"/var/spool/cron/root", "cron_persistence", "medium"},
		{"/etc/systemd/system/persist.service", "systemd_unit", "medium"},
		{"/Library/LaunchDaemons/com.evil.plist", "launchd_persistence", "medium"},
		{`C:\Windows\System32\Tasks\Microsoft\Windows\foo`, "windows_scheduled_task", "medium"},
		{"/home/alice/.bashrc", "shell_rc", "medium"},
		{"/etc/profile.d/foo.sh", "shell_rc", "medium"},
		// Negative — must not be tagged.
		{"/var/log/messages", "", ""},
		{"/tmp/somefile.txt", "", ""},
		{"/usr/bin/curl", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			cat, sev := classifySecurityCriticalPath(tt.path)
			if cat != tt.category || sev != tt.severity {
				t.Errorf("classifySecurityCriticalPath(%q) = (%q, %q), want (%q, %q)",
					tt.path, cat, sev, tt.category, tt.severity)
			}
		})
	}
}
