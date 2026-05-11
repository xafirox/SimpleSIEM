package sieg

import "testing"

func TestUserFromPath(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},

		{`C:\Users\Administrator\Downloads\file.zip`, "Administrator"},
		{`C:\Users\TestUser\Desktop`, "TestUser"},
		{`C:\Users\TestUser`, "TestUser"},
		{`c:\users\testuser\Documents\foo.txt`, "testuser"},
		{`D:\Users\Bob\Downloads\x.zip`, "Bob"},
		{`C:/Users/Admin/Downloads/file.zip`, "Admin"},
		{`C:\WINDOWS\System32\Tasks\X`, ""},
		{`C:\ProgramData\Microsoft\X`, ""},

		{"/Users/jake/Downloads/file.zip", "jake"},
		{"/Users/jake", "jake"},
		{"/users/jake/Library/Caches", "jake"},
		{"/Library/LaunchDaemons/x.plist", ""},

		{"/home/jake/.bashrc", "jake"},
		{"/home/jake", "jake"},
		{"/home/", ""},
		{"/etc/passwd", ""},

		{"/root", "root"},
		{"/root/", "root"},
		{"/root/.ssh/authorized_keys", "root"},

		{"/var/log/syslog", ""},
		{"/tmp/foo", ""},
	}
	for _, c := range cases {
		if got := userFromPath(c.in); got != c.want {
			t.Errorf("userFromPath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
