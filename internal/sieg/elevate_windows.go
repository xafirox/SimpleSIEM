//go:build windows

package sieg

import (
	"fmt"
	"os"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
)

// isAdmin reports whether the current process token is a member of the local
// Administrators group (the effective token under UAC).
func isAdmin() bool {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid,
	)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)
	token := windows.Token(0) // 0 = effective token of current thread
	member, err := token.IsMember(sid)
	return err == nil && member
}

// elevateAndRun runs a subcommand (plus optional args) elevated. If we're
// not admin, it spawns a UAC-elevated copy in a new console via
// ShellExecute("runas"). The child receives --interactive so it pauses
// before the new console closes. args[0] is the subcommand name;
// args[1:] are forwarded arguments — e.g. {"convert","agent","-y"}.
func elevateAndRun(args []string) {
	if len(args) == 0 {
		return
	}
	if isAdmin() {
		runSubcommand(args)
		return
	}
	exe, err := os.Executable()
	if err != nil {
		fmt.Println("cannot find self:", err)
		return
	}
	verb, _ := syscall.UTF16PtrFromString("runas")
	exePtr, _ := syscall.UTF16PtrFromString(exe)
	full := strings.Join(args, " ") + " --interactive"
	argsPtr, _ := syscall.UTF16PtrFromString(full)
	if err := windows.ShellExecute(0, verb, exePtr, argsPtr, nil, windows.SW_SHOWNORMAL); err != nil {
		fmt.Println("elevation failed:", err)
		return
	}
	fmt.Println("-> UAC prompt requested; the action will run in a new window.")
}
