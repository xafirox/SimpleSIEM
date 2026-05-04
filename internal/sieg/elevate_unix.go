//go:build linux || darwin

package sieg

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// isAdmin reports whether the current process has root privileges.
func isAdmin() bool { return os.Geteuid() == 0 }

// elevateAndRun runs a subcommand (with optional extra args) as root. If
// we're not root, we re-invoke ourselves via osascript (macOS) or sudo
// (Linux). args[0] is the subcommand name; args[1:] are forwarded
// arguments — e.g. {"convert", "agent", "-y"} or {"certs", "init"}.
func elevateAndRun(args []string) {
	if len(args) == 0 {
		return
	}
	if os.Geteuid() == 0 {
		runSubcommand(args)
		return
	}
	exe, err := os.Executable()
	if err != nil {
		fmt.Println("cannot find self:", err)
		return
	}
	if runtime.GOOS == "darwin" {
		// GUI password prompt via osascript. Output is captured and replayed.
		escaped := strings.ReplaceAll(exe, `"`, `\"`)
		joined := strings.Join(args, " ")
		script := `do shell script "\"` + escaped + `\" ` + joined +
			`" with administrator privileges`
		cmd := exec.Command("osascript", "-e", script)
		out, err := cmd.CombinedOutput()
		if len(out) > 0 {
			fmt.Print(string(out))
			if !strings.HasSuffix(string(out), "\n") {
				fmt.Println()
			}
		}
		if err != nil {
			fmt.Println("elevation failed:", err)
		}
		return
	}
	// Linux: inherit tty, let sudo prompt inline.
	cmd := exec.Command("sudo", append([]string{exe}, args...)...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		fmt.Println("sudo error:", err)
	}
}
