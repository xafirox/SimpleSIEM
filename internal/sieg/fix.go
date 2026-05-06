package sieg

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

// issue represents one install-integrity problem. fix is nil when we can
// only report the problem (no automatic remediation).
type issue struct {
	desc string
	fix  func() error
}

// runFix audits the install and repairs anything broken. Requires admin/root.
func runFix(args []string) {
	fs := flag.NewFlagSet("fix", flag.ExitOnError)
	dryRun := fs.Bool("dry-run", false, "report issues without fixing")
	// --config is accepted but largely informational here; the install
	// integrity checks run against the well-known install paths
	// (defaultInstallDir / defaultConfigDir / defaultLogDir), not against
	// an arbitrary config. Accepting the flag avoids the "flag provided
	// but not defined" error every other command tolerates.
	cfgPath := fs.String("config", defaultConfigPath(), "config file (informational)")
	_ = fs.Parse(args)
	_ = cfgPath

	if !isAdmin() {
		fatalf("must run as admin (sudo on unix; Administrator on Windows)")
	}

	fmt.Println("checking " + productName + " installation...")
	fmt.Println()

	issues := collectIssues()

	if len(issues) == 0 {
		fmt.Println("OK - installation looks healthy")
		printInstallInfo()
		return
	}

	fmt.Printf("found %d issue(s):\n", len(issues))
	for _, iss := range issues {
		fmt.Println("  -", iss.desc)
	}

	if *dryRun {
		fmt.Println("\n(dry-run) not applying fixes")
		os.Exit(1)
	}

	fmt.Println("\napplying fixes...")
	for _, iss := range issues {
		if iss.fix == nil {
			fmt.Printf("  SKIP  %s (no automatic fix)\n", iss.desc)
			continue
		}
		if err := iss.fix(); err != nil {
			fmt.Printf("  FAIL  %s: %v\n", iss.desc, err)
		} else {
			fmt.Printf("  OK    %s\n", iss.desc)
		}
	}

	fmt.Println("\nre-checking...")
	remaining := collectIssues()
	if len(remaining) == 0 {
		fmt.Println("OK - installation is now healthy")
		printInstallInfo()
		return
	}
	fmt.Printf("%d issue(s) remain:\n", len(remaining))
	for _, iss := range remaining {
		fmt.Println("  -", iss.desc)
	}
	os.Exit(1)
}

func collectIssues() []issue {
	var out []issue

	destBin := filepath.Join(defaultInstallDir(), defaultBinaryName())
	cfgDir := defaultConfigDir()
	cfgFile := filepath.Join(cfgDir, "config.json")

	if _, err := os.Stat(defaultInstallDir()); err != nil {
		installDir := defaultInstallDir()
		out = append(out, issue{
			desc: "install dir missing: " + installDir,
			fix:  func() error { return os.MkdirAll(installDir, 0o755) },
		})
	}

	if _, err := os.Stat(destBin); err != nil {
		out = append(out, issue{
			desc: "binary missing: " + destBin,
			fix: func() error {
				exe, err := os.Executable()
				if err != nil {
					return err
				}
				if err := os.MkdirAll(filepath.Dir(destBin), 0o755); err != nil {
					return err
				}
				return copyFile(exe, destBin)
			},
		})
	}

	if _, err := os.Stat(cfgDir); err != nil {
		out = append(out, issue{
			desc: "config dir missing: " + cfgDir,
			fix:  func() error { return os.MkdirAll(cfgDir, 0o755) },
		})
	}

	if data, err := os.ReadFile(cfgFile); err != nil {
		out = append(out, issue{
			desc: "config file missing: " + cfgFile,
			fix: func() error {
				if err := os.MkdirAll(cfgDir, 0o750); err != nil {
					return err
				}
				return atomicWriteFile(cfgFile, []byte(defaultConfigJSON()), 0o600)
			},
		})
	} else {
		var c Config
		if jerr := json.Unmarshal(data, &c); jerr != nil {
			out = append(out, issue{
				desc: fmt.Sprintf("config file is not valid JSON: %v", jerr),
				fix: func() error {
					_ = os.Rename(cfgFile, cfgFile+".broken")
					return atomicWriteFile(cfgFile, []byte(defaultConfigJSON()), 0o600)
				},
			})
		}
	}

	cfg := loadConfig(cfgFile)
	if _, err := os.Stat(cfg.LogDir); err != nil {
		out = append(out, issue{
			desc: "log dir missing: " + cfg.LogDir,
			fix:  func() error { return os.MkdirAll(cfg.LogDir, 0o755) },
		})
	}

	out = append(out, platformIssues(destBin, cfgFile, cfg.LogDir)...)
	return out
}

func printInstallInfo() {
	destBin := filepath.Join(defaultInstallDir(), defaultBinaryName())
	cfgFile := filepath.Join(defaultConfigDir(), "config.json")
	cfg := loadConfig(cfgFile)
	fmt.Println()
	fmt.Printf("  binary:  %s\n", destBin)
	fmt.Printf("  config:  %s\n", cfgFile)
	fmt.Printf("  logs:    %s\n", cfg.LogDir)
	fmt.Printf("  running: %v\n", isRunning())
}
