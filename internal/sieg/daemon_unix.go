//go:build linux || darwin

package sieg

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func runDaemon(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	_ = fs.Parse(args)

	d, err := startDaemon(*cfgPath)
	if err != nil {
		log.Fatalf("daemon: %v", err)
	}
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
	d.Stop()
}
