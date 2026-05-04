//go:build windows

package sieg

import (
	"flag"
	"log"
	"os"
	"os/signal"

	"golang.org/x/sys/windows/svc"
)

// winService bridges SCM control messages to our daemon lifecycle.
type winService struct {
	cfgPath string
}

func (s *winService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (svcSpecific bool, exitCode uint32) {
	const accepts = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	d, err := startDaemon(s.cfgPath)
	if err != nil {
		return true, 1
	}
	changes <- svc.Status{State: svc.Running, Accepts: accepts}

loop:
	for {
		req := <-r
		switch req.Cmd {
		case svc.Interrogate:
			changes <- req.CurrentStatus
		case svc.Stop, svc.Shutdown:
			break loop
		}
	}
	changes <- svc.Status{State: svc.StopPending}
	d.Stop()
	changes <- svc.Status{State: svc.Stopped}
	return false, 0
}

func runDaemon(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	_ = fs.Parse(args)

	isSvc, err := svc.IsWindowsService()
	if err != nil {
		log.Fatalf("windows service check: %v", err)
	}
	if isSvc {
		if err := svc.Run(serviceName, &winService{cfgPath: *cfgPath}); err != nil {
			log.Fatalf("svc.Run: %v", err)
		}
		return
	}
	// Console mode: Ctrl+C to stop.
	d, err := startDaemon(*cfgPath)
	if err != nil {
		log.Fatalf("daemon: %v", err)
	}
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt)
	<-sigs
	d.Stop()
}
