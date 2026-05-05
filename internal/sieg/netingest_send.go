package sieg

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// runNetSendCmd is a diagnostic test helper for the network-ingest
// listener. Sends a single syslog frame over UDP / TCP / TLS to the
// specified host:port. Used by the docker UAT to simulate firewalls
// and rogue devices.
//
//   simplesiem net-send --host <h> --port <p> --transport udp|tcp|tls \
//                       --message "<134>1 ..." [--insecure]
func runNetSendCmd(args []string) {
	args = permuteArgs(args, map[string]bool{
		"host": true, "port": true, "transport": true, "message": true,
		"count": true, "interval-ms": true,
	})
	fs := flag.NewFlagSet("net-send", flag.ExitOnError)
	host := fs.String("host", "", "destination host")
	port := fs.String("port", "514", "destination port")
	transport := fs.String("transport", "udp", "udp | tcp | tls")
	message := fs.String("message", "", "syslog frame to send (REQUIRED)")
	count := fs.Int("count", 1, "number of frames to send")
	intervalMs := fs.Int("interval-ms", 100, "delay between frames")
	insecure := fs.Bool("insecure", false, "skip TLS cert validation (testing)")
	_ = fs.Parse(args)
	if *host == "" || *message == "" {
		fatalf("usage: simplesiem net-send --host <h> --port <p> --transport udp|tcp|tls --message <frame>")
	}
	addr := net.JoinHostPort(*host, *port)
	frame := *message
	if !strings.HasSuffix(frame, "\n") {
		frame += "\n"
	}
	send := func() error {
		switch strings.ToLower(*transport) {
		case "udp":
			conn, err := net.Dial("udp", addr)
			if err != nil {
				return err
			}
			defer conn.Close()
			_, err = conn.Write([]byte(frame))
			return err
		case "tcp":
			conn, err := net.Dial("tcp", addr)
			if err != nil {
				return err
			}
			defer conn.Close()
			_, err = conn.Write([]byte(frame))
			return err
		case "tls":
			tcfg := &tls.Config{
				MinVersion:         tls.VersionTLS13,
				InsecureSkipVerify: *insecure,
				ServerName:         *host,
				CurvePreferences:   pqHybridCurvePrefs(),
			}
			conn, err := tls.Dial("tcp", addr, tcfg)
			if err != nil {
				return err
			}
			defer conn.Close()
			_, err = conn.Write([]byte(frame))
			return err
		}
		return fmt.Errorf("unknown transport %q", *transport)
	}
	for i := 0; i < *count; i++ {
		if err := send(); err != nil {
			fmt.Fprintf(os.Stderr, "send %d: %v\n", i+1, err)
			os.Exit(1)
		}
		if i+1 < *count {
			time.Sleep(time.Duration(*intervalMs) * time.Millisecond)
		}
	}
	fmt.Printf("sent %d frame(s) to %s://%s\n", *count, *transport, addr)
}
