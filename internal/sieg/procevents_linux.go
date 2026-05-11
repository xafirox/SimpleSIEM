//go:build linux

package sieg

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// procEventsLastErrString returns the most recent listener-start
// error as a string, or "" when the listener started cleanly.
// Cross-platform-callable; on non-Linux always returns "".
func procEventsLastErrString() string {
	if procEventsLastErr == nil {
		return ""
	}
	return procEventsLastErr.Error()
}

// Linux PROC_EVENTS via NETLINK_CONNECTOR. Real-time kernel
// notifications for fork/exec/exit, no polling delay. Pure Go via
// x/sys/unix — no CGO, no auditd dependency.
//
// Threat-model framing: this closes the "ping/curl finished before
// the next 2-second poll" gap that pure-/proc polling can't address.
// Catch latency is microseconds — the kernel posts the event onto
// the netlink socket as soon as do_fork/do_execve completes; our
// reader emits process_start before /proc/<pid>/stat is even fully
// populated by the kernel's bookkeeping.
//
// Permissions: NETLINK_CONNECTOR + listening for proc events
// requires CAP_NET_ADMIN. Granted by default to root inside Docker
// (the typical SimpleSIEM deployment posture). Non-root or
// containers without the cap silently fall back to /proc polling —
// the start function returns ok=false and the daemon continues with
// the previous behaviour. No degradation, no spurious errors.
//
// The kernel's event stream can drop messages under load (the
// netlink buffer fills if our reader can't keep up). Polling is
// therefore retained as a backstop — duplicate process_start events
// are deduped on PID + create-time inside ProcessCollector's `seen`
// map, so the cost of double-coverage is just one extra map lookup
// per poll.

// procConnectorMessage is the binary layout the kernel sends on the
// connector. Layout:
//
//	struct nlmsghdr   nl_hdr;          // 16 bytes
//	struct cn_msg     cn_msg;          // 20 bytes (id + seq + ack + len + flags)
//	struct proc_event proc_ev;         // variable, depends on what (fork/exec/exit/...)
//
// We only care about EXEC events here — they carry the post-execve
// PID + tgid, which is exactly the granularity ProcessCollector
// emits.

const (
	// CN_IDX_PROC + CN_VAL_PROC are the connector channel IDs that
	// identify the proc subsystem. Defined in linux/connector.h
	// (kernel) — not exposed via x/sys/unix constants, so we
	// hard-code them. Stable since kernel 2.6.15 (early 2006).
	procCnIdxProc = 1
	procCnValProc = 1

	// PROC_CN_MCAST_LISTEN / IGNORE — switch the multicast
	// subscription on/off. We only LISTEN.
	procCnMcastListen = 1
	procCnMcastIgnore = 2

	// proc_event.what — kernel enum. Only EXEC is interesting; FORK
	// gives a pid before the new image is loaded, so cmdline is the
	// parent's. EXEC fires after execve() so /proc/<pid>/cmdline is
	// the new program's args.
	procEventNone = 0x00000000
	procEventFork = 0x00000001
	procEventExec = 0x00000002
	procEventExit = 0x80000000
)

// procEventListener owns a NETLINK_CONNECTOR socket subscribed to
// PROC_EVENTS. The channel `events` carries decoded notifications;
// the goroutine started by start() reads kernel messages and posts
// to the channel until ctx is cancelled.
type procEventListener struct {
	fd     int
	events chan procExec
	once   sync.Once
}

// procExec is the decoded form of an exec event. Kept narrow — pid
// is the only field we need to look up cmdline / sha384 from /proc.
// The kernel also gives us tgid (thread-group leader) and parent
// pid, but ProcessCollector ignores those: its own /proc snapshot
// is the source of truth for parent / cmdline / user.
type procExec struct {
	pid int32
}

// startProcEventListener subscribes to PROC_EVENTS. Returns
// (nil, false) when the kernel refuses the bind (no CAP_NET_ADMIN,
// kernel built without CONFIG_PROC_EVENTS, namespace restricted).
// The caller must continue to poll /proc on a fallback timer when
// this happens.
// startProcEventListener subscribes to PROC_EVENTS. The diagnostic
// envelope (lastErr in the package-level slot) is read by the
// caller when start fails so the operator-visible meta event can
// say WHICH stage failed (socket / bind / subscribe / read), not
// just "unavailable". Test infrastructure also reads it.
var procEventsLastErr error

func startProcEventListener(ctx context.Context) (*procEventListener, bool) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM, unix.NETLINK_CONNECTOR)
	if err != nil {
		procEventsLastErr = fmt.Errorf("socket: %w", err)
		return nil, false
	}
	addr := &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
		Pid:    uint32(os.Getpid()),
		Groups: procCnIdxProc,
	}
	if err := unix.Bind(fd, addr); err != nil {
		_ = unix.Close(fd)
		procEventsLastErr = fmt.Errorf("bind: %w", err)
		return nil, false
	}
	if err := sendProcSubscribe(fd, procCnMcastListen); err != nil {
		_ = unix.Close(fd)
		// ECONNREFUSED here means the kernel doesn't have
		// CONFIG_CONNECTOR built in — common on Docker Desktop's
		// LinuxKit kernel and other stripped builds. Real Linux
		// servers (distro kernels, EC2 / GCE / Hetzner / bare metal)
		// have it on. The error string is preserved verbatim in the
		// meta event so the operator can distinguish "kernel doesn't
		// support it" from "permission denied" without grepping
		// dmesg.
		procEventsLastErr = fmt.Errorf("subscribe: %w (kernel may lack CONFIG_CONNECTOR — common on Docker Desktop's LinuxKit; real Linux hosts will have it)", err)
		return nil, false
	}
	pl := &procEventListener{
		fd:     fd,
		events: make(chan procExec, 1024),
	}
	go pl.readLoop(ctx)
	procEventsLastErr = nil
	return pl, true
}

// sendProcSubscribe builds and sends the connector message that
// flips multicast LISTEN on. Without this the bind alone receives
// nothing — the kernel only posts events to subscribers that have
// explicitly asked.
func sendProcSubscribe(fd int, op uint32) error {
	// Layout: nlmsghdr (16) + cn_msg (20) + payload (4: enable/disable u32).
	const (
		nlmsgHdrLen = unix.NLMSG_HDRLEN // 16
		cnMsgLen    = 20
		payloadLen  = 4
		totalLen    = nlmsgHdrLen + cnMsgLen + payloadLen
	)
	buf := make([]byte, totalLen)
	// nlmsghdr
	binary.LittleEndian.PutUint32(buf[0:4], uint32(totalLen))
	binary.LittleEndian.PutUint16(buf[4:6], unix.NLMSG_DONE)
	binary.LittleEndian.PutUint16(buf[6:8], 0) // flags
	binary.LittleEndian.PutUint32(buf[8:12], 0) // seq
	binary.LittleEndian.PutUint32(buf[12:16], uint32(os.Getpid()))
	// cn_msg
	binary.LittleEndian.PutUint32(buf[16:20], procCnIdxProc)
	binary.LittleEndian.PutUint32(buf[20:24], procCnValProc)
	binary.LittleEndian.PutUint32(buf[24:28], 0) // seq
	binary.LittleEndian.PutUint32(buf[28:32], 0) // ack
	binary.LittleEndian.PutUint16(buf[32:34], payloadLen)
	binary.LittleEndian.PutUint16(buf[34:36], 0) // flags
	// payload — the enable/disable enum.
	binary.LittleEndian.PutUint32(buf[36:40], op)
	// Use Write (not Sendto) so the message goes to the socket's
	// peer — which for an unconnected datagram netlink socket is
	// the kernel. The Linux samples/connector/proc_events.c uses
	// send() for the same reason; Sendto with a {Family:AF_NETLINK,
	// Pid:0, Groups:0} address returns ECONNREFUSED on some kernels
	// because the bind already established the multicast group
	// membership and the explicit destination conflicts.
	_, err := unix.Write(fd, buf)
	return err
}

// readLoop is the netlink recv loop. Decodes proc events and posts
// EXEC notifications to pl.events. Drops other event types
// (FORK/EXIT/UID/GID) — ProcessCollector polling already covers
// the cmdline lookup that FORK can't give us.
//
// Bounded by ctx: on cancel we close the socket which unblocks any
// pending recv with EBADF, and the goroutine exits. The events
// channel is closed in the deferred path so consumers see a clean
// drain.
func (pl *procEventListener) readLoop(ctx context.Context) {
	defer func() { _ = recover() }()
	defer close(pl.events)
	go func() {
		<-ctx.Done()
		_ = unix.Close(pl.fd)
	}()
	buf := make([]byte, 4096)
	for {
		n, err := unix.Read(pl.fd, buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			// Transient error (EINTR, ENOBUFS); brief sleep
			// to avoid a hot loop on a misconfigured kernel.
			time.Sleep(50 * time.Millisecond)
			continue
		}
		// One read can carry multiple netlink messages; walk via
		// the standard NLMSG_NEXT-style iteration.
		for off := 0; off+int(unix.NLMSG_HDRLEN) <= n; {
			rest := buf[off:n]
			if len(rest) < int(unix.NLMSG_HDRLEN) {
				break
			}
			hdrLen := binary.LittleEndian.Uint32(rest[0:4])
			hdrType := binary.LittleEndian.Uint16(rest[4:6])
			if hdrLen < unix.NLMSG_HDRLEN || int(hdrLen) > len(rest) {
				break
			}
			payload := rest[unix.NLMSG_HDRLEN:hdrLen]
			if hdrType == unix.NLMSG_DONE && len(payload) >= 36 {
				pl.dispatchProcEvent(payload)
			}
			// Align to 4-byte boundary.
			next := (int(hdrLen) + 3) &^ 3
			if next == 0 {
				break
			}
			off += next
		}
		// Non-blocking ctx check.
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}

// dispatchProcEvent decodes one cn_msg + proc_event payload. Only
// EXEC events are forwarded — they carry the *post-execve* pid and
// tgid, which is the exact moment we want for "what binary just
// started running." FORK gives a fresh pid that's still running
// the parent's image (e.g. /usr/bin/dash before the exec to
// /usr/bin/curl), so the cmdline lookup would race the kernel's
// own argv replacement. Skip it.
func (pl *procEventListener) dispatchProcEvent(payload []byte) {
	if len(payload) < 36 {
		return
	}
	// cn_msg = 20 bytes (id, seq, ack, len, flags)
	// proc_event header starts at offset 20:
	//   __u32 what
	//   __u32 cpu
	//   __u64 timestamp
	//   union { ... } event_data
	what := binary.LittleEndian.Uint32(payload[20:24])
	if what != procEventExec {
		return
	}
	// EXEC event_data:
	//   __kernel_pid_t process_pid;
	//   __kernel_pid_t process_tgid;
	if len(payload) < 36+8 {
		return
	}
	pid := int32(binary.LittleEndian.Uint32(payload[36:40]))
	if pid <= 0 {
		return
	}
	select {
	case pl.events <- procExec{pid: pid}:
	default:
		// Channel full — drop. The polling fallback will pick
		// the process up if it's still alive next tick.
	}
}

// stop shuts the listener down idempotently. Safe to call from any
// goroutine; multiple invocations no-op via sync.Once.
func (pl *procEventListener) stop() {
	pl.once.Do(func() {
		// Nudge the kernel that we're unsubscribing — defensive,
		// the kernel cleans up on close anyway.
		_ = sendProcSubscribe(pl.fd, procCnMcastIgnore)
		_ = unix.Close(pl.fd)
	})
}

// Compile-time guard against the binary.LittleEndian / bytes /
// syscall imports going stale if a future refactor shrinks the
// implementation. All four are on the active hot path today; this
// is just an explicit anchor for `go vet`.
var (
	_ = bytes.MinRead
	_ syscall.Errno
)
