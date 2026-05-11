//go:build linux

package sieg

import (
	"os"
	"strconv"
	"strings"
	"sync"
)

// icmpCounters mirrors the Icmp: line of /proc/net/snmp. Linux's
// ping(1) uses raw ICMP sockets that don't appear in
// /proc/net/icmp (which only lists the unprivileged
// IPPROTO_ICMP/SOCK_DGRAM variant); /proc/net/snmp's Icmp counters
// are the canonical place to see ICMP activity host-wide. Per-flow
// destination attribution still requires eBPF or pcap; what we get
// here is "InMsgs / OutMsgs / InEchos / OutEchos / etc." deltas.
//
// Surfaced into the periodic traffic/host_io event so an operator
// who pings google.com sees `icmp_sent / icmp_recv` deltas in the
// same row as `bytes_sent / bytes_recv`. The earlier confusion —
// "I pinged but triage shows nothing" — gets resolved with the
// same poll the host_io event already runs on.
type icmpCounters struct {
	InMsgs   int64
	InEchos  int64
	InEchoReps int64
	OutMsgs  int64
	OutEchos int64
	OutEchoReps int64
}

// readICMPCounters parses the Icmp: line of /proc/net/snmp. Returns
// zero counters if the file isn't readable (e.g. minimal containers
// without /proc, or non-Linux build paths). The format is two lines:
//
//	Icmp: InMsgs InErrors InCsumErrors InDestUnreachs ...
//	Icmp: 5 0 0 0 0 0 0 0 0 5 0 0 0 0 5 0 0 0 0 0 0 5 0 0 0 0 0
//
// First line is the header (column names); second carries values.
// Field indices used:
//
//	[0]  InMsgs        — total ICMP packets received
//	[8]  InEchos       — echo requests received
//	[9]  InEchoReps    — echo replies received
//	[10] OutMsgs       — total ICMP packets sent
//	[19] OutEchos      — echo requests sent
//	[20] OutEchoReps   — echo replies sent
//
// (Column count is kernel-version-dependent; we bounds-check to
// avoid panicking on a shorter line.)
func readICMPCounters() icmpCounters {
	data, err := os.ReadFile("/proc/net/snmp")
	if err != nil {
		return icmpCounters{}
	}
	var icmpHeader, icmpValues string
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "Icmp: ") {
			continue
		}
		// Two consecutive Icmp: lines — header then values.
		// Header line contains alphabetic words; values is integers.
		if icmpHeader == "" {
			icmpHeader = line
		} else if icmpValues == "" {
			icmpValues = line
			break
		}
	}
	if icmpValues == "" {
		return icmpCounters{}
	}
	headerFields := strings.Fields(strings.TrimPrefix(icmpHeader, "Icmp:"))
	valueFields := strings.Fields(strings.TrimPrefix(icmpValues, "Icmp:"))
	if len(headerFields) != len(valueFields) {
		return icmpCounters{}
	}
	out := icmpCounters{}
	// Map header names → values dynamically; kernel versions reorder.
	for i, name := range headerFields {
		v, err := strconv.ParseInt(valueFields[i], 10, 64)
		if err != nil {
			continue
		}
		switch name {
		case "InMsgs":
			out.InMsgs = v
		case "InEchos":
			out.InEchos = v
		case "InEchoReps":
			out.InEchoReps = v
		case "OutMsgs":
			out.OutMsgs = v
		case "OutEchos":
			out.OutEchos = v
		case "OutEchoReps":
			out.OutEchoReps = v
		}
	}
	return out
}

// icmpDeltaTracker holds the previous read so the next call can
// emit deltas. Single-instance per ProcessCollector; the mutex
// guards against concurrent calls if traffic emission ever moves
// off the existing single-goroutine path.
type icmpDeltaTracker struct {
	mu   sync.Mutex
	prev icmpCounters
	have bool
}

// snapshotDelta returns (current, delta) where delta is current
// minus the previous reading. The first call after creation
// returns a zero delta (nothing to compare against yet) — that's
// intentional: we shouldn't report "InMsgs increased by 12345"
// just because the host had been pinged before the daemon
// started. After the first call, every subsequent delta is an
// honest "since last poll" count.
func (t *icmpDeltaTracker) snapshotDelta() (icmpCounters, icmpCounters) {
	t.mu.Lock()
	defer t.mu.Unlock()
	cur := readICMPCounters()
	if !t.have {
		t.prev = cur
		t.have = true
		return cur, icmpCounters{}
	}
	delta := icmpCounters{
		InMsgs:      cur.InMsgs - t.prev.InMsgs,
		InEchos:     cur.InEchos - t.prev.InEchos,
		InEchoReps:  cur.InEchoReps - t.prev.InEchoReps,
		OutMsgs:     cur.OutMsgs - t.prev.OutMsgs,
		OutEchos:    cur.OutEchos - t.prev.OutEchos,
		OutEchoReps: cur.OutEchoReps - t.prev.OutEchoReps,
	}
	t.prev = cur
	return cur, delta
}

// nonZero reports whether any delta field is nonzero. Used by the
// host_io emitter to decide whether to attach the icmp_* fields to
// the event — we don't want to bloat every traffic row with zero
// counters when nothing pinged anything.
func (d icmpCounters) nonZero() bool {
	return d.InMsgs != 0 || d.OutMsgs != 0
}
