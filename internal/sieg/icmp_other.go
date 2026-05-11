//go:build !linux

package sieg

import "sync"

// icmpCounters is the cross-platform stub. Linux populates real
// values from /proc/net/snmp (see icmp_linux.go); Mac and Windows
// have no equivalent counter file, so the deltas always read as
// zero. Operators who need ICMP visibility on those platforms have
// to fall back to packet-capture tools — out of scope for this
// daemon.
type icmpCounters struct {
	InMsgs      int64
	InEchos     int64
	InEchoReps  int64
	OutMsgs     int64
	OutEchos    int64
	OutEchoReps int64
}

type icmpDeltaTracker struct {
	mu sync.Mutex
}

func (t *icmpDeltaTracker) snapshotDelta() (icmpCounters, icmpCounters) {
	return icmpCounters{}, icmpCounters{}
}

func (d icmpCounters) nonZero() bool { return false }
