package sieg

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// stateStore persists collector runtime state across restarts so we don't
// re-fire connection_open for every existing socket and don't re-read
// auth.log lines we already shipped. Best-effort: parse failures fall back
// to empty state, and writes only happen when we have something useful to
// save.
//
// Files are JSON in <stateDir>/<collector>.json. Mode 0o640.
type stateStore struct {
	dir string
	mu  sync.Mutex
}

func newStateStore(dir string) *stateStore {
	if dir == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil
	}
	return &stateStore{dir: dir}
}

func (s *stateStore) Save(name string, v any) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	tmp := filepath.Join(s.dir, name+".json.tmp")
	final := filepath.Join(s.dir, name+".json")
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, final)
}

func (s *stateStore) Load(name string, v any) error {
	if s == nil {
		return fmt.Errorf("no state dir")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(filepath.Join(s.dir, name+".json"))
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// stateNetwork is the wire form of NetworkCollector.seen — connection keys
// plus the time we first saw each one. Restored on startup so existing
// connections aren't re-reported as new.
type stateNetwork struct {
	SavedAt time.Time          `json:"saved_at"`
	Conns   []stateNetworkConn `json:"conns"`
}

type stateNetworkConn struct {
	Pid    int32     `json:"pid"`
	Local  string    `json:"local"`
	Remote string    `json:"remote"`
	Status string    `json:"status"`
	Seen   time.Time `json:"seen"`
}

// stateAuthLog stores the inode + byte offset of the auth.log we were
// tailing, so on restart we resume from the same position rather than
// jumping to EOF and missing whatever happened during the downtime.
type stateAuthLog struct {
	Path  string `json:"path"`
	Inode uint64 `json:"inode"`
	Pos   int64  `json:"pos"`
}

// stateAuthLogWin stores the highest Security event RecordId we've
// shipped so the Windows wevtutil poller resumes after a daemon
// restart instead of replaying the whole Security log.
type stateAuthLogWin struct {
	LastRecordID uint64 `json:"last_record_id"`
}

// stateAuthLogDarwin stores the timestamp of the most recent unified-log
// entry the macOS authlog collector parsed, so a daemon restart can
// `log show --start <ts>` to backfill the gap before resuming the
// `log stream` subprocess. Mirrors the Linux inode+offset checkpoint
// used by stateAuthLog.
type stateAuthLogDarwin struct {
	LastEventTS time.Time `json:"last_event_ts"`
}
