package sieg

import (
	"path/filepath"
	"sync"
)

// storageGroup tracks every Storage instance the daemon has opened
// under a common root path so the storage controller can swing them
// all to a failover location atomically. Without it, server mode (one
// Storage per agent) and master mode (one per registered server) would
// only fail over their first Storage and leave the rest writing into
// the halted volume.
//
// Members register a subpath relative to the group's root. When the
// root swings, each member is told to point at <newRoot>/<subpath>.
// An empty subpath means the member is anchored directly at the root
// (used by standalone mode whose Storage IS the root).
type storageGroup struct {
	mu      sync.Mutex
	root    string
	members []groupMember
}

type groupMember struct {
	storage *Storage
	subpath string
}

func newStorageGroup(root string) *storageGroup {
	return &storageGroup{root: root}
}

// Root returns the current active root.
func (g *storageGroup) Root() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.root
}

// Open creates a new Storage under <root>/<subpath> and registers it
// with the group. Subsequent SwitchRoot calls will move this Storage
// in lockstep with the rest of the group.
func (g *storageGroup) Open(subpath string, groupGID int, maxFileSize int64, queueSize int) (*Storage, error) {
	g.mu.Lock()
	root := g.root
	g.mu.Unlock()
	base := root
	if subpath != "" {
		base = filepath.Join(root, subpath)
	}
	s, err := NewStorage(base, groupGID, maxFileSize, queueSize)
	if err != nil {
		return nil, err
	}
	g.mu.Lock()
	g.members = append(g.members, groupMember{storage: s, subpath: subpath})
	g.mu.Unlock()
	return s, nil
}

// SwitchRoot retargets every registered Storage at <newRoot>/<subpath>
// and updates the group's recorded root. Called by the storage
// controller during failover (and failback). Returns the first error
// from SwitchBase, if any — partial-success is the realistic outcome
// when the new volume is broken in some way (read-only, permission
// error). Already-switched members remain on the new root; the
// controller is expected to log and let the next probe round
// re-evaluate.
func (g *storageGroup) SwitchRoot(newRoot string) error {
	g.mu.Lock()
	members := append([]groupMember(nil), g.members...)
	g.mu.Unlock()
	var firstErr error
	for _, m := range members {
		base := newRoot
		if m.subpath != "" {
			base = filepath.Join(newRoot, m.subpath)
		}
		if err := m.storage.SwitchBase(base); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	g.mu.Lock()
	g.root = newRoot
	g.mu.Unlock()
	return firstErr
}

// SetHalted broadcasts the halt flag to every member. The controller
// uses this when the active root crosses the halt threshold and no
// failover slot is available — every Storage in the group rejects
// writes until the operator frees space.
func (g *storageGroup) SetHalted(v bool) {
	g.mu.Lock()
	members := append([]groupMember(nil), g.members...)
	g.mu.Unlock()
	for _, m := range members {
		m.storage.SetHalted(v)
	}
}

// PrimaryStorage returns the first registered member, used by the
// controller to land its meta events somewhere visible. In every mode
// the daemon registers a "primary" Storage first (the standalone
// store, the agent forward store, the master/collector localStore,
// the server's _server pseudo-host store) so this is deterministic.
func (g *storageGroup) PrimaryStorage() *Storage {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.members) == 0 {
		return nil
	}
	return g.members[0].storage
}
