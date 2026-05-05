package sieg

// Gateway auto-discovery. Called from the server / master daemon
// startup paths to populate the allowlist with the host's own
// default gateway(s). Skipped inside container environments (Docker
// bridges produce nonsense entries).

const maxGatewaysPerPeer = 8

// autoDiscoverOwnGateways resolves the host's default gateway(s),
// ARPs each one, and upserts them into the allowlist as gateway
// entries owned by `peerID`.
func autoDiscoverOwnGateways(store *networkAllowlist, peerID string, logger *Storage) {
	if store == nil {
		return
	}
	gateways, err := discoverGatewaysAndMACs()
	if err != nil {
		if err == errSkipContainer {
			if logger != nil {
				logger.Write("meta", map[string]any{
					"event": "network_allowlist_skip_container",
					"hint":  "running inside a container; the docker bridge gateway was NOT auto-added. " +
						"Add manually with `simplesiem network-source add` if needed.",
				})
			}
			return
		}
		if logger != nil {
			logger.Write("errors", map[string]any{
				"collector": "network_ingest_discovery",
				"error":     err.Error(),
			})
		}
		return
	}
	count := 0
	for _, g := range gateways {
		if count >= maxGatewaysPerPeer {
			break
		}
		if g.IP == "" || g.MAC == "" {
			// Record but don't fail; entry stays as pending revalidation.
			if logger != nil {
				logger.Write("meta", map[string]any{
					"event":   "network_gateway_unresolvable",
					"peer_id": peerID,
					"ip":      g.IP,
				})
			}
			continue
		}
		if _, err := store.AddOrUpdateGateway(g.IP, g.MAC, peerID); err != nil {
			if logger != nil {
				logger.Write("errors", map[string]any{
					"collector": "network_ingest_discovery",
					"error":     err.Error(),
					"ip":        g.IP,
				})
			}
			continue
		}
		count++
	}
}
