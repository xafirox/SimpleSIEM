package sieg

// NetworkIngestConfig is the operator-tunable surface for the network
// device syslog listener. Servers and masters expose it under their
// respective config blocks (cfg.Server.NetworkIngest /
// cfg.Master.NetworkIngest); agent / standalone / collector modes
// refuse to enable it.
type NetworkIngestConfig struct {
	Enabled bool `json:"enabled"`

	// Bind addresses. Empty disables that listener; at least one must
	// be set when Enabled is true.
	SyslogUDPListen string `json:"syslog_udp_listen"`
	SyslogTCPListen string `json:"syslog_tcp_listen"`
	SyslogTLSListen string `json:"syslog_tls_listen"`

	// TLSCertMode = "server" | "operator" | "selfsigned" (default).
	//   server     - reuse cfg.Server.Cert / cfg.Server.Key. Vendors
	//                must trust the SimpleSIEM CA (import ca.pem).
	//   operator   - load TLSCert / TLSKey from disk. Use this with
	//                Let's Encrypt or internal PKI.
	//   selfsigned - generated at <state>/network_ingest/{cert,key}.pem
	//                on first start; the SHA-256 fingerprint is printed
	//                via meta:network_ingest_tls_cert so operators can
	//                pin it on each device.
	TLSCertMode string `json:"tls_cert_mode"`
	TLSCert     string `json:"tls_cert"`
	TLSKey      string `json:"tls_key"`

	// Frame and rate limits.
	MaxFrameBytes               int `json:"max_frame_bytes"`
	MaxFramesPerSourcePerSecond int `json:"max_frames_per_source_per_second"`

	// BindExplicit is required for any non-loopback bind. Defense
	// against accidentally exposing :514 on a public interface.
	BindExplicit bool `json:"bind_explicit"`

	// rDNS lookup cache TTL (seconds). Used to label devices with no
	// allowlist label set. Default 300.
	RDNSCacheTTLSeconds int `json:"rdns_cache_ttl_seconds"`

	// MasterCanPushAllowlist is the per-server consent flag for
	// /v1/master/network-allowlist push. Default false; same security
	// posture as MasterCanRotateCA / MasterCanUninstall — destructive
	// or fleet-wide config changes need explicit operator opt-in.
	// Lives in NetworkIngestConfig because it tracks the same feature.
	MasterCanPushAllowlist bool `json:"master_can_push_allowlist"`
}

// pickNetworkIngestConfig returns the active block based on mode.
// Server uses cfg.Server.NetworkIngest; master uses
// cfg.Master.NetworkIngest. Other modes return a zero-value config
// (Enabled=false).
func pickNetworkIngestConfig(cfg Config, mode string) NetworkIngestConfig {
	switch mode {
	case "server":
		return cfg.Server.NetworkIngest
	case "master":
		return cfg.Master.NetworkIngest
	}
	return NetworkIngestConfig{}
}

// pendingPushFile is the on-disk queue for server-originated changes
// that arrived while the master was offline. Written to
// <state>/server/network_allowlist_pending.json. Backup-included.
const pendingPushFile = "network_allowlist_pending.json"
