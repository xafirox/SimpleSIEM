// SimpleSIEM - single-binary on-box SIEM for Windows / macOS / Linux.
package sieg

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// init runs before main and clamps GOTRACEBACK so a panic doesn't dump full
// stack traces (which can include in-memory secrets like webhook URLs)
// to stderr or the systemd journal. Operators who want full traces can set
// GOTRACEBACK=all in the environment before starting the daemon.
func init() {
	if os.Getenv("GOTRACEBACK") == "" {
		os.Setenv("GOTRACEBACK", "none")
	}
}

const (
	version     = "0.1.0"
	serviceName = "simplesiem"
	productName = "SimpleSIEM"
)

// buildNumber is overridden at build time via:
//   -ldflags "-X simplesiem/internal/sieg.buildNumber=..."
// (build.ps1 already does this).
// Format YYYYMMDDHHMMSS (UTC) — set by build.ps1.
var buildNumber = "dev"

func versionString() string {
	return fmt.Sprintf("%s %s (build %s)", productName, version, buildNumber)
}

func defaultBinaryName() string {
	if runtime.GOOS == "windows" {
		return serviceName + ".exe"
	}
	return serviceName
}

func windowsProgramData() string {
	if v := os.Getenv("ProgramData"); v != "" {
		return v
	}
	return `C:\ProgramData`
}

func windowsProgramFiles() string {
	if v := os.Getenv("ProgramFiles"); v != "" {
		return v
	}
	return `C:\Program Files`
}

func defaultConfigPath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(windowsProgramData(), productName, "config.json")
	}
	return "/etc/" + serviceName + "/config.json"
}

func defaultInstallDir() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(windowsProgramFiles(), productName)
	}
	return "/usr/local/bin"
}

func defaultConfigDir() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(windowsProgramData(), productName)
	}
	return "/etc/" + serviceName
}

func defaultLogDir() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(windowsProgramData(), productName, "logs")
	}
	return "/var/log/" + serviceName
}

func defaultStateDir() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(windowsProgramData(), productName, "state")
	}
	return "/var/lib/" + serviceName + "/state"
}

type Config struct {
	// Mode selects the daemon's role: "standalone" (default — collect and
	// store on this host), "agent" (collect and ship to a server), or
	// "server" (receive batches from agents and store per host).
	Mode string `json:"mode"`

	LogDir             string   `json:"log_dir"`
	RetentionDays      int      `json:"retention_days"`
	NetworkInterval    int      `json:"network_interval"`
	DNSCacheTTL        int      `json:"dns_cache_ttl"`
	FileWatchPaths     []string `json:"file_watch_paths"`
	FileWatchRecursive bool     `json:"file_watch_recursive"`
	FilePollInterval   int      `json:"file_poll_interval"`
	AuthInterval       int      `json:"auth_interval"`
	ProcessInterval    int      `json:"process_interval"`
	TrafficInterval    int      `json:"traffic_interval"`
	AuthLogPaths       []string `json:"auth_log_paths"`
	AuthLogInterval    int      `json:"auth_log_interval"`
	RulesPath          string   `json:"rules_path"`
	LogOwnerGroup      string   `json:"log_owner_group"`
	MaxLogFileMB       int      `json:"max_log_file_mb"`
	WriteQueueSize     int      `json:"write_queue_size"`
	StateDir           string   `json:"state_dir"`

	Agent       AgentConfig       `json:"agent"`
	Server      ServerConfig      `json:"server"`
	Master      MasterConfig      `json:"master"`
	Collector   CollectorConfig   `json:"collector"`
	Storage     StorageConfig     `json:"storage"`
	ThreatIntel ThreatIntelConfig `json:"threatintel"`
	Incidents   IncidentsConfig   `json:"incidents"`
	FirstSeen   FirstSeenConfig   `json:"firstseen"`
	Mitre       MitreConfig       `json:"mitre"`
	RulesExtras RulesExtrasConfig `json:"rules_extras"`
	Baseline    BaselineConfig    `json:"baseline"`
	Honey       HoneyConfig       `json:"honey"`
}

// CollectorPushConfig is the operator-editable subset of collector
// state that masters (and servers acting as the collector's source)
// can push to the collector during its pull cycle. Limited to
// non-destructive knobs — CA settings, mode flips, etc. are
// off-limits.
type CollectorPushConfig struct {
	PullIntervalSeconds int `json:"pull_interval_seconds"`
}

// CollectorConfig drives collector mode — a backup-storage role that
// pulls a copy of every event from the highest-authority peer it can
// reach (master if available, otherwise a server). The collector
// never modifies the source; it just reads and writes to its own log
// directory under the same per-origin chain layout master mode uses.
type CollectorConfig struct {
	// SourceURL is the URL of the peer this collector is currently
	// associated with. Initially set by `simplesiem collector enroll`.
	// May be auto-promoted to a higher-authority peer on the next
	// pull cycle if /v1/sync/config reports a master_url that wasn't
	// previously known.
	SourceURL string `json:"source_url"`

	// FailoverServers is the list of fallback URLs in the same realm.
	// Populated automatically from the source's /v1/sync/config peer
	// list at enrollment / heartbeat time. The collector tries the
	// primary URL first and rotates through this list on connection
	// failure (sticky — same model as agent.failover_servers).
	FailoverServers []string `json:"failover_servers"`

	// PullIntervalSeconds is how often the collector pulls events.
	// Default 86400 (once per day). Configurable via `collector
	// interval <duration>` or by the master pushing a new value via
	// CollectorPushConfig. Setting it very low effectively turns the
	// collector into a near-real-time replica.
	PullIntervalSeconds int `json:"pull_interval_seconds"`

	// CollectorID is the cert CN this collector uses on its CSRs and
	// /v1/enroll-collector requests. Defaults to "collector-<hostname>";
	// once set, reused across re-enrollments so the source records
	// the same CN every time.
	CollectorID string `json:"collector_id"`

	// CertsDir is where per-source client certs live. Default
	// <config_dir>/collector/. Layout: <CertsDir>/<source-host>/{cert,key,ca}.pem
	// — same convention master mode uses for per-server certs.
	CertsDir string `json:"certs_dir"`

	// AuthorityHint records the authority kind of the current source:
	// "agent" (only valid in standalone-as-source mode, deferred), "server",
	// or "master". The collector uses this to decide whether to
	// auto-promote on the next cycle. Set automatically; not
	// operator-editable in normal operation.
	AuthorityHint string `json:"authority_hint"`

	// MasterListen is the optional TLS listen address for a master
	// query endpoint, e.g. ":9446". Off by default; opt in via
	// `simplesiem collector master enable`. Lets a paired master
	// query the collector's archive without touching its own (smaller)
	// retention window.
	//   - Single-master rule: only ONE master pairs with any collector
	//     (MasterCN + MasterPendingEnroll act as the slot gate).
	//   - Cert / Key / CACert below are the collector's own server-side
	//     PKI for this listener. Generated by `certs init` on the
	//     collector host when MasterListen is enabled.
	MasterListen           string `json:"master_listen"`
	Cert                   string `json:"cert"`
	Key                    string `json:"key"`
	CACert                 string `json:"ca_cert"`
	MasterCN               string `json:"master_cn"`
	MasterPendingEnroll    bool   `json:"master_pending_enroll"`
	MasterEnrollPSKPath    string `json:"master_enroll_psk_path"`

	// RealmServerCNs (c4) — when no master is paired, every realm
	// server may enroll concurrently to query this collector. Each
	// `simplesiem server query-collector enroll` adds a CN here.
	// Distinct from MasterCN's single-slot rule: this is a list,
	// not a slot. Empty when a master is paired (master is the
	// canonical querier in that case). The list is also gated by a
	// pending flag opened with `collector realm-servers accept-next`
	// so a leaked PSK can't enroll an unbounded number of CNs
	// silently — every accept-next opens the door for ONE new CN
	// to enroll, then closes it again.
	RealmServerCNs            []string `json:"realm_server_cns"`
	RealmServerPendingEnroll  bool     `json:"realm_server_pending_enroll"`

	// MasterCanUninstall opts this collector into being uninstalled
	// remotely by its paired master via the `master uninstall-all`
	// cascade. Defaults to false. Same rationale as the server-side
	// flag: a destructive cluster-wide command should require an
	// explicit per-node opt-in so a compromised master can't wipe
	// everything by surprise.
	MasterCanUninstall bool `json:"master_can_uninstall"`

	// AutoPromoteToMaster (r21) opts this collector into automatic
	// promotion when the source's /v1/sync/config surfaces a master_url
	// AND the operator has pre-staged the master's collector PSK at
	// `<state>/master_promote.psk` (mode 0600). When both are true,
	// the next pull cycle promotes the collector to pull from the
	// master without operator action on the collector host. The PSK
	// file is consumed (deleted) after a successful promote. Default
	// true; set false to require an operator to run `simplesiem
	// collector promote` by hand.
	AutoPromoteToMaster bool `json:"auto_promote_to_master"`

	// AutoRepairOnOutage (c5) opts this collector into automatic
	// re-pairing with a failover_server when the primary source has
	// been unreachable past RepairAfterMinutes AND the operator has
	// pre-staged a realm PSK at `<state>/realm_repair.psk` (mode
	// 0600). On a successful repair the source URL is swapped to the
	// new peer and the staged PSK file is consumed. Default true.
	AutoRepairOnOutage bool `json:"auto_repair_on_outage"`

	// RepairAfterMinutes is the threshold AutoRepairOnOutage applies
	// before triggering a repair attempt. Default 30 minutes; tune
	// down for hot collectors that must not lose visibility for long.
	RepairAfterMinutes int `json:"repair_after_minutes"`
}

// AgentConfig drives agent mode — the daemon collects events and ships
// them to a server over mTLS instead of writing to local disk.
type AgentConfig struct {
	ID          string `json:"id"`           // stable identifier; defaults to hostname
	ServerURL   string `json:"server_url"`   // e.g. https://siem.example.com:9443
	ClientCert  string `json:"client_cert"`  // PEM file; CN must equal ID
	ClientKey   string `json:"client_key"`   // PEM file
	CACert      string `json:"ca_cert"`      // CA that signed the server cert
	BearerToken string `json:"bearer_token"` // optional; sent as Authorization: Bearer ...

	SpoolDir         string `json:"spool_dir"`
	SpoolMaxMB       int    `json:"spool_max_mb"`
	BatchSize        int    `json:"batch_size"`
	BatchIntervalSec int    `json:"batch_interval_seconds"`
	InsecureSkipTLS  bool   `json:"insecure_skip_tls"` // dev only; never set in prod

	// FailoverServers lets the agent fail over to peer servers in the
	// same realm when the primary is unreachable. Populated automatically
	// by the server on enrollment (the server sends its realm.peers list
	// in the enroll response), but can also be set manually for static
	// HA deployments. Servers are tried in order; the agent sticks to
	// whichever one last succeeded and only rotates on failure.
	FailoverServers []string `json:"failover_servers"`

	// NoLocalStorage opts the agent OUT of every local on-disk fallback
	// for events the shipper hasn't yet flushed. Defaults to false —
	// the standard behaviour, which spools failed batches to
	// `agent.spool_dir` and mirrors them into `<log_dir>/_agent/` so
	// `simplesiem triage` / `verify` can inspect events even during a
	// server outage. Setting NoLocalStorage to true:
	//
	//   - DROPS batches that fail to ship (counter increments,
	//     reported in the meta log, but no spool file is written),
	//   - SKIPS the local-mirror write into `<log_dir>/_agent/` on
	//     ship failure,
	//   - SKIPS the shutdown-spool path so a graceful daemon stop
	//     leaves no in-flight batch on disk either.
	//
	// Use case: hosts where the threat model says "we'd rather lose
	// in-flight events than leave any plaintext on disk for an
	// attacker to exfiltrate." Combine with aggressive
	// `batch_interval_seconds: 1` and `batch_size: 1` so the
	// in-memory window is minimised.
	//
	// This flag is dangerous by default — the agent's shipper is
	// designed to preserve events through outages. Only enable it
	// after reading the threat-model section of docs/agent-server.md
	// ("Maximum exfiltration resistance").
	NoLocalStorage bool `json:"no_local_storage"`
}

// ServerConfig drives server mode — accepts batches from agents.
type ServerConfig struct {
	Listen            string   `json:"listen"`              // e.g. ":9443"
	Cert              string   `json:"cert"`                // PEM file
	Key               string   `json:"key"`                 // PEM file
	CACert            string   `json:"ca_cert"`             // CA that signs agent client certs
	RequireClientCert bool     `json:"require_client_cert"` // mTLS gate; default true
	BearerTokens      []string `json:"bearer_tokens"`       // optional; any token in this list grants access
	AgentAllowlist    []string `json:"agent_allowlist"`     // explicit list of authorized agent IDs; empty = any valid cert
	// MasterCNs is the list of cert CNs that are allowed to call
	// /v1/sync/events as masters (in addition to realm peers).
	// Populated automatically by /v1/enroll-master when a master
	// enrolls with this server. Manual entries are also honoured.
	MasterCNs []string `json:"master_cns"`

	// AgentRevoked is a tombstone map: agent_id -> RFC3339 timestamp
	// of revocation. Effective acceptance is `id in agent_allowlist
	// AND id not in agent_revoked`. Tombstones are propagated via the
	// realm sync so a single `simplesiem certs revoke <id>` blocks
	// the agent across every peer in the realm. Kept as a map (not a
	// list) so concurrent revocations from different peers merge
	// without losing entries.
	AgentRevoked map[string]string `json:"agent_revoked"`

	// MasterRevoked is the master-CN counterpart of AgentRevoked.
	// Same semantics: `cn in master_cns AND cn not in master_revoked`.
	MasterRevoked map[string]string `json:"master_revoked"`

	// AgentUnrevokeIntent / MasterUnrevokeIntent record this peer's
	// vote to undo a revocation. The map shape is identical to the
	// revoked maps; an entry indicates "this peer wants to unrevoke
	// at this timestamp". Realm sync collects intents from every
	// peer, and when the intent count reaches quorum (⌈peers/2⌉+1)
	// AND the latest intent timestamp is newer than the latest
	// revocation timestamp, every peer drops the tombstone. This
	// gives operators a way to undo accidental revocations without
	// hand-editing every peer's config.json.
	AgentUnrevokeIntent  map[string]string `json:"agent_unrevoke_intent"`
	MasterUnrevokeIntent map[string]string `json:"master_unrevoke_intent"`

	// MasterCanRotateCA grants masters in master_cns the privilege of
	// triggering this server's `certs init-rotate` and finalize-rotate
	// remotely via /v1/master/rotate-ca + /v1/master/finalize-rotate.
	// Defaults to false so a compromised master can't destroy CA keys
	// unless the operator explicitly opted in. Per-server: an operator
	// who runs a master across both critical and non-critical realms
	// can grant this only on the non-critical servers.
	MasterCanRotateCA bool `json:"master_can_rotate_ca"`

	// MasterCanUninstall is the analogous opt-in for the
	// `master uninstall-all` cascade. When true, a master in
	// master_cns can trigger this server's full uninstall
	// (service removal + optional --purge wipe) via
	// /v1/master/uninstall-self. Defaults to false.
	MasterCanUninstall bool `json:"master_can_uninstall"`

	// AlertWebhooks is a list of HTTPS URLs that receive every
	// fired alert as a POST with `Content-Type: application/json`
	// and the alert event verbatim as the body. Empty (default)
	// disables webhook delivery; alerts continue landing in
	// `<log_dir>/<host>/alerts/` regardless. Failures retry with
	// 1s/4s/16s backoff, then drop with a counter bump
	// (reported into `_server/meta` as `alert_webhook_drops`).
	// TLS validation is strict — operators with internal
	// self-signed receivers must add the receiver's CA to the
	// host's trust store rather than disabling validation.
	AlertWebhooks []string `json:"alert_webhooks"`

	// AlertWebhookMinSeverity filters which alerts get dispatched
	// to the webhooks. Accepted values: "low" (everything,
	// default), "medium", "high", "critical". Alerts at or above
	// the named threshold are sent; below are silently dropped
	// from the webhook stream (still recorded in alerts log).
	AlertWebhookMinSeverity string `json:"alert_webhook_min_severity"`

	// AlertSyslog forwards every fired alert to a single syslog
	// collector as an RFC 5424 message. Bridges into Splunk /
	// Elastic / rsyslog pipelines that ops teams already operate.
	// Empty .Address disables the feature; alerts still land on
	// disk regardless. Drops are reported as
	// `meta:alert_syslog_drops` every 30s.
	AlertSyslog AlertSyslogConfig `json:"alert_syslog"`

	// AlertEscalation re-fires unacked high-severity alerts after a
	// configurable window so a forgotten critical doesn't sit
	// indefinitely on the alerts dashboard. Operators typically
	// wire a separate webhook (PagerDuty / Slack #incidents) with
	// `severity_min: "critical"` to receive only escalations.
	AlertEscalation AlertEscalationConfig `json:"alert_escalation"`

	// VolumeAnomaly tunes the per-agent volume-drop detector. Zero
	// values fall back to safe defaults (5 events/min minimum
	// baseline, 0.05 drop ratio, 2 consecutive low minutes,
	// 30-minute per-agent cooldown). Operators with bursty
	// fleets (laptops, batch hosts) bump dropRatio up; ops teams
	// running steadier traffic (servers in a rack) tighten it
	// down. Values apply at hot-reload — no restart needed.
	VolumeAnomaly VolumeAnomalyConfig `json:"volume_anomaly"`

	// QueryCollectorURL is the URL of a paired collector this server
	// can query. r20 — server-direct collector queries are allowed
	// when the realm has no master (the master is the canonical
	// querier when present). Set by `simplesiem server
	// query-collector enroll`; per-collector cert lives under
	// <config>/server/query-collector/<peer-id>/.
	QueryCollectorURL string `json:"query_collector_url"`

	// CollectorCN is the cert CN of the single collector currently
	// associated with this server (only relevant when the server is
	// the highest-authority peer the collector found — i.e., when
	// the realm has no master). Zero value means no collector is
	// associated. The /v1/enroll-collector endpoint refuses any
	// enrollment that doesn't match an empty slot or this CN, so
	// only one collector can ever be paired with this server at a
	// time.
	CollectorCN string `json:"collector_cn"`

	// CollectorPendingEnroll is the operator-controlled gate that
	// must be true to accept a new collector enrollment. Set via
	// `simplesiem certs collector accept-next` (or by hand). Cleared
	// automatically on the next successful collector enrollment so
	// a leaked PSK can't enroll a second collector after the slot
	// is filled.
	CollectorPendingEnroll bool `json:"collector_pending_enroll"`
	CollectLocally    bool     `json:"collect_locally"`     // also run collectors on the server host (default true)
	LocalID           string   `json:"local_id"`            // identifier under which the server's own events are stored; default = hostname
	MaxBatchBytes        int `json:"max_batch_bytes"`         // hard cap on POST body (compressed)
	MaxDecompressedBytes int `json:"max_decompressed_bytes"`  // hard cap after gzip; defends against zip bombs
	MaxHeaderBytes       int `json:"max_header_bytes"`        // hard cap on request headers
	MaxConcurrent        int `json:"max_concurrent"`          // ceiling on simultaneous in-flight requests
	RatePerSecond        int `json:"rate_per_second"`         // per-IP token-bucket fill rate
	RateBurst            int `json:"rate_burst"`              // per-IP token-bucket capacity
	MaxClockSkew         int `json:"max_clock_skew_seconds"`  // accept ts within ±this many seconds of received_at
	// AgentReauthSeconds is how often each agent must hit /v1/heartbeat
	// to renew its session. Inside the window, /v1/events skips the
	// allowlist re-check; outside it, the agent is treated as expired
	// until the next heartbeat. Setting this on the server propagates
	// to agents via the heartbeat response, so an operator-driven
	// shortening or lengthening takes effect everywhere on the next
	// beat. Default 60s.
	AgentReauthSeconds int `json:"agent_reauth_seconds"`

	// Realm is the server's HA / replication group. Servers in the same
	// realm:
	//   - share a CA and an agent_allowlist (synced in Phase B)
	//   - tell agents about each other so an agent can fail over if its
	//     primary server goes down (Phase A — implemented now)
	//   - replicate event logs amongst themselves (Phase B)
	//
	// `name` is "default" on a fresh install. An operator can rename
	// from any server in the realm and the change synchronises to peers
	// (Phase B). When `master_url` is set, the realm is under master
	// control and local edits to realm config are refused — the master
	// is the source of truth (Phase C).
	Realm RealmConfig `json:"realm"`
}

// MasterConfig drives master mode — a tier above the realm. A master
// pulls events from one or more servers (typically the primary of
// each realm it aggregates) and supports cross-realm queries on a
// single host.
//
// Master mode is OPTIONAL. Servers run fine without one; the master
// is for operators with multiple realms or who want a single
// management plane on top of redundant servers.
type MasterConfig struct {
	// Servers is the list of server URLs this master pulls events
	// from. Populated by `simplesiem master enroll <url> --key <PSK>`,
	// or set manually by operators with externally-issued certs.
	Servers []string `json:"servers"`
	// SyncIntervalSeconds is how often the master pulls from each
	// server. Default 60 to match realm sync.
	SyncIntervalSeconds int `json:"sync_interval_seconds"`
	// CertsDir is where per-server client certs live. Layout is
	// <CertsDir>/<server-hostname>/{cert.pem, key.pem, ca.pem}.
	CertsDir string `json:"certs_dir"`
	// MasterID is the CN this master uses on its CSRs and enroll
	// requests. Defaults to "master-<hostname>". Each enrolled
	// server stores this CN in server.master_cns.
	MasterID string `json:"master_id"`

	// Listen is the optional bind address for the master's health
	// endpoint, e.g. ":9444". When empty (default), no listener is
	// started and operators have to observe behaviour (process
	// running, watermarks advancing) for liveness. When set, the
	// master exposes GET /health on plain HTTP returning {"ok":true}.
	// Plain HTTP is fine: a master is a pure dialer to its servers,
	// has no inbound trust relationship with anything; the only
	// thing /health reveals is "the master process is alive".
	Listen string `json:"listen"`

	// CollectorListen is the optional TLS listen address for the
	// master's collector-pull endpoint, e.g. ":9445". Off by default;
	// the master must be explicitly opted in. When set:
	//   - Cert / Key / CACert below must also be set.
	//   - Master generates its own CA via `simplesiem certs init`
	//     (run automatically on `convert master --enable-collector`).
	//   - The listener exposes /v1/health, /v1/sync/events,
	//     /v1/sync/config, /v1/enroll-collector, /v1/rotate.
	//   - Only ONE collector can ever be associated (CollectorCN +
	//     CollectorPendingEnroll act as a single-slot enforcement).
	CollectorListen string `json:"collector_listen"`
	// Cert / Key / CACert are the master's own server-side PKI for
	// the collector listener. Generated by `certs init` on the
	// master host when CollectorListen is enabled.
	Cert    string `json:"cert"`
	Key     string `json:"key"`
	CACert  string `json:"ca_cert"`
	// CollectorCN / CollectorPendingEnroll: same single-collector
	// semantics as on a server. Master can only ever be paired with
	// one collector at a time.
	CollectorCN            string `json:"collector_cn"`
	CollectorPendingEnroll bool   `json:"collector_pending_enroll"`
	// CollectorEnrollPSK is the master's enrollment PSK used by
	// /v1/enroll-collector. Stored in the master's state dir;
	// surfaced via `simplesiem certs collector psk show`.
	// Independent from any server's PSK.
	CollectorEnrollPSKPath string `json:"collector_enroll_psk_path"`
	// CollectorPushConfig is the master-controlled config that gets
	// delivered to the collector on every pull cycle's /v1/sync/config-for-collector
	// response. Operators edit it on the master; the collector
	// adopts it transparently. Currently just the pull interval.
	CollectorPushConfig CollectorPushConfig `json:"collector_push_config"`

	// RotationRealms is the per-realm CA-rotation policy. Each entry
	// is `realm_name: rfc3339_timestamp`. When the operator runs
	// `rotate-ca-all` or `rotate-ca-realm <r>`, the master records
	// the timestamp here. Every subsequent pull cycle queries the
	// server's CA state — if its CA NotBefore is older than the
	// policy timestamp for that server's realm, the master triggers
	// rotation automatically. This makes `rotate-ca-all` self-healing
	// across machines that were down at issuance time.
	RotationRealms map[string]string `json:"rotation_realms"`

	// FinalizeRealms is the per-realm finalize-rotate policy, same
	// shape as RotationRealms. Set by `finalize-rotate-all` /
	// `finalize-rotate-realm`. The master triggers finalize on a
	// server only when (a) the policy is set for that realm, AND
	// (b) the server has already rotated to at least the
	// rotation_realms timestamp — preventing finalize from running
	// on a server that's still behind on rotation.
	FinalizeRealms map[string]string `json:"finalize_realms"`

	// QueryCollectorURL is the URL of a paired collector this master
	// can query for archived events. Set by `simplesiem master
	// query-collector enroll <url> --key <psk>`. Read by
	// `simplesiem master query-collector run ...` to know where to
	// dial; the per-collector client cert lives under
	// <config>/master/query-collector/<peer-id>/.
	QueryCollectorURL string `json:"query_collector_url"`

	// RulesPath is the master-side detection rules file. When set,
	// every event the master pulls from a registered server is
	// evaluated against these rules; fired alerts land in
	// <log_dir>/_master/alerts/ and dispatch through the master's
	// alert webhooks + syslog (cfg.Server.AlertWebhooks /
	// AlertSyslog — the master shares the server-mode dispatcher
	// config). Empty (default) disables master-side rule evaluation;
	// per-server rules continue to fire on the originating server.
	// Use this for cross-host correlations like "5 different agents
	// see failed logins for user X in 10 min" — the master is the
	// natural place because it sees the cross-host stream.
	RulesPath string `json:"rules_path"`
}

// AlertEscalationConfig configures the escalation watcher. Setting
// `enabled: true` (or any non-zero AfterSeconds) turns the feature
// on — escalations re-fire through the same alert hook fanout as
// regular alerts, so operators don't configure a separate sink here;
// they configure a separate webhook / syslog with severity_min set
// to "critical" to receive only the escalations.
type AlertEscalationConfig struct {
	Enabled             bool   `json:"enabled"`              // explicit on-switch; setting AfterSeconds also enables
	AfterSeconds        int    `json:"after_seconds"`        // re-fire if still unacked after this many seconds (default 900 = 15 min)
	MinSeverity         string `json:"min_severity"`         // "high" / "critical"; default "critical"
	ScanIntervalSeconds int    `json:"scan_interval_seconds"` // how often to walk the alerts log (default 60)
	// Address kept for symmetry with the other alert sinks; today
	// it's only checked for "is the feature enabled" (non-empty
	// implies enabled). A future enhancement could route
	// escalations to a dedicated dispatcher rather than reusing
	// the existing webhook/syslog fanout.
	Address string `json:"address"`
}

// VolumeAnomalyConfig tunes the per-agent volume-drop detector. Zero
// values mean "use the built-in default."
type VolumeAnomalyConfig struct {
	MinBaseline float64 `json:"min_baseline"`         // events/min below which we never fire (default 5)
	DropRatio   float64 `json:"drop_ratio"`           // current/baseline ratio that counts as "quiet" (default 0.05)
	Consecutive int     `json:"consecutive_low_mins"` // minutes-low in a row before firing (default 2)
	CooldownMins int    `json:"cooldown_minutes"`     // per-agent re-fire suppression window (default 30)
}

// AlertSyslogConfig describes the optional RFC 5424 forwarder. Populated
// from `cfg.server.alert_syslog` in config.json. Empty .Address disables
// the dispatcher (caller checks for nil-receiver semantics).
type AlertSyslogConfig struct {
	Network     string `json:"network"`      // "udp" / "tcp" / "udp6" / "tcp6" (default: "udp")
	Address     string `json:"address"`      // e.g. "syslog.example.com:514"; empty = disabled
	Facility    int    `json:"facility"`     // RFC 5424 facility 0..23 (default: 16 = local0)
	Tag         string `json:"tag"`          // appname / msgid prefix (default: "simplesiem")
	SeverityMin string `json:"severity_min"` // "low"/"medium"/"high"/"critical"; default "low"
}

// RealmConfig groups the redundancy-related settings.
type RealmConfig struct {
	Name                string   `json:"name"`                  // default: "default"
	Peers               []string `json:"peers"`                 // peer server URLs in this realm; empty = single-server realm
	SyncIntervalSeconds int      `json:"sync_interval_seconds"` // how often peers replicate logs; default 60
	MasterURL           string   `json:"master_url"`            // optional master server URL; when set, this server defers realm config to the master
	// ConfigVersion is the unix-nano timestamp of the most recent
	// local edit to the realm config. Peers reconcile by adopting
	// the highest version they see, so a rename from any peer
	// propagates to the others within one sync interval.
	ConfigVersion int64 `json:"config_version"`
	// PendingJoinPeer + PendingJoinPSK queue a realm-join handshake
	// for the daemon to run on its next config-watch tick. Used by
	// master-driven server migration: the master tells the server
	// to migrate, the server clears its R1 state synchronously and
	// records the destination here; the running daemon picks it up
	// and completes the join without needing the operator to run a
	// follow-up CLI command on each migrated server.
	PendingJoinPeer string `json:"pending_join_peer,omitempty"`
	PendingJoinPSK  string `json:"pending_join_psk,omitempty"`
}

func defaultConfig() Config {
	// Intervals are aggressive enough to catch most admin commands
	// (apt-get run, curl, ssh login). Bump them up in config.json if CPU is
	// a concern on a busy host — at 3s, gopsutil polls /proc for every PID
	// each cycle, which runs a few percent of one core on a typical system.
	c := Config{
		Mode:               "standalone",
		LogDir:             defaultLogDir(),
		RetentionDays:      30,
		NetworkInterval:    2,
		DNSCacheTTL:        600,
		FileWatchRecursive: true,
		FilePollInterval:   30,
		AuthInterval:       5,
		ProcessInterval:    2,
		TrafficInterval:    30, // host_io rollups are coarse; no need for 2s cadence
		AuthLogInterval:    2,
		// auth_log_paths is only consulted on Linux. macOS uses unified
		// logging via `log stream`; Windows currently has no auth-log
		// implementation.
		AuthLogPaths:       []string{"/var/log/auth.log", "/var/log/secure", "/var/log/messages"},
		RulesPath:          filepath.Join(defaultConfigDir(), "rules.json"),
		MaxLogFileMB:       256,
		WriteQueueSize:     4096,
		StateDir:           defaultStateDir(),
		Storage: StorageConfig{
			WarnThreshold: "80%",
			HaltThreshold: "90%",
		},
		Agent: AgentConfig{
			SpoolDir:         filepath.Join(defaultStateDir(), "spool"),
			SpoolMaxMB:       512,
			BatchSize:        100,
			BatchIntervalSec: 5,
			ClientCert:       filepath.Join(defaultConfigDir(), "certs", "client.pem"),
			ClientKey:        filepath.Join(defaultConfigDir(), "certs", "client.key"),
			CACert:           filepath.Join(defaultConfigDir(), "certs", "ca.pem"),
		},
		Collector: CollectorConfig{
			// r21 — auto-promote to master is on by default. Operators
			// who want to require a hand-run `collector promote` set
			// false in config.json.
			AutoPromoteToMaster: true,
			// c5 — auto-repair on outage is on by default with a 30m
			// threshold. Both PSK files must still be operator-staged
			// for any auto-action to happen, so the default-on stance
			// only kicks in when the operator has explicitly opted in
			// by dropping a PSK file.
			AutoRepairOnOutage: true,
			RepairAfterMinutes: 30,
		},
		ThreatIntel: defaultThreatIntelConfig(),
		Incidents:   defaultIncidentsConfig(),
		FirstSeen:   defaultFirstSeenConfig(),
		Mitre:       defaultMitreConfig(),
		RulesExtras: RulesExtrasConfig{Fixtures: defaultFixturesConfig()},
		Baseline:    defaultBaselineConfig(),
		Honey:       defaultHoneyConfig(),
		Server: ServerConfig{
			Listen:            ":9443",
			Cert:              filepath.Join(defaultConfigDir(), "certs", "server.pem"),
			Key:               filepath.Join(defaultConfigDir(), "certs", "server.key"),
			CACert:            filepath.Join(defaultConfigDir(), "certs", "ca.pem"),
			RequireClientCert: true,
			CollectLocally:    true, // server hosts also monitor themselves
			MaxBatchBytes:        32 * 1024 * 1024,  // 32 MiB compressed
			MaxDecompressedBytes: 256 * 1024 * 1024, // 256 MiB after gzip; defeats zip bombs
			MaxHeaderBytes:       32 * 1024,         // 32 KiB; far above any legit request
			MaxConcurrent:        256,               // simultaneous in-flight uploads
			RatePerSecond:        200,               // bursts of 200 req/s per agent IP, then steady
			RateBurst:            400,
			MaxClockSkew:         300, // ±5 minutes between agent ts and server clock
			Realm: RealmConfig{
				// Every fresh install starts in a one-server realm
				// named "default". Operators add peers to grow it
				// into an HA group; the name is changeable from any
				// server in the realm (and syncs to peers in Phase B).
				Name:                "default",
				SyncIntervalSeconds: 60,
			},
		},
	}
	switch runtime.GOOS {
	case "linux":
		c.LogOwnerGroup = "adm"
	case "darwin":
		c.LogOwnerGroup = "admin"
	}
	switch runtime.GOOS {
	case "windows":
		root := os.Getenv("SystemRoot")
		if root == "" {
			root = `C:\Windows`
		}
		c.FileWatchPaths = []string{
			filepath.Join(root, `System32`, `drivers`, `etc`), // hosts, services
			`C:\ProgramData`,
			`C:\Users`,
			filepath.Join(root, `Temp`),
			filepath.Join(root, `System32`, `Tasks`), // scheduled tasks (persistence)
		}
	case "darwin":
		c.FileWatchPaths = []string{
			"/etc", "/private/etc",
			"/Users",
			"/tmp", "/var/tmp",
			"/opt",
			"/usr/local/bin", "/usr/local/sbin", "/usr/local/etc",
			// Persistence: launchd job definitions.
			"/Library/LaunchDaemons",
			"/Library/LaunchAgents",
			"/System/Library/LaunchDaemons",
			"/System/Library/LaunchAgents",
		}
	default: // linux
		c.FileWatchPaths = []string{
			"/etc",
			"/root",
			"/home",
			"/tmp", "/var/tmp",
			"/opt", "/srv",
			"/app", "/workspace", // common container/devcontainer working dirs
			"/usr/local/bin", "/usr/local/sbin",
			// Persistence: cron, at, and system-wide systemd unit dirs that
			// live outside /etc. /etc/systemd, /etc/cron.*, /etc/init.d, and
			// /root/.bashrc-style files are already covered by /etc and /root.
			"/var/spool/cron",
			"/var/spool/at",
			"/lib/systemd/system",
			"/usr/lib/systemd/system",
			"/usr/local/lib/systemd/system",
		}
	}
	return c
}

// loadConfigStrict is the loader the daemon and start preflight use:
// any parse error is returned, NOT silently fallen back to defaults.
// A malformed config used to flip the daemon to standalone mode
// without anyone noticing — operators trusted that the mode they set
// last week was still active.
func loadConfigStrict(path string) (Config, error) {
	c := defaultConfig()
	if path == "" {
		return c, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return c, nil
		}
		return c, fmt.Errorf("read %s: %w", path, err)
	}
	if jerr := json.Unmarshal(data, &c); jerr != nil {
		return c, fmt.Errorf("%s is not valid JSON: %w", path, jerr)
	}
	if v := os.Getenv("SIMPLESIEM_LOG_DIR"); v != "" {
		c.LogDir = v
	}
	return c, nil
}

func loadConfig(path string) Config {
	c := defaultConfig()
	if path != "" {
		data, err := os.ReadFile(path)
		switch {
		case err == nil:
			// File exists. If it's not valid JSON we still want to fall
			// back to defaults so read commands (which don't need every
			// field) keep working — but we surface a warning so a typo
			// or bad merge doesn't silently disable an operator's
			// careful configuration. Daemon-side callers must use
			// loadConfigStrict so a bad config doesn't silently demote
			// the install to standalone mode.
			if jerr := json.Unmarshal(data, &c); jerr != nil {
				fmt.Fprintf(os.Stderr,
					"warning: %s is not valid JSON (%v); falling back to defaults\n",
					path, jerr)
			}
		case os.IsNotExist(err):
			// Missing file is normal pre-install; stay quiet.
		default:
			fmt.Fprintf(os.Stderr, "warning: cannot read %s: %v\n", path, err)
		}
	}
	if v := os.Getenv("SIMPLESIEM_LOG_DIR"); v != "" {
		c.LogDir = v
	}
	return c
}

func defaultConfigJSON() string {
	data, _ := json.MarshalIndent(defaultConfig(), "", "  ")
	return string(data) + "\n"
}

// configJSONForMode returns a default config with the requested mode set.
// Used at install time so `simplesiem install --mode agent` (or the
// SIMPLESIEM_MODE env var on Windows) drops a config file already in the
// right shape.
func configJSONForMode(mode string) string {
	c := defaultConfig()
	c.Mode = normaliseMode(mode)
	data, _ := json.MarshalIndent(c, "", "  ")
	return string(data) + "\n"
}

func seconds(n int) time.Duration { return time.Duration(n) * time.Second }

// stdinIsTTY reports whether stdin is attached to a terminal. Used to suppress
// the interactive menu when the binary is invoked non-interactively (ssh
// without -t, CI, pipes, etc.) so it doesn't print a menu header and then
// exit silently on EOF.
func stdinIsTTY() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// interactiveFlag is true when the elevated child was launched from the
// double-click menu; it causes fatalf() to pause before the new console closes.
var interactiveFlag bool

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	if interactiveFlag {
		pause()
	}
	os.Exit(1)
}

// Run is the entry point invoked from the root main.go. The dispatcher
// stayed inside this package so cross-file references (parseArgs, the
// command handlers, fatalf, etc.) don't need to be exported across a
// package boundary just to reach func main.
func Run() {
	enableVTProcessing()

	var args []string
	for _, a := range os.Args[1:] {
		if a == "--interactive" {
			interactiveFlag = true
			continue
		}
		args = append(args, a)
	}

	if len(args) == 0 {
		if !stdinIsTTY() {
			// Remote shell / pipe / ssh-without-tty: don't open the menu
			// (its ReadString would hit EOF immediately). Show usage instead
			// so the caller knows what subcommands are available.
			usage()
			return
		}
		runInteractiveMenu()
		return
	}

	cmd := args[0]
	subArgs := args[1:]
	switch cmd {
	case "run":
		runDaemon(subArgs)
	case "install":
		installService(subArgs)
	case "uninstall":
		runUninstall(subArgs)
	case "uninstall-service-only":
		uninstallService(subArgs)
	case "start":
		startCommand(subArgs)
	case "stop":
		stopCommand(subArgs)
	case "restart":
		restartCommand(subArgs)
	case "fix", "repair", "doctor":
		runFix(subArgs)
	case "query":
		refuseInCollectorMode(loadConfig(defaultConfigPath()), "read")
		runQuery(subArgs)
	case "triage", "search":
		refuseInCollectorMode(loadConfig(defaultConfigPath()), "read")
		runTriage(subArgs)
	case "status":
		// status itself is allowed in collector mode (it shows the
		// daemon's own health, which is the operator's primary
		// reason to run it on a collector). No gate.
		runStatus(subArgs)
	case "tail":
		refuseInCollectorMode(loadConfig(defaultConfigPath()), "read")
		runTail(subArgs)
	case "alerts":
		refuseInCollectorMode(loadConfig(defaultConfigPath()), "read")
		runAlertsCmd(subArgs)
	case "rules":
		refuseInCollectorMode(loadConfig(defaultConfigPath()), "rules")
		runRulesCmd(subArgs)
	case "verify":
		runVerify(subArgs)
	case "certs":
		runCertsCmd(subArgs)
	case "master":
		runMasterCmd(subArgs)
	case "server":
		// Top-level server subcommand (today only `server
		// query-collector ...`). Server-mode-only operations land
		// here so they don't pollute the existing master / certs /
		// realm dispatchers.
		if len(subArgs) > 0 && subArgs[0] == "query-collector" {
			runServerQueryCollectorCmd(subArgs[1:])
		} else {
			fmt.Fprintln(os.Stderr, "usage: simplesiem server query-collector <enroll|run|status>")
			os.Exit(2)
		}
	case "collector":
		runCollectorCmd(subArgs)
	case "realm":
		refuseInCollectorMode(loadConfig(defaultConfigPath()), "realm")
		runRealmCmd(subArgs)
	case "convert":
		runConvertCmd(subArgs)
	case "backup":
		runBackupCmd(subArgs)
	case "restore":
		runRestoreCmd(subArgs)
	case "chainhead":
		runChainHeadCmd(subArgs)
	case "top":
		runTopCmd(subArgs)
	case "tree":
		runTreeCmd(subArgs)
	case "hunt":
		runHuntCmd(subArgs)
	case "log-dir":
		if len(subArgs) > 0 && subArgs[0] == "migrate" {
			runLogDirMigrate(subArgs[1:])
		} else {
			fmt.Fprintln(os.Stderr, "usage: simplesiem log-dir migrate <new-path> [-y]")
			os.Exit(2)
		}
	case "incidents":
		runIncidentsCmd(subArgs)
	case "threatintel":
		if len(subArgs) > 0 && subArgs[0] == "status" {
			runThreatIntelStatus(subArgs[1:])
		} else {
			fmt.Fprintln(os.Stderr, "usage: simplesiem threatintel status")
			os.Exit(2)
		}
	case "firstseen":
		if len(subArgs) > 0 && subArgs[0] == "status" {
			runFirstSeenStatus(subArgs[1:])
		} else {
			fmt.Fprintln(os.Stderr, "usage: simplesiem firstseen status")
			os.Exit(2)
		}
	case "mitre":
		runMitreCmd(subArgs)
	case "triage-pivot":
		runTriagePivotCmd(subArgs)
	case "baseline":
		if len(subArgs) > 0 && subArgs[0] == "status" {
			runBaselineStatus(subArgs[1:])
		} else {
			fmt.Fprintln(os.Stderr, "usage: simplesiem baseline status [--top N]")
			os.Exit(2)
		}
	case "honey":
		runHoneyCmd(subArgs)
	case "probe":
		runProbeCmd(subArgs)
	case "version", "-v", "--version":
		fmt.Println(versionString())
	case "help", "-h", "--help":
		usage()
	default:
		// If the user typed a flag where a subcommand belongs, they
		// almost certainly forgot the subcommand. Detect the common
		// case (triage flags first; the others are commands not
		// commonly invoked flag-first) and suggest a corrected line.
		fmt.Fprintf(os.Stderr, "%s\n", suggestForBadCommand(cmd, subArgs))
		usage()
		os.Exit(2)
	}

	if interactiveFlag {
		pause()
	}
}

// suggestForBadCommand turns an unknown first-argument into a useful
// error message. The common case is "user typed a flag instead of a
// subcommand" (e.g. `simplesiem --at now`); the message tells them the
// likely command and reprints their argv with it inserted.
func suggestForBadCommand(cmd string, rest []string) string {
	if !strings.HasPrefix(cmd, "-") {
		// Map of common typos / shortened forms to the real command.
		// Saves operators from copying the full usage and re-running.
		nearMiss := map[string]string{
			"psk":     "certs psk",
			"sign":    "convert agent --key <PSK>", // legacy `certs sign` was removed; agents enroll via PSK now
			"init":    "certs init",
			"rotate":  "certs psk rotate",
			"enroll":  "convert agent --key <PSK>",
			"agent":   "convert agent",
			"server":  "convert server",
			"refresh": "certs server $(hostname) --force",
			"reload":  "certs server $(hostname) --force",
			"check":   "rules check",
			"test":    "rules test",
			"help":    "(no args)",
			"-h":      "(no args)",
			"--help":  "(no args)",
		}
		if real, ok := nearMiss[cmd]; ok {
			out := fmt.Sprintf("unknown command: %s\n", cmd)
			argv := strings.TrimSpace(strings.Join(rest, " "))
			if real == "(no args)" {
				out += "  did you mean: simplesiem (with no arguments shows usage + interactive menu)?\n"
			} else {
				out += fmt.Sprintf("  did you mean: simplesiem %s %s?\n", real, argv)
			}
			return out
		}
		return fmt.Sprintf("unknown command: %s\n", cmd)
	}
	// Map of flags-that-clearly-belong-to-X to the subcommand name.
	flagOwner := map[string]string{
		"--at": "triage", "-at": "triage",
		"--pid": "triage", "-pid": "triage",
		"--file": "triage", "-file": "triage",
		"--grep": "triage", "-grep": "triage",
		"--window": "triage", "-window": "triage",
		"--explain": "triage", "-explain": "triage",
		"--max-pivots": "triage", "-max-pivots": "triage",
		"--scan-days": "triage", "-scan-days": "triage",
		"--start": "triage", "-start": "triage",
		"--end": "triage", "-end": "triage",
		"--since": "query/triage", "-since": "query/triage",
		"--until": "query", "-until": "query",
		"--limit": "query", "-limit": "query",
		"--severity": "alerts", "-severity": "alerts",
		"--alerts":  "tail", "-alerts": "tail",
		"--date":    "verify", "-date": "verify",
		"--all":     "verify", "-all": "verify",
		"--dry-run": "fix", "-dry-run": "fix",
		"--mode":    "install", "-mode": "install",
	}
	bareFlag := cmd
	if i := strings.Index(cmd, "="); i >= 0 {
		bareFlag = cmd[:i]
	}
	guessed := flagOwner[bareFlag]
	if guessed == "" {
		guessed = "triage" // most common flag-first invocation
	}
	original := strings.TrimSpace(cmd + " " + strings.Join(rest, " "))
	out := fmt.Sprintf("%q looks like a flag, not a command.\n", cmd)
	if strings.Contains(guessed, "/") {
		out += fmt.Sprintf("Did you mean: simplesiem <%s> %s\n", guessed, original)
	} else {
		out += fmt.Sprintf("Did you mean: simplesiem %s %s\n", guessed, original)
	}
	return out
}

func usage() {
	fmt.Fprintf(os.Stderr, `%s - single-binary on-box SIEM for Windows / macOS / Linux

usage: simplesiem <command> [flags]

commands:
  install      install as a system service (starts now + at boot)
  uninstall    stop and remove the service
  start        start the installed service
  stop         stop the running service
  restart      stop + start in one shot (skips stop if not running)
  fix          audit the install and repair anything broken (--dry-run to check only)
  run          run the collector daemon (invoked by the service)
  query        filter stored logs: --type, --since, --until, --grep, --limit
  triage       pivot on an event and show surrounding activity (±window)
  tail         follow new events live (filters: --type, --grep, --alerts)
  alerts       show recent alerts with severity colours
  rules        check / test rule definitions: simplesiem rules <check|test>
  verify       walk the hash chain in stored logs, report any tampering
  certs        manage the bundled PKI: simplesiem certs <init|server|sign>
  convert      switch this install's mode: simplesiem convert <agent|server|standalone|master|collector>
  master       master-mode operator commands: simplesiem master <enroll|collector|...>
  collector    collector-mode operator commands: simplesiem collector <enroll|status|...>
  status       show log volume, rule count, retention, last collector beat
  version      print version + build number

Mode is chosen via the "mode" key in config.json: "standalone" (default —
collect locally), "agent" (collect and forward to a server over mTLS),
"server" (receive from agents), "master" (cross-realm aggregator that pulls
from servers), or "collector" (single-source backup replicator that pulls
from a server or master). Read commands accept --host to scope to one
agent in server / master mode.

launched with no arguments (e.g., double-clicked), the binary shows an
interactive manager menu that auto-detects install/running state.

examples:
  Linux/macOS:   sudo ./simplesiem install
  Windows:       .\simplesiem.exe install         (run from elevated PowerShell)

  simplesiem triage --file /tmp/suspicious.exe --window 60s
  simplesiem triage --pid 1234 --window 10s
  simplesiem triage --grep evil.com --window 30s
  simplesiem triage --at 2026-04-24T13:48:35Z --window 15s
`, versionString())
}
