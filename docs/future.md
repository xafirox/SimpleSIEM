# Future implementations

Items intentionally deferred from the current build with notes about why and what they'd take to land.

## MITRE ATT&CK — additional curated templates

The current build ships Phase 1 (auto-catalog refresh) AND Phase 2 (curated technique→rule template generation via `simplesiem mitre generate-rules`). The shipped curated set covers the highest-volume techniques: T1110, T1110.001, T1059.001/003/004, T1003, T1136, T1547.001, T1562.001, T1078, T1486, T1490.

What's NOT shipped:

- A second-tier mapping covering the long tail of techniques (~600 more in MITRE's enterprise catalog). Each new template needs detection logic that maps to fields the existing collectors emit; contributions land in `internal/sieg/mitre_rule_generation.go`.
- Importing community detection packs (Sigma, Elastic detection-rules) with format translation. Each format has its own assumptions about field names and time windows. Adding a translator per format is a release-cycle commitment, not a code-only change.
- Real-time technique-emergence alerting ("MITRE just added T1059.NEW; here are 3 candidate rules to consider"). The existing `meta:mitre_catalog_updated` event already fires with the delta count; the next step is per-new-technique rule-template suggestion.

## Threat intel — additional providers

Current build: abuse.ch ThreatFox by default. Future:

- AlienVault OTX (community indicators with confidence)
- Spamhaus DROP / EDROP (network blocklists)
- Operator-supplied custom feeds (HTTP-fetchable JSON / NDJSON / CSV)
- MISP integration (organizations with their own MISP instance)

Each new provider needs a parser per their wire format and metadata-field mapping (confidence, age, source).

## Cross-tier sequence rules — production tuning

Current build ships the validation + state machine + caps. What's left:

- A proper benchmark of memory usage at realistic alert volumes so the default `sequence_max_per_rule_kb: 64` is informed by measurement, not guess.
- A `meta:sequence_state_size` event emitted periodically so operators can see how close they are to caps without digging into internals.
- A "drain on shutdown" path that persists in-flight partials so a master restart doesn't lose mid-sequence state.

## Incidents grouping — multi-host correlation

Current grouping key is `(host, time-window)`. Future: group across hosts when an incident spans the realm (lateral movement). Needs a correlation key beyond host (e.g., user, source IP, parent process) and bounded state size.

## Detection-as-code — git integration

Current build: `simplesiem rules fixture-test` runs locally + has a pre-push hook script. Future: a GitHub Action that runs the same test on PR + comments per-rule fixture pass/fail counts. Mostly a content task (write the action, not the binary).
