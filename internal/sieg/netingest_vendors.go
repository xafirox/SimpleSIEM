package sieg

import (
	"regexp"
	"sort"
	"strings"
)

// Vendor catalog for network-device ingest. Pass 1 ships generic
// recognition only — each profile carries a regex that recognises the
// vendor's frame format, plus the TLS posture the vendor supports.
// Deep field extraction (action, source_ip, destination_ip, etc.)
// lands in pass 2 where parsers are written per-vendor.

type vendorProfile struct {
	ID                 string         // canonical ID used in CLI / allowlist
	DisplayName        string         // human-facing name
	TLSSyslogSupported bool           // RFC 5425 (or vendor TLS) speakable?
	TLSSyslogRequired  bool           // vendor profile FORCES tls_required:true
	DefaultPort        int            // default TCP/UDP port for the listener bind hint
	TagPattern         *regexp.Regexp // matches in the syslog APP-NAME or message body
	Notes              string         // operator-facing description
}

var vendorProfiles = map[string]*vendorProfile{
	"other": {
		ID:                 "other",
		DisplayName:        "Other / unspecified",
		TLSSyslogSupported: true,
		TLSSyslogRequired:  false,
		DefaultPort:        514,
		TagPattern:         nil, // no auto-recognition
		Notes:              "Generic catch-all for unsupported vendors. TLS posture is operator-tunable per entry.",
	},
	"pfsense": {
		ID:                 "pfsense",
		DisplayName:        "pfSense",
		TLSSyslogSupported: true,
		TLSSyslogRequired:  true,
		DefaultPort:        6514,
		TagPattern:         regexp.MustCompile(`(?i)\bpf:|\bfilterlog\b|\bpfsense\b`),
		Notes:              "RFC 5425 TLS-syslog supported; netgate distros can be configured to mTLS as well.",
	},
	"fortigate": {
		ID:                 "fortigate",
		DisplayName:        "FortiGate",
		TLSSyslogSupported: true,
		TLSSyslogRequired:  true,
		DefaultPort:        6514,
		TagPattern:         regexp.MustCompile(`(?i)\bdevname=|\bdevid=FG[0-9A-Z]+|\bfortigate\b`),
		Notes:              "FortiOS supports reliable TLS syslog; recommend `set reliable enable` on the syslogd config.",
	},
	"cisco_ios": {
		ID:                 "cisco_ios",
		DisplayName:        "Cisco IOS / IOS-XE",
		TLSSyslogSupported: true,
		TLSSyslogRequired:  true,
		DefaultPort:        6514,
		TagPattern:         regexp.MustCompile(`(?i)\b%[A-Z]+-[0-9]-[A-Z_]+\b|\bcisco\b`),
		Notes:              "TLS-syslog (RFC 5425) is supported on modern IOS / IOS-XE. Operators with cleartext-only legacy gear must use --vendor other.",
	},
	"cisco_meraki": {
		ID:                 "cisco_meraki",
		DisplayName:        "Cisco Meraki",
		TLSSyslogSupported: true,
		TLSSyslogRequired:  true,
		DefaultPort:        6514,
		TagPattern:         regexp.MustCompile(`(?i)\bmeraki\b|\burls=|\bsrc=[0-9.]+:[0-9]+\b`),
		Notes:              "Cloud-managed; the dashboard supports TLS-syslog with operator-imported CA.",
	},
	"sonicwall": {
		ID:                 "sonicwall",
		DisplayName:        "SonicWall",
		TLSSyslogSupported: true,
		TLSSyslogRequired:  true,
		DefaultPort:        6514,
		TagPattern:         regexp.MustCompile(`(?i)\bid=firewall\b|\bsonicwall\b|\bm=\d+\b`),
		Notes:              "Enhanced (IDFV / Webtrends) format; SonicOS supports TLS syslog with CA import.",
	},
	"ubiquiti": {
		ID:                 "ubiquiti",
		DisplayName:        "Ubiquiti / UniFi",
		TLSSyslogSupported: true,
		TLSSyslogRequired:  true,
		DefaultPort:        6514,
		TagPattern:         regexp.MustCompile(`(?i)\bunifi\b|\bedgeos\b|\bubnt\b|\bpoe-controller\b`),
		Notes:              "Modern UniFi / EdgeOS supports TLS forwarding. Operators with cleartext-only legacy gear must use --vendor other.",
	},
	"hpe_aruba": {
		ID:                 "hpe_aruba",
		DisplayName:        "HPE Aruba",
		TLSSyslogSupported: true,
		TLSSyslogRequired:  true,
		DefaultPort:        6514,
		TagPattern:         regexp.MustCompile(`(?i)\baruba\b|\bAP\b.*\bauthmgr\b|\bstm\b.*\bauthmgr\b`),
		Notes:              "ArubaOS supports TLS syslog (`logging server <ip> tls`).",
	},
}

// lookupVendorProfile finds a vendor by ID (case-insensitive). Returns
// the profile pointer and whether it's a recognised vendor.
func lookupVendorProfile(id string) (*vendorProfile, bool) {
	v, ok := vendorProfiles[strings.ToLower(strings.TrimSpace(id))]
	return v, ok
}

// vendorIDs returns the canonical list of vendor IDs in stable order.
func vendorIDs() []string {
	out := make([]string, 0, len(vendorProfiles))
	for id := range vendorProfiles {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// detectVendorFromFrame runs each vendor's tag regex against the raw
// frame bytes and returns the first match. Empty string means no
// recognition; the frame is still ingested as generic syslog.
func detectVendorFromFrame(raw string) string {
	for _, id := range vendorIDs() {
		v := vendorProfiles[id]
		if v.TagPattern != nil && v.TagPattern.MatchString(raw) {
			return v.ID
		}
	}
	return ""
}
