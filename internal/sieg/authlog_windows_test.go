//go:build windows

package sieg

import "testing"

// TestParseWindowsAuthEvent_Success verifies a 4624 RenderedXml blob
// is decoded into the canonical SimpleSIEM auth-success shape, with
// the operator-relevant fields (user, source_ip, logon_type) lifted
// from EventData.
func TestParseWindowsAuthEvent_Success(t *testing.T) {
	const sample = `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4624</EventID><EventRecordID>4711</EventRecordID><TimeCreated SystemTime="2026-04-30T18:22:11.123Z"/><Computer>WIN-LAB-01</Computer></System><EventData><Data Name="TargetUserName">alice</Data><Data Name="TargetDomainName">WIN-LAB-01</Data><Data Name="LogonType">3</Data><Data Name="IpAddress">10.0.0.5</Data><Data Name="WorkstationName">DESK-7</Data></EventData></Event>`
	ev, recID, ok := parseWindowsAuthEvent(sample)
	if !ok {
		t.Fatal("parseWindowsAuthEvent returned ok=false on a valid 4624")
	}
	if recID != 4711 {
		t.Errorf("recID: got %d, want 4711", recID)
	}
	if ev["event"] != "auth_success" {
		t.Errorf("event: got %v, want auth_success", ev["event"])
	}
	if ev["user"] != "alice" {
		t.Errorf("user: got %v, want alice", ev["user"])
	}
	if ev["source_ip"] != "10.0.0.5" {
		t.Errorf("source_ip: got %v, want 10.0.0.5", ev["source_ip"])
	}
	if ev["logon_type"] != "3" {
		t.Errorf("logon_type: got %v, want 3", ev["logon_type"])
	}
	if ev["computer"] != "WIN-LAB-01" {
		t.Errorf("computer: got %v, want WIN-LAB-01", ev["computer"])
	}
	if ev["windows_event_time"] != "2026-04-30T18:22:11.123Z" {
		t.Errorf("windows_event_time: got %v", ev["windows_event_time"])
	}
}

// TestParseWindowsAuthEvent_Failed verifies a 4625 RenderedXml blob
// produces auth_failed and includes the failure reason fields when
// present.
func TestParseWindowsAuthEvent_Failed(t *testing.T) {
	const sample = `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4625</EventID><EventRecordID>4712</EventRecordID><TimeCreated SystemTime="2026-04-30T18:22:11.123Z"/><Computer>WIN-LAB-01</Computer></System><EventData><Data Name="TargetUserName">bob</Data><Data Name="IpAddress">203.0.113.7</Data><Data Name="FailureReason">%%2313</Data><Data Name="LogonType">10</Data></EventData></Event>`
	ev, _, ok := parseWindowsAuthEvent(sample)
	if !ok {
		t.Fatal("parseWindowsAuthEvent returned ok=false on a valid 4625")
	}
	if ev["event"] != "auth_failed" {
		t.Errorf("event: got %v, want auth_failed", ev["event"])
	}
	if ev["user"] != "bob" {
		t.Errorf("user: got %v, want bob", ev["user"])
	}
	if ev["source_ip"] != "203.0.113.7" {
		t.Errorf("source_ip: got %v, want 203.0.113.7", ev["source_ip"])
	}
	if ev["failure_reason"] != "%%2313" {
		t.Errorf("failure_reason: got %v", ev["failure_reason"])
	}
}

// TestParseWindowsAuthEvent_UnknownEventID verifies an event outside
// the four logon-relevant IDs is dropped (ok=false) so we don't emit
// noise from non-logon Security events that slip past the XPath.
func TestParseWindowsAuthEvent_UnknownEventID(t *testing.T) {
	const sample = `<Event><System><EventID>4688</EventID><EventRecordID>9999</EventRecordID></System><EventData></EventData></Event>`
	_, recID, ok := parseWindowsAuthEvent(sample)
	if ok {
		t.Errorf("parseWindowsAuthEvent: ok=true on unsupported EventID 4688, want false")
	}
	if recID != 9999 {
		t.Errorf("recID: got %d, want 9999 (caller still needs the watermark)", recID)
	}
}

// TestParseWindowsAuthEvent_MalformedXML returns ok=false rather than
// panicking; callers ignore the line and keep parsing the batch.
func TestParseWindowsAuthEvent_MalformedXML(t *testing.T) {
	_, _, ok := parseWindowsAuthEvent("<Event><System><EventID>4624</EventID")
	if ok {
		t.Error("parseWindowsAuthEvent: ok=true on truncated XML, want false")
	}
}
