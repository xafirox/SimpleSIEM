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

// TestParseWindowsAuthEvent_UserAdded verifies a 4720 (user account
// created) event is mapped to the canonical "user_added" event name
// shared with the Linux/macOS parsers, with the target on `user`
// and the admin on `actor`. This is the cross-platform leg of the s2
// fix — without it, Mac+Win triage would still miss user creation.
func TestParseWindowsAuthEvent_UserAdded(t *testing.T) {
	const sample = `<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4720</EventID><EventRecordID>5001</EventRecordID><TimeCreated SystemTime="2026-05-07T12:00:00.000Z"/><Computer>WIN-LAB-01</Computer></System><EventData><Data Name="TargetUserName">attacker</Data><Data Name="TargetDomainName">WIN-LAB-01</Data><Data Name="SubjectUserName">administrator</Data></EventData></Event>`
	ev, _, ok := parseWindowsAuthEvent(sample)
	if !ok {
		t.Fatal("parseWindowsAuthEvent: ok=false on valid 4720")
	}
	if ev["event"] != "user_added" {
		t.Errorf("event: got %v, want user_added", ev["event"])
	}
	if ev["user"] != "attacker" {
		t.Errorf("user: got %v, want attacker", ev["user"])
	}
	if ev["actor"] != "administrator" {
		t.Errorf("actor: got %v, want administrator", ev["actor"])
	}
}

// TestParseWindowsAuthEvent_GroupMembership verifies 4732 (member added
// to local group) maps target onto `group` and member onto `user` so
// triage's user_added_to_group case renders consistently with Linux.
func TestParseWindowsAuthEvent_GroupMembership(t *testing.T) {
	const sample = `<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4732</EventID><EventRecordID>5002</EventRecordID><TimeCreated SystemTime="2026-05-07T12:00:00.000Z"/><Computer>WIN-LAB-01</Computer></System><EventData><Data Name="MemberName">CN=alice</Data><Data Name="TargetUserName">Administrators</Data><Data Name="SubjectUserName">administrator</Data></EventData></Event>`
	ev, _, ok := parseWindowsAuthEvent(sample)
	if !ok {
		t.Fatal("parseWindowsAuthEvent: ok=false on valid 4732")
	}
	if ev["event"] != "user_added_to_group" {
		t.Errorf("event: got %v, want user_added_to_group", ev["event"])
	}
	if ev["group"] != "Administrators" {
		t.Errorf("group: got %v, want Administrators", ev["group"])
	}
	if ev["user"] != "CN=alice" {
		t.Errorf("user: got %v, want CN=alice", ev["user"])
	}
}

// TestSplitWevtutilEvents_MultilineUserAccountControl verifies the
// splitter recovers a complete 4720 Event whose UserAccountControl
// data field carries embedded newlines. The previous per-line
// `strings.Split` would have fragmented this Event across lines and
// xml.Unmarshal would have failed on each fragment — the bug that
// caused Add-LocalUser → 4720 events to never reach `simplesiem
// query` despite firing in the Security log.
func TestSplitWevtutilEvents_MultilineUserAccountControl(t *testing.T) {
	const raw = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4720</EventID><EventRecordID>26107</EventRecordID><TimeCreated SystemTime='2026-05-09T02:30:42Z'/><Computer>WindowsTest</Computer></System><EventData><Data Name='TargetUserName'>uatuser1</Data><Data Name='SubjectUserName'>Administrator</Data><Data Name='UserAccountControl'>
		%%2080
		%%2082
		%%2084</Data></EventData></Event>`
	blobs := splitWevtutilEvents(raw)
	if len(blobs) != 1 {
		t.Fatalf("expected 1 event blob, got %d", len(blobs))
	}
	ev, recID, ok := parseWindowsAuthEvent(blobs[0])
	if !ok {
		t.Fatalf("parseWindowsAuthEvent returned ok=false on a multi-line 4720 blob — the splitter handed back fragments")
	}
	if recID != 26107 {
		t.Errorf("recID: got %d, want 26107", recID)
	}
	if ev["event"] != "user_added" {
		t.Errorf("event: got %v, want user_added", ev["event"])
	}
	if ev["user"] != "uatuser1" {
		t.Errorf("user: got %v, want uatuser1", ev["user"])
	}
}

// TestSplitWevtutilEvents_MultipleEvents verifies the splitter pulls
// out two consecutive Events from a single wevtutil batch.
func TestSplitWevtutilEvents_MultipleEvents(t *testing.T) {
	const raw = `<Event><System><EventID>4624</EventID><EventRecordID>1</EventRecordID></System><EventData><Data Name='TargetUserName'>alice</Data></EventData></Event>
<Event><System><EventID>4720</EventID><EventRecordID>2</EventRecordID></System><EventData><Data Name='TargetUserName'>bob</Data><Data Name='UserAccountControl'>
		%%2080
		%%2082</Data></EventData></Event>`
	blobs := splitWevtutilEvents(raw)
	if len(blobs) != 2 {
		t.Fatalf("expected 2 event blobs, got %d", len(blobs))
	}
	ev1, _, ok := parseWindowsAuthEvent(blobs[0])
	if !ok || ev1["event"] != "auth_success" {
		t.Errorf("blob[0]: parsed=%v event=%v", ok, ev1["event"])
	}
	ev2, _, ok := parseWindowsAuthEvent(blobs[1])
	if !ok || ev2["event"] != "user_added" {
		t.Errorf("blob[1]: parsed=%v event=%v", ok, ev2["event"])
	}
}

// TestParseWindowsAuthEvent_UserDeleted verifies 4726 → user_deleted.
func TestParseWindowsAuthEvent_UserDeleted(t *testing.T) {
	const sample = `<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4726</EventID><EventRecordID>5003</EventRecordID><Computer>WIN-LAB-01</Computer></System><EventData><Data Name="TargetUserName">attacker</Data><Data Name="SubjectUserName">administrator</Data></EventData></Event>`
	ev, _, ok := parseWindowsAuthEvent(sample)
	if !ok {
		t.Fatal("parseWindowsAuthEvent: ok=false on valid 4726")
	}
	if ev["event"] != "user_deleted" {
		t.Errorf("event: got %v, want user_deleted", ev["event"])
	}
	if ev["user"] != "attacker" {
		t.Errorf("user: got %v, want attacker", ev["user"])
	}
}
