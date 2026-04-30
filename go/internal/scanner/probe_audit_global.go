package scanner

import "sync"

// globalAuditLog accumulates probe records across every CheckInjection call
// for a single scan run. Without this, the audit log was created freshly on
// each endpoint and discarded after returning — fine for stderr emission
// (the records had been printed already) but useless to anyone who wanted
// to read the post-scan audit, e.g. the --debug-bundle writer.
var (
	globalAuditMu  sync.Mutex
	globalAuditLog = NewProbeAuditLog()
)

// ResetGlobalAuditLog clears the per-scan audit log. Call this at the top
// of every scan run; otherwise records leak across runs in long-running
// processes (tests, future server mode).
func ResetGlobalAuditLog() {
	globalAuditMu.Lock()
	defer globalAuditMu.Unlock()
	globalAuditLog = NewProbeAuditLog()
}

// GlobalAuditRecords returns a snapshot of every probe recorded by the
// scan-wide audit log. Safe to call after the scan has finished.
func GlobalAuditRecords() []ProbeRecord {
	globalAuditMu.Lock()
	log := globalAuditLog
	globalAuditMu.Unlock()
	return log.Records()
}

// currentAuditLog returns the active scan-wide audit log. Used by
// CheckInjection so each per-endpoint call shares the same log.
func currentAuditLog() *ProbeAuditLog {
	globalAuditMu.Lock()
	defer globalAuditMu.Unlock()
	return globalAuditLog
}
