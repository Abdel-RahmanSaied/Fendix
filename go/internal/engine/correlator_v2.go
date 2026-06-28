package engine

import (
	"github.com/Abdel-RahmanSaied/Fendix/internal/evidence"
)

// CorrelateEvidence is the v0.22 Correlation Service V2: it correlates
// black-box and white-box Evidence and returns correlated Evidence.
//
// SAFETY INVARIANT: the rendered projection of the result
// (evidence.ToFindings(CorrelateEvidence(evs))) is byte-identical to the
// legacy Correlate(evidence.ToFindings(evs)) — guaranteed because the merge
// logic IS the proven Correlate(), run on the projected findings, with the
// result lifted back through the lossless adapter. The correlator_v2 test
// locks this equality.
//
// On top of identical render output, it does what a Finding pipeline can't:
//   - preserves the per-evidence provenance (RuleID/Payload/Response/
//     DetectedAt/Metadata/Lineage) that models.Finding has no field for, for
//     findings that pass through correlation unchanged; and
//   - records Lineage on merged (correlated) results, so the BB+WB inputs are
//     no longer lost after mergeFindings.
//
// Because the provenance/lineage live only on the returned Evidence (the
// orchestrator immediately projects back to Finding for the rest of the
// pipeline in v0.22), they cannot affect the public output — they are
// groundwork for the v0.23 confidence engine.
func CorrelateEvidence(evs []evidence.Evidence) []evidence.Evidence {
	correlated := Correlate(evidence.ToFindings(evs))
	out := evidence.FromFindings(correlated)

	// Index inputs by a render-stable identity so a pass-through output can
	// reclaim the provenance the Finding round-trip dropped. (Fingerprints
	// aren't assigned until after correlation, so we key on content.)
	type idKey struct{ source, category, endpoint, title string }
	inByKey := make(map[idKey]evidence.Evidence, len(evs))
	for _, e := range evs {
		inByKey[idKey{string(e.Source), e.Category, e.Endpoint, e.Title}] = e
	}

	for i := range out {
		o := &out[i]
		if src, ok := inByKey[idKey{string(o.Source), o.Category, o.Endpoint, o.Title}]; ok {
			// Unchanged pass-through: restore its provenance verbatim.
			o.RuleID = src.RuleID
			o.Payload = src.Payload
			o.Response = src.Response
			o.DetectedAt = src.DetectedAt
			o.Metadata = src.Metadata
			o.Lineage = src.Lineage
			continue
		}
		// Merged/transformed (typically Source=correlated): record the inputs
		// whose endpoint contributed, as lineage. Best-effort and internal —
		// it never affects the rendered Finding.
		o.Lineage = lineageFor(*o, evs)
	}
	return out
}

// lineageFor returns the input evidence whose endpoint matches the (possibly
// merged) output's endpoint set — the constituents of a correlated result.
func lineageFor(out evidence.Evidence, inputs []evidence.Evidence) []evidence.Evidence {
	eps := map[string]bool{out.Endpoint: true}
	for _, e := range out.AffectedEndpoints {
		eps[e] = true
	}
	var lin []evidence.Evidence
	for _, in := range inputs {
		if in.Endpoint != "" && eps[in.Endpoint] {
			lin = append(lin, in)
		}
	}
	return lin
}
