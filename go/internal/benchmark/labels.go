package benchmark

// FPClass is the false-positive taxonomy (design §5). It is also the enum
// used in a label's `fp_class:` field, so a labels file can never name a
// class the fixes don't track.
type FPClass string

const (
	FPConstantAuthority FPClass = "constant-authority"
	FPReceiverConfusion FPClass = "receiver-confusion"
	FPSafeAPIMisread    FPClass = "safe-api-misread"
	FPConstFoldMiss     FPClass = "const-fold-miss"
	FPGuardDominance    FPClass = "guard-dominance"
	FPTestFixture       FPClass = "test-fixture"
	FPHTTP4xxContext    FPClass = "http-4xx-context"
	FPStaticAssetCtx    FPClass = "static-asset-context"
	FPDoubleSanitize    FPClass = "double-sanitize"
	FPHeuristicOverfire FPClass = "heuristic-overfire"
	FPVersionRangeFloor FPClass = "version-range-floor"
	FPFabricatedChain   FPClass = "fabricated-chain"
)

var validFPClasses = map[FPClass]bool{
	FPConstantAuthority: true, FPReceiverConfusion: true, FPSafeAPIMisread: true,
	FPConstFoldMiss: true, FPGuardDominance: true, FPTestFixture: true,
	FPHTTP4xxContext: true, FPStaticAssetCtx: true, FPDoubleSanitize: true,
	FPHeuristicOverfire: true, FPVersionRangeFloor: true, FPFabricatedChain: true,
}

// Valid reports whether c is a recognized FP class.
func (c FPClass) Valid() bool { return validFPClasses[c] }
