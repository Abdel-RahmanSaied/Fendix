package reporters

import "github.com/Abdel-RahmanSaied/Fendix/internal/reporters/i18n"

// IsSupportedLang is a thin re-export of i18n.IsSupported, so the CLI
// can validate --lang without needing to import the subpackage. Used
// by cmd/fendix's resolveLang helper.
func IsSupportedLang(lang string) bool {
	return i18n.IsSupported(lang)
}
