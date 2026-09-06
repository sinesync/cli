// Package licenses carries the third-party attribution notice.
//
// Several dependencies require their notices to be reproduced wherever the
// software is distributed, and SQLCipher's BSD licence asks specifically for a
// user-accessible location. Embedding the notice means `sinesync licenses`
// answers offline, from the same binary the dependencies are compiled into,
// rather than pointing somewhere that might not be reachable or might have
// moved on.
package licenses

import _ "embed"

//go:generate go run ../../tools/gen-licenses notices.txt third_party.txt

//go:embed third_party.txt
var thirdParty string

// Text returns the full third-party notice.
func Text() string { return thirdParty }
