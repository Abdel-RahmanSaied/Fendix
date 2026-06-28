//go:build ignore

// This file is a scan FIXTURE, not part of the module build (the build
// constraint above excludes it from `go build ./...`). It exists so the
// fixture looks like a real Go project to a --code scan.
package main

import "fmt"

func main() {
	fmt.Println("fixture")
}
