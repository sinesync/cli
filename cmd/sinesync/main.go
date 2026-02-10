package main

import (
	"os"

	"github.com/miclip/sinesync/internal/cli"
)

// Set via -ldflags at build time
var (
	ver    = "dev"
	commit = "unknown"
)

func main() {
	cli.SetVersion(ver, commit)
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
