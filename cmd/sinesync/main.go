package main

import (
	"os"

	"github.com/miclip/sinesync/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
