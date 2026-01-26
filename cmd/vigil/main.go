package main

import (
	"os"

	"github.com/MSB-Labs/vigil/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
