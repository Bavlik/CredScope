// credscope-action is the internal entrypoint for the repository's composite
// GitHub Action. It is not included in release archives.
package main

import (
	"context"
	"os"

	"github.com/Bavlik/CredScope/internal/actionrunner"
)

func main() {
	os.Exit(actionrunner.Run(context.Background(), os.Getenv, os.Stdout, os.Stderr))
}
