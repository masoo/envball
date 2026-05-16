// Package cli is the cobra command surface for envball CLI mode. Each
// command translates argv into an application use-case Input and renders
// the Output back as user-facing text. No business logic here.
package cli

import (
	"github.com/spf13/cobra"

	"github.com/masaoshima/envball/internal/application/build"
	"github.com/masaoshima/envball/internal/application/initapp"
	"github.com/masaoshima/envball/internal/application/verify"
)

// Deps bundles every cross-command dependency so each command's
// constructor stays short.
type Deps struct {
	Build  *build.Service
	Init   *initapp.Service
	Verify *verify.Service
	// Version is the semantic version stamped at link time. See main.go.
	Version string
	// Commit is the source-control revision the binary was built from.
	Commit string
}

// NewRoot returns the root cobra command wired with d.
func NewRoot(d Deps) *cobra.Command {
	cmd := &cobra.Command{
		Use:           "envball",
		Short:         "Pack environment variables into an encrypted, self-extracting executable.",
		Long: "envball encrypts .env files into a single executable. Running the\n" +
			"executable execs your command with the env decrypted in memory only.\n" +
			"A separate token is required to decrypt; see https://envball.io for docs.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.AddCommand(
		newInitCommand(d),
		newBuildCommand(d),
		newVerifyCommand(d),
		newVersionCommand(d),
	)
	return cmd
}
