package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/masaoshima/envball/internal/application/initapp"
)

func newInitCommand(d Deps) *cobra.Command {
	var (
		projectDir string
		sampleName string
		overwrite  bool
	)
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Scaffold a project for envball (ignore files + sample .env).",
		Long: "Creates or updates .gitignore, .aiignore, .cursorignore, and\n" +
			".continueignore with the entries envball needs (token files,\n" +
			"built binaries, .env). Also creates .env.example unless one\n" +
			"already exists.",
		RunE: func(cmd *cobra.Command, args []string) error {
			out, err := d.Init.Init(initapp.Input{
				ProjectDir:    projectDir,
				SampleEnvName: sampleName,
				Overwrite:     overwrite,
			})
			if err != nil {
				return err
			}
			if len(out.ChangedIgnoreFiles) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "envball: ignore files are already up to date.")
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), "envball: updated ignore files:")
				for _, f := range out.ChangedIgnoreFiles {
					fmt.Fprintf(cmd.OutOrStdout(), "  - %s\n", f)
				}
			}
			if out.SampleEnvCreated {
				fmt.Fprintf(cmd.OutOrStdout(), "envball: wrote sample env: %s\n", out.SampleEnvPath)
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "envball: sample env already exists: %s (skipping)\n", out.SampleEnvPath)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "envball: next step — fill in .env, then run: envball build -f .env -o env.bin")
			return nil
		},
	}
	cmd.Flags().StringVarP(&projectDir, "dir", "C", "", "project directory (default: current directory)")
	cmd.Flags().StringVar(&sampleName, "sample", ".env.example", "filename to use for the sample env scaffold")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "overwrite an existing sample env file")
	return cmd
}
