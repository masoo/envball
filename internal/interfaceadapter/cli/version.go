package cli

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

func newVersionCommand(d Deps) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print envball version information.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ver := d.Version
			if ver == "" {
				ver = "dev"
			}
			commit := d.Commit
			if commit == "" {
				commit = "unknown"
			}
			fmt.Fprintf(cmd.OutOrStdout(), "envball %s (commit %s, %s/%s, %s)\n",
				ver, commit, runtime.GOOS, runtime.GOARCH, runtime.Version())
			return nil
		},
	}
}
