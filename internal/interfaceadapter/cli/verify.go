package cli

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/oklog/ulid/v2"
	"github.com/spf13/cobra"

	"github.com/masaoshima/envball/internal/application/verify"
)

func newVerifyCommand(d Deps) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify <binary>",
		Short: "Read an envball binary's metadata and validate its signature (if any).",
		Long: "Verify reads the bundle without decrypting. It checks the format\n" +
			"version, prints the metadata (binary id, built_at, target), and\n" +
			"verifies the Ed25519 signature when present. No token is needed.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			out, err := d.Verify.Verify(verify.Input{Path: args[0]})
			if err != nil {
				return err
			}
			b := out.Body

			binaryID := "<invalid>"
			if len(b.BinaryID) == 16 {
				var id ulid.ULID
				copy(id[:], b.BinaryID)
				binaryID = id.String()
			}

			fmt.Fprintf(cmd.OutOrStdout(), "format_version: v%d\n", b.Version)
			fmt.Fprintf(cmd.OutOrStdout(), "scheme:         0x%02x (XChaCha20-Poly1305 + HKDF-SHA256)\n", b.Scheme)
			fmt.Fprintf(cmd.OutOrStdout(), "binary_id:      %s\n", binaryID)
			fmt.Fprintf(cmd.OutOrStdout(), "built_at:       %s\n", b.BuiltAt)
			fmt.Fprintf(cmd.OutOrStdout(), "target:         %s/%s\n", b.Target.OS, b.Target.Arch)
			fmt.Fprintf(cmd.OutOrStdout(), "encrypted_size: %d bytes\n", len(b.EncryptedEnv))
			if out.SignaturePresent {
				fmt.Fprintf(cmd.OutOrStdout(), "signer_pubkey:  %s\n", hex.EncodeToString(b.SignerPubKey))
				if out.SignatureValid {
					fmt.Fprintln(cmd.OutOrStdout(), "signature:      VALID")
				} else {
					return errors.New("envball verify: signature INVALID")
				}
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), "signature:      (none)")
			}
			fmt.Fprintln(cmd.OutOrStdout(), "envball: this command does NOT decrypt the env. Use the runtime mode for that.")
			return nil
		},
	}
	return cmd
}
