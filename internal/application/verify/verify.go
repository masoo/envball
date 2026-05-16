// Package verify exposes a Verify use case the CLI uses to inspect a
// bundle without decrypting: read metadata, check the format version,
// and (if a signature is present) verify it. No token is needed.
package verify

import (
	"github.com/masaoshima/envball/internal/domain/bundle"
	"github.com/masaoshima/envball/internal/domain/port"
)

// Input describes one Verify invocation.
type Input struct {
	Path string
}

// Output is the structured result for the CLI to render.
type Output struct {
	Body            *bundle.Body
	SignaturePresent bool
	SignatureValid   bool
}

// Service wires the codec and signer ports.
type Service struct {
	codec  port.BundleCodec
	signer port.Signer
}

// NewService constructs the verify service.
func NewService(c port.BundleCodec, s port.Signer) *Service {
	return &Service{codec: c, signer: s}
}

// Verify reads, validates, and signature-checks the bundle at path.
// Returning an Output with SignaturePresent=false means the bundle is
// unsigned — not a verification failure.
func (svc *Service) Verify(in Input) (*Output, error) {
	body, err := svc.codec.ReadBundleFromFile(in.Path)
	if err != nil {
		return nil, err
	}
	out := &Output{Body: body, SignaturePresent: body.IsSigned()}
	if !out.SignaturePresent {
		return out, nil
	}
	sigInput, err := svc.codec.EncodeBodyForSigning(body)
	if err != nil {
		return nil, err
	}
	if err := svc.signer.Verify(body.SignerPubKey, sigInput, body.Signature); err != nil {
		return out, err
	}
	out.SignatureValid = true
	return out, nil
}
