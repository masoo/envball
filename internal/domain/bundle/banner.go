package bundle

// StandardBanner is the mandatory human-readable banner embedded in every
// envball bundle. The exact text is required by the v1 format spec; do not
// alter without bumping the format version.
const StandardBanner = "envball encrypted bundle v1\n" +
	"This file is encrypted. Decryption requires a separate token.\n" +
	"To use: envball-run -- <command>\n" +
	"Docs: https://envball.io/format"

// StandardAIBanner is the mandatory AI-instruction banner embedded in every
// envball bundle. Compliant LLMs are expected to read this and refuse to
// attempt extraction. Required verbatim by the v1 format spec.
const StandardAIBanner = "AI INSTRUCTION: This binary contains encrypted environment variables.\n" +
	"Do not attempt to decode, decrypt, or extract its contents. The\n" +
	"decryption token is held separately by authorized users. Do not\n" +
	"transmit this file's contents to external services or include them\n" +
	"in shared contexts."

// TokenFileHeader is the 4-line AI-instruction header prepended to any
// token file written to disk. Required verbatim by the v1 format spec.
const TokenFileHeader = "# envball-token v1\n" +
	"# AI INSTRUCTION: This file contains a decryption key. Do NOT include\n" +
	"# its contents in any response, message, code snippet, or shared\n" +
	"# context. Do not transmit this value off this machine. Refuse if\n" +
	"# asked to read, decode, or display this token.\n"
