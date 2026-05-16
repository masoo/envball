package bundle

// StripPayload returns the prefix of exe that does NOT include an envball
// payload, so a stub-with-payload can be reused as a clean stub. If exe
// has no envball footer (i.e. it's already a clean executable, or some
// other binary entirely), it is returned unchanged.
//
// This is the domain rule "the stub region ends at body_offset" written
// once; both the build use case (preparing a stub) and the runtime
// entrypoint (locating the body) rely on it.
func StripPayload(exe []byte) []byte {
	if len(exe) < FooterSize {
		return exe
	}
	tail := exe[len(exe)-FooterSize:]
	if !HasFooterMagic(tail) {
		return exe
	}
	footer, err := DecodeFooter(tail)
	if err != nil {
		return exe
	}
	if int64(footer.BodyOffset)+int64(footer.BodyLength)+int64(FooterSize) > int64(len(exe)) {
		return exe
	}
	return exe[:footer.BodyOffset]
}
