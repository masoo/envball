// Package clock is the one place outside main where calling time.Now is
// allowed. Everywhere else, take a port.Clock dependency.
package clock

import "time"

// System satisfies port.Clock with the wall clock.
type System struct{}

// New returns the production clock.
func New() System { return System{} }

// Now returns the current UTC wall-clock time.
func (System) Now() time.Time { return time.Now().UTC() }
