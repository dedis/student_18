package anon

import (
	"github.com/dedis/student_18/dgcosi/code/kyber"
)

// Suite represents the set of functionalities needed by the package anon.
type Suite interface {
	kyber.Group
	kyber.Encoding
	kyber.XOFFactory
	kyber.Random
}
