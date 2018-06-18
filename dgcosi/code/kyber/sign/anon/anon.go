// Package anon implements cryptographic primitives for anonymous communication.
package anon

import (
	"github.com/dedis/student_18/dgcosi/code/kyber"
)

// Set represents an explicit anonymity set
// as a list of public keys.
type Set []kyber.Point
