package cosi

import "github.com/dedis/student_18/dgcosi/code/kyber"

// Suite specifies the cryptographic building blocks required for the cosi package.
type Suite interface {
	kyber.Group
	kyber.HashFactory
	kyber.Random
}
