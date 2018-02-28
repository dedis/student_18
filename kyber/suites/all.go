package suites

import (
	"github.com/dedis/student_18_dgcosi/kyber/group/edwards25519"
)

func init() {
	register(edwards25519.NewBlakeSHA256Ed25519())
}
