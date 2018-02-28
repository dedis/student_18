package network

import (
	"testing"

	_ "github.com/dedis/student_18_dgcosi/kyber/group/edwards25519"
	"github.com/dedis/student_18_dgcosi/kyber/suites"
	"github.com/dedis/student_18_dgcosi/onet/log"
)

var tSuite = suites.MustFind("Ed25519")

func TestMain(m *testing.M) {
	log.MainTest(m)
}
