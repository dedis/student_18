package network

import (
	"testing"

	_ "github.com/dedis/student_18/dgcosi/code/kyber/group/edwards25519"
	"github.com/dedis/student_18/dgcosi/code/kyber/suites"
	"github.com/dedis/student_18/dgcosi/code/onet/log"
)

var tSuite = suites.MustFind("Ed25519")

func TestMain(m *testing.M) {
	log.MainTest(m)
}
