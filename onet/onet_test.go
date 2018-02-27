package onet

import (
	"testing"

	"github.com/dedis/student_18_dgcosi/onet/log"
)

// To avoid setting up testing-verbosity in all tests
func TestMain(m *testing.M) {

	log.MainTest(m)
}
