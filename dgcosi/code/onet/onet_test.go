package onet

import (
	"testing"

	"github.com/dedis/student_18/dgcosi/code/onet/log"
)

// To avoid setting up testing-verbosity in all tests
func TestMain(m *testing.M) {

	log.MainTest(m)
}
