package main

import (
	"testing"

	"github.com/dedis/student_18_dgcosi/onet/simul"
)

func TestSimulation(t *testing.T) {
	simul.Start("count.toml")
}
