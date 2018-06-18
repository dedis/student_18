package main

import (
	"gopkg.in/urfave/cli.v1"

	// Empty imports to have the init-functions called which should
	// register the protocol

	_ "github.com/dedis/student_18/dgcosi/code/cosi/protocol"
	_ "github.com/dedis/student_18/dgcosi/code/cosi/service"
	"github.com/dedis/student_18/dgcosi/code/onet/app"
)

func runServer(ctx *cli.Context) {
	// first check the options
	config := ctx.String("config")

	app.RunServer(config)
}
