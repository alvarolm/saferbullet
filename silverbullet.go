package main

import (
	_ "embed"

	"github.com/alvarolm/saferbullet/client_bundle"
	"github.com/alvarolm/saferbullet/server/cmd"
)

//go:embed public_version.ts
var VersionFileText string

func main() {
	c := cmd.ServerCommand(client_bundle.BundledFiles)
	c.AddCommand(cmd.VersionCommand(VersionFileText), cmd.UpgradeCommand(), cmd.UpgradeEdgeCommand())
	c.Execute()
}
