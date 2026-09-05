// Command omni-enrollment is the endpoint agent that enrolls a machine with
// Omni Identity and keeps its device credential fresh. The implementation
// lives in pkg/enrollcli so other programs can embed it; see that package
// for the usage.
package main

import (
	"os"

	"github.com/pod32g/omni-identity/pkg/enrollcli"
)

var version = "0.1.0-dev"

func main() {
	enrollcli.Version = version
	os.Exit(enrollcli.Main(os.Args[1:]))
}
