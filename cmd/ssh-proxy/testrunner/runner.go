package testrunner

import (
	"os/exec"
	"time"

	"github.com/tedsuo/ifrit/ginkgomon"
)

type Args struct {
	Address     string
	HostKey     string
	DiegoAPIURL string
	CCAPIURL    string
	CFOnly      bool
}

func (args Args) ArgSlice() []string {
	cfOnlyArg := ""
	if args.CFOnly {
		cfOnlyArg = "-cfOnly"
	}

	return []string{
		"-address=" + args.Address,
		"-hostKey=" + args.HostKey,
		"-diegoAPIURL=" + args.DiegoAPIURL,
		"-ccAPIURL=" + args.CCAPIURL,
		cfOnlyArg,
	}
}

func New(binPath string, args Args) *ginkgomon.Runner {
	return ginkgomon.New(ginkgomon.Config{
		Name:              "ssh-proxy",
		AnsiColorCode:     "1;95m",
		StartCheck:        "ssh-proxy.started",
		StartCheckTimeout: 10 * time.Second,
		Command:           exec.Command(binPath, args.ArgSlice()...),
	})
}
