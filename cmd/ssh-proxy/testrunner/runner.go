package testrunner

import (
	"os/exec"
	"strconv"
	"time"

	"github.com/tedsuo/ifrit/ginkgomon"
)

type Args struct {
	Address         string
	HostKey         string
	DiegoAPIURL     string
	CCAPIURL        string
	UAAURL          string
	SkipCertVerify  bool
	EnableCFAuth    bool
	EnableDiegoAuth bool
}

func (args Args) ArgSlice() []string {
	return []string{
		"-address=" + args.Address,
		"-hostKey=" + args.HostKey,
		"-diegoAPIURL=" + args.DiegoAPIURL,
		"-ccAPIURL=" + args.CCAPIURL,
		"-uaaURL=" + args.UAAURL,
		"-skipCertVerify=" + strconv.FormatBool(args.SkipCertVerify),
		"-enableCFAuth=" + strconv.FormatBool(args.EnableCFAuth),
		"-enableDiegoAuth=" + strconv.FormatBool(args.EnableDiegoAuth),
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
