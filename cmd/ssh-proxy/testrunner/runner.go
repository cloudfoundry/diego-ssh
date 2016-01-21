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
	BBSAddress      string
	CCAPIURL        string
	UAATokenURL     string
	UAAPassword     string
	UAAUsername     string
	ConsulCluster   string
	SkipCertVerify  bool
	EnableCFAuth    bool
	EnableDiegoAuth bool

	DiegoCredentials string
}

func (args Args) ArgSlice() []string {
	return []string{
		"-address=" + args.Address,
		"-hostKey=" + args.HostKey,
		"-bbsAddress=" + args.BBSAddress,
		"-ccAPIURL=" + args.CCAPIURL,
		"-uaaTokenURL=" + args.UAATokenURL,
		"-consulCluster=" + args.ConsulCluster,
		"-skipCertVerify=" + strconv.FormatBool(args.SkipCertVerify),
		"-enableCFAuth=" + strconv.FormatBool(args.EnableCFAuth),
		"-enableDiegoAuth=" + strconv.FormatBool(args.EnableDiegoAuth),
		"-diegoCredentials=" + args.DiegoCredentials,
		"-uaaPassword=" + args.UAAPassword,
		"-uaaUsername=" + args.UAAUsername,
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
