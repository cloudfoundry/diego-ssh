package testrunner

import (
	"os/exec"
	"strconv"
	"time"

	"github.com/tedsuo/ifrit/ginkgomon"
)

type Args struct {
	Address                     string
	HostKey                     string
	AuthorizedKey               string
	AllowUnauthenticatedClients bool
	PassDaemonEnv               bool
}

func (args Args) ArgSlice() []string {
	return []string{
		"-address=" + args.Address,
		"-hostKey=" + args.HostKey,
		"-authorizedKey=" + args.AuthorizedKey,
		"-allowUnauthenticatedClients=" + strconv.FormatBool(args.AllowUnauthenticatedClients),
		"-passDaemonEnv=" + strconv.FormatBool(args.PassDaemonEnv),
	}
}

func New(binPath string, args Args) *ginkgomon.Runner {
	return ginkgomon.New(ginkgomon.Config{
		Name:              "sshd",
		AnsiColorCode:     "1;96m",
		StartCheck:        "sshd.started",
		StartCheckTimeout: 10 * time.Second,
		Command:           exec.Command(binPath, args.ArgSlice()...),
	})
}
