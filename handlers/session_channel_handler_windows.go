// +build windows

package handlers

import (
	"os/exec"

	"golang.org/x/crypto/ssh"
)

func (sess *session) runWithPty(command *exec.Cmd) error {
	return nil
}

func (sess *session) serviceRequests(requests <-chan *ssh.Request) {
	logger := sess.logger
	logger.Info("starting")
	defer logger.Info("finished")

	defer sess.destroy()

	sess.channel.Stderr().Write([]byte("SSH is not supported on Windows cells\n"))
}
