// +build windows

package handlers

import (
	"os/exec"

	"github.com/pivotal-golang/lager"
)

func (sess *session) runWithPty(command *exec.Cmd) error {
	logger := sess.logger.Session("run")

	command.Stdout = sess.channel
	command.Stderr = sess.channel.Stderr()

	stdin, err := command.StdinPipe()
	if err != nil {
		return err
	}

	go func() {
		for {
			mybuffer := make([]byte, 255)
			n, err := sess.channel.Read(mybuffer)
			if err == nil {
				inp := mybuffer[0:n]
				logger.Info("stdin", lager.Data{"buffer": inp})
				stdin.Write(inp)
				if string(inp) == "\r" {
					stdin.Write([]byte("\r\n"))
				}
			}
		}
	}()

	return sess.runner.Start(command)
}
