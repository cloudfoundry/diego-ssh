// +build !windows

package handlers

import (
	"os/exec"
	"syscall"

	"golang.org/x/crypto/ssh"

	"github.com/cloudfoundry-incubator/diego-ssh/helpers"
	"github.com/kr/pty"
	"github.com/pivotal-golang/lager"
)

func (sess *session) runWithPty(command *exec.Cmd) error {
	logger := sess.logger.Session("run-with-pty")

	ptyMaster, ptySlave, err := pty.Open()
	if err != nil {
		logger.Error("failed-to-open-pty", err)
		return err
	}

	sess.ptyMaster = ptyMaster
	defer ptySlave.Close()

	command.Stdout = ptySlave
	command.Stdin = ptySlave
	command.Stderr = ptySlave

	command.SysProcAttr = &syscall.SysProcAttr{
		Setctty: true,
		Setsid:  true,
	}

	setTerminalAttributes(logger, ptyMaster, sess.ptyRequest.Modelist)
	setWindowSize(logger, ptyMaster, sess.ptyRequest.Columns, sess.ptyRequest.Rows)

	sess.wg.Add(1)
	go helpers.Copy(logger.Session("to-pty"), nil, ptyMaster, sess.channel)
	go func() {
		helpers.Copy(logger.Session("from-pty"), &sess.wg, sess.channel, ptyMaster)
		sess.channel.CloseWrite()
	}()

	err = sess.runner.Start(command)
	if err == nil {
		sess.keepaliveStopCh = make(chan struct{})
		go sess.keepalive(command, sess.keepaliveStopCh)
	}
	return err
}

func (sess *session) serviceRequests(requests <-chan *ssh.Request) {
	logger := sess.logger
	logger.Info("starting")
	defer logger.Info("finished")

	defer sess.destroy()

	for req := range requests {
		sess.logger.Info("received-request", lager.Data{"type": req.Type})
		switch req.Type {
		case "env":
			sess.handleEnvironmentRequest(req)
		case "signal":
			sess.handleSignalRequest(req)
		case "pty-req":
			sess.handlePtyRequest(req)
		case "window-change":
			sess.handleWindowChangeRequest(req)
		case "exec":
			sess.handleExecRequest(req)
		case "shell":
			sess.handleShellRequest(req)
		default:
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
}
