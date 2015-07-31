// +build !windows

package handlers

import (
	"os/exec"
	"syscall"

	"github.com/cloudfoundry-incubator/diego-ssh/helpers"
	"github.com/kr/pty"
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
