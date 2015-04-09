package handlers

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"syscall"

	"github.com/cloudfoundry-incubator/diego-ssh/helpers"
	"github.com/creack/termios/win"
	"github.com/kr/pty"
	"github.com/pivotal-golang/lager"
	"golang.org/x/crypto/ssh"
)

//go:generate counterfeiter -o fakes/fake_runner.go . Runner
type Runner interface {
	Start(cmd *exec.Cmd) error
	Wait(cmd *exec.Cmd) error
}

type commandRunner struct{}

func NewCommandRunner() Runner {
	return &commandRunner{}
}

func (commandRunner) Start(cmd *exec.Cmd) error {
	return cmd.Start()
}

func (commandRunner) Wait(cmd *exec.Cmd) error {
	return cmd.Wait()
}

type SessionChannelHandler struct {
	runner Runner
}

func NewSessionChannelHandler(runner Runner) *SessionChannelHandler {
	return &SessionChannelHandler{
		runner: runner,
	}
}

func (handler *SessionChannelHandler) HandleNewChannel(logger lager.Logger, newChannel ssh.NewChannel) {
	channel, requests, err := newChannel.Accept()
	if err != nil {
		logger.Error("handle-new-session-channel-failed", err)
		return
	}

	newSession(logger, handler.runner, channel).serviceRequests(requests)
}

type ptyRequestMsg struct {
	Term     string
	Columns  uint32
	Rows     uint32
	Width    uint32
	Height   uint32
	Modelist string
}

type session struct {
	logger   lager.Logger
	complete bool

	runner  Runner
	channel ssh.Channel

	sync.Mutex
	env     map[string]string
	command *exec.Cmd

	wg         sync.WaitGroup
	allocPty   bool
	ptyRequest ptyRequestMsg
	ptyMaster  *os.File
}

func newSession(logger lager.Logger, runner Runner, channel ssh.Channel) *session {
	return &session{
		logger:  logger.Session("session-channel"),
		runner:  runner,
		channel: channel,
		env:     map[string]string{},
	}
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
		case "exec":
			go sess.handleExecRequest(req)
		default:
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
}

func (sess *session) handleEnvironmentRequest(request *ssh.Request) {
	logger := sess.logger.Session("handle-environment-request")

	type envMsg struct {
		Name  string
		Value string
	}
	var envMessage envMsg

	err := ssh.Unmarshal(request.Payload, &envMessage)
	if err != nil {
		logger.Error("unmarshal-failed", err)
		request.Reply(false, nil)
		return
	}

	sess.Lock()
	sess.env[envMessage.Name] = envMessage.Value
	sess.Unlock()

	if request.WantReply {
		request.Reply(true, nil)
	}
}

func (sess *session) handleSignalRequest(request *ssh.Request) {
	logger := sess.logger.Session("handle-signal-request")

	type signalMsg struct {
		Signal string
	}
	var signalMessage signalMsg

	err := ssh.Unmarshal(request.Payload, &signalMessage)
	if err != nil {
		logger.Error("unmarshal-failed", err)
		if request.WantReply {
			request.Reply(false, nil)
		}
		return
	}

	sess.Lock()
	defer sess.Unlock()

	cmd := sess.command

	if cmd != nil {
		signal := SyscallSignals[ssh.Signal(signalMessage.Signal)]
		err := cmd.Process.Signal(signal)
		if err != nil {
			logger.Error("process-signal-failed", err)
		}
	}

	if request.WantReply {
		request.Reply(true, nil)
	}
}

func (sess *session) handlePtyRequest(request *ssh.Request) {
	logger := sess.logger.Session("handle-pty-request")

	var ptyRequestMessage ptyRequestMsg

	err := ssh.Unmarshal(request.Payload, &ptyRequestMessage)
	if err != nil {
		logger.Error("unmarshal-failed", err)
		if request.WantReply {
			request.Reply(false, nil)
		}
		return
	}

	sess.Lock()
	defer sess.Unlock()

	sess.allocPty = true
	sess.ptyRequest = ptyRequestMessage
	sess.env["TERM"] = ptyRequestMessage.Term

	if request.WantReply {
		request.Reply(true, nil)
	}
}

func (sess *session) handleExecRequest(request *ssh.Request) {
	logger := sess.logger.Session("handle-exec-request")

	type execMsg struct {
		Command string
	}
	var execMessage execMsg

	err := ssh.Unmarshal(request.Payload, &execMessage)
	if err != nil {
		logger.Error("unmarshal-failed", err)
		if request.WantReply {
			request.Reply(false, nil)
		}
		return
	}

	cmd, err := sess.createCommand(execMessage.Command)
	if err != nil {
		if request.WantReply {
			request.Reply(false, nil)
		}
		return
	}

	if request.WantReply {
		request.Reply(true, nil)
	}

	if sess.allocPty {
		err = sess.runWithPty(cmd)
	} else {
		err = sess.run(cmd)
	}

	if err == nil {
		err = sess.wait(cmd)
	}

	sess.sendExitMessage(err)

	sess.destroy()
}

func (sess *session) createCommand(command string) (*exec.Cmd, error) {
	sess.Lock()
	defer sess.Unlock()

	if sess.command != nil {
		return nil, errors.New("command already started")
	}

	cmd := exec.Command("/bin/sh", "-c", command)
	cmd.Env = sess.environment()
	sess.command = cmd

	return cmd, nil
}

func (sess *session) environment() []string {
	env := []string{}

	env = append(env, "PATH=/bin:/usr/bin")
	env = append(env, "LANG=en_US.UTF8")

	for k, v := range sess.env {
		if k != "HOME" && k != "USER" {
			env = append(env, fmt.Sprintf("%s=%s", k, v))
		}
	}

	env = append(env, fmt.Sprintf("HOME=%s", os.Getenv("HOME")))
	env = append(env, fmt.Sprintf("USER=%s", os.Getenv("USER")))

	return env
}

func (sess *session) sendExitMessage(err error) {
	logger := sess.logger

	if err != nil {
		logger.Error("building-exit-message-from-error", err)
	}

	type exitStatusMsg struct {
		Status uint32
	}

	type exitSignalMsg struct {
		Signal     string
		CoreDumped bool
		Error      string
		Lang       string
	}

	if err == nil {
		sess.channel.SendRequest("exit-status", false, ssh.Marshal(exitStatusMsg{}))
		return
	}

	exitError, ok := err.(*exec.ExitError)
	if !ok {
		exitMessage := exitStatusMsg{Status: 255}
		sess.channel.SendRequest("exit-status", false, ssh.Marshal(exitMessage))
		return
	}

	waitStatus, ok := exitError.Sys().(syscall.WaitStatus)
	if !ok {
		exitMessage := exitStatusMsg{Status: 255}
		sess.channel.SendRequest("exit-status", false, ssh.Marshal(exitMessage))
		return
	}

	if waitStatus.Signaled() {
		exitMessage := exitSignalMsg{
			Signal:     string(SSHSignals[waitStatus.Signal()]),
			CoreDumped: waitStatus.CoreDump(),
		}
		sess.channel.SendRequest("exit-signal", false, ssh.Marshal(exitMessage))
		return
	}

	exitMessage := exitStatusMsg{Status: uint32(waitStatus.ExitStatus())}
	sess.channel.SendRequest("exit-status", false, ssh.Marshal(exitMessage))
}

func setWindowSize(pseudoTty *os.File, columns, rows uint32) error {
	return win.SetWinsize(pseudoTty.Fd(), &win.Winsize{
		Width:  uint16(columns),
		Height: uint16(rows),
	})
}

func (sess *session) run(command *exec.Cmd) error {
	logger := sess.logger.Session("run")

	sess.Lock()
	defer sess.Unlock()

	command.Stdout = sess.channel
	command.Stderr = sess.channel.Stderr()

	stdin, err := command.StdinPipe()
	if err != nil {
		return err
	}

	sess.wg.Add(1)
	go helpers.CopyAndClose(logger, &sess.wg, stdin, sess.channel)

	return sess.runner.Start(command)
}

func (sess *session) runWithPty(command *exec.Cmd) error {
	logger := sess.logger.Session("run-with-pty")

	sess.Lock()
	defer sess.Unlock()

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

	setWindowSize(ptyMaster, sess.ptyRequest.Columns, sess.ptyRequest.Rows)

	sess.wg.Add(2)
	go helpers.Copy(logger, &sess.wg, ptyMaster, sess.channel)
	go helpers.Copy(logger, &sess.wg, sess.channel, ptyMaster)

	return sess.runner.Start(command)
}

func (sess *session) wait(command *exec.Cmd) error {
	return sess.runner.Wait(command)
}

func (sess *session) destroy() {
	sess.Lock()
	defer sess.Unlock()

	if sess.complete {
		return
	}

	sess.complete = true

	sess.wg.Wait()

	if sess.ptyMaster != nil {
		sess.ptyMaster.Close()
	}

	if sess.channel != nil {
		sess.channel.Close()
	}
}
