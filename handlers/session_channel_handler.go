package handlers

import (
	"errors"
	"fmt"
	"os/exec"
	"sync"
	"syscall"

	"github.com/cloudfoundry-incubator/diego-ssh/helpers"
	"github.com/pivotal-golang/lager"
	"golang.org/x/crypto/ssh"
)

type StarterFunc func(*exec.Cmd) error

func (f StarterFunc) Start(command *exec.Cmd) error {
	return f(command)
}

type SessionChannelHandler struct {
	Starter StarterFunc
}

func (handler *SessionChannelHandler) HandleNewChannel(logger lager.Logger, newChannel ssh.NewChannel) {
	channel, requests, err := newChannel.Accept()
	if err != nil {
		logger.Error("handle-new-session-channel-failed", err)
		return
	}

	newSession(logger, handler).serviceChannel(channel, requests)
}

type session struct {
	logger  lager.Logger
	handler *SessionChannelHandler

	sync.Mutex
	environment map[string]string
	command     *exec.Cmd
}

func newSession(logger lager.Logger, handler *SessionChannelHandler) *session {
	return &session{
		logger:      logger.Session("session-channel"),
		handler:     handler,
		environment: map[string]string{},
	}
}

func (sess *session) serviceChannel(channel ssh.Channel, requests <-chan *ssh.Request) {
	sess.logger.Info("starting")
	defer sess.logger.Info("finished")

	defer channel.Close()

	for req := range requests {
		sess.logger.Info("received-request", lager.Data{"type": req.Type})
		switch req.Type {
		case "exec":
			go sess.handleExecRequest(channel, req)
		case "env":
			sess.handleEnvironmentRequest(req)
		case "signal":
			sess.handleSignalRequest(req)
		default:
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
}

func (sess *session) handleEnvironmentRequest(request *ssh.Request) {
	type envMsg struct {
		Name  string
		Value string
	}
	var envMessage envMsg

	err := ssh.Unmarshal(request.Payload, &envMessage)
	if err != nil {
		sess.logger.Error("unmarshal-failed", err)
		request.Reply(false, nil)
		return
	}

	sess.Lock()
	sess.environment[envMessage.Name] = envMessage.Value
	sess.Unlock()

	if request.WantReply {
		request.Reply(true, nil)
	}
}

func (sess *session) handleSignalRequest(request *ssh.Request) {
	type signalMsg struct {
		Signal string
	}
	var signalMessage signalMsg

	err := ssh.Unmarshal(request.Payload, &signalMessage)
	if err != nil {
		sess.logger.Error("unmarshal-failed", err)
		if request.WantReply {
			request.Reply(false, nil)
		}
		return
	}

	sess.Lock()
	cmd := sess.command
	sess.Unlock()

	if cmd != nil {
		signal := SyscallSignals[ssh.Signal(signalMessage.Signal)]
		err := cmd.Process.Signal(signal)
		if err != nil {
			sess.logger.Error("process-signal-failed", err)
		}
	}

	if request.WantReply {
		request.Reply(true, nil)
	}
}

func (sess *session) handleExecRequest(channel ssh.Channel, request *ssh.Request) {
	type execMsg struct {
		Command string
	}
	var execMessage execMsg

	err := ssh.Unmarshal(request.Payload, &execMessage)
	if err != nil {
		sess.logger.Error("unmarshal-failed", err)
		if request.WantReply {
			request.Reply(false, nil)
		}
		return
	}

	cmd, err := sess.createCommand(channel, "-c", execMessage.Command)
	if err != nil {
		if request.WantReply {
			request.Reply(false, nil)
		}
		return
	}

	if request.WantReply {
		request.Reply(true, nil)
	}

	err = sess.Start(cmd)
	if err == nil {
		err = cmd.Wait()
	}
	sess.sendExitMessage(channel, err)

	channel.Close()
}

func (sess *session) createCommand(channel ssh.Channel, args ...string) (*exec.Cmd, error) {
	sess.Lock()
	defer sess.Unlock()

	if sess.command != nil {
		return nil, errors.New("command already started")
	}

	cmd := exec.Command("/bin/bash", args...)
	cmd.Stdout = channel
	cmd.Stderr = channel.Stderr()

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}

	for k, v := range sess.environment {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
	}

	sess.command = cmd

	go helpers.CopyAndClose(sess.logger, stdin, channel)

	return cmd, nil
}

func (sess *session) sendExitMessage(channel ssh.Channel, err error) {
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
		channel.SendRequest("exit-status", false, ssh.Marshal(exitStatusMsg{}))
		return
	}

	exitError, ok := err.(*exec.ExitError)
	if !ok {
		exitMessage := exitStatusMsg{Status: 255}
		channel.SendRequest("exit-status", false, ssh.Marshal(exitMessage))
		return
	}

	waitStatus, ok := exitError.Sys().(syscall.WaitStatus)
	if !ok {
		exitMessage := exitStatusMsg{Status: 255}
		channel.SendRequest("exit-status", false, ssh.Marshal(exitMessage))
		return
	}

	if waitStatus.Signaled() {
		exitMessage := exitSignalMsg{
			Signal:     string(SSHSignals[waitStatus.Signal()]),
			CoreDumped: waitStatus.CoreDump(),
		}
		channel.SendRequest("exit-signal", false, ssh.Marshal(exitMessage))
	} else {
		exitMessage := exitStatusMsg{Status: uint32(waitStatus.ExitStatus())}
		channel.SendRequest("exit-status", false, ssh.Marshal(exitMessage))
	}
}

func (sess *session) Start(command *exec.Cmd) error {
	sess.Lock()
	defer sess.Unlock()

	if sess.handler.Starter != nil {
		return sess.handler.Starter.Start(command)
	}
	return command.Start()
}
