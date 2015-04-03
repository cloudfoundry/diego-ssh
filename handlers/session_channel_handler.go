package handlers

import (
	"fmt"
	"os/exec"
	"syscall"

	"github.com/cloudfoundry-incubator/diego-ssh/helpers"
	"github.com/pivotal-golang/lager"
	"golang.org/x/crypto/ssh"
)

type RunnerFunc func(*exec.Cmd) error

type SessionChannelHandler struct {
	Runner RunnerFunc
}

type session struct {
	environment map[string]string
	command     *exec.Cmd
}

func newSession() *session {
	return &session{
		environment: map[string]string{},
	}
}

func (h *SessionChannelHandler) HandleNewChannel(logger lager.Logger, newChannel ssh.NewChannel) {
	channel, requests, _ := newChannel.Accept()

	h.handleSessionChannel(logger, channel, requests)
}

func (h *SessionChannelHandler) handleSessionChannel(logger lager.Logger, channel ssh.Channel, requests <-chan *ssh.Request) {
	logger = logger.Session("handle-channel-requests")
	logger.Info("starting")
	defer logger.Info("finished")

	defer channel.Close()

	session := newSession()

	for req := range requests {
		logger.Info("received-request", lager.Data{"type": req.Type})
		switch req.Type {
		case "exec":
			go h.handleExecRequest(logger, channel, session, req)
		case "env":
			h.handleEnvironmentRequest(logger, session, req)
		case "signal":
			h.handleSignalRequest(logger, session, req)
		default:
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
}

func (h *SessionChannelHandler) handleEnvironmentRequest(logger lager.Logger, session *session, request *ssh.Request) {
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

	session.environment[envMessage.Name] = envMessage.Value

	if request.WantReply {
		request.Reply(true, nil)
	}
}

func (h *SessionChannelHandler) handleSignalRequest(logger lager.Logger, session *session, request *ssh.Request) {
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

	signal := SyscallSignals[ssh.Signal(signalMessage.Signal)]
	if session.command != nil {
		err := session.command.Process.Signal(signal)
		if err != nil {
			logger.Error("process-signal-failed", err)
		}
	}

	if request.WantReply {
		request.Reply(true, nil)
	}
}

func (h *SessionChannelHandler) handleExecRequest(logger lager.Logger, channel ssh.Channel, session *session, request *ssh.Request) {
	defer channel.Close()

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

	session.command = exec.Command("/bin/bash", "-c", execMessage.Command)
	session.command.Stdout = channel
	session.command.Stderr = channel.Stderr()

	stdin, err := session.command.StdinPipe()
	if err != nil {
		if request.WantReply {
			request.Reply(false, nil)
		}
		return
	}

	go helpers.CopyAndClose(logger, stdin, channel)

	for k, v := range session.environment {
		session.command.Env = append(session.command.Env, fmt.Sprintf("%s=%s", k, v))
	}

	if request.WantReply {
		request.Reply(true, nil)
	}

	err = h.Run(session.command)

	sendExecReply(channel, err)
}

func sendExecReply(channel ssh.Channel, err error) {
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

func (f RunnerFunc) Run(command *exec.Cmd) error {
	return f(command)
}

func (h *SessionChannelHandler) Run(command *exec.Cmd) error {
	if h.Runner != nil {
		return h.Runner.Run(command)
	}
	return command.Run()
}
