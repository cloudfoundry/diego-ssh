package handlers

import (
	"fmt"
	"os/exec"
	"syscall"

	"github.com/pivotal-golang/lager"
	"golang.org/x/crypto/ssh"
)

type RunnerFunc func(*exec.Cmd) error

type SessionChannelHandler struct {
	Runner RunnerFunc
}

type session struct {
	environment map[string]string
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

	var session = newSession()

	for req := range requests {
		switch req.Type {
		case "exec":
			h.handleExecRequest(logger, channel, session, req)
		case "env":
			h.handleEnvironmentRequest(logger, session, req)
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

func (h *SessionChannelHandler) handleExecRequest(logger lager.Logger, channel ssh.Channel, session *session, request *ssh.Request) {
	type execMsg struct {
		Command string
	}
	var execMessage execMsg

	type exitStatusMsg struct {
		Status uint32
	}
	var exitMessage exitStatusMsg

	defer func() {
		channel.SendRequest("exit-status", false, ssh.Marshal(exitMessage))
		channel.Close()
	}()

	if request.WantReply {
		request.Reply(true, nil)
	}

	err := ssh.Unmarshal(request.Payload, &execMessage)
	if err != nil {
		logger.Error("unmarshal-failed", err)
		exitMessage.Status = 255
		return
	}

	cmd := exec.Command("/bin/bash", "-c", execMessage.Command)
	cmd.Stdout = channel
	cmd.Stderr = channel.Stderr()

	for k, v := range session.environment {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
	}

	err = h.Run(cmd)
	if err == nil {
		return
	}

	if exitError, ok := err.(*exec.ExitError); ok {
		waitStatus := exitError.Sys().(syscall.WaitStatus)
		exitMessage.Status = uint32(waitStatus.ExitStatus())
	} else {
		exitMessage.Status = 255
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
