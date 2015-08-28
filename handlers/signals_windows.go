// +build windows

package handlers

import (
	"syscall"

	"golang.org/x/crypto/ssh"
)

var SyscallSignals = map[ssh.Signal]syscall.Signal{}

var SSHSignals = map[syscall.Signal]ssh.Signal{}
