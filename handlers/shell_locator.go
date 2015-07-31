package handlers

import "os/exec"

//go:generate counterfeiter -o fakes/fake_shell_locator.go . ShellLocator
type ShellLocator interface {
	ShellPath() string
}

type shellLocator struct{}

func NewShellLocator() ShellLocator {
	return &shellLocator{}
}

func (shellLocator) ShellPath() string {
	for _, shell := range shellPaths {
		if path, err := exec.LookPath(shell); err == nil {
			return path
		}
	}

	return "/bin/sh"
}
