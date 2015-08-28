package handlers

import "os"

type TCSetter interface {
	Set(pty *os.File, termios *Termios, value uint32) error
}

type nopSetter struct{}

func (n *nopSetter) Set(pty *os.File, termios *Termios, value uint32) error {
	return nil
}
