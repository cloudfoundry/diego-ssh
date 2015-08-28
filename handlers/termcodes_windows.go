// +build windows

package handlers

import (
	"errors"
	"os"
)

func TcSetAttr(tty *os.File, termios *Termios) error {
	return nil
}

func TcGetAttr(tty *os.File) (*Termios, error) {
	return nil, errors.New("not supported")
}
