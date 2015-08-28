// +build darwin

package handlers

import (
	"os"
	"syscall"
	"unsafe"
)

type iflagSetter struct {
	Flag uint64
}

type lflagSetter struct {
	Flag uint64
}

type oflagSetter struct {
	Flag uint64
}

type cflagSetter struct {
	Flag uint64
}

func TcSetAttr(tty *os.File, termios *Termios) error {
	r, _, e := syscall.Syscall(syscall.SYS_IOCTL, tty.Fd(), syscall.TIOCSETA, uintptr(unsafe.Pointer(termios)))
	if r != 0 {
		return os.NewSyscallError("SYS_IOCTL", e)
	}

	return nil
}

func TcGetAttr(tty *os.File) (*Termios, error) {
	termios := &Termios{}

	r, _, e := syscall.Syscall(syscall.SYS_IOCTL, tty.Fd(), syscall.TIOCGETA, uintptr(unsafe.Pointer(termios)))
	if r != 0 {
		return nil, os.NewSyscallError("SYS_IOCTL", e)
	}

	return termios, nil
}
