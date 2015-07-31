// +build windows

package handlers

import (
	"os"

	"golang.org/x/crypto/ssh"
)

type Termios struct {
	Cc    []byte
	Cflag uint64
	Iflag uint64
	Lflag uint64
	Oflag uint64
}

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

var TermAttrSetters map[uint8]TCSetter = map[uint8]TCSetter{
	ssh.VINTR:    &nopSetter{},
	ssh.VQUIT:    &nopSetter{},
	ssh.VERASE:   &nopSetter{},
	ssh.VKILL:    &nopSetter{},
	ssh.VEOF:     &nopSetter{},
	ssh.VEOL:     &nopSetter{},
	ssh.VEOL2:    &nopSetter{},
	ssh.VSTART:   &nopSetter{},
	ssh.VSTOP:    &nopSetter{},
	ssh.VSUSP:    &nopSetter{},
	ssh.VDSUSP:   &nopSetter{},
	ssh.VREPRINT: &nopSetter{},
	ssh.VWERASE:  &nopSetter{},
	ssh.VLNEXT:   &nopSetter{},
	ssh.VFLUSH:   &nopSetter{},
	ssh.VSWTCH:   &nopSetter{},
	ssh.VSTATUS:  &nopSetter{},
	ssh.VDISCARD: &nopSetter{},

	// Input modes
	ssh.IGNPAR:  &nopSetter{},
	ssh.PARMRK:  &nopSetter{},
	ssh.INPCK:   &nopSetter{},
	ssh.ISTRIP:  &nopSetter{},
	ssh.INLCR:   &nopSetter{},
	ssh.IGNCR:   &nopSetter{},
	ssh.ICRNL:   &nopSetter{},
	ssh.IUCLC:   &nopSetter{},
	ssh.IXON:    &nopSetter{},
	ssh.IXANY:   &nopSetter{},
	ssh.IXOFF:   &nopSetter{},
	ssh.IMAXBEL: &nopSetter{},

	// Local modes
	ssh.ISIG:    &nopSetter{},
	ssh.ICANON:  &nopSetter{},
	ssh.XCASE:   &nopSetter{},
	ssh.ECHO:    &nopSetter{},
	ssh.ECHOE:   &nopSetter{},
	ssh.ECHOK:   &nopSetter{},
	ssh.ECHONL:  &nopSetter{},
	ssh.NOFLSH:  &nopSetter{},
	ssh.TOSTOP:  &nopSetter{},
	ssh.IEXTEN:  &nopSetter{},
	ssh.ECHOCTL: &nopSetter{},
	ssh.ECHOKE:  &nopSetter{},
	ssh.PENDIN:  &nopSetter{},

	// Output modes
	ssh.OPOST:  &nopSetter{},
	ssh.OLCUC:  &nopSetter{},
	ssh.ONLCR:  &nopSetter{},
	ssh.OCRNL:  &nopSetter{},
	ssh.ONOCR:  &nopSetter{},
	ssh.ONLRET: &nopSetter{},

	// Control modes
	ssh.CS7:    &nopSetter{},
	ssh.CS8:    &nopSetter{},
	ssh.PARENB: &nopSetter{},
	ssh.PARODD: &nopSetter{},

	// Baud rates (ignore)
	ssh.TTY_OP_ISPEED: &nopSetter{},
	ssh.TTY_OP_OSPEED: &nopSetter{},
}

func TcSetAttr(tty *os.File, termios *Termios) error {
	return nil
}

func TcGetAttr(tty *os.File) (*Termios, error) {
	termios := &Termios{}

	return termios, nil
}

func (c *cflagSetter) Set(pty *os.File, termios *Termios, value uint32) error {
	if value == 0 {
		termios.Cflag &^= c.Flag
	} else {
		termios.Cflag |= c.Flag
	}

	return TcSetAttr(pty, termios)
}
