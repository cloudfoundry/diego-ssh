package handlers

import "os"

type TCSetter interface {
	Set(pty *os.File, termios *Termios, value uint32) error
}

type nopSetter struct{}

type ccSetter struct {
	Character uint8
}

func (cc *ccSetter) Set(pty *os.File, termios *Termios, value uint32) error {
	termios.Cc[cc.Character] = byte(value)
	return TcSetAttr(pty, termios)
}

func (i *iflagSetter) Set(pty *os.File, termios *Termios, value uint32) error {
	if value == 0 {
		termios.Iflag &^= i.Flag
	} else {
		termios.Iflag |= i.Flag
	}
	return TcSetAttr(pty, termios)
}

func (l *lflagSetter) Set(pty *os.File, termios *Termios, value uint32) error {
	if value == 0 {
		termios.Lflag &^= l.Flag
	} else {
		termios.Lflag |= l.Flag
	}
	return TcSetAttr(pty, termios)
}

func (o *oflagSetter) Set(pty *os.File, termios *Termios, value uint32) error {
	if value == 0 {
		termios.Oflag &^= o.Flag
	} else {
		termios.Oflag |= o.Flag
	}

	return TcSetAttr(pty, termios)
}

func (n *nopSetter) Set(pty *os.File, termios *Termios, value uint32) error {
	return nil
}
