// +build windows

package handlers

type Termios struct {
	Cc    []byte
	Cflag uint64
	Iflag uint64
	Lflag uint64
	Oflag uint64
}
