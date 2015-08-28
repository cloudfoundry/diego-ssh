// +build windows

package atime

import (
	"os"
	"syscall"
)

func accessTimespec(fileInfo os.FileInfo) syscall.Timespec {
	return syscall.Timespec{}
}
