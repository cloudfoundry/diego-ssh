// +build windows

package atime

import (
	"os"
	"syscall"
)

func accessTimespec(fileInfo os.FileInfo) syscall.Timespec {
	atime := fileInfo.Sys().(*syscall.Win32FileAttributeData).LastAccessTime
	nsec := atime.Nanoseconds()
	return syscall.NsecToTimespec(nsec)
}
