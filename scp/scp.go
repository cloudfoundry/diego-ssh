package scp

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

var whitespace = regexp.MustCompile(`\s+`)

type SecureCopier interface {
	Copy() error
}

type secureCopy struct {
	options *SCPOptions
	stdin   *bufio.Reader
	stdout  io.Writer
	stderr  io.Writer
}

func New(command string, stdin io.Reader, stdout io.Writer, stderr io.Writer) (SecureCopier, error) {
	scpOptions, err := ParseFlags(parseCommand(command))
	if err != nil {
		return nil, err
	}

	return &secureCopy{
		options: scpOptions,
		stdin:   bufio.NewReader(stdin),
		stdout:  stdout,
		stderr:  stderr,
	}, nil
}

func parseCommand(command string) []string {
	// TODO: Proper implementation and test
	return whitespace.Split(command, -1)
}

func (s *secureCopy) Copy() error {
	if s.options.SourceMode {
		err := s.readResponse()
		if err != nil {
			return err
		}

		for _, source := range s.options.Sources {
			err := s.send(source)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (s *secureCopy) send(source string) error {
	file, err := os.Open(source)
	if err != nil {
		return err
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return err
	}

	if s.options.PreserveTimes {
		err := s.sendTimeMessage(fileInfo)
		if err != nil {
			return err
		}
	}

	if !fileInfo.IsDir() {
		return s.sendFile(file, fileInfo)
	} else if fileInfo.IsDir() && s.options.Recursive {
		return s.sendDir(file, fileInfo)
	} else {
		return fmt.Errorf("%s: not a regular file", fileInfo.Name())
	}
}

func (s *secureCopy) sendFile(file *os.File, fileInfo os.FileInfo) error {
	_, err := fmt.Fprintf(s.stdout, "C%.4o %d %s\n", fileInfo.Mode(), fileInfo.Size(), fileInfo.Name())
	if err != nil {
		return err
	}

	err = s.readResponse()
	if err != nil {
		return err
	}

	_, err = io.Copy(s.stdout, file)
	if err != nil {
		return err
	}

	err = s.readResponse()
	if err != nil {
		return err
	}

	return nil
}

func (s *secureCopy) sendDir(dir *os.File, dirInfo os.FileInfo) error {
	_, err := fmt.Fprintf(s.stdout, "D%.4o 0 %s\n", dirInfo.Mode()&07777, dirInfo.Name())
	if err != nil {
		return err
	}

	err = s.readResponse()
	if err != nil {
		return err
	}

	fileInfos, err := dir.Readdir(0)
	if err != nil {
		return err
	}

	for _, fileInfo := range fileInfos {
		source := filepath.Join(dir.Name(), fileInfo.Name())
		err := s.send(source)
		if err != nil {
			return err
		}
	}

	_, err = fmt.Fprint(s.stdout, "E\n")
	if err != nil {
		return err
	}

	err = s.readResponse()
	if err != nil {
		return err
	}

	return nil
}

func (s *secureCopy) sendTimeMessage(fileInfo os.FileInfo) error {
	mtime := fileInfo.ModTime()
	stat := fileInfo.Sys().(*syscall.Stat_t)
	atime := time.Unix(int64(stat.Atimespec.Sec), int64(stat.Atimespec.Nsec))

	_, err := fmt.Fprintf(s.stdout, "T%d %d %d %d\n", mtime.Unix(), 0, atime.Unix(), 0)

	err = s.readResponse()
	if err != nil {
		return err
	}

	return err
}

func (s *secureCopy) readResponse() error {
	response, err := s.stdin.ReadByte()
	if err != nil {
		return err
	}

	switch response {
	case 0:
		return nil
	case 1:
		//TODO: LOG THIS
		_, err := s.stdin.ReadString('\n')
		if err != nil {
			// swallow this error
		}

		return nil
	case 2:
		msg, err := s.stdin.ReadString('\n')
		if err != nil {
			return errors.New("Consumer terminated connection")
		}

		return errors.New(strings.TrimSpace(msg))
	}

	return errors.New("huh?")
}
