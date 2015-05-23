package scp

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
)

var whitespace = regexp.MustCompile(`\s+`)

type SecureCopier interface {
	Copy() error
}

type secureCopy struct {
	options *Options
	session *Session
}

func New(command string, stdin io.Reader, stdout io.Writer, stderr io.Writer) (SecureCopier, error) {
	options, err := ParseFlags(parseCommand(command))
	if err != nil {
		return nil, err
	}

	session := NewSession(stdin, stdout, stderr, options.PreserveTimesAndMode)

	return &secureCopy{
		options: options,
		session: session,
	}, nil
}

func parseCommand(command string) []string {
	// TODO: Proper implementation and test
	return whitespace.Split(command, -1)
}

func (s *secureCopy) Copy() error {
	if s.options.SourceMode {
		err := s.session.awaitConfirmation()
		if err != nil {
			return err
		}

		for _, source := range s.options.Sources {
			err := s.send(source)
			if err != nil {
				s.session.sendError(err.Error())
				return err
			}
		}
	}

	if s.options.TargetMode {
		targetIsDir := false
		targetInfo, err := os.Stat(s.options.Target)
		if err == nil {
			targetIsDir = targetInfo.IsDir()
		}

		if s.options.TargetIsDirectory {
			if !targetIsDir {
				return errors.New("target is not a directory")
			}
		}

		err = s.session.sendConfirmation()
		if err != nil {
			return err
		}

		for {
			var timeMessage *TimeMessage

			var err error
			messageType, err := s.session.peekByte()
			if err == io.EOF {
				return nil
			}

			if messageType == 'T' {
				timeMessage = &TimeMessage{}
				err := timeMessage.Receive(s.session)
				if err != nil {
					s.session.sendError(err.Error())
					return err
				}

				messageType, err = s.session.peekByte()
				if err == io.EOF {
					return nil
				}
			}

			if messageType == 'C' {
				err = ReceiveFile(s.session, s.options.Target, targetIsDir, timeMessage)
			} else if messageType == 'D' {
				err = ReceiveDirectory(s.session, s.options.Target, timeMessage)
			} else {
				err = fmt.Errorf("unexpected message type: %c", messageType)
				s.session.sendError(err.Error())
				return err
			}

			if err != nil {
				s.session.sendError(err.Error())
				return err
			}
		}
	}

	return nil
}

func (s *secureCopy) send(source string) error {
	var err error

	file, err := os.Open(source)
	if err != nil {
		return err
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return err
	}

	if !fileInfo.IsDir() {
		err = SendFile(s.session, file, fileInfo)
	} else if fileInfo.IsDir() && s.options.Recursive {
		err = SendDirectory(s.session, file.Name(), fileInfo)
	} else {
		err = fmt.Errorf("%s: not a regular file", fileInfo.Name())
	}

	if err != nil {
		return err
	}

	return err
}
