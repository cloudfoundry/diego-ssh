package scp

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"

	"github.com/pivotal-golang/lager"
)

var whitespace = regexp.MustCompile(`\s+`)

type SecureCopier interface {
	Copy() error
}

type secureCopy struct {
	options *Options
	session *Session
}

func New(options *Options, stdin io.Reader, stdout io.Writer, stderr io.Writer, logger lager.Logger) SecureCopier {
	session := NewSession(stdin, stdout, stderr, options.PreserveTimesAndMode, logger)

	return &secureCopy{
		options: options,
		session: session,
	}
}

func NewFromCommand(command string, stdin io.Reader, stdout io.Writer, stderr io.Writer, logger lager.Logger) (SecureCopier, error) {
	cmd, err := ParseCommand(command)
	if err != nil {
		return nil, err
	}

	options, err := ParseFlags(cmd)
	if err != nil {
		return nil, err
	}

	return New(options, stdin, stdout, stderr, logger), nil
}

func (s *secureCopy) Copy() error {
	if s.options.SourceMode {
		logger := s.session.logger.Session("source-mode")

		logger.Info("awaiting-connection-confirmation")
		err := s.session.awaitConfirmation()
		if err != nil {
			logger.Error("failed-confirmation", err)
			return err
		}
		logger.Info("received-connection-confirmation")

		for _, source := range s.options.Sources {
			logger.Info("sending-source", lager.Data{"Source": source})

			sourceInfo, err := os.Stat(source)
			if err != nil {
				s.session.sendError(err.Error())
				return err
			}

			if sourceInfo.IsDir() && !s.options.Recursive {
				err = errors.New(fmt.Sprintf("%s: not a regular file", sourceInfo.Name()))
				s.session.sendError(err.Error())
				return err
			}

			err = s.send(source)
			if err != nil {
				logger.Error("failed-sending-source", err, lager.Data{"Source": source})
				return err
			}
			logger.Info("sent-source", lager.Data{"Source": source})
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
				s.session.logger.Info("receiving-file", lager.Data{"Message Type": messageType})
				err = s.ReceiveFile(s.options.Target, targetIsDir, timeMessage)
			} else if messageType == 'D' {
				err = s.ReceiveDirectory(s.options.Target, timeMessage)
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

	defer func() {
		if err != nil {
			s.session.sendError(err.Error())
		}
	}()

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
		err = s.SendFile(file, fileInfo)
	} else {
		err = s.SendDirectory(file.Name(), fileInfo)
	}

	if err != nil {
		return err
	}

	return err
}
