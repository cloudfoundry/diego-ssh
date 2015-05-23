package scp

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
)

func SendFile(session *Session, file *os.File, fileInfo os.FileInfo) error {
	if fileInfo.IsDir() {
		return errors.New("cannot send a directory")
	}

	if session.preserveTimesAndMode {
		timeMessage := NewTimeMessage(fileInfo)
		err := timeMessage.Send(session)
		if err != nil {
			return err
		}
	}

	_, err := fmt.Fprintf(session.stdout, "C%.4o %d %s\n", fileInfo.Mode()&07777, fileInfo.Size(), fileInfo.Name())
	if err != nil {
		return err
	}

	err = session.awaitConfirmation()
	if err != nil {
		return err
	}

	_, err = io.CopyN(session.stdout, file, fileInfo.Size())
	if err != nil {
		return err
	}

	err = session.awaitConfirmation()
	if err != nil {
		return err
	}

	return nil
}

func ReceiveFile(session *Session, path string, pathIsDir bool, timeMessage *TimeMessage) error {
	messageType, err := session.readByte()
	if err != nil {
		return err
	}

	if messageType != byte('C') {
		return fmt.Errorf("unexpected message type: %c", messageType)
	}

	fileModeString, err := session.readString(SPACE)
	if err != nil {
		return err
	}

	fileMode, err := strconv.ParseUint(fileModeString, 8, 32)
	if err != nil {
		return err
	}

	lengthString, err := session.readString(SPACE)
	if err != nil {
		return err
	}

	length, err := strconv.ParseInt(lengthString, 10, 64)
	if err != nil {
		return err
	}

	fileName, err := session.readString(NEWLINE)
	if err != nil {
		return err
	}

	err = session.sendConfirmation()
	if err != nil {
		return err
	}

	targetPath := path
	if pathIsDir {
		targetPath = filepath.Join(path, fileName)
	}

	targetFile, err := os.OpenFile(targetPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, os.FileMode(fileMode))
	if err != nil {
		return err
	}
	defer targetFile.Close()

	_, err = io.CopyN(targetFile, session.stdin, length)
	if err != nil {
		return err
	}

	if session.preserveTimesAndMode {
		err := os.Chmod(targetPath, os.FileMode(fileMode))
		if err != nil {
			return err
		}
	}

	// OpenSSH does not check the flag
	if timeMessage != nil {
		err := os.Chtimes(targetPath, timeMessage.accessTime, timeMessage.modificationTime)
		if err != nil {
			return err
		}
	}

	err = session.sendConfirmation()
	if err != nil {
		return err
	}

	return nil
}
