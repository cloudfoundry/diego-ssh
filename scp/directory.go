package scp

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
)

func SendDirectory(session *Session, dir string, dirInfo os.FileInfo) error {
	return sendDirectory(session, dir, dirInfo)
}

func ReceiveDirectory(session *Session, dir string, timeMessage *TimeMessage) error {
	messageType, err := session.readByte()
	if err != nil {
		return err
	}

	if messageType != byte('D') {
		return fmt.Errorf("unexpected message type: %c", messageType)
	}

	dirModeString, err := session.readString(SPACE)
	if err != nil {
		return err
	}

	dirMode, err := strconv.ParseUint(dirModeString, 8, 32)
	if err != nil {
		return err
	}

	// Length field is ignored
	_, err = session.readString(SPACE)
	if err != nil {
		return err
	}

	dirName, err := session.readString(NEWLINE)
	if err != nil {
		return err
	}

	err = session.sendConfirmation()
	if err != nil {
		return err
	}

	targetPath := filepath.Join(dir, dirName)
	_, err = os.Stat(dir)
	if os.IsNotExist(err) {
		targetPath = dir
	}

	targetInfo, err := os.Stat(targetPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}

		err = os.Mkdir(targetPath, os.FileMode(dirMode))
		if err != nil {
			return err
		}
	} else if !targetInfo.Mode().IsDir() {
		return fmt.Errorf("target exists and is not a directory: %q", dirName)
	}

	err = processDirectoryMessages(session, targetPath)
	if err != nil {
		return err
	}

	message, err := session.readString(NEWLINE)
	if message != "E" {
		return fmt.Errorf("unexpected message type: %c", messageType)
	}

	if timeMessage != nil && session.preserveTimesAndMode {
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

func processDirectoryMessages(session *Session, dirPath string) error {
	for {
		messageType, err := session.peekByte()
		if err != nil {
			return err
		}

		var timeMessage *TimeMessage
		if messageType == 'T' && session.preserveTimesAndMode {
			timeMessage = &TimeMessage{}
			err := timeMessage.Receive(session)
			if err != nil {
				return err
			}

			messageType, err = session.peekByte()
			if err != nil {
				return err
			}
		}

		switch messageType {
		case 'D':
			err := ReceiveDirectory(session, dirPath, timeMessage)
			if err != nil {
				return err
			}
		case 'C':
			err := ReceiveFile(session, dirPath, true, timeMessage)
			if err != nil {
				return err
			}
		case 'E':
			if timeMessage != nil {
				return fmt.Errorf("unexpected message type: %c", messageType)
			}
			return nil
		default:
			return fmt.Errorf("unexpected message type: %c", messageType)
		}
	}
}

func sendDirectory(session *Session, dirname string, directoryInfo os.FileInfo) error {
	if session.preserveTimesAndMode {
		timeMessage := NewTimeMessage(directoryInfo)
		err := timeMessage.Send(session)
		if err != nil {
			return err
		}
	}

	_, err := fmt.Fprintf(session.stdout, "D%.4o 0 %s\n", directoryInfo.Mode()&07777, directoryInfo.Name())
	if err != nil {
		return err
	}

	err = session.awaitConfirmation()
	if err != nil {
		return err
	}

	fileInfos, err := ioutil.ReadDir(dirname)
	if err != nil {
		return err
	}

	for _, fileInfo := range fileInfos {
		source := filepath.Join(dirname, fileInfo.Name())
		if fileInfo.IsDir() {
			err := sendDirectory(session, source, fileInfo)
			if err != nil {
				return err
			}
		} else {
			err := sendFile(session, source, fileInfo)
			if err != nil {
				return err
			}
		}
	}

	_, err = fmt.Fprintf(session.stdout, "E\n")
	if err != nil {
		return err
	}

	err = session.awaitConfirmation()
	if err != nil {
		return err
	}

	return nil
}

func sendFile(session *Session, source string, fileInfo os.FileInfo) error {
	file, err := os.Open(source)
	if err != nil {
		return err
	}
	defer file.Close()

	err = SendFile(session, file, fileInfo)
	if err != nil {
		return err
	}

	return nil
}
