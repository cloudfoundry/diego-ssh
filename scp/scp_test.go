package scp_test

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cloudfoundry-incubator/diego-ssh/scp"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Scp", func() {
	var (
		stdout, stderr *bytes.Buffer
	)

	BeforeEach(func() {
		stdout = &bytes.Buffer{}
		stderr = &bytes.Buffer{}
	})

	Context("source mode", func() {
		var tempDir string
		var nestedTempDir string
		var generatedTextFile string
		var generatedNestedTextFile string
		var generatedBinaryFile string

		BeforeEach(func() {
			var err error
			tempDir, err = ioutil.TempDir("", "scp")
			Expect(err).NotTo(HaveOccurred())

			fileContents := []byte("---\nthis is a simple file\n\n")
			generatedTextFile = filepath.Join(tempDir, "textfile.txt")

			err = ioutil.WriteFile(generatedTextFile, fileContents, 0664)
			Expect(err).NotTo(HaveOccurred())

			fileContents = make([]byte, 1024)
			generatedBinaryFile = filepath.Join(tempDir, "binary.dat")

			_, err = rand.Read(fileContents)
			Expect(err).NotTo(HaveOccurred())

			err = ioutil.WriteFile(generatedBinaryFile, fileContents, 0400)
			Expect(err).NotTo(HaveOccurred())

			nestedTempDir, err = ioutil.TempDir(tempDir, "nested")
			Expect(err).NotTo(HaveOccurred())

			nestedFileContents := []byte("---\nthis is a simple nested file\n\n")
			generatedNestedTextFile = filepath.Join(nestedTempDir, "nested-textfile.txt")

			err = ioutil.WriteFile(generatedNestedTextFile, nestedFileContents, 0664)
			Expect(err).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			os.RemoveAll(tempDir)
		})

		Context("when no files are requested", func() {
			It("fails construct the copier", func() {
				stdin := &bytes.Buffer{}
				_, err := scp.New("scp -f", stdin, stdout, stderr)
				Expect(err).To(HaveOccurred())
			})
		})

		Context("message confirmation", func() {
			BeforeEach(func() {
				Expect(os.Remove(generatedNestedTextFile)).NotTo(HaveOccurred())
				Expect(os.RemoveAll(nestedTempDir)).NotTo(HaveOccurred())
				Expect(os.Remove(generatedBinaryFile)).NotTo(HaveOccurred())
			})

			It("does not send a message until it receives a confirmation", func() {
				stdin, stdinSource := io.Pipe()
				stdoutSource, stdout := io.Pipe()
				stdoutReader := bufio.NewReader(stdoutSource)
				copier, err := scp.New(fmt.Sprintf("scp -prf %s", tempDir), stdin, stdout, stderr)
				Expect(err).NotTo(HaveOccurred())

				go func() {
					defer GinkgoRecover()
					err := copier.Copy()
					Expect(err).NotTo(HaveOccurred())
					stdout.Close()
				}()

				expectedDirMessage := dirMessageFromDir(tempDir, true)
				expectedFileMessage := expectedDirMessage.contents[0].(*FileMessage)

				receivedMessages := make(chan []byte)

				By("Acknowledging the connection it sends the directory timestamp message")
				go readLine(receivedMessages, stdoutReader)
				Consistently(receivedMessages).ShouldNot(Receive())
				stdinSource.Write([]byte{0})
				Eventually(receivedMessages).Should(Receive(BeEquivalentTo(expectedDirMessage.timeMessage.messageHeader())))

				By("Acknowledging the directory timestamp message it sends the directory message")
				go readLine(receivedMessages, stdoutReader)
				Consistently(receivedMessages).ShouldNot(Receive())
				stdinSource.Write([]byte{0})
				Eventually(receivedMessages).Should(Receive(BeEquivalentTo(expectedDirMessage.messageHeader())))

				By("Acknowledging the directory message it sends the file timestamp message")
				go readLine(receivedMessages, stdoutReader)
				Consistently(receivedMessages).ShouldNot(Receive())
				stdinSource.Write([]byte{0})
				Eventually(receivedMessages).Should(Receive(BeEquivalentTo(expectedFileMessage.timeMessage.messageHeader())))

				By("Acknowledging the file timestamp message it sends the file message")
				go readLine(receivedMessages, stdoutReader)
				Consistently(receivedMessages).ShouldNot(Receive())
				stdinSource.Write([]byte{0})
				Eventually(receivedMessages).Should(Receive(BeEquivalentTo(expectedFileMessage.messageHeader())))

				By("Acknowledging the file message it sends the file contents")
				go readBytes(receivedMessages, stdoutReader, len(expectedFileMessage.contents))
				Consistently(receivedMessages).ShouldNot(Receive())
				stdinSource.Write([]byte{0})
				Eventually(receivedMessages).Should(Receive(Equal(expectedFileMessage.contents)))

				By("Acknowledging the file contents it sends the directory end message")
				go readLine(receivedMessages, stdoutReader)
				Consistently(receivedMessages).ShouldNot(Receive())
				stdinSource.Write([]byte{0})
				Eventually(receivedMessages).Should(Receive(BeEquivalentTo("E\n")))

				By("Acknowledging the directory end message")
				stdinSource.Write([]byte{0})

				_, err = stdoutReader.ReadByte()
				Expect(err).Should(Equal(io.EOF))
			})

			Context("when the sink sends an error", func() {
				var (
					stdoutReader             *bufio.Reader
					stdin, stdoutSource      *io.PipeReader
					stdinSource, stdout      *io.PipeWriter
					errChan                  chan error
					copier                   scp.SecureCopier
					err                      error
					expectedFileMessage      *FileMessage
					expectedDirectoryMessage *DirMessage
				)

				BeforeEach(func() {
					expectedFileMessage = fileMessageFromFile(generatedTextFile, true)
					expectedDirectoryMessage = dirMessageFromDir(tempDir, true)

					stdin, stdinSource = io.Pipe()
					stdoutSource, stdout = io.Pipe()
					stdoutReader = bufio.NewReader(stdoutSource)
					copier, err = scp.New(fmt.Sprintf("scp -prf %s", tempDir), stdin, stdout, stderr)
					Expect(err).NotTo(HaveOccurred())

					errChan = make(chan error)
					ready := make(chan struct{})
					go func() {
						defer GinkgoRecover()
						ready <- struct{}{}
						err := copier.Copy()
						errChan <- err
					}()

					<-ready
				})

				It("returns an error when acknowledging the connection fails", func() {
					By("Fail to acknowledge the connection")
					stdinSource.Write([]byte{2})
					stdinSource.Write([]byte("Failed to ack conn\n"))
					Eventually(errChan).Should(Receive(MatchError("Failed to ack conn")))
				})

				It("returns an error when acknowledging the timestamp message fails", func() {
					By("Succeed to acknowledge the connection")
					stdinSource.Write([]byte{0})

					By("Fail to acknowledge the timestamp directory message")
					readLine(nil, stdoutReader)
					stdinSource.Write([]byte{2})
					stdinSource.Write([]byte("Failed to ack timestamp\n"))

					Eventually(errChan).Should(Receive(MatchError("Failed to ack timestamp")))
				})

				It("returns an error when acknowledging the directory message fails", func() {
					By("Succeed to acknowledge the connection")
					stdinSource.Write([]byte{0})

					By("Succeed to acknowledge the directory timestamp message")
					readLine(nil, stdoutReader)
					stdinSource.Write([]byte{0})

					By("Fail to acknowledge the directory message")
					readLine(nil, stdoutReader)
					stdinSource.Write([]byte{2})
					stdinSource.Write([]byte("Failed to ack directory\n"))

					Eventually(errChan).Should(Receive(MatchError("Failed to ack directory")))
				})

				It("returns an error when acknowledging the file message fails", func() {
					By("Succeed to acknowledge the connection")
					stdinSource.Write([]byte{0})

					By("Succeed to acknowledge the directory timestamp message")
					readLine(nil, stdoutReader)
					stdinSource.Write([]byte{0})

					By("Succeed to acknowledge the directory message")
					readLine(nil, stdoutReader)
					stdinSource.Write([]byte{0})

					By("Succeed to acknowledge the file timestamp message")
					readLine(nil, stdoutReader)
					stdinSource.Write([]byte{0})

					By("Fail to acknowledge the file message")
					readLine(nil, stdoutReader)
					stdinSource.Write([]byte{2})
					stdinSource.Write([]byte("Failed to ack file\n"))

					Eventually(errChan).Should(Receive(MatchError("Failed to ack file")))
				})

				It("returns an error when acknowledging the file contents fails", func() {
					By("Succeed to acknowledge the connection")
					stdinSource.Write([]byte{0})

					By("Succeed to acknowledge the directory timestamp message")
					readLine(nil, stdoutReader)
					stdinSource.Write([]byte{0})

					By("Succeed to acknowledge the directory message")
					readLine(nil, stdoutReader)
					stdinSource.Write([]byte{0})

					By("Succeed to acknowledge the file timestamp message")
					readLine(nil, stdoutReader)
					stdinSource.Write([]byte{0})

					By("Succeed to acknowledge the file message")
					readLine(nil, stdoutReader)
					stdinSource.Write([]byte{0})

					By("Fail to acknowledge the file contents")
					readLine(nil, stdoutReader)
					stdinSource.Write([]byte{2})
					stdinSource.Write([]byte("Failed to ack file contents\n"))

					Eventually(errChan).Should(Receive(MatchError("Failed to ack file contents")))
				})

				It("returns an error when acknowledging the directory end message fails", func() {
					By("Succeed to acknowledge the connection")
					stdinSource.Write([]byte{0})

					By("Succeed to acknowledge the directory timestamp message")
					readLine(nil, stdoutReader)
					stdinSource.Write([]byte{0})

					By("Succeed to acknowledge the directory message")
					readLine(nil, stdoutReader)
					stdinSource.Write([]byte{0})

					By("Succeed to acknowledge the file timestamp message")
					readLine(nil, stdoutReader)
					stdinSource.Write([]byte{0})

					By("Succeed to acknowledge the file message")
					readLine(nil, stdoutReader)
					stdinSource.Write([]byte{0})

					By("Succeed to acknowledge the file contents")
					readBytes(nil, stdoutReader, len(expectedFileMessage.contents))
					stdinSource.Write([]byte{0})

					By("Fail to acknowledge the directory end")
					readLine(nil, stdoutReader)
					stdinSource.Write([]byte{2})
					stdinSource.Write([]byte("Failed to ack file directory end\n"))

					Eventually(errChan).Should(Receive(MatchError("Failed to ack file directory end")))
				})
			})
		})

		Context("when files are requested", func() {
			It("sends the files", func() {
				stdin := bytes.NewBuffer([]byte{0, 0, 0, 0, 0, 0, 0})
				copier, err := scp.New(fmt.Sprintf("scp -f %s %s", generatedTextFile, generatedBinaryFile), stdin, stdout, stderr)
				Expect(err).NotTo(HaveOccurred())

				err = copier.Copy()
				Expect(err).NotTo(HaveOccurred())

				expectedTextFileMessage := fileMessageFromFile(generatedTextFile, false)
				actualTextMessage := readNextMessage(stdout)
				Expect(actualTextMessage).To(Equal(expectedTextFileMessage))

				expectedBinaryFileMessage := fileMessageFromFile(generatedBinaryFile, false)
				actualBinaryMessage := readNextMessage(stdout)
				Expect(actualBinaryMessage).To(Equal(expectedBinaryFileMessage))

				_, err = stdout.ReadByte()
				Expect(err).Should(Equal(io.EOF))

				_, err = stdin.ReadByte()
				Expect(err).Should(Equal(io.EOF))
			})

			Context("when -p (preserve times) is specified", func() {
				It("sends the timestamp information before the file", func() {
					stdin := bytes.NewBuffer([]byte{0, 0, 0, 0, 0, 0, 0})
					copier, err := scp.New(fmt.Sprintf("scp -fp %s %s", generatedTextFile, generatedBinaryFile), stdin, stdout, stderr)
					Expect(err).NotTo(HaveOccurred())

					err = copier.Copy()
					Expect(err).NotTo(HaveOccurred())

					expectedTextFileMessage := fileMessageFromFile(generatedTextFile, true)
					actualTextMessage := readNextMessage(stdout)
					Expect(actualTextMessage).To(Equal(expectedTextFileMessage))

					expectedBinaryFileMessage := fileMessageFromFile(generatedBinaryFile, true)
					actualBinaryMessage := readNextMessage(stdout)
					Expect(actualBinaryMessage).To(Equal(expectedBinaryFileMessage))

					_, err = stdout.ReadByte()
					Expect(err).Should(Equal(io.EOF))

					_, err = stdin.ReadByte()
					Expect(err).Should(Equal(io.EOF))
				})
			})
		})

		Context("when a directory is requested", func() {
			Context("when the -r (recursive) flag is not specified", func() {
				It("returns an error", func() {
					stdin := bytes.NewBuffer([]byte{0})
					copier, err := scp.New(fmt.Sprintf("scp -f %s", tempDir), stdin, stdout, stderr)
					Expect(err).NotTo(HaveOccurred())

					err = copier.Copy()
					Expect(err).To(MatchError(fmt.Sprintf("%s: not a regular file", filepath.Base(tempDir))))

					_, err = stdout.ReadByte()
					Expect(err).Should(Equal(io.EOF))

					_, err = stdin.ReadByte()
					Expect(err).Should(Equal(io.EOF))
				})
			})

			Context("when the -r (recursive) flag is specified", func() {
				It("sends the directory and all the files", func() {
					stdin := bytes.NewBuffer([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
					copier, err := scp.New(fmt.Sprintf("scp -rf %s", tempDir), stdin, stdout, stderr)
					Expect(err).NotTo(HaveOccurred())

					err = copier.Copy()
					Expect(err).NotTo(HaveOccurred())

					expectedDirectoryMessage := dirMessageFromDir(tempDir, false)
					actualMessage := readNextMessage(stdout)
					Expect(actualMessage).To(Equal(expectedDirectoryMessage))

					_, err = stdout.ReadByte()
					Expect(err).Should(Equal(io.EOF))

					_, err = stdin.ReadByte()
					Expect(err).Should(Equal(io.EOF))
				})

				Context("when the -p is specified", func() {
					It("sends timestamp information before files and directories", func() {
						stdin := bytes.NewBuffer([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
						copier, err := scp.New(fmt.Sprintf("scp -rfp %s", tempDir), stdin, stdout, stderr)
						Expect(err).NotTo(HaveOccurred())

						err = copier.Copy()
						Expect(err).NotTo(HaveOccurred())

						expectedDirectoryMessage := dirMessageFromDir(tempDir, true)
						actualMessage := readNextMessage(stdout)
						Expect(actualMessage).To(Equal(expectedDirectoryMessage))

						_, err = stdout.ReadByte()
						Expect(err).Should(Equal(io.EOF))

						_, err = stdin.ReadByte()
						Expect(err).Should(Equal(io.EOF))
					})
				})
			})
		})
	})
})

// Helper Objects

type SCPMessage interface {
}

type TimeMessage struct {
	modificationTime time.Time
	accessTime       time.Time
}

func (t *TimeMessage) messageHeader() string {
	return fmt.Sprintf("T%d 0 %d 0\n", t.modificationTime.Unix(), t.accessTime.Unix())
}

type FileMessage struct {
	timeMessage *TimeMessage

	name     string
	mode     os.FileMode
	contents []byte
}

func (f *FileMessage) messageHeader() string {
	return fmt.Sprintf("C%.4o %d %s\n", f.mode, len(f.contents), f.name)
}

func fileMessageFromFile(filename string, withTimestamps bool) *FileMessage {
	var timeMessage *TimeMessage

	file, err := os.Open(filename)
	Expect(err).NotTo(HaveOccurred())
	defer file.Close()

	fileInfo, err := file.Stat()
	Expect(err).NotTo(HaveOccurred())

	if withTimestamps {
		mtime := fileInfo.ModTime()
		stat := fileInfo.Sys().(*syscall.Stat_t)
		atime := time.Unix(int64(stat.Atimespec.Sec), int64(stat.Atimespec.Nsec))

		timeMessage = &TimeMessage{modificationTime: mtime, accessTime: atime}
	}

	contents, err := ioutil.ReadAll(file)
	Expect(err).NotTo(HaveOccurred())

	return &FileMessage{
		name:        fileInfo.Name(),
		mode:        fileInfo.Mode(),
		contents:    contents,
		timeMessage: timeMessage,
	}
}

type DirMessage struct {
	timeMessage *TimeMessage

	name     string
	mode     os.FileMode
	contents []SCPMessage
}

func (d *DirMessage) messageHeader() string {
	return fmt.Sprintf("D%.4o 0 %s\n", d.mode&07777, d.name)
}

func dirMessageFromDir(dirname string, withTimestamps bool) *DirMessage {
	var timeMessage *TimeMessage

	dir, err := os.Open(dirname)
	Expect(err).NotTo(HaveOccurred())
	defer dir.Close()

	dirInfo, err := dir.Stat()
	Expect(err).NotTo(HaveOccurred())

	if withTimestamps {
		mtime := dirInfo.ModTime()
		stat := dirInfo.Sys().(*syscall.Stat_t)
		atime := time.Unix(int64(stat.Atimespec.Sec), int64(stat.Atimespec.Nsec))

		timeMessage = &TimeMessage{modificationTime: mtime, accessTime: atime}
	}

	fileInfos, err := dir.Readdir(0)
	Expect(err).NotTo(HaveOccurred())

	contents := []SCPMessage{}
	for _, fileInfo := range fileInfos {
		file := filepath.Join(dir.Name(), fileInfo.Name())
		if fileInfo.IsDir() {
			contents = append(contents, dirMessageFromDir(file, withTimestamps))
		} else {
			contents = append(contents, fileMessageFromFile(file, withTimestamps))
		}
	}

	return &DirMessage{
		name:        dirInfo.Name(),
		mode:        dirInfo.Mode(),
		contents:    contents,
		timeMessage: timeMessage,
	}
}

// Helper Functions

func readNextMessage(buffer *bytes.Buffer) SCPMessage {
	var timeMessage *TimeMessage
	messageType, err := buffer.ReadByte()
	Expect(err).NotTo(HaveOccurred())

	if messageType == 'T' {
		timeMessage = &TimeMessage{}
		modTimeValue, err := buffer.ReadString(' ')
		Expect(err).NotTo(HaveOccurred())

		modTimeValue = strings.TrimSpace(modTimeValue)
		timeValue, err := strconv.ParseInt(modTimeValue, 10, 64)
		Expect(err).NotTo(HaveOccurred())

		timeMessage.modificationTime = time.Unix(timeValue, 0)

		_, err = buffer.ReadString(' ')
		Expect(err).NotTo(HaveOccurred())

		accessTimeValue, err := buffer.ReadString(' ')
		Expect(err).NotTo(HaveOccurred())

		accessTimeValue = strings.TrimSpace(accessTimeValue)
		timeValue, err = strconv.ParseInt(accessTimeValue, 10, 64)
		Expect(err).NotTo(HaveOccurred())

		timeMessage.accessTime = time.Unix(timeValue, 0)

		_, err = buffer.ReadString('\n')
		Expect(err).NotTo(HaveOccurred())

		messageType, err = buffer.ReadByte()
		Expect(err).NotTo(HaveOccurred())
	}

	if messageType == 'C' {
		fileMessage := &FileMessage{timeMessage: timeMessage}

		mode, err := buffer.ReadString(' ')
		Expect(err).NotTo(HaveOccurred())

		mode = strings.TrimSpace(mode)
		fm, err := strconv.ParseInt(mode, 8, 32)
		fileMessage.mode = os.FileMode(fm)

		length, err := buffer.ReadString(' ')
		Expect(err).NotTo(HaveOccurred())

		contentLength, err := strconv.Atoi(strings.TrimSpace(length))

		fileName, err := buffer.ReadString('\n')
		Expect(err).NotTo(HaveOccurred())

		fileMessage.name = strings.TrimSpace(fileName)

		content := make([]byte, contentLength)

		bytesRead, err := buffer.Read(content)
		Expect(err).NotTo(HaveOccurred())
		Expect(bytesRead).To(Equal(contentLength))

		fileMessage.contents = content

		return fileMessage
	} else if messageType == 'D' {
		dirMessage := &DirMessage{timeMessage: timeMessage}
		mode, err := buffer.ReadString(' ')
		Expect(err).NotTo(HaveOccurred())

		mode = strings.TrimSpace(mode)
		dm, err := strconv.ParseInt(mode, 8, 32)
		dirMessage.mode = os.ModeDir | os.FileMode(dm)

		_, err = buffer.ReadString(' ')
		Expect(err).NotTo(HaveOccurred())

		dirName, err := buffer.ReadString('\n')
		Expect(err).NotTo(HaveOccurred())

		dirMessage.name = strings.TrimSpace(dirName)

		messageType, err = buffer.ReadByte()
		Expect(err).NotTo(HaveOccurred())

		dirMessage.contents = []SCPMessage{}

		for messageType != 'E' {
			err = buffer.UnreadByte()
			Expect(err).NotTo(HaveOccurred())

			message := readNextMessage(buffer)
			dirMessage.contents = append(dirMessage.contents, message)

			messageType, err = buffer.ReadByte()
			Expect(err).NotTo(HaveOccurred())
		}

		_, err = buffer.ReadString('\n')
		Expect(err).NotTo(HaveOccurred())

		return dirMessage
	} else {
		return nil
	}
}

func readLine(receivedMessages chan<- []byte, reader *bufio.Reader) {
	message, err := reader.ReadBytes('\n')
	Expect(err).NotTo(HaveOccurred())
	if receivedMessages != nil {
		receivedMessages <- message
	}
}

func readBytes(receivedMessages chan<- []byte, reader *bufio.Reader, length int) {
	message := make([]byte, length)
	n, err := reader.Read(message)
	Expect(err).NotTo(HaveOccurred())
	Expect(n).To(Equal(len(message)))
	if receivedMessages != nil {
		receivedMessages <- message
	}
}
