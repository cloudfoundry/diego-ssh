package handlers_test

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"runtime"
	"strings"

	"github.com/cloudfoundry-incubator/diego-ssh/daemon"
	"github.com/cloudfoundry-incubator/diego-ssh/handlers"
	"github.com/cloudfoundry-incubator/diego-ssh/handlers/fakes"
	"github.com/cloudfoundry-incubator/diego-ssh/test_helpers"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/pivotal-golang/lager/lagertest"
	"golang.org/x/crypto/ssh"
)

var _ = Describe("SessionChannelHandler", func() {
	var (
		sshd   *daemon.Daemon
		client *ssh.Client

		logger          *lagertest.TestLogger
		serverSSHConfig *ssh.ServerConfig

		runner                *fakes.FakeRunner
		shellLocator          *fakes.FakeShellLocator
		sessionChannelHandler *handlers.SessionChannelHandler

		newChannelHandlers map[string]handlers.NewChannelHandler
	)

	BeforeEach(func() {
		logger = lagertest.NewTestLogger("test")
		serverSSHConfig = &ssh.ServerConfig{
			NoClientAuth: true,
		}
		serverSSHConfig.AddHostKey(TestHostKey)

		runner = &fakes.FakeRunner{}
		realRunner := handlers.NewCommandRunner()
		runner.StartStub = realRunner.Start
		runner.WaitStub = realRunner.Wait

		shellLocator = &fakes.FakeShellLocator{}
		shellLocator.ShellPathReturns("/bin/sh")

		sessionChannelHandler = handlers.NewSessionChannelHandler(runner, shellLocator)

		newChannelHandlers = map[string]handlers.NewChannelHandler{
			"session": sessionChannelHandler,
		}

		serverNetConn, clientNetConn := test_helpers.Pipe()

		sshd = daemon.New(logger, serverSSHConfig, nil, newChannelHandlers)
		go sshd.HandleConnection(serverNetConn)

		client = test_helpers.NewClient(clientNetConn, nil)
	})

	AfterEach(func() {
		client.Close()
	})

	Context("when a session is opened", func() {
		var session *ssh.Session

		BeforeEach(func() {
			var sessionErr error
			session, sessionErr = client.NewSession()

			Ω(sessionErr).ShouldNot(HaveOccurred())
		})

		AfterEach(func() {
			session.Close()
		})

		It("can use the session to execute a command with stdout and stderr", func() {
			stdout, err := session.StdoutPipe()
			Ω(err).ShouldNot(HaveOccurred())

			stderr, err := session.StderrPipe()
			Ω(err).ShouldNot(HaveOccurred())

			err = session.Run("/bin/echo -n Hello; /bin/echo -n Goodbye >&2")
			Ω(err).ShouldNot(HaveOccurred())

			stdoutBytes, err := ioutil.ReadAll(stdout)
			Ω(err).ShouldNot(HaveOccurred())
			Ω(stdoutBytes).Should(Equal([]byte("Hello")))

			stderrBytes, err := ioutil.ReadAll(stderr)
			Ω(err).ShouldNot(HaveOccurred())
			Ω(stderrBytes).Should(Equal([]byte("Goodbye")))
		})

		Describe("the shell locator", func() {
			BeforeEach(func() {
				err := session.Run("true")
				Ω(err).ShouldNot(HaveOccurred())
			})

			It("uses the shell locator to find the default shell path", func() {
				Ω(shellLocator.ShellPathCallCount()).Should(Equal(1))

				cmd := runner.StartArgsForCall(0)
				Ω(cmd.Path).Should(Equal("/bin/sh"))
			})
		})

		Context("when stdin is provided by the client", func() {
			BeforeEach(func() {
				session.Stdin = strings.NewReader("Hello")
			})

			It("can use the session to execute a command that reads it", func() {
				result, err := session.Output("cat")
				Ω(err).ShouldNot(HaveOccurred())
				Ω(string(result)).Should(Equal("Hello"))
			})
		})

		Context("when the command exits with a non-zero value", func() {
			It("it preserve the exit code", func() {
				err := session.Run("exit 3")
				Ω(err).Should(HaveOccurred())

				exitErr, ok := err.(*ssh.ExitError)
				Ω(ok).Should(BeTrue())
				Ω(exitErr.ExitStatus()).Should(Equal(3))
			})
		})

		Context("when a signal is sent across the session", func() {
			Context("before a command has been run", func() {
				BeforeEach(func() {
					err := session.Signal(ssh.SIGTERM)
					Ω(err).ShouldNot(HaveOccurred())
				})

				It("does not prevent the command from running", func() {
					result, err := session.Output("/bin/echo -n 'still kicking'")
					Ω(err).ShouldNot(HaveOccurred())
					Ω(string(result)).Should(Equal("still kicking"))
				})
			})

			Context("while a command is running", func() {
				var stdin io.WriteCloser
				var stdout io.Reader

				BeforeEach(func() {
					var err error
					stdin, err = session.StdinPipe()
					Ω(err).ShouldNot(HaveOccurred())

					stdout, err = session.StdoutPipe()
					Ω(err).ShouldNot(HaveOccurred())

					err = session.Start("trap 'echo Caught SIGUSR1' USR1; echo trapped; cat")
					Ω(err).ShouldNot(HaveOccurred())

					reader := bufio.NewReader(stdout)
					Eventually(reader.ReadLine).Should(ContainSubstring("trapped"))
				})

				It("delivers the signal to the process", func() {
					err := session.Signal(ssh.SIGUSR1)
					Ω(err).ShouldNot(HaveOccurred())

					err = stdin.Close()
					Ω(err).ShouldNot(HaveOccurred())

					err = session.Wait()
					Ω(err).ShouldNot(HaveOccurred())

					stdoutBytes, err := ioutil.ReadAll(stdout)
					Ω(err).ShouldNot(HaveOccurred())
					Ω(stdoutBytes).Should(ContainSubstring("Caught SIGUSR1"))
				})

				It("exits with an exit-signal response", func() {
					err := session.Signal(ssh.SIGUSR2)
					Ω(err).ShouldNot(HaveOccurred())

					err = stdin.Close()
					Ω(err).ShouldNot(HaveOccurred())

					err = session.Wait()
					Ω(err).Should(HaveOccurred())

					exitErr, ok := err.(*ssh.ExitError)
					Ω(ok).Should(BeTrue())
					Ω(exitErr.Signal()).Should(Equal("USR2"))
				})
			})
		})

		Context("when running a command without an explitict environemnt", func() {
			It("does not inherit daemon's environment", func() {
				os.Setenv("DAEMON_ENV", "daemon_env_value")

				result, err := session.Output("/usr/bin/env")
				Ω(err).ShouldNot(HaveOccurred())

				Ω(result).ShouldNot(ContainSubstring("DAEMON_ENV=daemon_env_value"))
			})

			It("includes a default environment", func() {
				result, err := session.Output("/usr/bin/env")
				Ω(err).ShouldNot(HaveOccurred())

				Ω(result).Should(ContainSubstring(fmt.Sprintf("PATH=/bin:/usr/bin")))
				Ω(result).Should(ContainSubstring(fmt.Sprintf("LANG=en_US.UTF8")))
				Ω(result).Should(ContainSubstring(fmt.Sprintf("HOME=%s", os.Getenv("HOME"))))
				Ω(result).Should(ContainSubstring(fmt.Sprintf("USER=%s", os.Getenv("USER"))))
			})
		})

		Context("when environment variables are requested", func() {
			Context("before starting the command", func() {
				It("runs the command with the specified environment", func() {
					err := session.Setenv("ENV1", "value1")
					Ω(err).ShouldNot(HaveOccurred())

					err = session.Setenv("ENV2", "value2")
					Ω(err).ShouldNot(HaveOccurred())

					result, err := session.Output("/usr/bin/env")
					Ω(err).ShouldNot(HaveOccurred())

					Ω(result).Should(ContainSubstring("ENV1=value1"))
					Ω(result).Should(ContainSubstring("ENV2=value2"))
				})

				It("uses the value last specified", func() {
					err := session.Setenv("ENV1", "original")
					Ω(err).ShouldNot(HaveOccurred())

					err = session.Setenv("ENV1", "updated")
					Ω(err).ShouldNot(HaveOccurred())

					result, err := session.Output("/usr/bin/env")
					Ω(err).ShouldNot(HaveOccurred())

					Ω(result).Should(ContainSubstring("ENV1=updated"))
				})

				It("can override PATH and LANG", func() {
					err := session.Setenv("PATH", "/bin:/usr/local/bin:/sbin")
					Ω(err).ShouldNot(HaveOccurred())

					err = session.Setenv("LANG", "en_UK.UTF8")
					Ω(err).ShouldNot(HaveOccurred())

					result, err := session.Output("/usr/bin/env")
					Ω(err).ShouldNot(HaveOccurred())

					Ω(result).Should(ContainSubstring("PATH=/bin:/usr/local/bin:/sbin"))
					Ω(result).Should(ContainSubstring("LANG=en_UK.UTF8"))
				})

				It("cannot override HOME and USER", func() {
					err := session.Setenv("HOME", "/some/other/home")
					Ω(err).ShouldNot(HaveOccurred())

					err = session.Setenv("USER", "not-a-user")
					Ω(err).ShouldNot(HaveOccurred())

					result, err := session.Output("/usr/bin/env")
					Ω(err).ShouldNot(HaveOccurred())

					Ω(result).Should(ContainSubstring(fmt.Sprintf("HOME=%s", os.Getenv("HOME"))))
					Ω(result).Should(ContainSubstring(fmt.Sprintf("USER=%s", os.Getenv("USER"))))
				})
			})

			Context("after starting the command", func() {
				var stdin io.WriteCloser
				var stdout io.Reader

				BeforeEach(func() {
					var err error
					stdin, err = session.StdinPipe()
					Ω(err).ShouldNot(HaveOccurred())

					stdout, err = session.StdoutPipe()
					Ω(err).ShouldNot(HaveOccurred())

					err = session.Start("cat && /usr/bin/env")
					Ω(err).ShouldNot(HaveOccurred())
				})

				It("ignores the request", func() {
					err := session.Setenv("ENV3", "value3")
					Ω(err).ShouldNot(HaveOccurred())

					stdin.Close()

					err = session.Wait()
					Ω(err).ShouldNot(HaveOccurred())

					stdoutBytes, err := ioutil.ReadAll(stdout)
					Ω(err).ShouldNot(HaveOccurred())

					Ω(stdoutBytes).ShouldNot(ContainSubstring("ENV3"))
				})
			})
		})

		Context("when a pty request is received", func() {
			var terminalModes ssh.TerminalModes

			BeforeEach(func() {
				terminalModes = ssh.TerminalModes{}
			})

			JustBeforeEach(func() {
				err := session.RequestPty("vt100", 43, 80, terminalModes)
				Ω(err).ShouldNot(HaveOccurred())
			})

			It("should allocate a tty for the session", func() {
				result, err := session.Output("tty")
				Ω(err).ShouldNot(HaveOccurred())

				Ω(result).ShouldNot(ContainSubstring("not a tty"))
			})

			It("should set the terminal type", func() {
				result, err := session.Output(`/bin/echo -n "$TERM"`)
				Ω(err).ShouldNot(HaveOccurred())

				Ω(string(result)).Should(Equal("vt100"))
			})

			It("sets the correct window size for the terminal", func() {
				result, err := session.Output("stty size")
				Ω(err).ShouldNot(HaveOccurred())

				Ω(result).Should(ContainSubstring("43 80"))
			})

			Context("when control character mappings are specified in TerminalModes", func() {
				BeforeEach(func() {
					// Swap CTRL-Z (suspend) with CTRL-D (eof)
					terminalModes[ssh.VEOF] = 26
					terminalModes[ssh.VSUSP] = 4
				})

				It("honors the control character changes", func() {
					result, err := session.Output("stty -a")
					Ω(err).ShouldNot(HaveOccurred())

					Ω(string(result)).Should(ContainSubstring("susp = ^D"))
					Ω(string(result)).Should(ContainSubstring("eof = ^Z"))
				})
			})

			Context("when input modes are specified in TerminalModes", func() {
				BeforeEach(func() {
					terminalModes[ssh.IGNPAR] = 1
					terminalModes[ssh.IXON] = 0
					terminalModes[ssh.IXANY] = 0
				})

				It("honors the input mode changes", func() {
					result, err := session.Output("stty -a")
					Ω(err).ShouldNot(HaveOccurred())

					Ω(string(result)).Should(ContainSubstring(" ignpar"))
					Ω(string(result)).Should(ContainSubstring(" -ixon"))
					Ω(string(result)).Should(ContainSubstring(" -ixany"))
				})
			})

			// Looks like there are some issues with terminal attributes on Linux.
			// These need further investigation there.
			if runtime.GOOS == "darwin" {
				Context("when local modes are specified in TerminalModes", func() {
					BeforeEach(func() {
						terminalModes[ssh.IEXTEN] = 0
						terminalModes[ssh.ECHOCTL] = 1
					})

					It("honors the local mode changes", func() {
						result, err := session.Output("stty -a")
						Ω(err).ShouldNot(HaveOccurred())

						Ω(string(result)).Should(ContainSubstring(" -iexten"))
						Ω(string(result)).Should(ContainSubstring(" echoctl"))
					})
				})

				Context("when output modes are specified in TerminalModes", func() {
					BeforeEach(func() {
						terminalModes[ssh.ONLCR] = 0
						terminalModes[ssh.ONLRET] = 1
					})

					It("honors the output mode changes", func() {
						result, err := session.Output("stty -a")
						Ω(err).ShouldNot(HaveOccurred())

						Ω(string(result)).Should(ContainSubstring(" -onlcr"))
						Ω(string(result)).Should(ContainSubstring(" -onlret"))
					})
				})

				Context("when control character modes are specified in TerminalModes", func() {
					BeforeEach(func() {
						// Set to E71
						terminalModes[ssh.PARODD] = 0
						terminalModes[ssh.CS7] = 1
						terminalModes[ssh.PARENB] = 1
					})

					It("honors the control mode changes", func() {
						result, err := session.Output("stty -a")
						Ω(err).ShouldNot(HaveOccurred())

						Ω(string(result)).Should(ContainSubstring(" -parodd"))
						Ω(string(result)).Should(ContainSubstring(" cs7"))
						Ω(string(result)).Should(ContainSubstring(" parenb"))
					})
				})
			}

			Context("when an interactive command is executed", func() {
				var stdin io.WriteCloser

				JustBeforeEach(func() {
					var err error
					stdin, err = session.StdinPipe()
					Ω(err).ShouldNot(HaveOccurred())
				})

				It("terminates the session when the shell exits", func() {
					err := session.Start("/bin/sh")
					Ω(err).ShouldNot(HaveOccurred())

					_, err = stdin.Write([]byte("exit\n"))
					Ω(err).ShouldNot(HaveOccurred())

					err = session.Wait()
					Ω(err).ShouldNot(HaveOccurred())
				})
			})
		})

		Context("when a window change request is received", func() {
			type winChangeMsg struct {
				Columns  uint32
				Rows     uint32
				WidthPx  uint32
				HeightPx uint32
			}

			var result []byte

			Context("before a pty is allocated", func() {
				BeforeEach(func() {
					_, err := session.SendRequest("window-change", false, ssh.Marshal(winChangeMsg{
						Rows:    50,
						Columns: 132,
					}))
					Ω(err).ShouldNot(HaveOccurred())

					err = session.RequestPty("vt100", 43, 80, ssh.TerminalModes{})
					Ω(err).ShouldNot(HaveOccurred())

					result, err = session.Output("stty size")
					Ω(err).ShouldNot(HaveOccurred())
				})

				It("ignores the request", func() {
					Ω(result).Should(ContainSubstring("43 80"))
				})
			})

			Context("after a pty is allocated", func() {
				BeforeEach(func() {
					err := session.RequestPty("vt100", 43, 80, ssh.TerminalModes{})
					Ω(err).ShouldNot(HaveOccurred())

					_, err = session.SendRequest("window-change", false, ssh.Marshal(winChangeMsg{
						Rows:    50,
						Columns: 132,
					}))
					Ω(err).ShouldNot(HaveOccurred())

					result, err = session.Output("stty size")
					Ω(err).ShouldNot(HaveOccurred())
				})

				It("changes the the size of the terminal", func() {
					Ω(result).Should(ContainSubstring("50 132"))
				})
			})
		})

		Context("after executing a command", func() {
			BeforeEach(func() {
				err := session.Run("true")
				Ω(err).ShouldNot(HaveOccurred())
			})

			It("the session is no longer usable", func() {
				_, err := session.SendRequest("exec", true, ssh.Marshal(struct{ Command string }{Command: "true"}))
				Ω(err).Should(HaveOccurred())

				_, err = session.SendRequest("bogus", true, nil)
				Ω(err).Should(HaveOccurred())

				err = session.Setenv("foo", "bar")
				Ω(err).Should(HaveOccurred())
			})
		})

		Context("when an interactive shell is requested", func() {
			var stdin io.WriteCloser

			BeforeEach(func() {
				var err error
				stdin, err = session.StdinPipe()
				Ω(err).ShouldNot(HaveOccurred())

				err = session.Shell()
				Ω(err).ShouldNot(HaveOccurred())
			})

			AfterEach(func() {
				session.Close()
			})

			It("starts the shell with the runner", func() {
				Eventually(runner.StartCallCount).Should(Equal(1))

				command := runner.StartArgsForCall(0)
				Ω(command.Path).Should(Equal("/bin/sh"))
				Ω(command.Args).Should(ConsistOf("/bin/sh"))
			})

			It("terminates the session when the shell exits", func() {
				_, err := stdin.Write([]byte("exit\n"))
				Ω(err).ShouldNot(HaveOccurred())

				err = session.Wait()
				Ω(err).ShouldNot(HaveOccurred())
			})
		})

		Context("and a StarterFunc is provided", func() {
			BeforeEach(func() {
				err := session.Run("true")
				Ω(err).ShouldNot(HaveOccurred())
			})

			It("uses the provided runner to start the command", func() {
				Ω(runner.StartCallCount()).Should(Equal(1))
				Ω(runner.WaitCallCount()).Should(Equal(1))
			})

			It("passes the correct command to the runner", func() {
				command := runner.StartArgsForCall(0)
				Ω(command.Path).Should(Equal("/bin/sh"))
				Ω(command.Args).Should(ConsistOf("/bin/sh", "-c", "true"))
			})

			It("passes the same command to Start and Wait", func() {
				command := runner.StartArgsForCall(0)
				Ω(runner.WaitArgsForCall(0)).Should(Equal(command))
			})
		})

		Context("when executing an invalid command", func() {
			It("returns an exit error with a non-zero exit status", func() {
				err := session.Run("not-a-command")
				Ω(err).Should(HaveOccurred())

				exitErr, ok := err.(*ssh.ExitError)
				Ω(ok).Should(BeTrue())
				Ω(exitErr.ExitStatus()).ShouldNot(Equal(0))
			})

			Context("when starting the command fails", func() {
				BeforeEach(func() {
					runner.StartReturns(errors.New("oops"))
				})

				It("returns an exit status message with a non-zero status", func() {
					err := session.Run("true")
					Ω(err).Should(HaveOccurred())

					exitErr, ok := err.(*ssh.ExitError)
					Ω(ok).Should(BeTrue())
					Ω(exitErr.ExitStatus()).ShouldNot(Equal(0))
				})
			})

			Context("when waiting on the command fails", func() {
				BeforeEach(func() {
					runner.WaitReturns(errors.New("oops"))
				})

				It("returns an exit status message with a non-zero status", func() {
					err := session.Run("true")
					Ω(err).Should(HaveOccurred())

					exitErr, ok := err.(*ssh.ExitError)
					Ω(ok).Should(BeTrue())
					Ω(exitErr.ExitStatus()).ShouldNot(Equal(0))
				})
			})
		})

		Context("when an unknown request type is sent", func() {
			var accepted bool

			BeforeEach(func() {
				var err error
				accepted, err = session.SendRequest("unknown-request-type", true, []byte("payload"))
				Ω(err).ShouldNot(HaveOccurred())
			})

			It("rejects the request", func() {
				Ω(accepted).Should(BeFalse())
			})

			It("does not terminate the session", func() {
				response, err := session.Output("/bin/echo -n Hello")
				Ω(err).ShouldNot(HaveOccurred())
				Ω(response).Should(Equal([]byte("Hello")))
			})
		})
	})

	Context("when a session channel is opened", func() {
		var channel ssh.Channel
		var requests <-chan *ssh.Request

		BeforeEach(func() {
			var err error
			channel, requests, err = client.OpenChannel("session", nil)
			Ω(err).ShouldNot(HaveOccurred())

			go ssh.DiscardRequests(requests)
		})

		AfterEach(func() {
			if channel != nil {
				channel.Close()
			}
		})

		Context("and an exec request fails to unmarshal", func() {
			It("rejects the request", func() {
				accepted, err := channel.SendRequest("exec", true, ssh.Marshal(struct{ Bogus uint32 }{Bogus: 1138}))
				Ω(err).ShouldNot(HaveOccurred())
				Ω(accepted).Should(BeFalse())
			})
		})

		Context("and an env request fails to unmarshal", func() {
			It("rejects the request", func() {
				accepted, err := channel.SendRequest("env", true, ssh.Marshal(struct{ Bogus int }{Bogus: 1234}))
				Ω(err).ShouldNot(HaveOccurred())
				Ω(accepted).Should(BeFalse())
			})
		})

		Context("and a signal request fails to unmarshal", func() {
			It("rejects the request", func() {
				accepted, err := channel.SendRequest("signal", true, ssh.Marshal(struct{ Bogus int }{Bogus: 1234}))
				Ω(err).ShouldNot(HaveOccurred())
				Ω(accepted).Should(BeFalse())
			})
		})

		Context("and a pty request fails to unmarshal", func() {
			It("rejects the request", func() {
				accepted, err := channel.SendRequest("pty-req", true, ssh.Marshal(struct{ Bogus int }{Bogus: 1234}))
				Ω(err).ShouldNot(HaveOccurred())
				Ω(accepted).Should(BeFalse())
			})
		})

		Context("and a window change request fails to unmarshal", func() {
			It("rejects the request", func() {
				accepted, err := channel.SendRequest("window-change", true, ssh.Marshal(struct{ Bogus int }{Bogus: 1234}))
				Ω(err).ShouldNot(HaveOccurred())
				Ω(accepted).Should(BeFalse())
			})
		})
	})
})
