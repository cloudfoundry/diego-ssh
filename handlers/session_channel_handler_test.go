package handlers_test

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
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

		sessionChannelHandler = handlers.NewSessionChannelHandler(runner)

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

					err = session.Start("trap 'echo Caught SIGUSR1' USR1; cat")
					Ω(err).ShouldNot(HaveOccurred())
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

			Context("and the request fails to unmarshal", func() {
				It("rejects the request", func() {
					accepted, err := session.SendRequest("env", true, ssh.Marshal(struct{ Bogus int }{Bogus: 1234}))
					Ω(err).ShouldNot(HaveOccurred())
					Ω(accepted).Should(BeFalse())
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

		Context("and an exec request is sent with a malformed payload", func() {
			It("rejects the request", func() {
				accepted, err := channel.SendRequest("exec", true, ssh.Marshal(struct{ Bogus uint32 }{Bogus: 1138}))
				Ω(err).ShouldNot(HaveOccurred())
				Ω(accepted).Should(BeFalse())
			})
		})
	})
})
