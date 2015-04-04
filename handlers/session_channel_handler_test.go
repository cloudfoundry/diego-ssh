package handlers_test

import (
	"errors"
	"io"
	"io/ioutil"
	"os/exec"
	"strings"

	"github.com/cloudfoundry-incubator/diego-ssh/daemon"
	"github.com/cloudfoundry-incubator/diego-ssh/handlers"
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

		sessionChannelHandler *handlers.SessionChannelHandler

		newChannelHandlers map[string]handlers.NewChannelHandler
	)

	BeforeEach(func() {
		logger = lagertest.NewTestLogger("test")
		serverSSHConfig = &ssh.ServerConfig{
			NoClientAuth: true,
		}
		serverSSHConfig.AddHostKey(TestHostKey)

		sessionChannelHandler = &handlers.SessionChannelHandler{}
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

			err = session.Run("echo -n Hello; echo -n Goodbye >&2")
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
					result, err := session.Output("echo -n 'still kicking'")
					Ω(err).ShouldNot(HaveOccurred())
					Ω(string(result)).Should(Equal("still kicking"))
				})
			})

			Context("while a command is running", func() {
				var stdin io.WriteCloser

				BeforeEach(func() {
					var err error
					stdin, err = session.StdinPipe()
					Ω(err).ShouldNot(HaveOccurred())

					err = session.Start("cat")
					Ω(err).ShouldNot(HaveOccurred())
				})

				AfterEach(func() {
					stdin.Close()
				})

				It("delivers the signal to the process", func() {
					err := session.Signal(ssh.SIGTERM)
					Ω(err).ShouldNot(HaveOccurred())

					err = test_helpers.WaitFor(func() error {
						return session.Wait()
					})
					Ω(err).Should(HaveOccurred())

					exitErr, ok := err.(*ssh.ExitError)
					Ω(ok).Should(BeTrue())
					Ω(exitErr.Signal()).Should(Equal(string(ssh.SIGTERM)))
				})
			})
		})

		Context("when environment variables are requested", func() {
			Context("before starting the command", func() {
				BeforeEach(func() {
					err := session.Setenv("ENV1", "value1")
					Ω(err).ShouldNot(HaveOccurred())

					err = session.Setenv("ENV2", "value2")
					Ω(err).ShouldNot(HaveOccurred())
				})

				It("runs the command in the specified environment", func() {
					result, err := session.Output("/usr/bin/env")
					Ω(err).ShouldNot(HaveOccurred())

					Ω(result).Should(ContainSubstring("ENV1=value1"))
					Ω(result).Should(ContainSubstring("ENV2=value2"))
				})
			})

			Context("after starting the command", func() {
				BeforeEach(func() {
					_, err := session.Output("/usr/bin/env")
					Ω(err).ShouldNot(HaveOccurred())
				})

				It("rejects the request", func() {
					err := session.Setenv("ENV3", "value3")
					Ω(err).Should(HaveOccurred())
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
			var startCallCount int
			var runCommand *exec.Cmd

			BeforeEach(func() {
				sessionChannelHandler.Starter = func(command *exec.Cmd) error {
					startCallCount++
					runCommand = command
					return command.Start()
				}

				err := session.Run("true")
				Ω(err).ShouldNot(HaveOccurred())
			})

			It("uses the provided starter to start the command", func() {
				Ω(startCallCount).Should(Equal(1))
			})

			It("passes the correct command to the starter", func() {
				Ω(runCommand.Path).Should(Equal("/bin/bash"))
				Ω(runCommand.Args).Should(ConsistOf("/bin/bash", "-c", "true"))
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
					sessionChannelHandler.Starter = func(command *exec.Cmd) error {
						return errors.New("oops")
					}
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
				response, err := session.Output("echo -n Hello")
				Ω(err).ShouldNot(HaveOccurred())
				Ω(response).Should(Equal([]byte("Hello")))
			})
		})
	})

	Context("when a session channel is opened", func() {
		var (
			channel  ssh.Channel
			requests <-chan *ssh.Request
		)

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
