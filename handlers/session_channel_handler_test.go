package handlers_test

import (
	"errors"
	"io/ioutil"
	"os/exec"

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

		It("can use the session to execute a command and preserve its exit code", func() {
			err := session.Run("false")
			Ω(err).Should(HaveOccurred())

			exitErr, ok := err.(*ssh.ExitError)
			Ω(ok).Should(BeTrue())
			Ω(exitErr.ExitStatus()).Should(Equal(1))
		})

		Context("and environment variables are requested", func() {
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

			Context("and the request fails to unmarshal", func() {
				It("rejects the request", func() {
					accepted, err := session.SendRequest("env", true, ssh.Marshal(struct{ Bogus int }{Bogus: 1234}))
					Ω(err).ShouldNot(HaveOccurred())
					Ω(accepted).Should(BeFalse())
				})
			})
		})

		Context("and a RunnerFunc is provided", func() {
			var runCallCount int
			var runCommand *exec.Cmd

			BeforeEach(func() {
				sessionChannelHandler.Runner = func(command *exec.Cmd) error {
					runCallCount++
					runCommand = command
					return command.Run()
				}

				err := session.Run("true")
				Ω(err).ShouldNot(HaveOccurred())
			})

			It("uses the provided runner to run the command", func() {
				Ω(runCallCount).Should(Equal(1))
			})

			It("passes the correct command to the runner", func() {
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

			Context("when executing the command fails", func() {
				BeforeEach(func() {
					sessionChannelHandler.Runner = func(command *exec.Cmd) error {
						return errors.New("oops")
					}
				})

				It("returns an exit status message with a 255 status", func() {
					err := session.Run("true")
					Ω(err).Should(HaveOccurred())

					exitErr, ok := err.(*ssh.ExitError)
					Ω(ok).Should(BeTrue())
					Ω(exitErr.ExitStatus()).ShouldNot(Equal(0))
				})
			})
		})

		Context("and an unknown request type is sent", func() {
			var (
				accepted   bool
				requestErr error
			)

			BeforeEach(func() {
				accepted, requestErr = session.SendRequest("unknown-request-type", true, []byte("payload"))
			})

			It("rejects the request", func() {
				Ω(requestErr).ShouldNot(HaveOccurred())
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
		})

		AfterEach(func() {
			if channel != nil {
				channel.Close()
			}
		})

		Context("and an exec request is sent with a malformed payload", func() {
			BeforeEach(func() {
				accepted, requestErr := channel.SendRequest("exec", true, ssh.Marshal(struct{ Bogus uint32 }{Bogus: 1138}))
				Ω(requestErr).ShouldNot(HaveOccurred())
				Ω(accepted).Should(BeTrue())
			})

			It("returns an exit status message with a 255 status", func() {
				var req *ssh.Request
				Eventually(requests).Should(Receive(&req))

				type exitStatusMsg struct {
					Status uint32
				}
				var exitMessage exitStatusMsg
				err := ssh.Unmarshal(req.Payload, &exitMessage)
				Ω(err).ShouldNot(HaveOccurred())

				Ω(exitMessage.Status).Should(Equal(uint32(255)))
			})
		})

		Context("and an env request is sent with a malformed payload", func() {
		})
	})
})
