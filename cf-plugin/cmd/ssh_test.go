package cmd_test

import (
	"errors"
	"io"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/cloudfoundry-incubator/diego-ssh/cf-plugin/cmd"
	"github.com/cloudfoundry-incubator/diego-ssh/cf-plugin/cmd/fakes"
	"github.com/cloudfoundry-incubator/diego-ssh/cf-plugin/models/app"
	"github.com/cloudfoundry-incubator/diego-ssh/cf-plugin/models/app/app_fakes"
	"github.com/cloudfoundry-incubator/diego-ssh/cf-plugin/models/credential"
	"github.com/cloudfoundry-incubator/diego-ssh/cf-plugin/models/credential/credential_fakes"
	"github.com/cloudfoundry-incubator/diego-ssh/cf-plugin/models/info"
	"github.com/cloudfoundry-incubator/diego-ssh/cf-plugin/models/info/info_fakes"
	"github.com/cloudfoundry-incubator/diego-ssh/cf-plugin/options"
	"github.com/cloudfoundry-incubator/diego-ssh/cf-plugin/terminal"
	"github.com/cloudfoundry-incubator/diego-ssh/cf-plugin/terminal/terminal_helper_fakes"
	"github.com/cloudfoundry-incubator/diego-ssh/test_helpers/fake_io"
	"github.com/cloudfoundry-incubator/diego-ssh/test_helpers/fake_ssh"
	"github.com/docker/docker/pkg/term"
	"github.com/kr/pty"
	"golang.org/x/crypto/ssh"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Diego SSH Plugin", func() {
	var (
		fakeTerminalHelper *terminal_helper_fakes.FakeTerminalHelper
		fakeAppFactory     *app_fakes.FakeAppFactory
		fakeInfoFactory    *info_fakes.FakeInfoFactory
		fakeCredFactory    *credential_fakes.FakeCredentialFactory

		fakeConnection    *fake_ssh.FakeConn
		fakeSecureClient  *fakes.FakeSecureClient
		fakeSecureDialer  *fakes.FakeSecureDialer
		fakeSecureSession *fakes.FakeSecureSession

		terminalHelper    terminal.TerminalHelper
		keepAliveDuration time.Duration
		secureShell       cmd.SecureShell
	)

	BeforeEach(func() {
		fakeTerminalHelper = &terminal_helper_fakes.FakeTerminalHelper{}
		terminalHelper = terminal.DefaultHelper()

		keepAliveDuration = 30 * time.Second

		fakeAppFactory = &app_fakes.FakeAppFactory{}
		fakeInfoFactory = &info_fakes.FakeInfoFactory{}
		fakeCredFactory = &credential_fakes.FakeCredentialFactory{}

		fakeConnection = &fake_ssh.FakeConn{}
		fakeSecureClient = &fakes.FakeSecureClient{}
		fakeSecureDialer = &fakes.FakeSecureDialer{}
		fakeSecureSession = &fakes.FakeSecureSession{}

		fakeSecureDialer.DialReturns(fakeConnection, fakeSecureClient, nil)
		fakeSecureClient.NewSessionReturns(fakeSecureSession, nil)

		stdinPipe := &fake_io.FakeWriteCloser{}
		stdinPipe.WriteStub = func(p []byte) (int, error) {
			return len(p), nil
		}

		stdoutPipe := &fake_io.FakeReader{}
		stdoutPipe.ReadStub = func(p []byte) (int, error) {
			return 0, io.EOF
		}

		stderrPipe := &fake_io.FakeReader{}
		stderrPipe.ReadStub = func(p []byte) (int, error) {
			return 0, io.EOF
		}

		fakeSecureSession.StdinPipeReturns(stdinPipe, nil)
		fakeSecureSession.StdoutPipeReturns(stdoutPipe, nil)
		fakeSecureSession.StderrPipeReturns(stderrPipe, nil)
	})

	JustBeforeEach(func() {
		secureShell = cmd.NewSecureShell(
			fakeSecureDialer,
			terminalHelper,
			keepAliveDuration,
			fakeAppFactory,
			fakeInfoFactory,
			fakeCredFactory,
		)
	})

	Describe("Validation", func() {
		var sshError error
		var opts *options.SSHOptions

		BeforeEach(func() {
			opts = &options.SSHOptions{
				AppName: "app-1",
			}
		})

		JustBeforeEach(func() {
			sshError = secureShell.InteractiveSession(opts)
		})

		Context("when there is an error getting the app model", func() {
			BeforeEach(func() {
				fakeAppFactory.GetReturns(app.App{}, errors.New("woops"))
			})

			It("returns the error", func() {
				Expect(fakeAppFactory.GetCallCount()).To(Equal(1))
				Expect(sshError).To(Equal(errors.New("woops")))
			})

			It("does not attempt to acquire endpoint info", func() {
				Expect(fakeInfoFactory.GetCallCount()).To(Equal(0))
			})
		})

		Context("when the app model is successfully acquired", func() {
			BeforeEach(func() {
				fakeAppFactory.GetReturns(app.App{}, nil)
				fakeInfoFactory.GetReturns(info.Info{}, nil)
			})

			It("gets the ssh endpoint information", func() {
				Expect(fakeInfoFactory.GetCallCount()).To(Equal(1))
			})

			Context("when getting the endpoint info fails", func() {
				BeforeEach(func() {
					fakeInfoFactory.GetReturns(info.Info{}, errors.New("woops"))
				})

				It("returns the error", func() {
					Expect(fakeAppFactory.GetCallCount()).To(Equal(1))
					Expect(sshError).To(Equal(errors.New("woops")))
				})
			})
		})

		Context("when the app model and endpoint info are successfully acquired", func() {
			BeforeEach(func() {
				fakeAppFactory.GetReturns(app.App{}, nil)
				fakeInfoFactory.GetReturns(info.Info{}, nil)
				fakeCredFactory.GetReturns(credential.Credential{}, nil)
			})

			It("gets the current oauth token credential", func() {
				Expect(fakeCredFactory.GetCallCount()).To(Equal(1))
			})

			Context("when getting the credential fails", func() {
				BeforeEach(func() {
					fakeCredFactory.GetReturns(credential.Credential{}, errors.New("woops"))
				})

				It("returns the error", func() {
					Expect(fakeCredFactory.GetCallCount()).To(Equal(1))
					Expect(sshError).To(Equal(errors.New("woops")))
				})
			})
		})

		Context("when the app is not in the 'STARTED' state", func() {
			BeforeEach(func() {
				stoppedApp := app.App{
					State: "STOPPED",
				}
				fakeAppFactory.GetReturns(stoppedApp, nil)
			})

			It("returns an error", func() {
				Expect(fakeAppFactory.GetCallCount()).To(Equal(1))
				Expect(sshError).To(MatchError(MatchRegexp("Application.*not in the STARTED state")))
			})
		})

		Context("when the app is not a Diego app", func() {
			BeforeEach(func() {
				deaApp := app.App{
					State: "STARTED",
					Diego: false,
				}
				fakeAppFactory.GetReturns(deaApp, nil)
			})

			It("returns an error", func() {
				Expect(fakeAppFactory.GetCallCount()).To(Equal(1))
				Expect(sshError).To(MatchError(MatchRegexp("Application.*not running on Diego")))
			})
		})
	})

	Describe("InteractiveSession", func() {
		var opts *options.SSHOptions
		var sessionError error

		BeforeEach(func() {
			sshInfo := info.Info{
				SSHEndpoint:            "ssh.example.com:22",
				SSHEndpointFingerprint: TestHostKeyFingerprint,
			}

			app := app.App{
				Guid:      "app-guid",
				EnableSSH: true,
				Diego:     true,
				State:     "STARTED",
			}

			cred := credential.Credential{
				Token: "bearer token",
			}

			opts = &options.SSHOptions{
				AppName:  "app-name",
				Instance: 2,
			}

			fakeAppFactory.GetReturns(app, nil)
			fakeCredFactory.GetReturns(cred, nil)
			fakeInfoFactory.GetReturns(sshInfo, nil)
		})

		JustBeforeEach(func() {
			sessionError = secureShell.InteractiveSession(opts)
		})

		It("dials the correct endpoint as the correct user", func() {
			Expect(fakeSecureDialer.DialCallCount()).To(Equal(1))

			network, address, config := fakeSecureDialer.DialArgsForCall(0)
			Expect(network).To(Equal("tcp"))
			Expect(address).To(Equal("ssh.example.com:22"))
			Expect(config.Auth).NotTo(BeEmpty())
			Expect(config.User).To(Equal("cf:app-guid/2"))
			Expect(config.HostKeyCallback).NotTo(BeNil())
		})

		It("closes the client", func() {
			Expect(fakeSecureClient.CloseCallCount()).To(Equal(1))
		})

		Context("when host key validation is enabled", func() {
			var callback func(hostname string, remote net.Addr, key ssh.PublicKey) error
			var addr net.Addr

			JustBeforeEach(func() {
				Expect(fakeSecureDialer.DialCallCount()).To(Equal(1))
				_, _, config := fakeSecureDialer.DialArgsForCall(0)
				callback = config.HostKeyCallback

				listener, err := net.Listen("tcp", "localhost:0")
				Expect(err).NotTo(HaveOccurred())

				addr = listener.Addr()
				listener.Close()
			})

			Context("when the SHA1 fingerprint does not match", func() {
				BeforeEach(func() {
					info := info.Info{
						SSHEndpointFingerprint: "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00",
					}
					fakeInfoFactory.GetReturns(info, nil)
				})

				It("returns an error'", func() {
					err := callback("", addr, TestHostKey.PublicKey())
					Expect(err).To(MatchError(MatchRegexp("Host key verification failed\\.")))
					Expect(err).To(MatchError(MatchRegexp("The fingerprint of the received key was \".*\"")))
				})
			})

			Context("when the MD5 fingerprint does not match", func() {
				BeforeEach(func() {
					info := info.Info{
						SSHEndpointFingerprint: "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00",
					}
					fakeInfoFactory.GetReturns(info, nil)
				})

				It("returns an error'", func() {
					err := callback("", addr, TestHostKey.PublicKey())
					Expect(err).To(MatchError(MatchRegexp("Host key verification failed\\.")))
					Expect(err).To(MatchError(MatchRegexp("The fingerprint of the received key was \".*\"")))
				})
			})

			Context("when no fingerprint is present in endpoint info", func() {
				BeforeEach(func() {
					info := info.Info{}
					fakeInfoFactory.GetReturns(info, nil)
				})

				It("returns an error'", func() {
					err := callback("", addr, TestHostKey.PublicKey())
					Expect(err).To(MatchError(MatchRegexp("Unable to verify identity of host\\.")))
					Expect(err).To(MatchError(MatchRegexp("The fingerprint of the received key was \".*\"")))
				})
			})

			Context("when the fingerprint length doesn't make sense", func() {
				BeforeEach(func() {
					info := info.Info{
						SSHEndpointFingerprint: "garbage",
					}
					fakeInfoFactory.GetReturns(info, nil)
				})

				It("returns an error", func() {
					err := callback("", addr, TestHostKey.PublicKey())
					Eventually(err).Should(MatchError(MatchRegexp("Unsupported host key fingerprint format")))
				})
			})
		})

		Context("when the skip host validation flag is set", func() {
			BeforeEach(func() {
				opts.SkipHostValidation = true
			})

			It("removes the HostKeyCallback from the client config", func() {
				Expect(fakeSecureDialer.DialCallCount()).To(Equal(1))

				_, _, config := fakeSecureDialer.DialArgsForCall(0)
				Expect(config.HostKeyCallback).To(BeNil())
			})
		})

		Context("when dialing fails", func() {
			var dialError = errors.New("woops")

			BeforeEach(func() {
				fakeSecureDialer.DialReturns(nil, nil, dialError)
			})

			It("returns the dial error", func() {
				Expect(fakeSecureDialer.DialCallCount()).To(Equal(1))

				Expect(sessionError).To(Equal(dialError))
			})
		})

		Context("when dialing is successful", func() {
			BeforeEach(func() {
				fakeTerminalHelper.StdStreamsStub = terminalHelper.StdStreams
				terminalHelper = fakeTerminalHelper
			})

			It("creates a new secure shell session", func() {
				Expect(fakeSecureClient.NewSessionCallCount()).To(Equal(1))
			})

			It("closes the session", func() {
				Expect(fakeSecureSession.CloseCallCount()).To(Equal(1))
			})

			It("allocates standard streams", func() {
				Expect(fakeTerminalHelper.StdStreamsCallCount()).To(Equal(1))
			})

			It("gets a stdin pipe for the session", func() {
				Expect(fakeSecureSession.StdinPipeCallCount()).To(Equal(1))
			})

			Context("when getting the stdin pipe fails", func() {
				BeforeEach(func() {
					fakeSecureSession.StdinPipeReturns(nil, errors.New("woops"))
				})

				It("returns the error", func() {
					Expect(sessionError).Should(MatchError("woops"))
				})
			})

			It("gets a stdout pipe for the session", func() {
				Expect(fakeSecureSession.StdoutPipeCallCount()).To(Equal(1))
			})

			Context("when getting the stdout pipe fails", func() {
				BeforeEach(func() {
					fakeSecureSession.StdoutPipeReturns(nil, errors.New("woops"))
				})

				It("returns the error", func() {
					Expect(sessionError).Should(MatchError("woops"))
				})
			})

			It("gets a stderr pipe for the session", func() {
				Expect(fakeSecureSession.StderrPipeCallCount()).To(Equal(1))
			})

			Context("when getting the stderr pipe fails", func() {
				BeforeEach(func() {
					fakeSecureSession.StderrPipeReturns(nil, errors.New("woops"))
				})

				It("returns the error", func() {
					Expect(sessionError).Should(MatchError("woops"))
				})
			})
		})

		Context("when stdin is a terminal", func() {
			var master, slave *os.File

			BeforeEach(func() {
				_, stdout, stderr := terminalHelper.StdStreams()

				var err error
				master, slave, err = pty.Open()
				Expect(err).NotTo(HaveOccurred())

				fakeTerminalHelper.IsTerminalStub = terminalHelper.IsTerminal
				fakeTerminalHelper.GetFdInfoStub = terminalHelper.GetFdInfo
				fakeTerminalHelper.GetWinsizeStub = terminalHelper.GetWinsize
				fakeTerminalHelper.StdStreamsReturns(slave, stdout, stderr)
				terminalHelper = fakeTerminalHelper
			})

			AfterEach(func() {
				master.Close()
				// slave.Close() // TODO: race
			})

			Context("when a command is not specified", func() {
				var terminalType string

				BeforeEach(func() {
					terminalType = os.Getenv("TERM")
					os.Setenv("TERM", "test-terminal-type")

					winsize := &term.Winsize{Width: 1024, Height: 256}
					fakeTerminalHelper.GetWinsizeReturns(winsize, nil)

					fakeSecureSession.ShellStub = func() error {
						Expect(fakeTerminalHelper.SetRawTerminalCallCount()).To(Equal(1))
						Expect(fakeTerminalHelper.RestoreTerminalCallCount()).To(Equal(0))
						return nil
					}
				})

				AfterEach(func() {
					os.Setenv("TERM", terminalType)
				})

				It("requests a pty with the correct terminal type, window size, and modes", func() {
					Expect(fakeSecureSession.RequestPtyCallCount()).To(Equal(1))
					Expect(fakeTerminalHelper.GetWinsizeCallCount()).To(Equal(1))

					termType, height, width, modes := fakeSecureSession.RequestPtyArgsForCall(0)
					Expect(termType).To(Equal("test-terminal-type"))
					Expect(height).To(Equal(256))
					Expect(width).To(Equal(1024))

					expectedModes := ssh.TerminalModes{
						ssh.ECHO:          1,
						ssh.TTY_OP_ISPEED: 115200,
						ssh.TTY_OP_OSPEED: 115200,
					}
					Expect(modes).To(Equal(expectedModes))
				})

				Context("when the TERM environment variable is not set", func() {
					BeforeEach(func() {
						os.Unsetenv("TERM")
					})

					It("requests a pty with the default terminal type", func() {
						Expect(fakeSecureSession.RequestPtyCallCount()).To(Equal(1))

						termType, _, _, _ := fakeSecureSession.RequestPtyArgsForCall(0)
						Expect(termType).To(Equal("xterm"))
					})
				})

				It("puts the terminal into raw mode and restores it after running the shell", func() {
					Expect(fakeSecureSession.ShellCallCount()).To(Equal(1))
					Expect(fakeTerminalHelper.SetRawTerminalCallCount()).To(Equal(1))
					Expect(fakeTerminalHelper.RestoreTerminalCallCount()).To(Equal(1))
				})

				Context("when the pty allocation fails", func() {
					var ptyError error

					BeforeEach(func() {
						ptyError = errors.New("pty allocation error")
						fakeSecureSession.RequestPtyReturns(ptyError)
					})

					It("returns the error", func() {
						Expect(sessionError).To(Equal(ptyError))
					})
				})

				Context("when placing the terminal into raw mode fails", func() {
					BeforeEach(func() {
						fakeTerminalHelper.SetRawTerminalReturns(nil, errors.New("woops"))
					})

					It("keeps calm and carries on", func() {
						Expect(fakeSecureSession.ShellCallCount()).To(Equal(1))
					})

					It("does not not restore the terminal", func() {
						Expect(fakeSecureSession.ShellCallCount()).To(Equal(1))
						Expect(fakeTerminalHelper.SetRawTerminalCallCount()).To(Equal(1))
						Expect(fakeTerminalHelper.RestoreTerminalCallCount()).To(Equal(0))
					})
				})
			})

			Context("when a command is specified", func() {
				BeforeEach(func() {
					opts.Command = []string{"echo", "-n", "hello"}
				})

				Context("when a terminal is requested", func() {
					BeforeEach(func() {
						opts.TerminalRequest = options.REQUEST_TTY_YES
					})

					It("requests a pty", func() {
						Expect(fakeSecureSession.RequestPtyCallCount()).To(Equal(1))
					})
				})

				Context("when a terminal is not explicitly requested", func() {
					It("does not request a pty", func() {
						Expect(fakeSecureSession.RequestPtyCallCount()).To(Equal(0))
					})
				})
			})
		})

		Context("when stdin is not a terminal", func() {
			BeforeEach(func() {
				_, stdout, stderr := terminalHelper.StdStreams()

				stdin := &fake_io.FakeReadCloser{}
				stdin.ReadStub = func(p []byte) (int, error) {
					return 0, io.EOF
				}

				fakeTerminalHelper.IsTerminalStub = terminalHelper.IsTerminal
				fakeTerminalHelper.GetFdInfoStub = terminalHelper.GetFdInfo
				fakeTerminalHelper.GetWinsizeStub = terminalHelper.GetWinsize
				fakeTerminalHelper.StdStreamsReturns(stdin, stdout, stderr)
				terminalHelper = fakeTerminalHelper
			})

			Context("when a terminal is not requested", func() {
				It("does not request a pty", func() {
					Expect(fakeSecureSession.RequestPtyCallCount()).To(Equal(0))
				})
			})

			Context("when a terminal is requested", func() {
				BeforeEach(func() {
					opts.TerminalRequest = options.REQUEST_TTY_YES
				})

				It("does not request a pty", func() {
					Expect(fakeSecureSession.RequestPtyCallCount()).To(Equal(0))
				})
			})
		})

		Context("when a terminal is forced", func() {
			BeforeEach(func() {
				opts.TerminalRequest = options.REQUEST_TTY_FORCE
			})

			It("requests a pty", func() {
				Expect(fakeSecureSession.RequestPtyCallCount()).To(Equal(1))
			})
		})

		Context("when a terminal is disabled", func() {
			BeforeEach(func() {
				opts.TerminalRequest = options.REQUEST_TTY_NO
			})

			It("does not request a pty", func() {
				Expect(fakeSecureSession.RequestPtyCallCount()).To(Equal(0))
			})
		})

		Context("when a command is not specified", func() {
			It("requests an interactive shell", func() {
				Expect(fakeSecureSession.ShellCallCount()).To(Equal(1))
			})

			Context("when the shell request returns an error", func() {
				BeforeEach(func() {
					fakeSecureSession.ShellReturns(errors.New("oh bother"))
				})

				It("returns the error", func() {
					Expect(sessionError).To(MatchError("oh bother"))
				})
			})
		})

		Context("when a command is specifed", func() {
			BeforeEach(func() {
				opts.Command = []string{"echo", "-n", "hello"}
			})

			It("starts the command", func() {
				Expect(fakeSecureSession.StartCallCount()).To(Equal(1))
				Expect(fakeSecureSession.StartArgsForCall(0)).To(Equal("echo -n hello"))
			})

			Context("when the command fails to start", func() {
				BeforeEach(func() {
					fakeSecureSession.StartReturns(errors.New("oh well"))
				})

				It("returns the error", func() {
					Expect(sessionError).To(MatchError("oh well"))
				})
			})
		})

		Context("when the shell or command has started", func() {
			var (
				stdin                  *fake_io.FakeReadCloser
				stdout, stderr         *fake_io.FakeWriter
				stdinPipe              *fake_io.FakeWriteCloser
				stdoutPipe, stderrPipe *fake_io.FakeReader
			)

			BeforeEach(func() {
				stdin = &fake_io.FakeReadCloser{}
				stdin.ReadStub = func(p []byte) (int, error) {
					p[0] = 0
					return 1, io.EOF
				}
				stdinPipe = &fake_io.FakeWriteCloser{}
				stdinPipe.WriteStub = func(p []byte) (int, error) {
					defer GinkgoRecover()
					Expect(p[0]).To(Equal(byte(0)))
					return 1, nil
				}

				stdoutPipe = &fake_io.FakeReader{}
				stdoutPipe.ReadStub = func(p []byte) (int, error) {
					p[0] = 1
					return 1, io.EOF
				}
				stdout = &fake_io.FakeWriter{}
				stdout.WriteStub = func(p []byte) (int, error) {
					defer GinkgoRecover()
					Expect(p[0]).To(Equal(byte(1)))
					return 1, nil
				}

				stderrPipe = &fake_io.FakeReader{}
				stderrPipe.ReadStub = func(p []byte) (int, error) {
					p[0] = 2
					return 1, io.EOF
				}
				stderr = &fake_io.FakeWriter{}
				stderr.WriteStub = func(p []byte) (int, error) {
					defer GinkgoRecover()
					Expect(p[0]).To(Equal(byte(2)))
					return 1, nil
				}

				fakeTerminalHelper.StdStreamsReturns(stdin, stdout, stderr)
				terminalHelper = fakeTerminalHelper

				fakeSecureSession.StdinPipeReturns(stdinPipe, nil)
				fakeSecureSession.StdoutPipeReturns(stdoutPipe, nil)
				fakeSecureSession.StderrPipeReturns(stderrPipe, nil)

				fakeSecureSession.WaitReturns(errors.New("error result"))
			})

			It("copies data from the stdin stream to the session stdin pipe", func() {
				Eventually(stdin.ReadCallCount).Should(Equal(1))
				Eventually(stdinPipe.WriteCallCount).Should(Equal(1))
			})

			It("copies data from the session stdout pipe to the stdout stream", func() {
				Eventually(stdoutPipe.ReadCallCount).Should(Equal(1))
				Eventually(stdout.WriteCallCount).Should(Equal(1))
			})

			It("copies data from the session stderr pipe to the stderr stream", func() {
				Eventually(stderrPipe.ReadCallCount).Should(Equal(1))
				Eventually(stderr.WriteCallCount).Should(Equal(1))
			})

			It("waits for the session to end", func() {
				Expect(fakeSecureSession.WaitCallCount()).To(Equal(1))
			})

			It("returns the result from wait", func() {
				Expect(sessionError).To(MatchError("error result"))
			})
		})

		Context("when stdout is a terminal and a window size change occurs", func() {
			var master, slave *os.File

			BeforeEach(func() {
				stdin, _, stderr := terminalHelper.StdStreams()

				var err error
				master, slave, err = pty.Open()
				Expect(err).NotTo(HaveOccurred())

				fakeTerminalHelper.IsTerminalStub = terminalHelper.IsTerminal
				fakeTerminalHelper.GetFdInfoStub = terminalHelper.GetFdInfo
				fakeTerminalHelper.GetWinsizeStub = terminalHelper.GetWinsize
				fakeTerminalHelper.StdStreamsReturns(stdin, slave, stderr)
				terminalHelper = fakeTerminalHelper

				winsize := &term.Winsize{Height: 100, Width: 100}
				err = term.SetWinsize(slave.Fd(), winsize)
				Expect(err).NotTo(HaveOccurred())

				fakeSecureSession.WaitStub = func() error {
					fakeSecureSession.SendRequestCallCount()
					Expect(fakeSecureSession.SendRequestCallCount()).To(Equal(0))

					// No dimension change
					for i := 0; i < 3; i++ {
						winsize := &term.Winsize{Height: 100, Width: 100}
						err = term.SetWinsize(slave.Fd(), winsize)
						Expect(err).NotTo(HaveOccurred())
					}

					winsize := &term.Winsize{Height: 100, Width: 200}
					err = term.SetWinsize(slave.Fd(), winsize)
					Expect(err).NotTo(HaveOccurred())

					err = syscall.Kill(syscall.Getpid(), syscall.SIGWINCH)
					Expect(err).NotTo(HaveOccurred())

					Eventually(fakeSecureSession.SendRequestCallCount).Should(Equal(1))
					return nil
				}
			})

			AfterEach(func() {
				master.Close()
				slave.Close()
			})

			It("sends window change events when the window dimensions change", func() {
				Expect(fakeSecureSession.SendRequestCallCount()).To(Equal(1))

				requestType, wantReply, message := fakeSecureSession.SendRequestArgsForCall(0)
				Expect(requestType).To(Equal("window-change"))
				Expect(wantReply).To(BeFalse())

				type resizeMessage struct {
					Width       uint32
					Height      uint32
					PixelWidth  uint32
					PixelHeight uint32
				}
				var resizeMsg resizeMessage

				err := ssh.Unmarshal(message, &resizeMsg)
				Expect(err).NotTo(HaveOccurred())

				Expect(resizeMsg).To(Equal(resizeMessage{Height: 100, Width: 200}))
			})
		})

		Describe("keep alive messages", func() {
			var times []time.Time
			var timesCh chan []time.Time
			var done chan struct{}

			BeforeEach(func() {
				keepAliveDuration = 100 * time.Millisecond

				times = []time.Time{}
				timesCh = make(chan []time.Time, 1)
				done = make(chan struct{}, 1)

				fakeConnection.SendRequestStub = func(reqName string, wantReply bool, message []byte) (bool, []byte, error) {
					Expect(reqName).To(Equal("keepalive@cloudfoundry.org"))
					Expect(wantReply).To(BeTrue())
					Expect(message).To(BeNil())

					times = append(times, time.Now())
					if len(times) == 3 {
						timesCh <- times
						close(done)
					}
					return true, nil, nil
				}

				fakeSecureSession.WaitStub = func() error {
					Eventually(done).Should(BeClosed())
					return nil
				}
			})

			It("sends keep alive messages at the expected interval", func() {
				times := <-timesCh
				Expect(times[2]).To(BeTemporally("~", times[0].Add(200*time.Millisecond), 100*time.Millisecond))
			})
		})
	})
})
