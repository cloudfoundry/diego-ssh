package proxy_test

import (
	"encoding/json"
	"errors"
	"io"
	"net"

	"github.com/cloudfoundry-incubator/diego-ssh/authenticators/fake_authenticators"
	"github.com/cloudfoundry-incubator/diego-ssh/daemon"
	"github.com/cloudfoundry-incubator/diego-ssh/handlers"
	"github.com/cloudfoundry-incubator/diego-ssh/handlers/fake_handlers"
	"github.com/cloudfoundry-incubator/diego-ssh/proxy"
	"github.com/cloudfoundry-incubator/diego-ssh/server"
	server_fakes "github.com/cloudfoundry-incubator/diego-ssh/server/fakes"
	"github.com/cloudfoundry-incubator/diego-ssh/test_helpers"
	"github.com/cloudfoundry-incubator/diego-ssh/test_helpers/fake_net"
	"github.com/cloudfoundry-incubator/diego-ssh/test_helpers/fake_ssh"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/pivotal-golang/lager"
	"github.com/pivotal-golang/lager/lagertest"
	"golang.org/x/crypto/ssh"
)

var _ = Describe("Proxy", func() {
	var logger lager.Logger

	BeforeEach(func() {
		logger = lagertest.NewTestLogger("test")
	})

	Describe("HandleConnection", func() {
		var (
			proxyAuthenticator *fake_authenticators.FakePasswordAuthenticator
			proxySSHConfig     *ssh.ServerConfig
			sshProxy           *proxy.Proxy

			daemonTargetConfig          proxy.TargetConfig
			daemonAuthenticator         *fake_authenticators.FakePasswordAuthenticator
			daemonSSHConfig             *ssh.ServerConfig
			daemonGlobalRequestHandlers map[string]handlers.GlobalRequestHandler
			daemonNewChannelHandlers    map[string]handlers.NewChannelHandler
			sshDaemon                   *daemon.Daemon

			proxyListener net.Listener
			sshdListener  net.Listener

			proxyAddress  string
			daemonAddress string

			proxyServer *server.Server
			sshdServer  *server.Server
		)

		BeforeEach(func() {
			proxyAuthenticator = &fake_authenticators.FakePasswordAuthenticator{}

			proxySSHConfig = &ssh.ServerConfig{}
			proxySSHConfig.PasswordCallback = proxyAuthenticator.Authenticate
			proxySSHConfig.AddHostKey(TestHostKey)

			daemonAuthenticator = &fake_authenticators.FakePasswordAuthenticator{}
			daemonAuthenticator.AuthenticateReturns(&ssh.Permissions{}, nil)

			daemonSSHConfig = &ssh.ServerConfig{}
			daemonSSHConfig.PasswordCallback = daemonAuthenticator.Authenticate
			daemonSSHConfig.AddHostKey(TestHostKey)
			daemonGlobalRequestHandlers = map[string]handlers.GlobalRequestHandler{}
			daemonNewChannelHandlers = map[string]handlers.NewChannelHandler{}

			var err error
			proxyListener, err = net.Listen("tcp", "127.0.0.1:0")
			Ω(err).ShouldNot(HaveOccurred())
			proxyAddress = proxyListener.Addr().String()

			sshdListener, err = net.Listen("tcp", "127.0.0.1:0")
			Ω(err).ShouldNot(HaveOccurred())
			daemonAddress = sshdListener.Addr().String()

			daemonTargetConfig = proxy.TargetConfig{
				Address:  daemonAddress,
				User:     "some-user",
				Password: "some-password",
			}

			targetConfigJson, err := json.Marshal(daemonTargetConfig)
			Ω(err).ShouldNot(HaveOccurred())

			permissions := &ssh.Permissions{
				CriticalOptions: map[string]string{
					"proxy-target-config": string(targetConfigJson),
				},
			}
			proxyAuthenticator.AuthenticateReturns(permissions, nil)
		})

		JustBeforeEach(func() {
			sshProxy = proxy.New(logger.Session("proxy"), proxySSHConfig)
			proxyServer = server.NewServer(logger, "127.0.0.1:0", sshProxy)
			proxyServer.SetListener(proxyListener)
			go proxyServer.Serve()

			sshDaemon = daemon.New(logger.Session("sshd"), daemonSSHConfig, daemonGlobalRequestHandlers, daemonNewChannelHandlers)
			sshdServer = server.NewServer(logger, "127.0.0.1:0", sshDaemon)
			sshdServer.SetListener(sshdListener)
			go sshdServer.Serve()
		})

		AfterEach(func() {
			proxyServer.Shutdown()
			sshdServer.Shutdown()
		})

		Context("when a new connection arrives", func() {
			var clientConfig *ssh.ClientConfig

			BeforeEach(func() {
				clientConfig = &ssh.ClientConfig{
					User: "diego:some-instance-guid",
					Auth: []ssh.AuthMethod{
						ssh.Password("diego-user:diego-password"),
					},
				}
			})

			It("performs a handshake with the client using the proxy server config", func() {
				_, err := ssh.Dial("tcp", proxyAddress, clientConfig)
				Ω(err).ShouldNot(HaveOccurred())

				Ω(proxyAuthenticator.AuthenticateCallCount()).Should(Equal(1))

				metadata, password := proxyAuthenticator.AuthenticateArgsForCall(0)
				Ω(metadata.User()).Should(Equal("diego:some-instance-guid"))
				Ω(string(password)).Should(Equal("diego-user:diego-password"))
			})

			Context("when the handshake fails", func() {
				BeforeEach(func() {
					proxyAuthenticator.AuthenticateReturns(nil, errors.New("go away"))
				})

				JustBeforeEach(func() {
					_, err := ssh.Dial("tcp", proxyAddress, clientConfig)
					Ω(err).Should(MatchError(ContainSubstring("ssh: handshake failed: ssh: unable to authenticate")))
				})

				It("logs the failure", func() {
					Eventually(logger).Should(gbytes.Say(`handshake-failed`))
					Ω(proxyAuthenticator.AuthenticateCallCount()).Should(Equal(1))
				})
			})

			Context("when the handshake is successful", func() {
				var client *ssh.Client

				JustBeforeEach(func() {
					var err error
					client, err = ssh.Dial("tcp", proxyAddress, clientConfig)
					Ω(err).ShouldNot(HaveOccurred())
				})

				It("handshakes with the target using the provided configuration", func() {
					Eventually(daemonAuthenticator.AuthenticateCallCount).Should(Equal(1))

					metadata, password := daemonAuthenticator.AuthenticateArgsForCall(0)
					Ω(metadata.User()).Should(Equal("some-user"))
					Ω(string(password)).Should(Equal("some-password"))
				})

				Context("when the target address is unreachable", func() {
					BeforeEach(func() {
						permissions := &ssh.Permissions{
							CriticalOptions: map[string]string{
								"proxy-target-config": `{"address": "0.0.0.0:0"}`,
							},
						}
						proxyAuthenticator.AuthenticateReturns(permissions, nil)
					})

					It("closes the connection", func() {
						Eventually(client.Wait).Should(Equal(io.EOF))
					})

					It("logs the failure", func() {
						Eventually(logger).Should(gbytes.Say(`new-client-conn.dial-failed.*0\.0\.0\.0:0`))
					})
				})

				Context("when the handshake fails", func() {
					BeforeEach(func() {
						daemonAuthenticator.AuthenticateReturns(nil, errors.New("go away"))
					})

					It("closes the connection", func() {
						Eventually(client.Wait).Should(Equal(io.EOF))
					})

					It("logs the failure", func() {
						Eventually(logger).Should(gbytes.Say(`new-client-conn.handshake-failed`))
					})
				})
			})

			Context("when HandleConnection returns", func() {
				var fakeServerConnection *fake_net.FakeConn

				BeforeEach(func() {
					proxySSHConfig.NoClientAuth = true
					daemonSSHConfig.NoClientAuth = true
				})

				JustBeforeEach(func() {
					clientNetConn, serverNetConn := test_helpers.Pipe()

					fakeServerConnection = &fake_net.FakeConn{}
					fakeServerConnection.ReadStub = serverNetConn.Read
					fakeServerConnection.WriteStub = serverNetConn.Write
					fakeServerConnection.CloseStub = serverNetConn.Close

					go sshProxy.HandleConnection(fakeServerConnection)

					clientConn, clientChannels, clientRequests, err := ssh.NewClientConn(clientNetConn, "0.0.0.0", clientConfig)
					Ω(err).ShouldNot(HaveOccurred())

					client := ssh.NewClient(clientConn, clientChannels, clientRequests)
					client.Close()
				})

				It("ensures the network connection is closed", func() {
					Eventually(fakeServerConnection.CloseCallCount).Should(BeNumerically(">=", 1))
				})
			})
		})

		Context("after both handshakes have been performed", func() {
			var clientConfig *ssh.ClientConfig

			BeforeEach(func() {
				clientConfig = &ssh.ClientConfig{
					User: "diego:some-instance-guid",
					Auth: []ssh.AuthMethod{
						ssh.Password("diego-user:diego-password"),
					},
				}
				daemonSSHConfig.NoClientAuth = true
			})

			Describe("client requests to target", func() {
				var client *ssh.Client

				JustBeforeEach(func() {
					var err error
					client, err = ssh.Dial("tcp", proxyAddress, clientConfig)
					Ω(err).ShouldNot(HaveOccurred())
				})

				AfterEach(func() {
					client.Close()
				})

				Context("when the client sends a global request", func() {
					var globalRequestHandler *fake_handlers.FakeGlobalRequestHandler

					BeforeEach(func() {
						globalRequestHandler = &fake_handlers.FakeGlobalRequestHandler{}
						globalRequestHandler.HandleRequestStub = func(logger lager.Logger, request *ssh.Request) {
							request.Reply(true, []byte("response-payload"))
						}
						daemonGlobalRequestHandlers["test-global-request"] = globalRequestHandler
					})

					It("gets forwarded to the daemon and the response comes back", func() {
						accepted, response, err := client.SendRequest("test-global-request", true, []byte("request-payload"))
						Ω(err).ShouldNot(HaveOccurred())
						Ω(accepted).Should(BeTrue())
						Ω(response).Should(Equal([]byte("response-payload")))

						Ω(globalRequestHandler.HandleRequestCallCount()).Should(Equal(1))

						_, request := globalRequestHandler.HandleRequestArgsForCall(0)
						Ω(request.Type).Should(Equal("test-global-request"))
						Ω(request.WantReply).Should(BeTrue())
						Ω(request.Payload).Should(Equal([]byte("request-payload")))
					})
				})

				Context("when the client requests a new channel", func() {
					var newChannelHandler *fake_handlers.FakeNewChannelHandler

					BeforeEach(func() {
						newChannelHandler = &fake_handlers.FakeNewChannelHandler{}
						newChannelHandler.HandleNewChannelStub = func(logger lager.Logger, newChannel ssh.NewChannel) {
							newChannel.Reject(ssh.Prohibited, "not now")
						}
						daemonNewChannelHandlers["test"] = newChannelHandler
					})

					It("gets forwarded to the daemon", func() {
						_, _, err := client.OpenChannel("test", nil)
						Ω(err).Should(Equal(&ssh.OpenChannelError{Reason: ssh.Prohibited, Message: "not now"}))
					})
				})
			})

			Describe("target requests to client", func() {
				var (
					connectionHandler *server_fakes.FakeConnectionHandler

					target        *server.Server
					listener      net.Listener
					targetAddress string

					clientConn     ssh.Conn
					clientChannels <-chan ssh.NewChannel
					clientRequests <-chan *ssh.Request
				)

				BeforeEach(func() {
					var err error
					listener, err = net.Listen("tcp", "127.0.0.1:0")
					Ω(err).ShouldNot(HaveOccurred())
					targetAddress = listener.Addr().String()

					connectionHandler = &server_fakes.FakeConnectionHandler{}
				})

				JustBeforeEach(func() {
					target = server.NewServer(logger.Session("target"), "127.0.0.1", connectionHandler)
					target.SetListener(listener)
					go target.Serve()

					clientNetConn, err := net.Dial("tcp", targetAddress)
					clientConn, clientChannels, clientRequests, err = ssh.NewClientConn(clientNetConn, "0.0.0.0", &ssh.ClientConfig{})
					Ω(err).ShouldNot(HaveOccurred())
				})

				AfterEach(func() {
					target.Shutdown()
				})

				Context("when the target sends a global request", func() {
					BeforeEach(func() {
						connectionHandler.HandleConnectionStub = func(conn net.Conn) {
							defer GinkgoRecover()

							serverConn, _, _, err := ssh.NewServerConn(conn, daemonSSHConfig)
							Ω(err).ShouldNot(HaveOccurred())

							accepted, response, err := serverConn.SendRequest("test", true, []byte("test-data"))
							Ω(err).ShouldNot(HaveOccurred())
							Ω(accepted).Should(BeTrue())
							Ω(response).Should(Equal([]byte("response-data")))

							serverConn.Close()
						}
					})

					It("gets forwarded to the client", func() {
						var req *ssh.Request
						Eventually(clientRequests).Should(Receive(&req))

						req.Reply(true, []byte("response-data"))
					})
				})

				Context("when the target requests a new channel", func() {
					BeforeEach(func() {
						connectionHandler.HandleConnectionStub = func(conn net.Conn) {
							defer GinkgoRecover()

							serverConn, _, _, err := ssh.NewServerConn(conn, daemonSSHConfig)
							Ω(err).ShouldNot(HaveOccurred())

							channel, requests, err := serverConn.OpenChannel("test-channel", []byte("extra-data"))
							Ω(err).ShouldNot(HaveOccurred())
							Ω(channel).ShouldNot(BeNil())
							Ω(requests).ShouldNot(BeClosed())

							channel.Write([]byte("hello"))

							channelResponse := make([]byte, 7)
							channel.Read(channelResponse)
							Ω(string(channelResponse)).Should(Equal("goodbye"))

							channel.Close()
							serverConn.Close()
						}
					})

					It("gets forwarded to the client", func() {
						var newChannel ssh.NewChannel
						Eventually(clientChannels).Should(Receive(&newChannel))

						Ω(newChannel.ChannelType()).Should(Equal("test-channel"))
						Ω(newChannel.ExtraData()).Should(Equal([]byte("extra-data")))

						channel, requests, err := newChannel.Accept()
						Ω(err).ShouldNot(HaveOccurred())
						Ω(channel).ShouldNot(BeNil())
						Ω(requests).ShouldNot(BeClosed())

						channelRequest := make([]byte, 5)
						channel.Read(channelRequest)
						Ω(string(channelRequest)).Should(Equal("hello"))

						channel.Write([]byte("goodbye"))
						channel.Close()
					})
				})
			})
		})
	})

	Describe("ProxyGlobalRequests", func() {
		var (
			sshConn *fake_ssh.FakeConn
			reqChan chan *ssh.Request

			done chan struct{}
		)

		BeforeEach(func() {
			sshConn = &fake_ssh.FakeConn{}
			reqChan = make(chan *ssh.Request, 2)
			done = make(chan struct{}, 1)
		})

		JustBeforeEach(func() {
			go func(done chan<- struct{}) {
				proxy.ProxyGlobalRequests(logger, sshConn, reqChan)
				done <- struct{}{}
			}(done)
		})

		Context("when a request is received", func() {
			BeforeEach(func() {
				request := &ssh.Request{Type: "test", WantReply: false, Payload: []byte("test-data")}
				reqChan <- request
				reqChan <- request
			})

			AfterEach(func() {
				close(reqChan)
			})

			It("forwards requests from the channel to the connection", func() {
				Eventually(sshConn.SendRequestCallCount).Should(Equal(2))
				Consistently(sshConn.SendRequestCallCount).Should(Equal(2))

				reqType, wantReply, payload := sshConn.SendRequestArgsForCall(0)
				Ω(reqType).Should(Equal("test"))
				Ω(wantReply).Should(BeFalse())
				Ω(payload).Should(Equal([]byte("test-data")))

				reqType, wantReply, payload = sshConn.SendRequestArgsForCall(1)
				Ω(reqType).Should(Equal("test"))
				Ω(wantReply).Should(BeFalse())
				Ω(payload).Should(Equal([]byte("test-data")))
			})
		})

		Context("when SendRequest fails", func() {
			BeforeEach(func() {
				callCount := 0
				sshConn.SendRequestStub = func(rt string, wr bool, p []byte) (bool, []byte, error) {
					callCount++
					if callCount == 1 {
						return false, nil, errors.New("woops")
					}
					return true, nil, nil
				}

				reqChan <- &ssh.Request{}
				reqChan <- &ssh.Request{}
			})

			AfterEach(func() {
				close(reqChan)
			})

			It("continues processing requests", func() {
				Eventually(sshConn.SendRequestCallCount).Should(Equal(2))
			})

			It("logs the failure", func() {
				Eventually(logger).Should(gbytes.Say(`send-request-failed.*woops`))
			})
		})

		Context("when the request channel closes", func() {
			JustBeforeEach(func() {
				Consistently(reqChan).ShouldNot(BeClosed())
				close(reqChan)
			})

			It("returns gracefully", func() {
				Eventually(done).Should(Receive())
			})
		})
	})

	Describe("ProxyChannels", func() {
		var (
			targetConn  *fake_ssh.FakeConn
			newChanChan chan ssh.NewChannel

			newChan       *fake_ssh.FakeNewChannel
			sourceChannel *fake_ssh.FakeChannel
			sourceReqChan chan *ssh.Request

			targetChannel *fake_ssh.FakeChannel
			targetReqChan chan *ssh.Request

			done chan struct{}
		)

		BeforeEach(func() {
			targetConn = &fake_ssh.FakeConn{}
			newChanChan = make(chan ssh.NewChannel, 1)

			newChan = &fake_ssh.FakeNewChannel{}
			sourceChannel = &fake_ssh.FakeChannel{}
			sourceReqChan = make(chan *ssh.Request, 2)

			targetChannel = &fake_ssh.FakeChannel{}
			targetReqChan = make(chan *ssh.Request, 2)

			done = make(chan struct{}, 1)
		})

		JustBeforeEach(func() {
			go func(done chan<- struct{}) {
				proxy.ProxyChannels(logger, targetConn, newChanChan)
				done <- struct{}{}
			}(done)
		})

		Context("when a new channel is opened by the client", func() {
			BeforeEach(func() {
				sourceChannel.ReadReturns(0, io.EOF)
				targetChannel.ReadReturns(0, io.EOF)

				newChan.ChannelTypeReturns("test")
				newChan.ExtraDataReturns([]byte("extra-data"))
				newChan.AcceptReturns(sourceChannel, sourceReqChan, nil)

				targetConn.OpenChannelReturns(targetChannel, targetReqChan, nil)

				newChanChan <- newChan
			})

			AfterEach(func() {
				close(newChanChan)
			})

			It("forwards the NewChannel request to the target", func() {
				Eventually(targetConn.OpenChannelCallCount).Should(Equal(1))
				Consistently(targetConn.OpenChannelCallCount).Should(Equal(1))

				channelType, extraData := targetConn.OpenChannelArgsForCall(0)
				Ω(channelType).Should(Equal("test"))
				Ω(extraData).Should(Equal([]byte("extra-data")))
			})

			Context("when the target accepts the connection", func() {
				It("accepts the source request", func() {
					Eventually(newChan.AcceptCallCount).Should(Equal(1))
				})

				Context("when the source channel has data available", func() {
					BeforeEach(func() {
						sourceChannel.ReadStub = func(dest []byte) (int, error) {
							if cap(dest) >= 3 {
								copy(dest, []byte("abc"))
								return 3, io.EOF
							}
							return 0, io.EOF
						}
					})

					It("copies the source channel to the target channel", func() {
						Eventually(targetChannel.WriteCallCount).ShouldNot(Equal(0))

						data := targetChannel.WriteArgsForCall(0)
						Ω(data).Should(Equal([]byte("abc")))
					})
				})

				Context("when the target channel has data available", func() {
					BeforeEach(func() {
						targetChannel.ReadStub = func(dest []byte) (int, error) {
							if cap(dest) >= 3 {
								copy(dest, []byte("xyz"))
								return 3, io.EOF
							}
							return 0, io.EOF
						}
					})

					It("copies the target channel to the source channel", func() {
						Eventually(sourceChannel.WriteCallCount).ShouldNot(Equal(0))

						data := sourceChannel.WriteArgsForCall(0)
						Ω(data).Should(Equal([]byte("xyz")))
					})
				})

				Context("when the source channel closes", func() {
					BeforeEach(func() {
						sourceChannel.ReadReturns(0, io.EOF)
					})

					It("closes the target channel", func() {
						Eventually(sourceChannel.ReadCallCount).Should(Equal(1))
						Eventually(targetChannel.CloseWriteCallCount).Should(Equal(1))
					})
				})

				Context("when the target channel closes", func() {
					BeforeEach(func() {
						targetChannel.ReadReturns(0, io.EOF)
					})

					It("closes the source channel", func() {
						Eventually(sourceChannel.ReadCallCount).Should(Equal(1))
						Eventually(targetChannel.CloseWriteCallCount).Should(Equal(1))
					})
				})

				Context("when out of band requests are received on the source channel", func() {
					BeforeEach(func() {
						request := &ssh.Request{Type: "test", WantReply: false, Payload: []byte("test-data")}
						sourceReqChan <- request
					})

					It("forwards the request to the target channel", func() {
						Eventually(targetChannel.SendRequestCallCount).Should(Equal(1))

						reqType, wantReply, payload := targetChannel.SendRequestArgsForCall(0)
						Ω(reqType).Should(Equal("test"))
						Ω(wantReply).Should(BeFalse())
						Ω(payload).Should(Equal([]byte("test-data")))
					})
				})

				Context("when out of band requests are received from the target channel", func() {
					BeforeEach(func() {
						request := &ssh.Request{Type: "test", WantReply: false, Payload: []byte("test-data")}
						targetReqChan <- request
					})

					It("forwards the request to the target channel", func() {
						Eventually(sourceChannel.SendRequestCallCount).Should(Equal(1))

						reqType, wantReply, payload := sourceChannel.SendRequestArgsForCall(0)
						Ω(reqType).Should(Equal("test"))
						Ω(wantReply).Should(BeFalse())
						Ω(payload).Should(Equal([]byte("test-data")))
					})
				})
			})

			Context("when the target rejects the connection", func() {
				BeforeEach(func() {
					openError := &ssh.OpenChannelError{
						Reason:  ssh.Prohibited,
						Message: "go away",
					}
					targetConn.OpenChannelReturns(nil, nil, openError)
				})

				It("rejects the source request with the upstream error", func() {
					Eventually(newChan.RejectCallCount).Should(Equal(1))

					reason, message := newChan.RejectArgsForCall(0)
					Ω(reason).Should(Equal(ssh.Prohibited))
					Ω(message).Should(Equal("go away"))
				})

				It("continues processing new channel requests", func() {
					newChanChan <- newChan
					Eventually(newChan.RejectCallCount).Should(Equal(2))
				})
			})

			Context("when openning a channel failsfails", func() {
				BeforeEach(func() {
					targetConn.OpenChannelReturns(nil, nil, errors.New("woops"))
				})

				It("rejects the source request with a connection failed reason", func() {
					Eventually(newChan.RejectCallCount).Should(Equal(1))

					reason, message := newChan.RejectArgsForCall(0)
					Ω(reason).Should(Equal(ssh.ConnectionFailed))
					Ω(message).Should(Equal("woops"))
				})

				It("continues processing new channel requests", func() {
					newChanChan <- newChan
					Eventually(newChan.RejectCallCount).Should(Equal(2))
				})
			})
		})

		Context("when the new channel channel closes", func() {
			JustBeforeEach(func() {
				Consistently(newChanChan).ShouldNot(BeClosed())
				close(newChanChan)
			})

			It("returns gracefully", func() {
				Eventually(done).Should(Receive())
			})
		})
	})

	Describe("ProxyRequests", func() {
		var (
			channel *fake_ssh.FakeChannel
			reqChan chan *ssh.Request

			done chan struct{}
		)

		BeforeEach(func() {
			channel = &fake_ssh.FakeChannel{}
			reqChan = make(chan *ssh.Request, 2)
			done = make(chan struct{}, 1)
		})

		JustBeforeEach(func() {
			go func(done chan<- struct{}) {
				proxy.ProxyRequests(logger, "test", reqChan, channel)
				done <- struct{}{}
			}(done)
		})

		Context("when a request is received", func() {
			BeforeEach(func() {
				request := &ssh.Request{Type: "test", WantReply: false, Payload: []byte("test-data")}
				reqChan <- request
				reqChan <- request
			})

			AfterEach(func() {
				close(reqChan)
			})

			It("forwards requests from the channel to the connection", func() {
				Eventually(channel.SendRequestCallCount).Should(Equal(2))
				Consistently(channel.SendRequestCallCount).Should(Equal(2))

				reqType, wantReply, payload := channel.SendRequestArgsForCall(0)
				Ω(reqType).Should(Equal("test"))
				Ω(wantReply).Should(BeFalse())
				Ω(payload).Should(Equal([]byte("test-data")))

				reqType, wantReply, payload = channel.SendRequestArgsForCall(1)
				Ω(reqType).Should(Equal("test"))
				Ω(wantReply).Should(BeFalse())
				Ω(payload).Should(Equal([]byte("test-data")))
			})
		})

		Context("when SendRequest fails", func() {
			BeforeEach(func() {
				callCount := 0
				channel.SendRequestStub = func(rt string, wr bool, p []byte) (bool, error) {
					callCount++
					if callCount == 1 {
						return false, errors.New("woops")
					}
					return true, nil
				}

				reqChan <- &ssh.Request{}
				reqChan <- &ssh.Request{}
			})

			AfterEach(func() {
				close(reqChan)
			})

			It("continues processing requests", func() {
				Eventually(channel.SendRequestCallCount).Should(Equal(2))
			})

			It("logs the failure", func() {
				Eventually(logger).Should(gbytes.Say(`send-request-failed.*woops`))
			})
		})

		Context("when the request channel closes", func() {
			JustBeforeEach(func() {
				Consistently(reqChan).ShouldNot(BeClosed())
				close(reqChan)
			})

			It("returns gracefully", func() {
				Eventually(done).Should(Receive())
			})
		})
	})

	Describe("NewClientConn", func() {
		var (
			permissions *ssh.Permissions

			daemonSSHConfig *ssh.ServerConfig
			sshDaemon       *daemon.Daemon
			sshdListener    net.Listener
			sshdServer      *server.Server

			clientConn       ssh.Conn
			newChannelChan   <-chan ssh.NewChannel
			requestChannel   <-chan *ssh.Request
			newClientConnErr error
		)

		BeforeEach(func() {
			permissions = &ssh.Permissions{
				CriticalOptions: map[string]string{},
			}

			daemonSSHConfig = &ssh.ServerConfig{}
			daemonSSHConfig.AddHostKey(TestHostKey)

			listener, err := net.Listen("tcp", "127.0.0.1:0")
			Ω(err).ShouldNot(HaveOccurred())

			sshdListener = listener
		})

		JustBeforeEach(func() {
			sshDaemon = daemon.New(logger.Session("sshd"), daemonSSHConfig, nil, nil)
			sshdServer = server.NewServer(logger, "127.0.0.1:0", sshDaemon)
			sshdServer.SetListener(sshdListener)
			go sshdServer.Serve()

			clientConn, newChannelChan, requestChannel, newClientConnErr = proxy.NewClientConn(logger, permissions)
		})

		AfterEach(func() {
			sshdServer.Shutdown()
		})

		Context("when permissions is nil", func() {
			BeforeEach(func() {
				permissions = nil
			})

			It("returns an error", func() {
				Ω(newClientConnErr).Should(HaveOccurred())
			})

			It("logs the failure", func() {
				Eventually(logger).Should(gbytes.Say("permissions-and-critical-options-required"))
			})
		})

		Context("when permissions.CriticalOptions is nil", func() {
			BeforeEach(func() {
				permissions.CriticalOptions = nil
			})

			It("returns an error", func() {
				Ω(newClientConnErr).Should(HaveOccurred())
			})

			It("logs the failure", func() {
				Eventually(logger).Should(gbytes.Say("permissions-and-critical-options-required"))
			})
		})

		Context("when the config is missing", func() {
			BeforeEach(func() {
				delete(permissions.CriticalOptions, "proxy-target-config")
			})

			It("returns an error", func() {
				Ω(newClientConnErr).Should(HaveOccurred())
			})

			It("logs the failure", func() {
				Eventually(logger).Should(gbytes.Say("unmarshal-failed"))
			})
		})

		Context("when the config fails to unmarshal", func() {
			BeforeEach(func() {
				permissions.CriticalOptions["proxy-target-config"] = "{ this_is: invalid json"
			})

			It("returns an error", func() {
				Ω(newClientConnErr).Should(HaveOccurred())
			})

			It("logs the failure", func() {
				Eventually(logger).Should(gbytes.Say("unmarshal-failed"))
			})
		})

		Context("when the address in the config is bad", func() {
			BeforeEach(func() {
				permissions.CriticalOptions["proxy-target-config"] = `{ "address": "0.0.0.0:0" }`
			})

			It("returns an error", func() {
				Ω(newClientConnErr).Should(HaveOccurred())
			})

			It("logs the failure", func() {
				Eventually(logger).Should(gbytes.Say("dial-failed"))
			})
		})

		Context("when the config contains a user and password", func() {
			var passwordAuthenticator *fake_authenticators.FakePasswordAuthenticator

			BeforeEach(func() {
				targetConfigJson, err := json.Marshal(proxy.TargetConfig{
					Address:  sshdListener.Addr().String(),
					User:     "my-user",
					Password: "my-password",
				})
				Ω(err).ShouldNot(HaveOccurred())

				permissions = &ssh.Permissions{
					CriticalOptions: map[string]string{
						"proxy-target-config": string(targetConfigJson),
					},
				}

				passwordAuthenticator = &fake_authenticators.FakePasswordAuthenticator{}
				daemonSSHConfig.PasswordCallback = passwordAuthenticator.Authenticate
			})

			It("uses the user and password for authentication", func() {
				Ω(passwordAuthenticator.AuthenticateCallCount()).Should(Equal(1))

				metadata, password := passwordAuthenticator.AuthenticateArgsForCall(0)
				Ω(metadata.User()).Should(Equal("my-user"))
				Ω(string(password)).Should(Equal("my-password"))
			})
		})

		Context("when the config contains a public key", func() {
			var publicKeyAuthenticator *fake_authenticators.FakePublicKeyAuthenticator

			BeforeEach(func() {
				targetConfigJson, err := json.Marshal(proxy.TargetConfig{
					Address:    sshdListener.Addr().String(),
					PrivateKey: TestPrivatePem,
				})
				Ω(err).ShouldNot(HaveOccurred())

				permissions = &ssh.Permissions{
					CriticalOptions: map[string]string{
						"proxy-target-config": string(targetConfigJson),
					},
				}

				publicKeyAuthenticator = &fake_authenticators.FakePublicKeyAuthenticator{}
				publicKeyAuthenticator.AuthenticateReturns(&ssh.Permissions{}, nil)
				daemonSSHConfig.PublicKeyCallback = publicKeyAuthenticator.Authenticate
			})

			It("will attempt to use the public key for authentication before the password", func() {
				expectedKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(TestPublicAuthorizedKey))
				Ω(err).ShouldNot(HaveOccurred())

				Ω(publicKeyAuthenticator.AuthenticateCallCount()).Should(Equal(1))

				_, actualKey := publicKeyAuthenticator.AuthenticateArgsForCall(0)
				Ω(actualKey.Marshal()).Should(Equal(expectedKey.Marshal()))
			})
		})

		Context("when the config contains a user, password, a public key", func() {
			var publicKeyAuthenticator *fake_authenticators.FakePublicKeyAuthenticator
			var passwordAuthenticator *fake_authenticators.FakePasswordAuthenticator

			BeforeEach(func() {
				targetConfigJson, err := json.Marshal(proxy.TargetConfig{
					Address:    sshdListener.Addr().String(),
					User:       "my-user",
					Password:   "my-password",
					PrivateKey: TestPrivatePem,
				})
				Ω(err).ShouldNot(HaveOccurred())

				permissions = &ssh.Permissions{
					CriticalOptions: map[string]string{
						"proxy-target-config": string(targetConfigJson),
					},
				}

				passwordAuthenticator = &fake_authenticators.FakePasswordAuthenticator{}
				daemonSSHConfig.PasswordCallback = passwordAuthenticator.Authenticate

				publicKeyAuthenticator = &fake_authenticators.FakePublicKeyAuthenticator{}
				publicKeyAuthenticator.AuthenticateReturns(&ssh.Permissions{}, nil)
				daemonSSHConfig.PublicKeyCallback = publicKeyAuthenticator.Authenticate
			})

			It("will attempt to use the public key for authentication before the password", func() {
				Ω(publicKeyAuthenticator.AuthenticateCallCount()).Should(Equal(1))
				Ω(passwordAuthenticator.AuthenticateCallCount()).Should(Equal(0))
			})

			Context("when public key authentication fails", func() {
				BeforeEach(func() {
					passwordAuthenticator.AuthenticateReturns(&ssh.Permissions{}, nil)
					publicKeyAuthenticator.AuthenticateReturns(nil, errors.New("go away"))
				})

				It("will fall back to password authentication", func() {
					Ω(publicKeyAuthenticator.AuthenticateCallCount()).Should(Equal(1))
					Ω(passwordAuthenticator.AuthenticateCallCount()).Should(Equal(1))
				})
			})
		})
	})

	Describe("Wait", func() {
		var (
			waitChans []chan struct{}
			waiters   []proxy.Waiter

			done chan struct{}
		)

		BeforeEach(func() {
			for i := 0; i < 3; i++ {
				idx := i
				waitChans = append(waitChans, make(chan struct{}))

				conn := &fake_ssh.FakeConn{}
				conn.WaitStub = func() error {
					<-waitChans[idx]
					return nil
				}
				waiters = append(waiters, conn)
			}

			done = make(chan struct{}, 1)
		})

		JustBeforeEach(func() {
			go func(done chan<- struct{}) {
				proxy.Wait(logger, waiters...)
				done <- struct{}{}
			}(done)
		})

		It("waits for all Waiters to finish", func() {
			Consistently(done).ShouldNot(Receive())
			close(waitChans[0])

			Consistently(done).ShouldNot(Receive())
			close(waitChans[1])

			Consistently(done).ShouldNot(Receive())
			close(waitChans[2])

			Eventually(done).Should(Receive())
		})
	})
})
