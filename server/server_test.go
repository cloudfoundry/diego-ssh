package server_test

import (
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/cloudfoundry-incubator/diego-ssh/server"
	"github.com/cloudfoundry-incubator/diego-ssh/server/fake_net"
	"github.com/cloudfoundry-incubator/diego-ssh/server/fakes"
	"github.com/pivotal-golang/lager"
	"github.com/pivotal-golang/lager/lagertest"
	"github.com/tedsuo/ifrit"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
)

var _ = Describe("Server", func() {
	var (
		logger lager.Logger
		srv    *server.Server

		handler *fakes.FakeConnectionHandler

		address string
	)

	BeforeEach(func() {
		handler = &fakes.FakeConnectionHandler{}
		address = fmt.Sprintf("127.0.0.1:%d", 7001+GinkgoParallelNode())
		logger = lagertest.NewTestLogger("test")
	})

	Describe("Run", func() {
		var process ifrit.Process

		BeforeEach(func() {
			srv = server.NewServer(logger, address, handler)
			process = ifrit.Invoke(srv)
		})

		AfterEach(func() {
			process.Signal(os.Interrupt)
			Eventually(process.Wait()).Should(Receive())
		})

		It("accepts connections on the specified address", func() {
			_, err := net.Dial("tcp", address)
			Ω(err).ShouldNot(HaveOccurred())
		})

		Context("when a second client connects", func() {
			JustBeforeEach(func() {
				_, err := net.Dial("tcp", address)
				Ω(err).ShouldNot(HaveOccurred())
			})

			It("accepts the new connection", func() {
				_, err := net.Dial("tcp", address)
				Ω(err).ShouldNot(HaveOccurred())
			})
		})
	})

	Describe("SetListener", func() {
		var fakeListener *fake_net.FakeListener

		BeforeEach(func() {
			fakeListener = &fake_net.FakeListener{}

			srv = server.NewServer(logger, address, handler)
			srv.SetListener(fakeListener)
		})

		Context("when a listener has already been set", func() {
			It("returns an error", func() {
				listener := &fake_net.FakeListener{}
				err := srv.SetListener(listener)
				Ω(err).Should(MatchError("Listener has already been set"))
			})
		})
	})

	Describe("Serve", func() {
		var fakeListener *fake_net.FakeListener
		var fakeConn *fake_net.FakeConn

		BeforeEach(func() {
			fakeListener = &fake_net.FakeListener{}
			fakeConn = &fake_net.FakeConn{}

			connectionCh := make(chan net.Conn, 1)
			connectionCh <- fakeConn

			fakeListener.AcceptStub = func() (net.Conn, error) {
				cx := connectionCh
				select {
				case conn := <-cx:
					return conn, nil
				default:
					return nil, errors.New("fail")
				}
			}
		})

		JustBeforeEach(func() {
			srv = server.NewServer(logger, address, handler)
			srv.SetListener(fakeListener)
			srv.Serve()
		})

		It("accepts inbound connections", func() {
			Ω(fakeListener.AcceptCallCount()).Should(Equal(2))
		})

		It("passes the connection to the connection handler", func() {
			Eventually(handler.HandleConnectionCallCount).Should(Equal(1))
			Ω(handler.HandleConnectionArgsForCall(0)).Should(Equal(fakeConn))
		})

		Context("when accept returns a permanent error", func() {
			BeforeEach(func() {
				fakeListener.AcceptReturns(nil, errors.New("oops"))
			})

			It("closes the listener", func() {
				Ω(fakeListener.CloseCallCount()).Should(Equal(1))
			})
		})

		Context("when accept returns a temporary error", func() {
			var timeCh chan time.Time

			BeforeEach(func() {
				timeCh = make(chan time.Time, 3)

				fakeListener.AcceptStub = func() (net.Conn, error) {
					timeCh := timeCh
					select {
					case timeCh <- time.Now():
						return nil, &testNetError{temporary: true}
					default:
						close(timeCh)
						return nil, &testNetError{temporary: false}
					}
				}
			})

			It("retries the accept after a short delay", func() {
				Ω(timeCh).Should(HaveLen(3))

				times := make([]time.Time, 0)
				for t := range timeCh {
					times = append(times, t)
				}

				Ω(times[1]).Should(BeTemporally("~", times[0].Add(100*time.Millisecond), 20*time.Millisecond))
				Ω(times[2]).Should(BeTemporally("~", times[1].Add(100*time.Millisecond), 20*time.Millisecond))
			})
		})
	})

	Describe("Shutdown", func() {
		var fakeListener *fake_net.FakeListener

		BeforeEach(func() {
			fakeListener = &fake_net.FakeListener{}

			srv = server.NewServer(logger, address, handler)
			srv.SetListener(fakeListener)
		})

		Context("when the server is shutdown", func() {
			BeforeEach(func() {
				srv.Shutdown()
			})

			It("closes the listener", func() {
				Ω(fakeListener.CloseCallCount()).Should(Equal(1))
			})

			It("marks the server as stopping", func() {
				Ω(srv.IsStopping()).Should(BeTrue())
			})

			It("does not log an accept failure", func() {
				Eventually(func() error {
					_, err := net.Dial("tcp", address)
					return err
				}).Should(HaveOccurred())
				Consistently(logger).ShouldNot(gbytes.Say("test.serve.accept-failed"))
			})
		})
	})
})

type testNetError struct {
	timeout   bool
	temporary bool
}

func (e *testNetError) Error() string   { return "test error" }
func (e *testNetError) Timeout() bool   { return e.timeout }
func (e *testNetError) Temporary() bool { return e.temporary }
