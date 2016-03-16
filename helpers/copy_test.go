package helpers_test

import (
	"errors"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/cloudfoundry-incubator/diego-ssh/helpers"
	"github.com/cloudfoundry-incubator/diego-ssh/test_helpers/fake_io"
	"github.com/pivotal-golang/lager"
	"github.com/pivotal-golang/lager/lagertest"
	"github.com/tedsuo/ifrit"
	"github.com/tedsuo/ifrit/ginkgomon"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Copy", func() {
	var logger lager.Logger

	BeforeEach(func() {
		logger = lagertest.NewTestLogger("test")
	})

	Describe("Copy", func() {
		var reader io.Reader
		var fakeWriter *fake_io.FakeWriter
		var wg *sync.WaitGroup

		BeforeEach(func() {
			reader = strings.NewReader("message")
			fakeWriter = &fake_io.FakeWriter{}
			wg = nil
		})

		JustBeforeEach(func() {
			helpers.Copy(logger, wg, fakeWriter, reader)
		})

		It("copies from source to target", func() {
			Expect(fakeWriter.WriteCallCount()).To(Equal(1))
			Expect(string(fakeWriter.WriteArgsForCall(0))).To(Equal("message"))
		})

		Context("when a wait group is provided", func() {
			BeforeEach(func() {
				wg = &sync.WaitGroup{}
				wg.Add(1)
			})

			It("calls done before returning", func() {
				wg.Wait()
			})
		})
	})

	Describe("CopyAndClose", func() {
		var reader io.Reader
		var fakeWriteCloser *fake_io.FakeWriteCloser
		var wg *sync.WaitGroup

		BeforeEach(func() {
			reader = strings.NewReader("message")
			fakeWriteCloser = &fake_io.FakeWriteCloser{}
			wg = nil
		})

		JustBeforeEach(func() {
			helpers.CopyAndClose(logger, wg, fakeWriteCloser, reader)
		})

		It("copies from source to target", func() {
			Expect(fakeWriteCloser.WriteCallCount()).To(Equal(1))
			Expect(string(fakeWriteCloser.WriteArgsForCall(0))).To(Equal("message"))
		})

		It("closes the target when the copy is complete", func() {
			Expect(fakeWriteCloser.CloseCallCount()).To(Equal(1))
		})

		Context("when a wait group is provided", func() {
			BeforeEach(func() {
				wg = &sync.WaitGroup{}
				wg.Add(1)
			})

			It("calls done before returning", func() {
				wg.Wait()
			})
		})
	})

	Describe("CopyRunner", func() {
		var (
			reader     io.Reader
			fakeWriter *fake_io.FakeWriteCloser
			runner     *helpers.CopyRunner
			process    ifrit.Process
		)

		BeforeEach(func() {
			reader = strings.NewReader("message")
			fakeWriter = &fake_io.FakeWriteCloser{}
			fakeWriter.WriteReturns(7, nil)
			runner = helpers.NewCopyRunner(logger, fakeWriter, reader)
		})

		JustBeforeEach(func() {
			process = ginkgomon.Invoke(runner)
		})

		AfterEach(func() {
			ginkgomon.Kill(process)
		})

		It("copies from source to target", func() {
			Eventually(process.Wait()).Should(Receive())
			Expect(fakeWriter.WriteCallCount()).To(Equal(1))
			Expect(string(fakeWriter.WriteArgsForCall(0))).To(Equal("message"))
		})

		Context("when writing fails", func() {
			BeforeEach(func() {
				fakeWriter.WriteReturns(0, errors.New("writing failed yo"))
			})

			It("returns an error", func() {
				var err error
				Eventually(process.Wait()).Should(Receive(&err))
				Expect(err).To(HaveOccurred())
			})
		})

		Context("when signalling the process", func() {
			var closed chan struct{}

			BeforeEach(func() {
				closed = make(chan struct{})
				fakeWriter.WriteStub = func(p []byte) (int, error) {
					<-closed
					return 0, nil
				}

				fakeWriter.CloseStub = func() error {
					close(closed)
					return nil
				}
			})

			It("closes the writer/reader and returns immediately", func() {
				var err error
				Consistently(process.Wait()).ShouldNot(Receive())
				process.Signal(os.Kill)
				Eventually(process.Wait()).Should(Receive(&err))
				Expect(err).NotTo(HaveOccurred())
				Expect(fakeWriter.CloseCallCount()).To(Equal(1))
			})
		})
	})
})
