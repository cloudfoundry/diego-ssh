package helpers_test

import (
	"strings"

	"github.com/cloudfoundry-incubator/diego-ssh/helpers"
	"github.com/cloudfoundry-incubator/diego-ssh/test_helpers/fake_io"
	"github.com/pivotal-golang/lager"
	"github.com/pivotal-golang/lager/lagertest"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Copy", func() {
	var logger lager.Logger

	BeforeEach(func() {
		logger = lagertest.NewTestLogger("test")
	})

	Describe("Copy", func() {
		var fakeWriter *fake_io.FakeWriter

		BeforeEach(func() {
			reader := strings.NewReader("message")
			fakeWriter = &fake_io.FakeWriter{}
			helpers.Copy(logger, fakeWriter, reader)
		})

		It("copies from source to target", func() {
			Ω(fakeWriter.WriteCallCount()).Should(Equal(1))
			Ω(string(fakeWriter.WriteArgsForCall(0))).Should(Equal("message"))
		})
	})

	Describe("CopyAndClose", func() {
		var fakeWriteCloser *fake_io.FakeWriteCloser

		BeforeEach(func() {
			reader := strings.NewReader("message")
			fakeWriteCloser = &fake_io.FakeWriteCloser{}
			helpers.CopyAndClose(logger, fakeWriteCloser, reader)
		})

		It("copies from source to target", func() {
			Ω(fakeWriteCloser.WriteCallCount()).Should(Equal(1))
			Ω(string(fakeWriteCloser.WriteArgsForCall(0))).Should(Equal("message"))
		})

		It("closes the target when the copy is complete", func() {
			Ω(fakeWriteCloser.CloseCallCount()).Should(Equal(1))
		})
	})
})
