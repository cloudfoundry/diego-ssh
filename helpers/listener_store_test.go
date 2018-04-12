package helpers_test

import (
	"net"
	"sync"

	"code.cloudfoundry.org/diego-ssh/helpers"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("ListenerStore", func() {
	var lnStore *helpers.ListenerStore
	JustBeforeEach(func() {
		lnStore = helpers.NewListenerStore()
	})

	It("concurrently adds and removes", func() {
		wg := sync.WaitGroup{}
		wg.Add(20)
		for i := 0; i < 20; i++ {
			go func() {
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				Expect(err).ToNot(HaveOccurred())
				lnStore.AddListener(ln.Addr().String(), ln)
				wg.Done()
			}()
		}
		wg.Wait()

		addrs := lnStore.ListAll()
		Expect(addrs).To(HaveLen(20))

		wg.Add(20)
		for i := 0; i < 20; i++ {
			go func(n int) {
				defer GinkgoRecover()
				err := lnStore.RemoveListener(addrs[n])
				Expect(err).ToNot(HaveOccurred())
				wg.Done()
			}(i)
		}
		wg.Wait()

		Expect(lnStore.ListAll()).To(HaveLen(0))
	})

	Describe("RemoveListener", func() {
		It("closes listeners when it removes them", func() {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			Expect(err).ToNot(HaveOccurred())
			lnStore.AddListener(ln.Addr().String(), ln)
			lnStore.RemoveListener(ln.Addr().String())
			_, err = ln.Accept()
			Expect(err).To(HaveOccurred())
		})

		It("errors if the requested listener does not exist", func() {
			err := lnStore.RemoveListener("127.0.0.1:12345")
			Expect(err).To(MatchError("RemoveListener error: addr 127.0.0.1:12345 doesn't exist"))
		})
	})

	Describe("RemoveAll", func() {
		It("removes and closes all listeners", func() {
			ln1, err := net.Listen("tcp", "127.0.0.1:0")
			Expect(err).ToNot(HaveOccurred())
			ln2, err := net.Listen("tcp", "127.0.0.1:0")

			lnStore.AddListener(ln1.Addr().String(), ln1)
			lnStore.AddListener(ln2.Addr().String(), ln2)

			lnStore.RemoveAll()
			Expect(lnStore.ListAll()).To(HaveLen(0))
			_, err = ln1.Accept()
			Expect(err).To(HaveOccurred())
			_, err = ln2.Accept()
			Expect(err).To(HaveOccurred())
		})
	})
})
