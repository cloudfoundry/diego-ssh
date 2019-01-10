package helpers_test

import (
	"crypto/x509"
	"io/ioutil"
	"net/http"
	"time"

	"code.cloudfoundry.org/diego-ssh/helpers"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("NewHTTPSClient", func() {
	var (
		caCertFiles        []string
		insecureSkipVerify bool
		timeout            time.Duration
	)

	BeforeEach(func() {
		caCertFiles = []string{}
	})

	It("sets InsecureSkipVerify on the TLS config", func() {
		client, err := helpers.NewHTTPSClient(true, caCertFiles, timeout)
		Expect(err).NotTo(HaveOccurred())
		httpTrans, ok := client.Transport.(*http.Transport)
		Expect(ok).To(BeTrue())
		Expect(httpTrans.TLSClientConfig.InsecureSkipVerify).To(BeTrue())
	})

	It("sets the client timeout", func() {
		client, err := helpers.NewHTTPSClient(insecureSkipVerify, caCertFiles, 5*time.Second)
		Expect(err).NotTo(HaveOccurred())
		Expect(client.Timeout).To(Equal(5 * time.Second))
	})

	Context("when a list of ca Cert files is provided", func() {
		BeforeEach(func() {
			caCertFiles = []string{"fixtures/ca_cert_0.crt", "fixtures/ca_cert_1.crt"}
		})

		It("sets the RootCAs with a pool consisting of those CAs", func() {
			expectedPool := x509.NewCertPool()
			for _, caCert := range caCertFiles {
				certBytes, err := ioutil.ReadFile(caCert)
				Expect(err).NotTo(HaveOccurred())

				Expect(expectedPool.AppendCertsFromPEM(certBytes)).To(BeTrue())
			}

			client, err := helpers.NewHTTPSClient(insecureSkipVerify, caCertFiles, timeout)
			Expect(err).NotTo(HaveOccurred())
			httpTrans, ok := client.Transport.(*http.Transport)
			Expect(ok).To(BeTrue())

			caPool := httpTrans.TLSClientConfig.RootCAs

			Expect(expectedPool).To(Equal(caPool))
		})

		Context("when an invalid tls cert is provided", func() {
			BeforeEach(func() {
				caCertFiles = []string{"fixtures/ca_cert_0.crt", "fixtures/invalid.crt"}
			})

			It("returns an error", func() {
				_, err := helpers.NewHTTPSClient(insecureSkipVerify, caCertFiles, timeout)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("Unable to load caCert"))
			})
		})

		Context("when the UAA tls cert does not exist", func() {
			BeforeEach(func() {
				caCertFiles = []string{"fixtures/ca_cert_0.crt", "doesntexist"}
			})

			It("returns an error", func() {
				_, err := helpers.NewHTTPSClient(insecureSkipVerify, caCertFiles, timeout)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("failed to read ca cert file"))
			})
		})
	})
})
