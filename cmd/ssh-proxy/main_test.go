package main_test

import (
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"time"

	"github.com/cloudfoundry-incubator/receptor"
	"github.com/tedsuo/ifrit"
	"github.com/tedsuo/ifrit/ginkgomon"
	"golang.org/x/crypto/ssh"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/onsi/gomega/gexec"
	"github.com/onsi/gomega/ghttp"
)

var _ = Describe("SSH proxy", func() {
	var (
		fakeReceptor *ghttp.Server
		runner       ifrit.Runner
		process      ifrit.Process
		exitDuration = 3 * time.Second

		address string
		hostKey []byte
	)

	startSSHProxy := func() *ginkgomon.Runner {
		runner := ginkgomon.New(ginkgomon.Config{
			Name:              "ssh-proxy",
			AnsiColorCode:     "1;97m",
			StartCheck:        "ssh-proxy.started",
			StartCheckTimeout: 10 * time.Second,
			Command: exec.Command(
				sshProxyPath,
				"-address", address,
				"-hostKey", string(hostKey),
				"-privateKey", string(hostKey),
				"-diegoAPIURL", fakeReceptor.URL(),
			),
		})

		return runner
	}

	BeforeEach(func() {
		hostKey = hostKeyPem
		address = fmt.Sprintf("127.0.0.1:%d", sshProxyPort)

		actualLRP := receptor.ActualLRPResponse{
			ProcessGuid:  "process-guid",
			Index:        0,
			InstanceGuid: "some-instance-guid",
			Address:      "1.2.3.4",
			Ports: []receptor.PortMapping{
				{ContainerPort: 2222, HostPort: 3333},
			},
		}

		fakeReceptor = ghttp.NewServer()
		fakeReceptor.AppendHandlers(
			ghttp.CombineHandlers(
				ghttp.VerifyRequest("GET", "/v1/actual_lrps/process-guid/index/0"),
				ghttp.RespondWithJSONEncoded(http.StatusOK, actualLRP),
			),
		)
	})

	Describe("argument validation", func() {
		JustBeforeEach(func() {
			runner = startSSHProxy()
			process = ifrit.Invoke(runner)
		})

		AfterEach(func() {
			ginkgomon.Kill(process, exitDuration)
		})

		Context("when an ill-formed host key is provided", func() {
			BeforeEach(func() {
				hostKey = []byte("host-key")
			})

			It("reports and dies", func() {
				Ω(runner).Should(gbytes.Say("failed-to-parse-host-key"))
				Ω(runner).ShouldNot(gexec.Exit(0))
			})
		})

	})

	Describe("execution", func() {
		var (
			client       *ssh.Client
			dialErr      error
			clientConfig *ssh.ClientConfig
		)

		JustBeforeEach(func() {
			runner = startSSHProxy()
			process = ginkgomon.Invoke(runner)
			Ω(process).ShouldNot(BeNil())

			client, dialErr = ssh.Dial("tcp", address, clientConfig)
		})

		AfterEach(func() {
			ginkgomon.Interrupt(process, exitDuration)

			if client != nil {
				client.Close()
			}
		})

		Context("when a host key is specified", func() {
			var handshakeHostKey ssh.PublicKey

			BeforeEach(func() {
				clientConfig = &ssh.ClientConfig{
					HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
						handshakeHostKey = key
						return nil
					},
					User: "diego:process-guid/0",
					Auth: []ssh.AuthMethod{
						ssh.Password(":"),
					},
				}
			})

			It("uses the host key provided on the command line", func() {
				sshHostKey, err := ssh.ParsePrivateKey(hostKeyPem)
				Ω(err).ShouldNot(HaveOccurred())

				sshPublicHostKey := sshHostKey.PublicKey()
				Ω(sshPublicHostKey.Marshal()).Should(Equal(handshakeHostKey.Marshal()))
			})
		})
	})
})
