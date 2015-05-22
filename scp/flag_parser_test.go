package scp_test

import (
	"github.com/cloudfoundry-incubator/diego-ssh/scp"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("FlagParser", func() {
	Context("when invalid flags are specified", func() {
		It("returns an error", func() {
			_, err := scp.ParseFlags([]string{"scp", "-xxx", "/tmp/foo"})
			Expect(err).To(HaveOccurred())
		})
	})

	Context("when unix style command concatenated args are used", func() {
		It("parses command line flags and returns SCPOptions", func() {
			scpOptions, err := scp.ParseFlags([]string{"scp", "-tdvpr", "/tmp/foo"})
			Expect(err).NotTo(HaveOccurred())

			Expect(scpOptions.TargetMode).To(BeTrue())
			Expect(scpOptions.SourceMode).To(BeFalse())
			Expect(scpOptions.TargetIsDirectory).To(BeTrue())
			Expect(scpOptions.Verbose).To(BeTrue())
			Expect(scpOptions.PreserveTimes).To(BeTrue())
			Expect(scpOptions.Recursive).To(BeTrue())
			Expect(scpOptions.Target).To(Equal("/tmp/foo"))
		})
	})

	Context("when separate flags arguments are used", func() {
		It("parses command line flags and returns SCPOptions", func() {
			scpOptions, err := scp.ParseFlags([]string{"scp", "-t", "-d", "-v", "-p", "-r", "/tmp/foo"})
			Expect(err).NotTo(HaveOccurred())

			Expect(scpOptions.TargetMode).To(BeTrue())
			Expect(scpOptions.SourceMode).To(BeFalse())
			Expect(scpOptions.TargetIsDirectory).To(BeTrue())
			Expect(scpOptions.Verbose).To(BeTrue())
			Expect(scpOptions.PreserveTimes).To(BeTrue())
			Expect(scpOptions.Recursive).To(BeTrue())
			Expect(scpOptions.Target).To(Equal("/tmp/foo"))
		})
	})

	Context("when source mode is specified", func() {
		It("returns SCPOptions with SourceMode enabled", func() {
			scpOptions, err := scp.ParseFlags([]string{"scp", "-f", "/tmp/foo"})
			Expect(err).NotTo(HaveOccurred())
			Expect(scpOptions.SourceMode).To(BeTrue())
		})

		It("does not allow TargetMode to be enabled", func() {
			_, err := scp.ParseFlags([]string{"scp", "-ft"})
			Expect(err).To(HaveOccurred())
		})

		Context("Arguments", func() {
			It("populates the Sources with following arguments", func() {
				scpOptions, err := scp.ParseFlags([]string{"scp", "-f", "/foo/bar", "/baz/buzz"})
				Expect(err).NotTo(HaveOccurred())
				Expect(scpOptions.Sources).To(Equal([]string{"/foo/bar", "/baz/buzz"}))
			})

			It("returns an empty string for Target", func() {
				scpOptions, err := scp.ParseFlags([]string{"scp", "-f", "/foo/bar", "/baz/buzz"})
				Expect(err).NotTo(HaveOccurred())
				Expect(scpOptions.Target).To(BeEmpty())
			})

			Context("when no argument is provided", func() {
				It("returns an error", func() {
					_, err := scp.ParseFlags([]string{"scp", "-f"})
					Expect(err).To(MatchError("Must specify at least one source in source mode"))
				})
			})
		})
	})

	Context("when target mode is specified", func() {
		It("returns SCPOptions with TargetMode enabled", func() {
			scpOptions, err := scp.ParseFlags([]string{"scp", "-t", "/tmp/foo"})
			Expect(err).NotTo(HaveOccurred())
			Expect(scpOptions.TargetMode).To(BeTrue())
		})

		It("does not allow SourceMode to be enabled", func() {
			_, err := scp.ParseFlags([]string{"scp", "-tf"})
			Expect(err).To(HaveOccurred())
		})

		Context("Arguments", func() {
			It("populates the Target with the argument", func() {
				scpOptions, err := scp.ParseFlags([]string{"scp", "-t", "/foo/bar"})
				Expect(err).NotTo(HaveOccurred())
				Expect(scpOptions.Target).To(Equal("/foo/bar"))
			})

			It("returns an empty array for Sources", func() {
				scpOptions, err := scp.ParseFlags([]string{"scp", "-t", "/foo/bar"})
				Expect(err).NotTo(HaveOccurred())
				Expect(scpOptions.Sources).To(BeEmpty())
			})

			Context("when no argument is provided", func() {
				It("returns an error", func() {
					_, err := scp.ParseFlags([]string{"scp", "-t"})
					Expect(err).To(MatchError("Must specify one target in target mode"))
				})
			})

			Context("when more than one argument is provided", func() {
				It("returns an error", func() {
					_, err := scp.ParseFlags([]string{"scp", "-t", "/foo/bar", "/baz/buzz"})
					Expect(err).To(MatchError("Must specify one target in target mode"))
				})
			})
		})
	})

	Context("when neither target or source mode is specified", func() {
		It("does not allow this", func() {
			_, err := scp.ParseFlags([]string{"scp", ""})
			Expect(err).To(HaveOccurred())
		})
	})

	Context("when the command is not scp", func() {
		It("returns an error", func() {
			_, err := scp.ParseFlags([]string{"foobar", ""})
			Expect(err).To(HaveOccurred())
		})
	})
})
