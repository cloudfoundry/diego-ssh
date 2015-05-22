package scp_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestScp(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Scp Suite")
}
