package helpers

import (
	"io"

	"github.com/pivotal-golang/lager"
)

func Copy(logger lager.Logger, dest io.Writer, src io.Reader) {
	logger = logger.Session("copy")
	logger.Info("started")

	io.Copy(dest, src)

	logger.Info("completed")
}

func CopyAndClose(logger lager.Logger, dest io.WriteCloser, src io.Reader) {
	logger = logger.Session("copy")
	logger.Info("started")

	io.Copy(dest, src)
	dest.Close()

	logger.Info("completed")
}
