package helpers

import (
	"io"

	"github.com/pivotal-golang/lager"
)

func Copy(logger lager.Logger, dest io.Writer, src io.Reader) {
	logger = logger.Session("copy")
	logger.Info("started")
	defer logger.Info("completed")

	io.Copy(dest, src)
}

func CopyAndClose(logger lager.Logger, dest io.WriteCloser, src io.Reader) {
	logger = logger.Session("copy")
	logger.Info("started")
	defer logger.Info("completed")

	defer dest.Close()
	io.Copy(dest, src)
}
