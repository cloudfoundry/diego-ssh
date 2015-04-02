package helpers

import (
	"io"

	"github.com/pivotal-golang/lager"
)

func Copy(logger lager.Logger, dest io.Writer, src io.Reader) {
	logger = logger.Session("copy")
	logger.Info("started")
	defer logger.Info("completed")

	bytes, err := io.Copy(dest, src)
	logger.Info("copy-return", lager.Data{"bytes": bytes, "err": err})
}

func CopyAndClose(logger lager.Logger, dest io.WriteCloser, src io.Reader) {
	logger = logger.Session("copy")
	logger.Info("started")
	defer logger.Info("completed")

	defer dest.Close()
	io.Copy(dest, src)
}
