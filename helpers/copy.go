package helpers

import (
	"io"
	"sync"

	"github.com/pivotal-golang/lager"
)

func Copy(logger lager.Logger, wg *sync.WaitGroup, dest io.Writer, src io.Reader) {
	logger = logger.Session("copy")
	logger.Info("started")

	io.Copy(dest, src)

	if wg != nil {
		wg.Done()
	}

	logger.Info("completed")
}

func CopyAndClose(logger lager.Logger, wg *sync.WaitGroup, dest io.WriteCloser, src io.Reader) {
	logger = logger.Session("copy")
	logger.Info("started")

	io.Copy(dest, src)
	dest.Close()

	if wg != nil {
		wg.Done()
	}

	logger.Info("completed")
}
