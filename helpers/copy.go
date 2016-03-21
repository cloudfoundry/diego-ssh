package helpers

import (
	"io"
	"sync"

	"github.com/pivotal-golang/lager"
)

func Copy(logger lager.Logger, wg *sync.WaitGroup, dest io.Writer, src io.Reader) {
	logger = logger.Session("copy")
	logger.Info("started")

	n, err := io.Copy(dest, src)
	if err != nil {
		logger.Error("copy-error", err)
	}

	logger.Info("completed", lager.Data{"bytes-copied": n})

	if wg != nil {
		wg.Done()
	}
}

func CopyAndClose(logger lager.Logger, wg *sync.WaitGroup, dest io.WriteCloser, src io.Reader, closeFunc func()) {
	logger = logger.Session("copy-and-close")
	logger.Info("started")

	defer func() {
		closeFunc()

		if wg != nil {
			wg.Done()
		}
	}()

	n, err := io.Copy(dest, src)
	if err != nil {
		logger.Error("copy-error", err)
	}

	logger.Info("completed", lager.Data{"bytes-copied": n})
}
