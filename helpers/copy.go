package helpers

import (
	"io"
	"os"
	"sync"

	"github.com/pivotal-golang/lager"
)

func Copy(logger lager.Logger, wg *sync.WaitGroup, dest io.Writer, src io.Reader) {
	defer func() {
		if wg != nil {
			wg.Done()
		}
	}()

	logger = logger.Session("copy")
	logger.Info("started")

	n, err := io.Copy(dest, src)
	if err != nil {
		logger.Error("copy-error", err)
	}

	logger.Info("completed", lager.Data{"bytes-copied": n})
}

func CopyAndClose(logger lager.Logger, wg *sync.WaitGroup, dest io.WriteCloser, src io.Reader) {
	defer func() {
		if wg != nil {
			wg.Done()
		}
	}()

	logger = logger.Session("copy-and-close")
	logger.Info("started")

	n, err := io.Copy(dest, src)
	if err != nil {
		logger.Error("copy-error", err)
	}

	dest.Close()

	logger.Info("completed", lager.Data{"bytes-copied": n})
}

type CopyRunner struct {
	logger lager.Logger
	dest   io.WriteCloser
	src    io.Reader
}

func NewCopyRunner(logger lager.Logger, dest io.WriteCloser, src io.Reader) *CopyRunner {
	return &CopyRunner{
		logger: logger,
		dest:   dest,
		src:    src,
	}
}

func (r *CopyRunner) Run(signals <-chan os.Signal, ready chan<- struct{}) error {
	errCh := make(chan error)

	logger := r.logger.Session("copy-runner")
	logger.Info("started")

	go func() {
		n, err := io.Copy(r.dest, r.src)
		if err != nil {
			logger.Error("copy-error", err)
		} else {
			logger.Info("copy-finished", lager.Data{"bytes-copied": n})
		}
		errCh <- err
	}()

	close(ready)

	var err error

	select {
	case signal := <-signals:
		logger.Info("signaled", lager.Data{"signal": signal})
		r.dest.Close()
	case err = <-errCh:
		logger.Info("completed")
	}

	return err
}
