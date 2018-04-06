package helpers

import (
	"fmt"
	"io"
	"sync"

	"code.cloudfoundry.org/lager"
)

func Copy(logger lager.Logger, wg *sync.WaitGroup, dest io.Writer, src io.Reader) {
	logger = logger.Session("copy")
	logger.Info("start")
	defer logger.Info("done")

	defer func() {
		if e := recover(); e != nil {
			logger.Error("PANIC", fmt.Errorf("%#v  --  %s", e, e), lager.Data{"panic": e})
		} else {
			logger.Info("clean-exit")
		}
	}()

	defer func() {
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

func CopyAndClose(logger lager.Logger, wg *sync.WaitGroup, dest io.WriteCloser, src io.Reader, closeFunc func()) {
	logger = logger.Session("copy-and-close")
	logger.Info("start")
	defer logger.Info("done")

	defer func() {
		if e := recover(); e != nil {
			logger.Error("PANIC", fmt.Errorf("%#v  --  %s", e, e), lager.Data{"panic": e})
		} else {
			logger.Info("clean-exit")
		}
	}()

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
