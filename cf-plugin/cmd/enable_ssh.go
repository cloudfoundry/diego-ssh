package cmd

import (
	"fmt"
	"io"

	"github.com/cloudfoundry-incubator/diego-ssh/cf-plugin/models/app"
)

const EnableSSHUsage = "cf enable-ssh APP_NAME"

func EnableSSH(args []string, appFactory app.AppFactory, output io.Writer) error {
	if len(args) != 2 || args[0] != "enable-ssh" {
		fmt.Fprintf(output, "FAILED\n\n%s\n%s", "Invalid usage", EnableSSHUsage)
		return nil
	}

	app, err := appFactory.Get(args[1])
	if err != nil {
		return err
	}

	err = appFactory.SetBool(app, "enable-ssh", true)
	if err != nil {
		return err
	}

	return nil
}
