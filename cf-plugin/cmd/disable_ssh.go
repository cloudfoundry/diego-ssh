package cmd

import (
	"fmt"
	"io"

	"github.com/cloudfoundry-incubator/diego-ssh/cf-plugin/models/app"
)

const DisableSSHUsage = "cf disable-ssh APP_NAME"

func DisableSSH(args []string, appFactory app.AppFactory, output io.Writer) error {
	if len(args) != 2 || args[0] != "disable-ssh" {
		fmt.Fprintf(output, "FAILED\n\n%s\n%s", "Invalid usage", DisableSSHUsage)
		return nil
	}

	app, err := appFactory.Get(args[1])
	if err != nil {
		return err
	}

	err = appFactory.SetBool(app, "enable_ssh", false)
	if err != nil {
		return err
	}

	return nil
}
