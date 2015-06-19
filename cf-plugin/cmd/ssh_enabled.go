package cmd

import (
	"fmt"
	"io"

	"github.com/cloudfoundry-incubator/diego-ssh/cf-plugin/models/app"
)

const SSHEnabledUsage = "cf ssh-enabled APP_NAME"

func SSHEnabled(args []string, appFactory app.AppFactory, output io.Writer) error {
	if len(args) != 2 || args[0] != "ssh-enabled" {
		fmt.Fprintf(output, "FAILED\n\n%s\n%s", "Invalid usage", SSHEnabledUsage)
		return nil
	}

	app, err := appFactory.Get(args[1])
	if err != nil {
		return err
	}

	fmt.Fprintf(output, "%t", app.EnableSSH)
	return nil
}
