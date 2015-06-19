package cmd

import (
	"fmt"
	"io"

	"github.com/cloudfoundry-incubator/diego-ssh/cf-plugin/models/space"
)

const AllowSSHUsage = "cf allow-space-ssh SPACE_NAME"

func AllowSSH(args []string, spaceFactory space.SpaceFactory, output io.Writer) error {
	if len(args) != 2 || args[0] != "allow-space-ssh" {
		fmt.Fprintf(output, "FAILED\n\n%s\n%s", "Invalid usage", AllowSSHUsage)
		return nil
	}

	space, err := spaceFactory.Get(args[1])
	if err != nil {
		return err
	}

	err = spaceFactory.SetBool(space, "allow_ssh", true)
	if err != nil {
		return err
	}

	return nil
}
