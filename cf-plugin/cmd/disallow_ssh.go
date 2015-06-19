package cmd

import (
	"fmt"
	"io"

	"github.com/cloudfoundry-incubator/diego-ssh/cf-plugin/models/space"
)

const DisallowSSHUsage = "cf disallow-space-ssh SPACE_NAME"

func DisallowSSH(args []string, spaceFactory space.SpaceFactory, output io.Writer) error {
	if len(args) != 2 || args[0] != "disallow-space-ssh" {
		fmt.Fprintf(output, "FAILED\n\n%s\n%s", "Invalid usage", DisallowSSHUsage)
		return nil
	}

	space, err := spaceFactory.Get(args[1])
	if err != nil {
		return err
	}

	err = spaceFactory.SetBool(space, "allow_ssh", false)
	if err != nil {
		return err
	}

	return nil
}
