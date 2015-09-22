package cmd

import (
	"fmt"
	"io"

	"github.com/cloudfoundry-incubator/diego-ssh/cf-plugin/models/credential"
)

const GetSSHCodeUsage = "cf get-ssh-code"

func GetSSHCode(
	args []string,
	credFactory credential.CredentialFactory,
	output io.Writer,
) error {
	if len(args) != 1 || args[0] != "get-ssh-code" {
		return fmt.Errorf("%s\n%s", "Invalid usage", GetSSHCodeUsage)
	}

	code, err := credFactory.AuthorizationCode()
	if err != nil {
		return err
	}

	fmt.Fprintf(output, "%s\n", code)
	return nil
}
