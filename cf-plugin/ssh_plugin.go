package main

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/cloudfoundry-incubator/diego-ssh/cf-plugin/cmd"
	"github.com/cloudfoundry-incubator/diego-ssh/cf-plugin/models"
	"github.com/cloudfoundry-incubator/diego-ssh/cf-plugin/models/app"
	"github.com/cloudfoundry-incubator/diego-ssh/cf-plugin/models/credential"
	"github.com/cloudfoundry-incubator/diego-ssh/cf-plugin/models/info"
	"github.com/cloudfoundry-incubator/diego-ssh/cf-plugin/models/space"
	"github.com/cloudfoundry-incubator/diego-ssh/cf-plugin/options"
	"github.com/cloudfoundry-incubator/diego-ssh/cf-plugin/terminal"
	"github.com/cloudfoundry/cli/plugin"
	"golang.org/x/crypto/ssh"
)

type SSHPlugin struct {
	OutputWriter io.Writer
}

func (p *SSHPlugin) GetMetadata() plugin.PluginMetadata {
	return plugin.PluginMetadata{
		Name: "Diego-SSH",
		Version: plugin.VersionType{
			Major: 0,
			Minor: 2,
			Build: 1,
		},
		Commands: []plugin.Command{
			{
				Name:     "ssh",
				HelpText: "ssh to an application container instance",
				UsageDetails: plugin.Usage{
					Usage: options.SSHUsage(),
				},
			},
			{
				Name:     "enable-ssh",
				HelpText: "enable ssh for the application",
				UsageDetails: plugin.Usage{
					Usage: cmd.EnableSSHUsage,
				},
			},
			{
				Name:     "disable-ssh",
				HelpText: "disable ssh for the application",
				UsageDetails: plugin.Usage{
					Usage: cmd.DisableSSHUsage,
				},
			},
			{
				Name:     "ssh-enabled",
				HelpText: "reports whether SSH is enabled on an application container instance",
				UsageDetails: plugin.Usage{
					Usage: cmd.SSHEnabledUsage,
				},
			},
			{
				Name:     "allow-space-ssh",
				HelpText: "allow SSH access for the space",
				UsageDetails: plugin.Usage{
					Usage: cmd.AllowSSHUsage,
				},
			},
			{
				Name:     "disallow-space-ssh",
				HelpText: "disallow SSH access for the space",
				UsageDetails: plugin.Usage{
					Usage: cmd.DisallowSSHUsage,
				},
			},
			{
				Name:     "space-ssh-allowed",
				HelpText: "reports whether SSH is allowed in a space",
				UsageDetails: plugin.Usage{
					Usage: cmd.SSHAllowedUsage,
				},
			},
			{
				Name:     "get-ssh-code",
				HelpText: "get a one time password for ssh clients",
				UsageDetails: plugin.Usage{
					Usage: cmd.GetSSHCodeUsage,
				},
			},
		},
	}
}

func (p *SSHPlugin) Run(cli plugin.CliConnection, args []string) {
	p.OutputWriter = os.Stdout
	appFactory := app.NewAppFactory(cli, models.Curl)
	infoFactory := info.NewInfoFactory(cli)
	credFactory := credential.NewCredentialFactory(cli, infoFactory)
	spaceFactory := space.NewSpaceFactory(cli, models.Curl)

	switch args[0] {
	case "CLI-MESSAGE-UNINSTALL":
		return
	case "enable-ssh":
		err := cmd.EnableSSH(args, appFactory)
		if err != nil {
			p.Fatal(err)
		}
	case "disable-ssh":
		err := cmd.DisableSSH(args, appFactory)
		if err != nil {
			p.Fatal(err)
		}
	case "ssh-enabled":
		err := cmd.SSHEnabled(args, appFactory, p.OutputWriter)
		if err != nil {
			p.Fatal(err)
		}
	case "allow-space-ssh":
		err := cmd.AllowSSH(args, spaceFactory)
		if err != nil {
			p.Fatal(err)
		}
	case "disallow-space-ssh":
		err := cmd.DisallowSSH(args, spaceFactory)
		if err != nil {
			p.Fatal(err)
		}
	case "space-ssh-allowed":
		err := cmd.SSHAllowed(args, spaceFactory, p.OutputWriter)
		if err != nil {
			p.Fatal(err)
		}
	case "get-ssh-code":
		err := cmd.GetSSHCode(args, credFactory, p.OutputWriter)
		if err != nil {
			p.Fatal(err)
		}
	case "ssh":
		opts := options.NewSSHOptions()
		err := opts.Parse(args)
		if err != nil {
			p.Fail(err.Error())
			fmt.Fprintf(p.OutputWriter, options.SSHUsage())
			return
		}

		secureShell := cmd.NewSecureShell(
			cmd.DefaultSecureDialer(),
			terminal.DefaultHelper(),
			cmd.DefaultListenerFactory(),
			30*time.Second,
			appFactory,
			infoFactory,
			credFactory,
		)

		err = secureShell.Connect(opts)
		if err != nil {
			p.Fail(err.Error())
			return
		}
		defer secureShell.Close()

		err = secureShell.LocalPortForward()
		if err != nil {
			return
		}

		if opts.SkipRemoteExecution {
			err = secureShell.Wait()
		} else {
			err = secureShell.InteractiveSession()
		}

		if err == nil {
			return
		}

		if exitError, ok := err.(*ssh.ExitError); ok {
			exitStatus := exitError.ExitStatus()
			if sig := exitError.Signal(); sig != "" {
				fmt.Printf("Process terminated by signal: %s. Exited with %d.\n", sig, exitStatus)
			}
			os.Exit(exitStatus)
		} else {
			p.Fail(err.Error())
		}

	default:
		p.Fail("Invalid command")
	}
}

func (p *SSHPlugin) Fatal(err error) {
	p.Fail(err.Error())
	os.Exit(1)
}

func (p *SSHPlugin) Fail(message string) {
	fmt.Fprintf(p.OutputWriter, "FAILED\n\n%s\n", message)
}
