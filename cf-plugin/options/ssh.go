package options

import (
	"bytes"
	"errors"

	"github.com/pborman/getopt"
)

type TTYRequest int

const (
	REQUEST_TTY_AUTO TTYRequest = iota
	REQUEST_TTY_NO
	REQUEST_TTY_YES
	REQUEST_TTY_FORCE
)

type SSHOptions struct {
	AppName            string
	Command            []string
	Instance           uint
	SkipHostValidation bool
	TerminalRequest    TTYRequest

	getoptSet                       *getopt.Set
	instanceOption                  getopt.Option
	skipHostValidationOption        getopt.Option
	disableTerminalAllocationOption getopt.Option
	forceTerminalAllocationOption   getopt.Option
}

var UsageError = errors.New("Invalid usage")

func NewSSHOptions() *SSHOptions {
	sshOptions := &SSHOptions{}

	opts := getopt.New()

	sshOptions.instanceOption = opts.UintVarLong(&sshOptions.Instance, "instance", 'i', "application instance id", "instance-id")
	sshOptions.skipHostValidationOption = opts.BoolVarLong(&sshOptions.SkipHostValidation, "skip-host-validation", 'k', "skip host key validation").SetFlag()

	var force, disable bool
	sshOptions.forceTerminalAllocationOption = opts.BoolVar(&force, 't', "force pseudo-tty allocation").SetFlag()
	sshOptions.disableTerminalAllocationOption = opts.BoolVar(&disable, 'T', "disable pseudo-tty allocation").SetFlag()

	sshOptions.getoptSet = opts

	return sshOptions
}

func (o *SSHOptions) Parse(args []string) error {
	opts := o.getoptSet
	err := opts.Getopt(args, nil)
	if err != nil {
		return err
	}

	if len(args) == 0 || args[0] != "ssh" {
		return UsageError
	}

	if opts.NArgs() == 0 {
		return UsageError
	}

	o.AppName = opts.Arg(0)

	if opts.NArgs() > 0 {
		err = opts.Getopt(opts.Args(), nil)
		if err != nil {
			return err
		}

		o.Command = opts.Args()
	}

	if o.forceTerminalAllocationOption.Count() == 1 {
		o.TerminalRequest = REQUEST_TTY_YES
	} else if o.forceTerminalAllocationOption.Count() > 1 {
		o.TerminalRequest = REQUEST_TTY_FORCE
	}

	if o.disableTerminalAllocationOption.Count() != 0 {
		o.TerminalRequest = REQUEST_TTY_NO
	}

	return nil
}

func SSHUsage() string {
	b := &bytes.Buffer{}

	o := NewSSHOptions()
	o.getoptSet.SetProgram("ssh")
	o.getoptSet.SetParameters("app-name [command]")
	o.getoptSet.PrintUsage(b)

	return b.String()
}
