package main

import "github.com/cloudfoundry/cli/plugin"

func main() {
	sshPlugin := &SSHPlugin{}
	plugin.Start(sshPlugin)
}
