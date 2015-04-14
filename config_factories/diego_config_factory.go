package config_factories

import (
	"errors"
	"fmt"

	"github.com/pivotal-golang/lager"
	"golang.org/x/crypto/ssh"
)

type DiegoConfigFactory struct {
	logger     lager.Logger
	privateKey ssh.Signer
}

func NewDiegoConfigFactory(logger lager.Logger, privateKey ssh.Signer) *DiegoConfigFactory {
	return &DiegoConfigFactory{
		logger:     logger,
		privateKey: privateKey,
	}
}

func (factory *DiegoConfigFactory) Create(perms *ssh.Permissions) (*ssh.ClientConfig, string, error) {
	if perms == nil {
		return nil, "", errors.New("permissions are required")
	}

	address := fmt.Sprintf("%s:%s", perms.CriticalOptions["diego:container-address"], perms.CriticalOptions["diego:ssh-daemon-port"])

	clientConfig := &ssh.ClientConfig{
		Auth: []ssh.AuthMethod{ssh.PublicKeys(factory.privateKey)},
	}

	return clientConfig, address, nil
}
