package authenticators

import (
	"bytes"
	"regexp"
	"strconv"

	"github.com/pivotal-golang/lager"
	"golang.org/x/crypto/ssh"
)

var DiegoUserRegex *regexp.Regexp = regexp.MustCompile(`diego:(.+)/(\d+)`)

type DiegoProxyAuthenticator struct {
	logger             lager.Logger
	credentials        []byte
	permissionsBuilder PermissionsBuilder
}

func NewDiegoProxyAuthenticator(
	logger lager.Logger,
	credentials []byte,
	permissionsBuilder PermissionsBuilder,
) *DiegoProxyAuthenticator {
	return &DiegoProxyAuthenticator{
		logger:             logger,
		credentials:        credentials,
		permissionsBuilder: permissionsBuilder,
	}
}

func (dpa *DiegoProxyAuthenticator) UserRegexp() *regexp.Regexp {
	return DiegoUserRegex
}

func (dpa *DiegoProxyAuthenticator) Authenticate(metadata ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	logger := dpa.logger.Session("authenticate")
	logger.Info("authentication-starting")
	defer logger.Info("authentication-finished")

	if !DiegoUserRegex.MatchString(metadata.User()) {
		logger.Error("regex-match-fail", InvalidDomainErr)
		return nil, InvalidDomainErr
	}

	if !bytes.Equal(dpa.credentials, password) {
		logger.Error("invalid-credentials", InvalidCredentialsErr)
		return nil, InvalidCredentialsErr
	}

	guidAndIndex := DiegoUserRegex.FindStringSubmatch(metadata.User())

	processGuid := guidAndIndex[1]
	index, err := strconv.Atoi(guidAndIndex[2])
	if err != nil {
		logger.Error("atoi-failed", err)
		return nil, err
	}

	permissions, err := dpa.permissionsBuilder.Build(processGuid, index, metadata)
	if err != nil {
		logger.Error("building-ssh-permissions-failed", err)
	}
	return permissions, err
}
