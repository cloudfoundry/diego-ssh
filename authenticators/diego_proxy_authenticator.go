package authenticators

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"strconv"

	"github.com/cloudfoundry-incubator/receptor"
	"github.com/pivotal-golang/lager"
	"golang.org/x/crypto/ssh"
)

type DiegoProxyAuthenticator struct {
	logger         lager.Logger
	receptorCreds  []byte
	receptorClient receptor.Client
}

var UserRegex *regexp.Regexp = regexp.MustCompile(`diego:(.*)/(\d+)`)

var InvalidDomainErr error = errors.New("Invalid authentication domain")
var InvalidCredentialsErr error = errors.New("Invalid credentials")

func NewDiegoProxyAuthenticator(logger lager.Logger, receptorClient receptor.Client, receptorCreds []byte) *DiegoProxyAuthenticator {
	return &DiegoProxyAuthenticator{
		logger:         logger,
		receptorCreds:  receptorCreds,
		receptorClient: receptorClient,
	}
}

func (dpa *DiegoProxyAuthenticator) Authenticate(metadata ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	logger := dpa.logger.Session("authenticate")
	logger.Info("authentication-starting")
	defer logger.Info("authentication-finished")

	if !UserRegex.MatchString(metadata.User()) {
		logger.Error("regex-match-fail", InvalidDomainErr)
		return nil, InvalidDomainErr
	}

	if !bytes.Equal(dpa.receptorCreds, password) {
		logger.Error("invalid-credentials", InvalidCredentialsErr)
		return nil, InvalidCredentialsErr
	}

	guidAndIndex := UserRegex.FindStringSubmatch(metadata.User())

	processGuid := guidAndIndex[1]
	index, err := strconv.Atoi(guidAndIndex[2])
	if err != nil {
		logger.Error("atoi-failed", err)
		return nil, err
	}

	lrpResponse, err := dpa.receptorClient.ActualLRPByProcessGuidAndIndex(processGuid, index)
	if err != nil {
		logger.Error("get-lrp-failed", err)
		return nil, err
	}

	return dpa.createPermissions(&lrpResponse), nil
}

func (dpa *DiegoProxyAuthenticator) createPermissions(lrp *receptor.ActualLRPResponse) *ssh.Permissions {
	for _, mapping := range lrp.Ports {
		if mapping.ContainerPort == 2222 {
			return &ssh.Permissions{
				CriticalOptions: map[string]string{
					"diego:process-guid":      lrp.ProcessGuid,
					"diego:index":             fmt.Sprintf("%d", lrp.Index),
					"diego:instance-guid":     lrp.InstanceGuid,
					"diego:container-address": lrp.Address,
					"diego:ssh-daemon-port":   fmt.Sprintf("%d", mapping.HostPort),
				},
			}
		}
	}

	return nil
}
