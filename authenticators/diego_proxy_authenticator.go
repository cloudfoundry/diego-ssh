package authenticators

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"

	"github.com/cloudfoundry-incubator/diego-ssh/models"
	"github.com/cloudfoundry-incubator/diego-ssh/proxy"
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
var RouteNotFoundErr error = errors.New("SSH routing info not found")

func NewDiegoProxyAuthenticator(
	logger lager.Logger,
	receptorClient receptor.Client,
	receptorCreds []byte,
) *DiegoProxyAuthenticator {
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

	actual, err := dpa.receptorClient.ActualLRPByProcessGuidAndIndex(processGuid, index)
	if err != nil {
		logger.Error("get-actual-lrp-failed", err)
		return nil, err
	}

	desired, err := dpa.receptorClient.GetDesiredLRP(processGuid)
	if err != nil {
		logger.Error("get-desired-lrp-failed", err)
		return nil, err
	}

	sshRoute, err := getRoutingInfo(&desired)
	if err != nil {
		logger.Error("get-routing-info-failed", err)
		return nil, err
	}

	return dpa.createPermissions(sshRoute, &actual)
}

func (dpa *DiegoProxyAuthenticator) createPermissions(
	sshRoute *models.SSHRoute,
	actual *receptor.ActualLRPResponse,
) (*ssh.Permissions, error) {
	var targetConfig *proxy.TargetConfig

	for _, mapping := range actual.Ports {
		if mapping.ContainerPort == sshRoute.ContainerPort {
			targetConfig = &proxy.TargetConfig{
				Address:         fmt.Sprintf("%s:%d", actual.Address, mapping.HostPort),
				HostFingerprint: sshRoute.HostFingerprint,
				PrivateKey:      sshRoute.PrivateKey,
				User:            sshRoute.User,
				Password:        sshRoute.Password,
			}
			break
		}
	}

	if targetConfig == nil {
		return &ssh.Permissions{}, nil
	}

	targetConfigJson, err := json.Marshal(targetConfig)
	if err != nil {
		return nil, err
	}

	return &ssh.Permissions{
		CriticalOptions: map[string]string{
			"proxy-target-config": string(targetConfigJson),
		},
	}, nil
}

func getRoutingInfo(desired *receptor.DesiredLRPResponse) (*models.SSHRoute, error) {
	if desired.Routes == nil {
		return nil, RouteNotFoundErr
	}

	rawMessage := desired.Routes[models.DIEGO_SSH]
	if rawMessage == nil {
		return nil, RouteNotFoundErr
	}

	var sshRoute models.SSHRoute
	err := json.Unmarshal(*rawMessage, &sshRoute)
	if err != nil {
		return nil, err
	}

	return &sshRoute, nil
}
