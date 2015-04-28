package authenticators

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"

	"github.com/cloudfoundry-incubator/diego-ssh/proxy"
	"github.com/cloudfoundry-incubator/diego-ssh/routes"
	"github.com/cloudfoundry-incubator/receptor"
	"github.com/pivotal-golang/lager"
	"golang.org/x/crypto/ssh"
)

const DIEGO_REALM = "diego"

type DiegoProxyAuthenticator struct {
	logger         lager.Logger
	receptorCreds  []byte
	receptorClient receptor.Client
}

var DiegoUserRegex *regexp.Regexp = regexp.MustCompile(DIEGO_REALM + `:(.*)/(\d+)`)

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

func (dpa *DiegoProxyAuthenticator) Realm() string {
	return DIEGO_REALM
}

func (dpa *DiegoProxyAuthenticator) Authenticate(metadata ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	logger := dpa.logger.Session("authenticate")
	logger.Info("authentication-starting")
	defer logger.Info("authentication-finished")

	if !DiegoUserRegex.MatchString(metadata.User()) {
		logger.Error("regex-match-fail", InvalidDomainErr)
		return nil, InvalidDomainErr
	}

	if !bytes.Equal(dpa.receptorCreds, password) {
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

	permissions, err := sshPermissionsFromProcess(processGuid, index, dpa.receptorClient)
	if err != nil {
		logger.Error("building-ssh-permissions-failed", err)
	}
	return permissions, err
}

func sshPermissionsFromProcess(processGuid string, index int, receptorClient receptor.Client) (*ssh.Permissions, error) {
	actual, err := receptorClient.ActualLRPByProcessGuidAndIndex(processGuid, index)
	if err != nil {
		return nil, err
	}

	desired, err := receptorClient.GetDesiredLRP(processGuid)
	if err != nil {
		return nil, err
	}

	sshRoute, err := getRoutingInfo(&desired)
	if err != nil {
		return nil, err
	}

	return createPermissions(sshRoute, &actual)
}

func createPermissions(
	sshRoute *routes.SSHRoute,
	actual *receptor.ActualLRPResponse,
) (*ssh.Permissions, error) {
	var targetConfig *proxy.TargetConfig

	for _, mapping := range actual.Ports {
		if mapping.ContainerPort == sshRoute.ContainerPort {
			targetConfig = &proxy.TargetConfig{
				Address:         fmt.Sprintf("%s:%d", actual.Address, mapping.HostPort),
				HostFingerprint: sshRoute.HostFingerprint,
				User:            sshRoute.User,
				Password:        sshRoute.Password,
				PrivateKey:      sshRoute.PrivateKey,
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

func getRoutingInfo(desired *receptor.DesiredLRPResponse) (*routes.SSHRoute, error) {
	if desired.Routes == nil {
		return nil, RouteNotFoundErr
	}

	rawMessage := desired.Routes[routes.DIEGO_SSH]
	if rawMessage == nil {
		return nil, RouteNotFoundErr
	}

	var sshRoute routes.SSHRoute
	err := json.Unmarshal(*rawMessage, &sshRoute)
	if err != nil {
		return nil, err
	}

	return &sshRoute, nil
}
