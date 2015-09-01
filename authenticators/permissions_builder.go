package authenticators

import (
	"encoding/json"
	"fmt"

	"github.com/cloudfoundry-incubator/diego-ssh/proxy"
	"github.com/cloudfoundry-incubator/diego-ssh/routes"
	"github.com/cloudfoundry-incubator/receptor"
	"golang.org/x/crypto/ssh"
)

type permissionsBuilder struct {
	receptorClient receptor.Client
}

func NewPermissionsBuiler(receptorClient receptor.Client) PermissionsBuilder {
	return &permissionsBuilder{receptorClient}
}

func (pb *permissionsBuilder) Build(processGuid string, index int, metadata ssh.ConnMetadata) (*ssh.Permissions, error) {
	actual, err := pb.receptorClient.ActualLRPByProcessGuidAndIndex(processGuid, index)
	if err != nil {
		return nil, err
	}

	desired, err := pb.receptorClient.GetDesiredLRP(processGuid)
	if err != nil {
		return nil, err
	}

	sshRoute, err := getRoutingInfo(&desired)
	if err != nil {
		return nil, err
	}

	logMessage := fmt.Sprintf("Successful remote access by %s", metadata.RemoteAddr().String())

	return createPermissions(sshRoute, &actual, desired.LogGuid, logMessage, index)
}

func createPermissions(
	sshRoute *routes.SSHRoute,
	actual *receptor.ActualLRPResponse,
	logGuid string,
	logMessage string,
	index int,
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

	logMessageJson, err := json.Marshal(proxy.LogMessage{
		Guid:    logGuid,
		Message: logMessage,
		Index:   index,
	})
	if err != nil {
		return nil, err
	}

	return &ssh.Permissions{
		CriticalOptions: map[string]string{
			"proxy-target-config": string(targetConfigJson),
			"log-message":         string(logMessageJson),
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
