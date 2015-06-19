package space

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/cloudfoundry/cli/plugin"
)

//go:generate counterfeiter -o space_fakes/fake_space_factory.go . SpaceFactory
type SpaceFactory interface {
	Get(string) (Space, error)
	SetBool(aSpace Space, key string, value bool) error
}

type spaceFactory struct {
	cli plugin.CliConnection
}

func NewSpaceFactory(cli plugin.CliConnection) SpaceFactory {
	return &spaceFactory{cli: cli}
}

type Space struct {
	Guid     string
	AllowSSH bool
}

type metadata struct {
	Guid string `json:"guid"`
}

type entity struct {
	AllowSSH bool `json:"allow_ssh"`
}

type cfSpace struct {
	Metadata metadata `json:"metadata"`
	Entity   entity   `json:"entity"`
}

func (sf *spaceFactory) Get(spaceName string) (Space, error) {
	output, err := sf.cli.CliCommandWithoutTerminalOutput("space", spaceName, "--guid")
	if err != nil {
		return Space{}, errors.New(output[len(output)-1])
	}

	guid := strings.TrimSpace(output[0])

	output, err = sf.cli.CliCommandWithoutTerminalOutput("curl", "/v2/spaces/"+guid)
	if err != nil {
		return Space{}, errors.New("Failed to acquire " + spaceName + " info")
	}

	response := []byte(output[0])
	space := cfSpace{}

	err = json.Unmarshal(response, &space)
	if err != nil {
		return Space{}, err
	}

	return Space{
		Guid:     space.Metadata.Guid,
		AllowSSH: space.Entity.AllowSSH,
	}, nil

	return Space{}, nil
}

func (sf *spaceFactory) SetBool(aSpace Space, key string, value bool) error {
	output, err := sf.cli.CliCommandWithoutTerminalOutput("curl", "/v2/spaces/"+aSpace.Guid, "-X", "PUT", "-d", `{"`+key+`":`+strconv.FormatBool(value)+`}`)
	if err != nil {
		return errors.New(output[len(output)-1])
	}

	return nil
}
