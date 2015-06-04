package app

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/cloudfoundry/cli/plugin"
)

//go:generate counterfeiter -o fakes/fake_app_factory.go . AppFactory
type AppFactory interface {
	Get(string) (App, error)
}

type appFactory struct {
	cli plugin.CliConnection
}

func NewAppFactory(cli plugin.CliConnection) AppFactory {
	return &appFactory{cli: cli}
}

type App struct {
	Guid      string
	EnableSSH bool
	Diego     bool
	State     string
}

type metadata struct {
	Guid string `json:"guid"`
}

type entity struct {
	EnableSSH bool   `json:"enable_ssh"`
	Diego     bool   `json:"diego"`
	State     string `json:"state"`
}

type cfApp struct {
	Metadata metadata `json:"metadata"`
	Entity   entity   `json:"entity"`
}

func (af *appFactory) Get(appName string) (App, error) {
	output, err := af.cli.CliCommandWithoutTerminalOutput("app", appName, "--guid")
	if err != nil {
		return App{}, errors.New(output[len(output)-1])
	}

	guid := strings.TrimSpace(output[0])

	output, err = af.cli.CliCommandWithoutTerminalOutput("curl", "/v2/apps/"+guid)
	if err != nil {
		return App{}, errors.New("Failed to acquire " + appName + " info")
	}

	response := []byte(output[0])
	app := cfApp{}

	err = json.Unmarshal(response, &app)
	if err != nil {
		return App{}, err
	}

	return App{
		Guid:      app.Metadata.Guid,
		EnableSSH: app.Entity.EnableSSH,
		Diego:     app.Entity.Diego,
		State:     app.Entity.State,
	}, nil

	return App{}, nil
}
