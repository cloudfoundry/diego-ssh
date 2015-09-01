package authenticators

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"

	"github.com/pivotal-golang/lager"
	"golang.org/x/crypto/ssh"
)

type CFAuthenticator struct {
	logger             lager.Logger
	ccClient           *http.Client
	ccURL              string
	permissionsBuilder PermissionsBuilder
}

type AppSSHResponse struct {
	ProcessGuid string `json:"process_guid"`
}

var CFUserRegex *regexp.Regexp = regexp.MustCompile(`cf:(.+)/(\d+)`)

func NewCFAuthenticator(
	logger lager.Logger,
	ccClient *http.Client,
	ccURL string,
	permissionsBuilder PermissionsBuilder,
) *CFAuthenticator {
	return &CFAuthenticator{
		logger:             logger,
		ccClient:           ccClient,
		ccURL:              ccURL,
		permissionsBuilder: permissionsBuilder,
	}
}

func (cfa *CFAuthenticator) UserRegexp() *regexp.Regexp {
	return CFUserRegex
}

func (cfa *CFAuthenticator) Authenticate(metadata ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	logger := cfa.logger.Session("authenticate")
	logger.Info("authentication-starting")
	defer logger.Info("authentication-finished")

	if !CFUserRegex.MatchString(metadata.User()) {
		logger.Error("regex-match-fail", InvalidCredentialsErr)
		return nil, InvalidCredentialsErr
	}

	guidAndIndex := CFUserRegex.FindStringSubmatch(metadata.User())

	appGuid := guidAndIndex[1]

	index, err := strconv.Atoi(guidAndIndex[2])
	if err != nil {
		logger.Error("atoi-failed", err)
		return nil, InvalidCredentialsErr
	}

	processGuid, err := cfa.CheckAccess(logger, appGuid, string(password))
	if err != nil {
		return nil, err
	}

	permissions, err := cfa.permissionsBuilder.Build(processGuid, index, metadata)
	if err != nil {
		logger.Error("building-ssh-permissions-failed", err)
	}

	return permissions, err
}

func (cfa *CFAuthenticator) CheckAccess(logger lager.Logger, appGuid string, token string) (string, error) {
	path := fmt.Sprintf("%s/internal/apps/%s/ssh_access", cfa.ccURL, appGuid)

	req, err := http.NewRequest("GET", path, nil)
	if err != nil {
		logger.Error("creating-request-failed", InvalidRequestErr)
		return "", InvalidRequestErr
	}
	req.Header.Add("Authorization", token)

	resp, err := cfa.ccClient.Do(req)
	if err != nil {
		logger.Error("fetching-app-failed", err)
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logger.Error("fetching-app-failed", FetchAppFailedErr, lager.Data{
			"StatusCode":   resp.Status,
			"ResponseBody": resp.Body,
		})
		return "", FetchAppFailedErr
	}

	var app AppSSHResponse
	err = json.NewDecoder(resp.Body).Decode(&app)
	if err != nil {
		logger.Error("invalid-cc-response", err)
		return "", InvalidCCResponse
	}

	return app.ProcessGuid, nil
}
