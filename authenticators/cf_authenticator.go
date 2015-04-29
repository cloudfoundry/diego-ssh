package authenticators

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"

	"github.com/cloudfoundry-incubator/receptor"
	"github.com/pivotal-golang/lager"
	"golang.org/x/crypto/ssh"
)

const CF_REALM = "cf"

type CFAuthenticator struct {
	logger         lager.Logger
	ccClient       *http.Client
	ccURL          string
	receptorClient receptor.Client
}

var CFPrincipalRegex *regexp.Regexp = regexp.MustCompile(`(.*)/(\d+)`)
var CFRealmRegex *regexp.Regexp = regexp.MustCompile(CF_REALM + `:(.*)`)

func NewCFAuthenticator(
	logger lager.Logger,
	ccClient *http.Client,
	ccURL string,
	receptorClient receptor.Client,
) *CFAuthenticator {
	return &CFAuthenticator{
		logger:         logger,
		ccClient:       ccClient,
		ccURL:          ccURL,
		receptorClient: receptorClient,
	}
}

func (cfa *CFAuthenticator) Realm() string {
	return CF_REALM
}

type AppSSHResponse struct {
	ProcessGuid string `json:"process_guid"`
}

func (cfa *CFAuthenticator) Authenticate(metadata ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	logger := cfa.logger.Session("authenticate")
	if !CFRealmRegex.Match([]byte(metadata.User())) {
		return nil, InvalidDomainErr
	}

	principal := CFRealmRegex.FindStringSubmatch(metadata.User())[1]
	if !CFPrincipalRegex.Match([]byte(principal)) {
		return nil, InvalidCredentialsErr
	}

	guidAndIndex := CFPrincipalRegex.FindStringSubmatch(principal)

	index, err := strconv.Atoi(guidAndIndex[2])
	if err != nil {
		logger.Error("atoi-failed", err)
		return nil, InvalidCredentialsErr
	}

	appGuid := guidAndIndex[1]
	path := fmt.Sprintf("%s/internal/apps/%s/ssh_access", cfa.ccURL, appGuid)

	req, err := http.NewRequest("GET", path, nil)
	if err != nil {
		logger.Error("creating-request-failed", InvalidRequestErr)
		return nil, InvalidRequestErr
	}
	req.Header.Add("Authorization", string(password))

	resp, err := cfa.ccClient.Do(req)
	if err != nil {
		logger.Error("fetching-app-failed", err)
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		logger.Error("fetching-app-failed", FetchAppFailedErr, lager.Data{
			"StatusCode":   resp.Status,
			"ResponseBody": resp.Body,
		})
		return nil, FetchAppFailedErr
	}

	var app AppSSHResponse
	err = json.NewDecoder(resp.Body).Decode(&app)
	if err != nil {
		logger.Error("invalid-cc-response", err)
		return nil, InvalidCCResponse
	}

	permissions, err := sshPermissionsFromProcess(app.ProcessGuid, index, cfa.receptorClient)
	if err != nil {
		logger.Error("building-ssh-permissions-failed", err)
	}

	return permissions, err
}
