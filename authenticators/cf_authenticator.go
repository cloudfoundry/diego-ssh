package authenticators

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

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

type AppMetadata struct {
	Guid string `json:"guid"`
}

type AppEntity struct {
	AllowSSH bool   `json:"allow_ssh"`
	Diego    bool   `json:"diego"`
	Version  string `json:"version"`
}

type AppResponse struct {
	Metadata AppMetadata `json:"metadata"`
	Entity   AppEntity   `json:"entity"`
}

func (cfa *CFAuthenticator) Authenticate(metadata ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	logger := cfa.logger.Session("authenticate")
	if !CFRealmRegex.Match([]byte(metadata.User())) {
		return nil, InvalidDomainErr
	}

	if !isBearerToken(password) {
		return nil, InvalidCredentialsErr
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
	path := fmt.Sprintf("%s/v2/apps/%s", cfa.ccURL, appGuid)

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

	var app AppResponse
	err = json.NewDecoder(resp.Body).Decode(&app)
	if err != nil {
		logger.Error("invalid-cc-response", err)
		return nil, InvalidCCResponse
	}

	if !app.Entity.Diego {
		return nil, NotDiegoErr
	}

	if !app.Entity.AllowSSH {
		return nil, SSHDisabledErr
	}

	processGuid := app.Metadata.Guid + "-" + app.Entity.Version

	permissions, err := sshPermissionsFromProcess(processGuid, index, cfa.receptorClient)
	if err != nil {
		logger.Error("building-ssh-permissions-failed", err)
	}

	return permissions, err
}

func isBearerToken(cred []byte) bool {
	if len(cred) < len("bearer ")+1 {
		return false
	}

	if strings.ToLower(string(cred)[0:len("bearer ")]) == "bearer " {
		return true
	}

	return false
}
