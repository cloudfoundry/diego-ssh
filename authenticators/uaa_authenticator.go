package authenticators

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/pivotal-golang/lager"
)

type UAAAuthenticator struct {
	logger             lager.Logger
	uaaClient          *http.Client
	uaaURL             string
	ccAccessChecker    CCAccessChecker
	permissionsBuilder PermissionsBuilder
}

var UAAUserRegex *regexp.Regexp = regexp.MustCompile(`(.+)@(.+)/(\d+)`)

func NewUAAAuthenticator(
	logger lager.Logger,
	uaaClient *http.Client,
	uaaURL string,
	ccAccessChecker CCAccessChecker,
	permissionsBuilder PermissionsBuilder,
) *UAAAuthenticator {
	return &UAAAuthenticator{
		logger:             logger,
		uaaClient:          uaaClient,
		uaaURL:             uaaURL,
		ccAccessChecker:    ccAccessChecker,
		permissionsBuilder: permissionsBuilder,
	}
}

func (uaa *UAAAuthenticator) UserRegexp() *regexp.Regexp {
	return UAAUserRegex
}

func (uaaa *UAAAuthenticator) Authenticate(metadata ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	logger := uaaa.logger.Session("authenticate")
	logger.Info("authentication-starting")
	defer logger.Info("authentication-finished")

	userGuidIndex := UAAUserRegex.FindStringSubmatch(metadata.User())
	if len(userGuidIndex) != 4 {
		return nil, InvalidUserFormatErr
	}

	username := userGuidIndex[1]
	appGuid := userGuidIndex[2]
	index := userGuidIndex[3]

	formValues := make(url.Values)
	formValues.Set("grant_type", "password")
	formValues.Set("username", username)
	formValues.Set("password", string(password))

	tokenURL := uaaa.uaaURL + "/oauth/token"
	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(formValues.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := uaaa.uaaClient.Do(req)
	if err != nil {
		return nil, AuthenticationFailedErr
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, AuthenticationFailedErr
	}

	var tokenResponse UAAAuthTokenResponse
	err = json.NewDecoder(resp.Body).Decode(&tokenResponse)
	if err != nil {
		logger.Error("decode-token-response-failed", err)
		return nil, AuthenticationFailedErr
	}

	token := fmt.Sprintf("%s %s", tokenResponse.TokenType, tokenResponse.AccessToken)
	processGuid, err := uaaa.ccAccessChecker.CheckAccess(logger, appGuid, token)
	if err != nil {
		return nil, err
	}

	idx, err := strconv.Atoi(index)
	if err != nil {
		return nil, err
	}

	permissions, err := uaaa.permissionsBuilder.Build(processGuid, idx, metadata)
	if err != nil {
		logger.Error("building-ssh-permissions-failed", err)
	}

	return permissions, err
}

type UAAAuthTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
}
