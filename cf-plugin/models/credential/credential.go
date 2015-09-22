package credential

import (
	"crypto/tls"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/cloudfoundry-incubator/diego-ssh/cf-plugin/models/info"
	"github.com/cloudfoundry/cli/plugin"
)

//go:generate counterfeiter -o credential_fakes/fake_credential_factory.go . CredentialFactory
type CredentialFactory interface {
	AuthorizationToken() (string, error)
	AuthorizationCode() (string, error)
}

type credFactory struct {
	cli         plugin.CliConnection
	infoFactory info.InfoFactory
}

var NoRedirectsErr = errors.New("No redirects")

func NewCredentialFactory(cli plugin.CliConnection, infoFactory info.InfoFactory) CredentialFactory {
	return &credFactory{
		cli:         cli,
		infoFactory: infoFactory,
	}
}

func (c *credFactory) AuthorizationToken() (string, error) {
	_, err := c.cli.CliCommandWithoutTerminalOutput("oauth-token")
	if err != nil {
		return "", err
	}

	return c.cli.AccessToken()
}

func (c *credFactory) AuthorizationCode() (string, error) {
	v2Info, err := c.infoFactory.Get()
	if err != nil {
		return "", err
	}

	authzToken, err := c.AuthorizationToken()
	if err != nil {
		return "", err
	}

	skipCertificateVerify, err := c.cli.IsSSLDisabled()
	if err != nil {
		return "", err
	}

	httpClient := &http.Client{
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			return NoRedirectsErr
		},
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: skipCertificateVerify,
			},
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}

	authorizeURL, err := url.Parse(v2Info.TokenEndpoint)
	if err != nil {
		return "", err
	}

	values := url.Values{}
	values.Set("response_type", "code")
	values.Set("grant_type", "authorization_code")
	values.Set("client_id", v2Info.SSHOAuthClient)

	authorizeURL.Path = "/oauth/authorize"
	authorizeURL.RawQuery = values.Encode()

	authorizeReq, err := http.NewRequest("GET", authorizeURL.String(), nil)
	if err != nil {
		return "", err
	}
	authorizeReq.Header.Add("authorization", authzToken)

	resp, err := httpClient.Do(authorizeReq)
	if err == nil {
		return "", errors.New("Authorization server did not redirect with one time code")
	}

	if netErr, ok := err.(*url.Error); !ok || netErr.Err != NoRedirectsErr {
		return "", err
	}

	loc, err := resp.Location()
	if err != nil {
		return "", err
	}

	codes := loc.Query()["code"]
	if len(codes) != 1 {
		return "", errors.New("Unable to acquire one time code from authorization response")
	}

	return codes[0], nil
}
