package cmd

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/cloudfoundry-incubator/diego-ssh/cf-plugin/models/credential"
	"github.com/cloudfoundry-incubator/diego-ssh/cf-plugin/models/info"
)

const GetSSHCodeUsage = "cf get-ssh-code"

var NoRedirectsErr = errors.New("No redirects")

func GetSSHCode(
	args []string,
	infoFactory info.InfoFactory,
	credFactory credential.CredentialFactory,
	skipCertificateVerify bool,
	output io.Writer,
) error {
	if len(args) != 1 || args[0] != "get-ssh-code" {
		return fmt.Errorf("%s\n%s", "Invalid usage", GetSSHCodeUsage)
	}

	v2Info, err := infoFactory.Get()
	if err != nil {
		return err
	}

	cred, err := credFactory.Get()
	if err != nil {
		return err
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
		return err
	}

	values := url.Values{}
	values.Set("response_type", "code")
	values.Set("grant_type", "authorization_code")
	values.Set("client_id", v2Info.SSHOAuthClient)

	authorizeURL.Path = "/oauth/authorize"
	authorizeURL.RawQuery = values.Encode()

	authorizeReq, err := http.NewRequest("GET", authorizeURL.String(), nil)
	if err != nil {
		return err
	}
	authorizeReq.Header.Add("authorization", cred.Token)

	resp, err := httpClient.Do(authorizeReq)
	if err == nil {
		return errors.New("Authorization server did not redirect with one time code")
	}

	if netErr, ok := err.(*url.Error); !ok || netErr.Err != NoRedirectsErr {
		return err
	}

	loc, err := resp.Location()
	if err != nil {
		return err
	}

	codes := loc.Query()["code"]
	if len(codes) != 1 {
		return errors.New("Unable to acquire one time code from authorization response")
	}

	fmt.Fprintf(output, "%s\n", codes[0])
	return nil
}
