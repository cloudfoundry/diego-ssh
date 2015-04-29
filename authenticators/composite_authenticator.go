package authenticators

import (
	"strings"

	"golang.org/x/crypto/ssh"
)

type CompositeAuthenticator struct {
	authenticatorMap map[string]PasswordAuthenticator
}

func NewCompositeAuthenticator(authenticatorMap map[string]PasswordAuthenticator) *CompositeAuthenticator {
	return &CompositeAuthenticator{authenticatorMap: authenticatorMap}
}

func (a *CompositeAuthenticator) Authenticate(metadata ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	if parts := strings.SplitN(metadata.User(), ":", 2); len(parts) == 2 {
		authenticator := a.authenticatorMap[parts[0]]
		if authenticator != nil {
			return authenticator.Authenticate(metadata, password)
		}
	}
	return nil, InvalidCredentialsErr
}
