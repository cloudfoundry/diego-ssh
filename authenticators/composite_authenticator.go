package authenticators

import (
	"errors"

	"golang.org/x/crypto/ssh"
)

var InvalidCredentialsError error = errors.New("Invalid credentials")

type CompositeAuthenticator struct {
	authenticators []PasswordAuthenticator
}

func NewCompositeAuthenticator(authenticators []PasswordAuthenticator) *CompositeAuthenticator {
	return &CompositeAuthenticator{authenticators: authenticators}
}

func (a *CompositeAuthenticator) Authenticate(metadata ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	for _, authenticator := range a.authenticators {
		if authenticator.ShouldAuthenticate(metadata) {
			return authenticator.Authenticate(metadata, password)
		}
	}
	return nil, InvalidCredentialsError
}
