package authenticators

import "golang.org/x/crypto/ssh"

type PublicKeyAuthenticator interface {
	Authenticate(metadata ssh.ConnMetadata, publicKey ssh.PublicKey) (*ssh.Permissions, error)
	PublicKey() ssh.PublicKey
}

//go:generate counterfeiter -o fake_authenticators/fake_password_authenticator.go . PasswordAuthenticator
type PasswordAuthenticator interface {
	Authenticate(metadata ssh.ConnMetadata, password []byte) (*ssh.Permissions, error)
}
