package authenticators

import (
	"bytes"
	"errors"

	"golang.org/x/crypto/ssh"
)

type PublicKeyAuthenticator interface {
	Authenticate(conn ssh.ConnMetadata, publicKey ssh.PublicKey) (*ssh.Permissions, error)
	PublicKey() ssh.PublicKey
	User() string
}

type publicKeyAuthenticator struct {
	user               string
	publicKey          ssh.PublicKey
	marshaledPublicKey []byte
}

func NewPublicKeyAuthenticator(user string, publicKey ssh.PublicKey) PublicKeyAuthenticator {
	return &publicKeyAuthenticator{
		user:               user,
		publicKey:          publicKey,
		marshaledPublicKey: publicKey.Marshal(),
	}
}

func (a *publicKeyAuthenticator) PublicKey() ssh.PublicKey {
	return a.publicKey
}

func (a *publicKeyAuthenticator) User() string {
	return a.user
}

func (a *publicKeyAuthenticator) Authenticate(conn ssh.ConnMetadata, publicKey ssh.PublicKey) (*ssh.Permissions, error) {
	if conn.User() == a.user && bytes.Equal(publicKey.Marshal(), a.marshaledPublicKey) {
		return &ssh.Permissions{}, nil
	}

	return nil, errors.New("authentication failed")
}
