package helpers

import (
	"crypto/sha256"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

const SHA256_FINGERPRINT_LENGTH = 95

func SHA256Fingerprint(key ssh.PublicKey) string {
	sha256sum := sha256.Sum256(key.Marshal())
	return colonize(fmt.Sprintf("% x", sha256sum))
}

func colonize(s string) string {
	return strings.Replace(s, " ", ":", -1)
}
