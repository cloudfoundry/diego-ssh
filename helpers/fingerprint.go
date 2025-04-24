package helpers

import (
	"strings"

	"golang.org/x/crypto/ssh"
)

const SHA256_FINGERPRINT_LENGTH = 44

func SHA256Fingerprint(key ssh.PublicKey) string {
	value := ssh.FingerprintSHA256(key)
	return strings.TrimPrefix(value, "SHA256:")
}
