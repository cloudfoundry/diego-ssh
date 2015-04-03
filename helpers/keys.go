package helpers

import (
	"crypto/dsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
)

func GeneratePemEncodedRsaKey() ([]byte, error) {
	generatedKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	encoded := pem.EncodeToMemory(&pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   x509.MarshalPKCS1PrivateKey(generatedKey),
	})

	return encoded, nil
}

func GeneratePemEncodedDsaKey() ([]byte, error) {
	generatedKey := &dsa.PrivateKey{}
	err := dsa.GenerateParameters(&generatedKey.Parameters, rand.Reader, dsa.L2048N256)
	if err != nil {
		return nil, err
	}

	err = dsa.GenerateKey(generatedKey, rand.Reader)
	if err != nil {
		return nil, err
	}

	type derKeyFormat struct {
		Version       int
		P, Q, G, Y, X *big.Int
	}

	val := derKeyFormat{
		P: generatedKey.P,
		Q: generatedKey.Q,
		G: generatedKey.G,
		Y: generatedKey.Y,
		X: generatedKey.X,
	}
	bytes, err := asn1.Marshal(val)
	if err != nil {
		return nil, err
	}

	encoded := pem.EncodeToMemory(&pem.Block{
		Type:    "DSA PRIVATE KEY",
		Headers: nil,
		Bytes:   bytes,
	})

	return encoded, nil
}
