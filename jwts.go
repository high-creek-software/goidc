package goidc

import (
	"crypto/x509"
	"encoding/pem"
	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/json"
	"time"
)

func generateJWT(key key, aud string) (string, error) {
	block, _ := pem.Decode([]byte(key.Key))

	b := block.Bytes

	k, err := x509.ParsePKCS1PrivateKey(b)
	if err != nil {
		return "", err
	}

	signingKey := jose.SigningKey{Algorithm: jose.RS256,
		Key: &jose.JSONWebKey{Key: k, KeyID: key.KeyID},
	}
	signer, err := jose.NewSigner(signingKey, &jose.SignerOptions{})
	if err != nil {
		return "", err
	}

	iat := time.Now()
	exp := iat.Add(time.Hour)

	p := payload{
		Issuer:   key.ClientID,
		Subject:  key.ClientID,
		Audience: aud,
		IssuedAt: iat.UTC().Unix(),
		Expires:  exp.UTC().Unix(),
	}

	bs, err := json.Marshal(p)
	if err != nil {
		return "", err
	}

	result, err := signer.Sign(bs)
	if err != nil {
		return "", err
	}

	return result.CompactSerialize()
}

type payload struct {
	Issuer   string `json:"iss"`
	Subject  string `json:"sub"`
	Audience string `json:"aud"`
	IssuedAt int64  `json:"iat"`
	Expires  int64  `json:"exp"`
}
