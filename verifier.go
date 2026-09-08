package traefikoidc

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"log/slog"
)

type verifier struct {
	audiences []string
	ecdsaKeys []*ecdsaKey
	jwksUri   string
	rsaKeys   []*rsaKey
}

func (verifier *verifier) findEcdsaKey(kid string) *ecdsaKey {
	for i := range verifier.ecdsaKeys {
		if kid == verifier.ecdsaKeys[i].kid {
			return verifier.ecdsaKeys[i]
		}
	}

	return nil
}

func (verifier *verifier) findRsaKey(kid string) *rsaKey {
	for i := range verifier.rsaKeys {
		if kid == verifier.rsaKeys[i].kid {
			return verifier.rsaKeys[i]
		}
	}

	return nil
}

func (verifier *verifier) getEcdsaKey(kid string) (*ecdsa.PublicKey, error) {
	k := verifier.findEcdsaKey(kid)

	if k != nil {
		return k.key, nil
	}

	err := verifier.reloadKeys()
	if err != nil {
		return nil, err
	}

	k = verifier.findEcdsaKey(kid)

	if k == nil {
		for i := range verifier.ecdsaKeys {
			slog.Info(" " + verifier.ecdsaKeys[i].kid)
		}

		return nil, errors.New("unknown kid " + kid)
	}

	return k.key, nil
}

func (verifier *verifier) getRsaKey(kid string) (*rsa.PublicKey, error) {
	k := verifier.findRsaKey(kid)

	if k != nil {
		return k.key, nil
	}

	err := verifier.reloadKeys()
	if err != nil {
		return nil, err
	}

	k = verifier.findRsaKey(kid)

	if k == nil {
		for i := range verifier.ecdsaKeys {
			slog.Info(" " + verifier.ecdsaKeys[i].kid)
		}

		return nil, errors.New("unknown kid " + kid)
	}

	return k.key, nil
}

func (verifier *verifier) reloadKeys() error {
	rsaKeys, ecdsaKeys, err := loadKeys(verifier.jwksUri)
	if err != nil {
		return err
	}

	verifier.rsaKeys = rsaKeys
	verifier.ecdsaKeys = ecdsaKeys

	return nil
}
