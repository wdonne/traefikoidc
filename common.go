package traefikoidc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
)

const (
	ecType  = "EC"
	rsaType = "RSA"
)

type ecdsaKey struct {
	key *ecdsa.PublicKey
	kid string
}

type key struct {
	Crv string `json:"crv,omitempty"`
	E   string `json:"e,omitempty"`
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	N   string `json:"n,omitempty"`
	Use string `json:"use,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

type keys struct {
	Keys []key `json:"Keys"`
}

type rsaKey struct {
	key *rsa.PublicKey
	kid string
}

type secretFile struct {
	filename  string
	timestamp int64
}

func appendEcdsa(ecdsaKeys []*ecdsaKey, k *key) ([]*ecdsaKey, error) {
	extracted, err := extractEcdsaKey(k)
	if err != nil {
		return nil, err
	}

	return append(ecdsaKeys, extracted), nil
}

func appendRsa(rsaKeys []*rsaKey, k *key) ([]*rsaKey, error) {
	extracted, err := extractRsaKey(k)
	if err != nil {
		return nil, err
	}

	return append(rsaKeys, extracted), nil
}

func callbackUrl(req *http.Request, contextPath string) string {
	return url.QueryEscape("https://" + req.Host + contextPath + callback)
}

func curve(crv string) elliptic.Curve {
	switch crv {
	case "P-224":
		return elliptic.P224()
	case "P-256":
		return elliptic.P256()
	case "P-384":
		return elliptic.P384()
	case "P-521":
		return elliptic.P521()
	default:
		return nil
	}
}

func decodeBigInt(s string) (*big.Int, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}

	return big.NewInt(0).SetBytes(b), nil
}

func decodeInt(s string) (int, error) {
	v, err := decodeBigInt(s)
	if err != nil {
		return -1, err
	}

	return int(v.Int64()), nil
}

func extractEcdsaKey(key *key) (*ecdsaKey, error) {
	slog.Info(fmt.Sprintf("Decode key.x of key %s", key.Kid))
	decodedX, err := decodeBigInt(key.X)
	if err != nil {
		return nil, err
	}

	slog.Info(fmt.Sprintf("Decode key.y of key %s", key.Kid))
	decodedY, err := decodeBigInt(key.Y)
	if err != nil {
		return nil, err
	}

	return &ecdsaKey{
		key: &ecdsa.PublicKey{Curve: curve(key.Crv), X: decodedX, Y: decodedY},
		kid: key.Kid,
	}, nil
}

func extractKeys(keys *keys) ([]*rsaKey, []*ecdsaKey, error) {
	ecdsaKeys := []*ecdsaKey{}
	var err error = nil
	rsaKeys := []*rsaKey{}

	for i := 0; i < len(keys.Keys) && err == nil; i++ {
		k := keys.Keys[i]

		if k.Use == sig {
			switch k.Kty {
			case rsaType:
				rsaKeys, err = appendRsa(rsaKeys, &k)
			case ecType:
				ecdsaKeys, err = appendEcdsa(ecdsaKeys, &k)
			}
		}
	}

	if err != nil {
		return nil, nil, err
	}

	if len(ecdsaKeys) == 0 && len(rsaKeys) == 0 {
		return nil, nil, errors.New("no public Keys found")
	}

	return rsaKeys, ecdsaKeys, nil
}

func extractRsaKey(key *key) (*rsaKey, error) {
	slog.Info(fmt.Sprintf("Decode key.n of key %s", key.Kid))
	decodedN, err := decodeBigInt(key.N)
	if err != nil {
		return nil, err
	}

	slog.Info(fmt.Sprintf("Decode key.e of key %s", key.Kid))
	decodedE, err := decodeInt(key.E)
	if err != nil {
		return nil, err
	}

	return &rsaKey{key: &rsa.PublicKey{N: decodedN, E: decodedE}, kid: key.Kid}, nil
}

func fileChanged(file *secretFile) (bool, error) {
	info, err := os.Stat(file.filename)
	if err != nil {
		return false, err
	}

	modified := info.ModTime().UnixMilli()

	if modified != file.timestamp {
		file.timestamp = modified

		return true, nil
	}

	return false, nil
}

func isBearer(s string) bool {
	return strings.ToLower(s) == bearer
}

func loadKeys(jwksUri string) ([]*rsaKey, []*ecdsaKey, error) {
	resp, err := http.Get(jwksUri)
	if err != nil {
		return nil, nil, err
	}

	defer streamCloser(resp.Body, "JWKS response stream could not be closed")
	loaded := keys{}
	err = json.NewDecoder(resp.Body).Decode(&loaded)
	if err != nil {
		return nil, nil, err
	}

	b, _ := json.Marshal(loaded)
	var s string

	if b != nil {
		s = string(b)
	} else {
		s = "cannot decode"
	}

	slog.Info(fmt.Sprintf("Loaded %d keys from %s\n", len(loaded.Keys), jwksUri))
	slog.Info(fmt.Sprintf("Loaded keys response %s\n", s))
	return extractKeys(&loaded)
}

func logErr(err error) error {
	slog.Error(err.Error())
	return err
}

func streamCloser(closer io.Closer, errorMessage string) {
	if err := closer.Close(); err != nil {
		slog.Error(errorMessage + "\n" + err.Error())
	}
}
