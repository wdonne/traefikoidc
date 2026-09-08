package traefikoidc

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
)

type idp struct {
	clientSecret     *secret
	clientSecretFile *secretFile
	contextPath      string
	discovered       *discovered
	name             string
	postLogoutUrl    string
	scopeParameter   string
	verifier         *verifier
}

func (idp *idp) endSessionUrl(req *http.Request) string {
	return idp.discovered.EndSessionEndpoint +
		"?client_id=" +
		callbackUrl(req, idp.contextPath) +
		"&post_logout_redirect_uri=" +
		idp.logoutUrl()
}

func (idp *idp) getClientSecret() (*secret, error) {
	changed, err := fileChanged(idp.clientSecretFile)
	if err != nil {
		return nil, err
	}

	if changed || idp.clientSecret == nil {
		sec, e := readClientSecret(idp.clientSecretFile.filename)

		if e != nil {
			return nil, e
		}

		idp.clientSecret = sec
	}

	return idp.clientSecret, nil
}

func (idp *idp) getIdToken(authRes *authenticationResponse, req *http.Request) (*idTokenResponse, error) {
	reader, err := idp.tokenRequestBody(authRes.code, req)
	if err != nil {
		return nil, err
	}

	tokenRes, err := http.Post(idp.discovered.TokenEndpoint,
		"application/x-www-form-urlencoded",
		reader)
	if err != nil {
		return nil, err
	}

	defer streamCloser(tokenRes.Body, "token response stream could not be closed")

	if tokenRes.StatusCode == http.StatusOK {
		token := idTokenResponse{}
		err = json.NewDecoder(tokenRes.Body).Decode(&token)
		if err != nil {
			return nil, err
		}

		if !isBearer(token.TokenType) {
			return nil, errors.New("only bearer token types are supported")
		}

		return &token, nil
	}

	return nil, errors.New(tokenRes.Status)
}

func (idp *idp) logoutUrl() string {
	return url.QueryEscape(idp.postLogoutUrl)
}

func (idp *idp) tokenRequestBody(code string, req *http.Request) (io.Reader, error) {
	c, err := idp.getClientSecret()
	if err != nil {
		return nil, err
	}

	body := "grant_type=authorization_code&code=" +
		url.QueryEscape(code) +
		"&client_id=" +
		url.QueryEscape(c.ClientID) +
		"&client_secret=" +
		url.QueryEscape(c.ClientSecret) +
		"&redirect_uri=" +
		callbackUrl(req, idp.contextPath)

	slog.Info("tokenRequestBody: " + body)
	return strings.NewReader(body), nil
}

func readClientSecret(file string) (*secret, error) {
	content, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	sec := secret{}
	err = json.Unmarshal(content, &sec)

	return &sec, err
}
