package traefikoidc

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	accessToken                 = "access_token"
	authorization               = "Authorization"
	bearer                      = "bearer"
	callback                    = "/callback"
	codeField                   = "code"
	defaultClientSecretFile     = "/clientSecret.json"
	defaultEncryptionSecretFile = "/encryption_secret"
	deleted                     = "deleted"
	defaultIdp                  = "default"
	errorDescriptionField       = "error_description"
	forRequest                  = " for request "
	forToken                    = " for token "
	idpField                    = "idp"
	kid                         = "kid"
	logout                      = "/logout"
	logoutself                  = "/logoutself"
	offlineAccess               = "offline_access"
	onBehalfOfCallback          = "/onbehalfof"
	originalIss                 = "originalIss"
	redirectTo                  = "Redirect to "
	requestedWithHeader         = "X-Requested-With"
	sig                         = "sig"
	stateField                  = "state"
	wellKnown                   = ".well-known/openid-configuration"
	whoami                      = "whoami"
	xmlHttpRequest              = "XMLHttpRequest"
)

type Config struct {
	ContextPath          string          `json:"contextPath,omitempty"`
	EncryptionSecretFile string          `json:"encryptionSecretFile,omitempty"`
	Idps                 []*IdpConfig    `json:"idps"`
	InternalIssuer       *InternalIssuer `json:"internalIssuer,omitempty"`
	LazyDiscovery        bool            `json:"lazyDiscovery,omitempty"`
	NotBearerToken       bool            `json:"notBearerToken,omitempty"`
	TokenHeader          string          `json:"tokenHeader,omitempty"`
	Whoami               bool            `json:"whoami,omitempty"`
}

type IdpConfig struct {
	Audiences        []string `json:"audiences,omitempty"`
	ClientSecretFile string   `json:"clientSecretFile"`
	Name             string   `json:"name"`
	PostLogoutUrl    string   `json:"postLogoutUrl,omitempty"`
	ProviderUrl      string   `json:"providerUrl"`
	Scopes           []string `json:"scopes,omitempty"`
}

type InternalIssuer struct {
	Audiences  []string    `json:"audiences,omitempty"`
	OnBehalfOf *OnBehalfOf `json:"onBehalfOf,omitempty"`
	Url        string      `json:"url"`
}

type OnBehalfOf struct {
	CallbackPath  string `json:"callbackPath"`
	EligibleClaim string `json:"eligibleClaim"`
	IssuerPath    string `json:"issuerPath"`
	RedirectPath  string `json:"redirectPath"`
}

type Serve struct {
	config               *Config
	encryptionSecretFile *secretFile
	idps                 []*idp
	internalVerifier     *verifier
	next                 http.Handler
	parser               *jwt.Parser
	secret               []byte
}

type authenticationResponse struct {
	code        string
	idp         string
	originalUrl string
}

type discovered struct {
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	EndSessionEndpoint                         string   `json:"end_session_endpoint,omitempty"`
	Issuer                                     string   `json:"issuer"`
	JwksUri                                    string   `json:"jwks_uri"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	ScopesSupported                            []string `json:"scopes_supported,omitempty"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`
	UserinfoEndpoint                           string   `json:"userinfo_endpoint,omitempty"`
}

type encryptionSecret struct {
	Secret string `json:"secret"`
}

type idTokenResponse struct {
	IdToken   string `json:"id_token"`
	State     string `json:"state"`
	TokenType string `json:"token_type"`
}

type secret struct {
	ClientID     string `json:"clientID"`
	ClientSecret string `json:"clientSecret"`
}

func CreateConfig() *Config {
	return &Config{}
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	var idps []*idp = nil
	var internalVerifier *verifier = nil

	if !config.LazyDiscovery {
		var err error
		idps, err = discoverIdps(config)
		if err != nil {
			slog.Error(err.Error())
			return nil, err
		}

		internalVerifier, err = discoverInternalIssuer(config)
		if err != nil {
			slog.Error(err.Error())
			return nil, err
		}
	}

	encryptionSecretFile := config.EncryptionSecretFile

	if encryptionSecretFile == "" {
		encryptionSecretFile = defaultEncryptionSecretFile
	}

	if config.TokenHeader == "" {
		config.TokenHeader = authorization
	}

	return &Serve{
		config:               config,
		encryptionSecretFile: &secretFile{filename: encryptionSecretFile, timestamp: -1},
		idps:                 idps,
		internalVerifier:     internalVerifier,
		next:                 next,
		parser:               jwt.NewParser(),
	}, nil
}

func (serve *Serve) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	var err error
	err = serve.lazyDiscoverIdps()
	if err != nil {
		report500(rw, req, err)
		return
	}

	err = serve.lazyDiscoverInternalIssuer()
	if err != nil {
		report500(rw, req, err)
		return
	}

	if serve.isCallback(req) {
		slog.Info("Callback from " + req.URL.String())
		serve.handleCallback(rw, req)
	} else if serve.isLogoutSelf(req) {
		slog.Info("Log out of IDP")
		serve.logoutIdp(rw, req)
	} else {
		token, claims, err := serve.validToken(req)

		if err != nil {
			serve.handleInvalidToken(rw, req)
		} else {
			serve.handleValidToken(rw, req, token, claims)
		}
	}
}

func (serve *Serve) authenticate(rw http.ResponseWriter, req *http.Request) {
	i, err := serve.getIdpForRequest(req)

	if err != nil {
		report401(rw, req, err)
	} else {
		u, err := serve.authenticationUrl(req, i)

		if err == nil {
			slog.Info(redirectTo + u)
			http.Redirect(rw, req, u, http.StatusFound)
		} else {
			report400(rw, req, err)
		}
	}
}

func (serve *Serve) authenticationUrl(req *http.Request, idp *idp) (string, error) {
	sec, err := serve.getEncryptionSecret()
	if err != nil {
		return "", err
	}

	s, err := idp.getClientSecret()
	if err != nil {
		return "", err
	}

	enc, err := encrypt(addIdp(req.URL, idp.name).String(), sec)
	if err != nil {
		return "", err
	}

	return idp.discovered.AuthorizationEndpoint +
			"?response_type=" +
			codeField +
			"&client_id=" +
			s.ClientID +
			"&redirect_uri=" +
			callbackUrl(req, serve.config.ContextPath) +
			"&scope=" +
			idp.scopeParameter +
			"&" +
			stateField +
			"=" +
			enc,
		nil
}

func (serve *Serve) forwardRequest(rw http.ResponseWriter, req *http.Request) {
	slog.Info("Forwarding request")
	serve.setTokenOnHeader(req)
	serve.next.ServeHTTP(rw, req)
}

func (serve *Serve) getAuthenticationResponse(req *http.Request) (*authenticationResponse, error) {
	q, err := url.ParseQuery(req.URL.RawQuery)
	if err != nil {
		return nil, err
	}

	if !q.Has(codeField) || !q.Has(stateField) {
		if q.Has(errorDescriptionField) {
			return nil, errors.New(q.Get(errorDescriptionField))
		}

		return nil, errors.New("missing code or state query parameters")
	}

	sec, err := serve.getEncryptionSecret()
	if err != nil {
		return nil, err
	}

	decrypted, err := decrypt(q.Get(stateField), sec)
	if err != nil {
		return nil, err
	}

	slog.Info("Decrypted callback state: " + decrypted)
	idpName := getIdpForUrlAsString(decrypted)

	return &authenticationResponse{
		code:        q.Get(codeField),
		idp:         idpName,
		originalUrl: removeParameter(decrypted, idpField),
	}, nil
}

func (serve *Serve) getEncryptionSecret() ([]byte, error) {
	changed, err := fileChanged(serve.encryptionSecretFile)
	if err != nil {
		return nil, err
	}

	if changed || serve.secret == nil {
		se, e := readEncryptionSecret(serve.encryptionSecretFile.filename)

		if e != nil {
			return nil, e
		}

		serve.secret = []byte(se.Secret)
	}

	return serve.secret, nil
}

func (serve *Serve) getIdp(name string) (*idp, error) {
	for i := range serve.idps {
		if name == serve.idps[i].name {
			slog.Info("Using IDP " + serve.idps[i].name)
			return serve.idps[i], nil
		}
	}

	if name != defaultIdp {
		tryDefault, _ := serve.getIdp(defaultIdp)

		if tryDefault != nil {
			return tryDefault, nil
		}
	}

	return nil, errors.New("idp " + name + " is not configured")
}

func (serve *Serve) getIdpForIssuer(issuer string) (*idp, error) {
	for i := range serve.idps {
		if issuer == serve.idps[i].discovered.Issuer {
			return serve.idps[i], nil
		}
	}

	return nil, errors.New("idp is not configured for issuer " + issuer)
}

func (serve *Serve) getIdpForIssuerOrOriginalIssuer(issuer string, originalIssuer string) (*idp, error) {
	i, _ := serve.getIdpForIssuer(issuer)

	if i != nil {
		return i, nil
	}

	return serve.getIdpForIssuer(originalIssuer)
}

func (serve *Serve) getIdpForRequest(req *http.Request) (*idp, error) {
	i, _ := serve.getIdp(getIdpForUrl(req.URL))

	if i != nil && i.name != defaultIdp {
		return i, nil
	}

	token, claims, _ := serve.getParsedToken(req)

	if token != nil {
		i, _ = serve.getIdpForToken(token, claims)

		if i != nil {
			return i, nil
		}
	}

	return serve.getIdp(defaultIdp)
}

func (serve *Serve) getIdpForToken(token *jwt.Token, claims *jwt.MapClaims) (*idp, error) {
	issuer, err := token.Claims.GetIssuer()
	if err != nil {
		return nil, err
	}

	idp, err := serve.getIdpForIssuerOrOriginalIssuer(issuer, (*claims)[originalIss].(string))
	if err != nil {
		return nil, err
	}

	return idp, nil
}

func (serve *Serve) getParsedToken(req *http.Request) (*jwt.Token, *jwt.MapClaims, error) {
	token, err := getToken(req)
	if err != nil {
		return nil, nil, err
	}

	tok, claims, err := serve.parseToken(token)
	if err != nil {
		return nil, nil, err
	}

	return tok, claims, nil
}

func (serve *Serve) getVerifierForToken(token *jwt.Token, claims *jwt.MapClaims) (*verifier, error) {
	issuer, err := token.Claims.GetIssuer()
	if err != nil {
		return nil, err
	}

	if serve.config.InternalIssuer != nil && issuer == serve.config.InternalIssuer.Url {
		return serve.internalVerifier, nil
	}

	idp, err := serve.getIdpForIssuerOrOriginalIssuer(issuer, (*claims)[originalIss].(string))
	if err != nil {
		return nil, err
	}

	return idp.verifier, nil
}

func (serve *Serve) handleCallback(rw http.ResponseWriter, req *http.Request) {
	authRes, err := serve.getAuthenticationResponse(req)
	if err != nil {
		report400(rw, req, errors.New("getAuthenticationResponse: "+err.Error()+forRequest+requestToString(req)))
		return
	}

	i, err := serve.getIdp(authRes.idp)
	if err != nil {
		report400(rw, req, errors.New("getIdp: "+err.Error()))
		return
	}

	slog.Info(fmt.Sprintf("getIdToken for code %s", authRes.code))
	tokenRes, err := i.getIdToken(authRes, req)
	if err != nil {
		report400(rw, req, errors.New("getIdToken: "+err.Error()))
		return
	}

	_, err = serve.validateIdToken(tokenRes.IdToken, i)
	if err != nil {
		report400(rw, req, errors.New("validateIdToken: "+err.Error()+forToken+tokenRes.IdToken))
		return
	}

	token, err := serve.replaceWithInternalToken(tokenRes.IdToken, "")
	if err != nil {
		report500(rw, req, err)
		return
	}

	serve.setAccessTokenCookie(rw, req, token)
	slog.Info(redirectTo + authRes.originalUrl)
	http.Redirect(rw, req, authRes.originalUrl, http.StatusFound)
}

func (serve *Serve) handleInvalidToken(rw http.ResponseWriter, req *http.Request) {
	if isXhr(req) {
		report401(rw, req, errors.New("Unauthorized"))
	} else {
		slog.Info("Authenticating")
		serve.authenticate(rw, req)
	}
}

func (serve *Serve) handleOnBehalfOf(rw http.ResponseWriter, req *http.Request, token string) {
	slog.Info("Handling onbehalfof")
	newToken, err := serve.replaceWithInternalToken(token,
		serve.config.InternalIssuer.OnBehalfOf.IssuerPath+"?user="+
			url.QueryEscape(req.URL.Query()["user"][0]))
	if err != nil {
		report500(rw, req, err)
		return
	}

	serve.setAccessTokenCookie(rw, req, newToken)
	http.Redirect(rw, req, req.URL.Query().Get("url"), http.StatusFound)
}

func (serve *Serve) handleOnBehalfOfUserSelection(rw http.ResponseWriter, req *http.Request, token string) {
	if serve.isOnBehalfOfCallback(req) {
		serve.handleOnBehalfOf(rw, req, token)
	} else if !serve.isFromOnBehalfOf(req) {
		slog.Info("Redirecting to onbehalfof page")
		newUrl := serve.onBehalfOfRedirectUrl(req)
		slog.Info(redirectTo + newUrl)
		http.Redirect(rw, req, newUrl, http.StatusFound)
	} else {
		serve.forwardRequest(rw, req)
	}
}

func (serve *Serve) handleValidToken(rw http.ResponseWriter, req *http.Request, token *jwt.Token,
	claims *jwt.MapClaims,
) {
	slog.Info("Valid token")
	slog.Info(fmt.Sprintf("Request, path: %s, query: %s", req.URL.Path, req.URL.RawQuery))

	if serve.isLogout(req) {
		slog.Info("Logging out")
		serve.logoutSelf(rw, req)
	} else if serve.isOnBehalfOfUser(token, claims) {
		serve.handleOnBehalfOfUserSelection(rw, req, token.Raw)
	} else {
		serve.forwardRequest(rw, req)
	}
}

func (serve *Serve) isCallback(req *http.Request) bool {
	return serve.isPath(req, callback)
}

func (serve *Serve) isFromOnBehalfOf(req *http.Request) bool {
	return serve.isOnBehalfOfRedirect(req.URL) || serve.isReferredByOnBehalfOfRedirect(req)
}

func (serve *Serve) isLogout(req *http.Request) bool {
	return serve.isPath(req, logout)
}

func (serve *Serve) isLogoutSelf(req *http.Request) bool {
	return serve.isPath(req, logoutself)
}

func (serve *Serve) isOnBehalfOfCallback(req *http.Request) bool {
	return serve.startsWithPath(req.URL, onBehalfOfCallback)
}

func (serve *Serve) isOnBehalfOfUser(token *jwt.Token, claims *jwt.MapClaims) bool {
	if serve.config.InternalIssuer == nil || serve.config.InternalIssuer.OnBehalfOf == nil {
		return false
	}

	issuer, _ := token.Claims.GetIssuer()

	if issuer != serve.config.InternalIssuer.Url {
		return false
	}

	if v, ok := (*claims)[serve.config.InternalIssuer.OnBehalfOf.EligibleClaim].(bool); ok {
		return v
	}

	return false
}

func (serve *Serve) isOnBehalfOfRedirect(url *url.URL) bool {
	return serve.config.InternalIssuer != nil && serve.config.InternalIssuer.OnBehalfOf != nil &&
		serve.startsWithPath(url, serve.config.InternalIssuer.OnBehalfOf.RedirectPath)
}

func (serve *Serve) isPath(req *http.Request, path string) bool {
	return req.URL.Path == serve.config.ContextPath+path
}

func (serve *Serve) isReferredByOnBehalfOfRedirect(req *http.Request) bool {
	u, err := url.Parse(req.Referer())
	if err != nil {
		return false
	}

	return serve.isOnBehalfOfRedirect(u)
}

func (serve *Serve) lazyDiscoverIdps() error {
	if serve.idps == nil {
		var err error
		serve.idps, err = discoverIdps(serve.config)

		return err
	}

	return nil
}

func (serve *Serve) lazyDiscoverInternalIssuer() error {
	if serve.internalVerifier == nil && serve.config.InternalIssuer != nil {
		var err error
		serve.internalVerifier, err = discoverInternalIssuer(serve.config)

		return err
	}

	return nil
}

func (serve *Serve) logoutIdp(rw http.ResponseWriter, req *http.Request) {
	i, err := serve.getIdpForRequest(req)

	if err != nil {
		report404(rw, req, errors.New("No IDP found"))
	} else if i.postLogoutUrl == "" {
		report501(rw, req, errors.New("not implemented"))
	} else if i.discovered.EndSessionEndpoint != "" {
		slog.Info(redirectTo + i.endSessionUrl(req))
		http.Redirect(rw, req, i.endSessionUrl(req), http.StatusFound)
	} else {
		slog.Info(redirectTo + i.postLogoutUrl)
		http.Redirect(rw, req, i.postLogoutUrl, http.StatusFound)
	}
}

func (serve *Serve) logoutSelf(rw http.ResponseWriter, req *http.Request) {
	idp, err := serve.getIdpForRequest(req)

	if err != nil {
		report404(rw, req, errors.New("No IDP found"))
	} else {
		serve.setAccessTokenCookie(rw, req, deleted)
		slog.Info(redirectTo + serve.logoutSelfUrl(req, idp))
		http.Redirect(rw, req, serve.logoutSelfUrl(req, idp), http.StatusFound)
	}
}

func (serve *Serve) logoutSelfUrl(req *http.Request, idp *idp) string {
	return "https://" + req.URL.Host + serve.config.ContextPath + logoutself + "?" + idpField +
		"=" + url.QueryEscape(idp.name)
}

func (serve *Serve) onBehalfOfRedirectUrl(req *http.Request) string {
	if serve.config.InternalIssuer != nil && serve.config.InternalIssuer.OnBehalfOf != nil {
		return serve.config.ContextPath + serve.config.InternalIssuer.OnBehalfOf.RedirectPath +
			"?url=" + url.QueryEscape(serve.onBehalfOfUrl(req))
	}

	return ""
}

func (serve *Serve) onBehalfOfUrl(req *http.Request) string {
	if serve.config.InternalIssuer != nil && serve.config.InternalIssuer.OnBehalfOf != nil {
		return serve.config.ContextPath + serve.config.InternalIssuer.OnBehalfOf.CallbackPath +
			"?url=" + url.QueryEscape(req.RequestURI)
	}

	return ""
}

func (serve *Serve) parseToken(token string) (*jwt.Token, *jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	t, _, err := serve.parser.ParseUnverified(token, claims)

	return t, &claims, err
}

func (serve *Serve) replaceWithInternalToken(token string, path string) (string, error) {
	if serve.config.InternalIssuer != nil {
		slog.Info(fmt.Sprintf("Get internal token for ID token %s", token))
		client := &http.Client{}
		request, err := http.NewRequest("GET", serve.config.InternalIssuer.Url+path, nil)
		if err != nil {
			return "", err
		}

		request.Header.Set(authorization, "Bearer "+token)
		response, err := client.Do(request)
		if err != nil {
			return "", err
		}

		if response.StatusCode == 404 {
			return token, nil
		}

		if response.StatusCode != 200 {
			return "", errors.New(response.Status)
		}

		defer streamCloser(response.Body, "internal issuer response stream could not be closed")

		body, err := io.ReadAll(response.Body)
		if err != nil {
			return "", err
		}

		return string(body), nil
	}

	return token, nil
}

func (serve *Serve) setAccessTokenCookie(rw http.ResponseWriter, req *http.Request, value string) {
	p := serve.config.ContextPath

	if p == "" {
		p = "/"
	}

	http.SetCookie(rw, &http.Cookie{
		Name:     accessToken,
		Value:    value,
		Path:     p,
		Domain:   req.Host,
		SameSite: http.SameSiteNoneMode,
		Secure:   true,
		HttpOnly: true,
	})

	if serve.config.Whoami {
		json := serve.whoami(value)

		if json != "" {
			http.SetCookie(rw, &http.Cookie{
				Name:     whoami,
				Value:    url.QueryEscape(json),
				Path:     p,
				Domain:   req.Host,
				SameSite: http.SameSiteNoneMode,
				Secure:   true,
				HttpOnly: false,
			})
		}
	}
}

func (serve *Serve) setTokenOnHeader(req *http.Request) {
	token, err := getToken(req)

	if err == nil {
		tok := token

		if !serve.config.NotBearerToken {
			tok = bearer + " " + token
		}

		req.Header.Set(serve.config.TokenHeader, tok)
	}
}

func (serve *Serve) startsWithPath(url *url.URL, path string) bool {
	return strings.HasPrefix(url.Path, serve.config.ContextPath+path)
}

func (serve *Serve) validateIdToken(token string, idp *idp) (*jwt.Token, error) {
	tok, _, err := serve.parseToken(token)
	if err != nil {
		return nil, err
	}

	validated, err := serve.validateJwt(tok, token, idp.verifier)
	if err != nil {
		return nil, err
	}

	issuer, err := validated.Claims.GetIssuer()
	if err != nil {
		return nil, err
	}

	if idp.discovered.Issuer != issuer {
		return nil, errors.New("the issuer doesn't match")
	}

	audience, err := validated.Claims.GetAudience()
	if err != nil {
		return nil, err
	}

	if indexOf(audience, idp.clientSecret.ClientID) == -1 {
		return nil, errors.New("the audience doesn't match")
	}

	expiration, err := validated.Claims.GetExpirationTime()
	if err != nil {
		return nil, err
	}

	if time.Now().After(expiration.Time) {
		return nil, errors.New("the ID token is expired")
	}

	return validated, nil
}

func (serve *Serve) validateJwt(token *jwt.Token, unparsedToken string, verifier *verifier) (*jwt.Token, error) {
	audiences, _ := token.Claims.GetAudience()

	if len(verifier.audiences) > 0 && !intersect(audiences, verifier.audiences) {
		return nil, errors.New("wrong audience")
	}

	if strings.HasPrefix(token.Method.Alg(), "RS") {
		k, err := verifier.getRsaKey(token.Header[kid].(string))
		if err != nil {
			return nil, err
		}

		return validate(unparsedToken, k, serve)
	}

	if strings.HasPrefix(token.Method.Alg(), "EC") ||
		strings.HasPrefix(token.Method.Alg(), "ES") {
		k, err := verifier.getEcdsaKey(token.Header[kid].(string))
		if err != nil {
			return nil, err
		}

		return validate(unparsedToken, k, serve)
	}

	return nil, errors.New("unsupported algorithm " + token.Method.Alg())
}

func (serve *Serve) validToken(req *http.Request) (*jwt.Token, *jwt.MapClaims, error) {
	token, claims, err := serve.getParsedToken(req)
	if err != nil {
		return nil, nil, err
	}

	verifier, err := serve.getVerifierForToken(token, claims)
	if err != nil {
		return nil, nil, err
	}

	verified, err := serve.validateJwt(token, token.Raw, verifier)
	if err != nil {
		return nil, nil, err
	}

	return verified, claims, nil
}

func (serve *Serve) whoami(token string) string {
	_, claims, err := serve.parseToken(token)
	if err != nil {
		return ""
	}

	json, err := json.Marshal(claims)
	if err != nil {
		return ""
	}

	slog.Info(fmt.Sprintf("Whoami: %s", string(json)))
	return string(json)
}

func addIdp(u *url.URL, idp string) *url.URL {
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		slog.Error(err.Error())
		return u
	}

	if !q.Has(idpField) {
		if u.RawQuery != "" {
			u.RawQuery += "&" + idpField + "=" + idp
		} else {
			u.RawQuery = idpField + "=" + idp
		}
	}

	return u
}

func bearerToken(req *http.Request) string {
	if req.Header == nil {
		return ""
	}

	header := req.Header.Get(authorization)

	if header == "" {
		return ""
	}

	parts := strings.Split(header, " ")

	if len(parts) != 2 || !isBearer(parts[0]) {
		return ""
	}

	return parts[1]
}

func cookieToken(req *http.Request) (string, error) {
	cookie, err := req.Cookie(accessToken)
	if err != nil {
		return "", err
	}

	if cookie.Value == deleted {
		return "", errors.New("deleted token cookie")
	}

	return cookie.Value, nil
}

func decrypt(s string, secret []byte) (string, error) {
	decoded, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(s)
	if err != nil {
		return "", err
	}

	gcm, err := getGcm(secret)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	nonce, encrypted := decoded[:nonceSize], decoded[nonceSize:]

	decrypted, err := gcm.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return "", err
	}

	return string(decrypted), nil
}

func deleteElement[T any](a []T, index int) []T {
	result := make([]T, len(a)-1)

	for i := range a {
		if i < index {
			result[i] = a[i]
		} else if i > index {
			result[i-1] = a[i]
		}
	}

	return result
}

func discover(providerUrl string) (*discovered, error) {
	u, err := discoveryUrl(providerUrl)
	if err != nil {
		return nil, err
	}

	slog.Info("Discovering " + u)
	response, err := http.Get(u)
	if err != nil {
		return nil, err
	}

	if response.StatusCode != 200 {
		return nil, errors.New(response.Status)
	}

	defer streamCloser(response.Body, "OIDC discovery response stream could not be closed")

	res := discovered{}
	err = json.NewDecoder(response.Body).Decode(&res)

	return &res, err
}

func discoverIdp(idpConfig *IdpConfig, config *Config) (*idp, error) {
	disc, err := discover(idpConfig.ProviderUrl)
	if err != nil {
		return nil, err
	}

	rsaKeys, ecdsaKeys, err := loadKeys(disc.JwksUri)
	if err != nil {
		return nil, err
	}

	clientSecretFile := idpConfig.ClientSecretFile

	if clientSecretFile == "" {
		clientSecretFile = defaultClientSecretFile
	}

	return &idp{
		clientSecretFile: &secretFile{filename: clientSecretFile, timestamp: -1},
		contextPath:      config.ContextPath,
		discovered:       disc,
		name:             idpConfig.Name,
		postLogoutUrl:    idpConfig.PostLogoutUrl,
		scopeParameter:   scopeParameter(scopes(idpConfig.Scopes, disc.ScopesSupported)),
		verifier: &verifier{
			audiences: idpConfig.Audiences,
			ecdsaKeys: ecdsaKeys,
			jwksUri:   disc.JwksUri,
			rsaKeys:   rsaKeys,
		},
	}, nil
}

func discoverIdps(config *Config) ([]*idp, error) {
	idps := make([]*idp, len(config.Idps))

	for i := range config.Idps {
		idp, err := discoverIdp(config.Idps[i], config)
		if err != nil {
			return nil, err
		}

		idps[i] = idp
	}

	return idps, nil
}

func discoverInternalIssuer(config *Config) (*verifier, error) {
	if config.InternalIssuer != nil {
		disc, err := discover(config.InternalIssuer.Url)
		if err != nil {
			return nil, err
		}

		rsaKeys, ecdsaKeys, err := loadKeys(disc.JwksUri)
		if err != nil {
			return nil, err
		}

		return &verifier{
			audiences: config.InternalIssuer.Audiences,
			ecdsaKeys: ecdsaKeys,
			jwksUri:   disc.JwksUri,
			rsaKeys:   rsaKeys,
		}, nil
	}

	return nil, nil
}

func discoveryUrl(providerUrl string) (string, error) {
	parsed, err := url.Parse(providerUrl)
	if err != nil {
		return "", err
	}

	parsed.Path = path.Join(parsed.Path, wellKnown)

	return parsed.String(), nil
}

func encrypt(s string, secret []byte) (string, error) {
	gcm, err := getGcm(secret)
	if err != nil {
		return "", nil
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return "", err
	}

	encrypted := gcm.Seal(nonce, nonce, []byte(s), nil)

	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(encrypted), nil
}

func getGcm(secret []byte) (cipher.AEAD, error) {
	ciph, err := aes.NewCipher(secret)
	if err != nil {
		return nil, err
	}

	return cipher.NewGCM(ciph)
}

func getIdpForUrl(u *url.URL) string {
	idp := u.Query().Get(idpField)

	if idp != "" {
		return idp
	}

	return strings.Split(u.Host, ".")[0]
}

func getIdpForUrlAsString(u string) string {
	parsed, err := url.Parse(u)
	if err != nil {
		return ""
	}

	return getIdpForUrl(parsed)
}

func getToken(req *http.Request) (string, error) {
	if token := bearerToken(req); token != "" {
		return token, nil
	}

	return cookieToken(req)
}

func hasValues(s []string) bool {
	return len(s) > 0
}

func headerToString(header http.Header) string {
	s := strings.Builder{}

	for k, v := range header {
		s.WriteString(k)
		s.WriteString(": ")
		s.WriteString(strings.Join(v, ","))
		s.WriteString(" ")
	}

	return s.String()
}

func indexOf(a []string, e string) int {
	for i := range a {
		if e == a[i] {
			return i
		}
	}

	return -1
}

func intersect(a1 []string, a2 []string) bool {
	for i := range a1 {
		if slices.Contains(a2, a1[i]) {
			return true
		}
	}

	return false
}

func isXhr(req *http.Request) bool {
	return req.Header.Get(requestedWithHeader) == xmlHttpRequest
}

func readEncryptionSecret(file string) (*encryptionSecret, error) {
	content, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	sec := encryptionSecret{}
	err = json.Unmarshal(content, &sec)

	return &sec, err
}

func removeParameter(u string, name string) string {
	parsed, err := url.Parse(u)
	if err != nil {
		return ""
	}

	pars := parsed.Query()
	pars.Del(name)
	parsed.RawQuery = pars.Encode()

	return parsed.String()
}

func report400(rw http.ResponseWriter, req *http.Request, err error) {
	reportError(rw, req, err, http.StatusBadRequest)
}

func report401(rw http.ResponseWriter, req *http.Request, err error) {
	slog.Error(err.Error() + forRequest + requestToString(req))
	http.Error(rw, "Unauthorized", http.StatusUnauthorized)
}

func report404(rw http.ResponseWriter, req *http.Request, err error) {
	reportError(rw, req, err, http.StatusNotFound)
}

func report500(rw http.ResponseWriter, req *http.Request, err error) {
	reportError(rw, req, err, http.StatusInternalServerError)
}

func report501(rw http.ResponseWriter, req *http.Request, err error) {
	reportError(rw, req, err, http.StatusNotImplemented)
}

func reportError(rw http.ResponseWriter, req *http.Request, err error, status int) {
	slog.Error(err.Error() + forRequest + requestToString(req))
	http.Error(rw, err.Error(), status)
}

func requestToString(req *http.Request) string {
	return req.Method + " " + req.URL.String() + " with headers " + headerToString(req.Header)
}

func scopeParameter(scopes []string) string {
	return strings.Join(scopes, "%20")
}

func scopes(configured []string, discovered []string) []string {
	if hasValues(configured) {
		return configured
	}

	return withoutOfflineAccess(discovered)
}

func validate[T any](token string, key *T, serve *Serve) (*jwt.Token, error) {
	return serve.parser.Parse(token, func(t *jwt.Token) (any, error) {
		return key, nil
	})
}

func withoutOfflineAccess(scopes []string) []string {
	index := indexOf(scopes, offlineAccess)

	if index == -1 {
		return scopes
	}

	return deleteElement(scopes, index)
}
