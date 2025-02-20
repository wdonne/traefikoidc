package traefikoidc

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"
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
	ecType                      = "EC"
	errorDescriptionField       = "error_description"
	forRequest                  = " for request "
	forToken                    = " for token "
	idpField                    = "idp"
	kid                         = "kid"
	logout                      = "/logout"
	logoutself                  = "/logoutself"
	offlineAccess               = "offline_access"
	redirectTo                  = "Redirect to "
	requestedWithHeader         = "X-Requested-With"
	rsaType                     = "RSA"
	sig                         = "sig"
	stateField                  = "state"
	wellKnown                   = ".well-known/openid-configuration"
	xmlHttpRequest              = "XMLHttpRequest"
)

type Config struct {
	ContextPath          string       `json:"contextPath,omitempty"`
	EncryptionSecretFile string       `json:"encryptionSecretFile,omitempty"`
	Idps                 []*IdpConfig `json:"idps"`
	LazyDiscovery        bool         `json:"lazyDiscovery,omitempty"`
	NotBearerToken       bool         `json:"notBearerToken,omitempty"`
	TokenHeader          string       `json:"tokenHeader,omitempty"`
}

type IdpConfig struct {
	ClientSecretFile string   `json:"clientSecretFile"`
	Name             string   `json:"name"`
	PostLogoutUrl    string   `json:"postLogoutUrl,omitempty"`
	ProviderUrl      string   `json:"providerUrl"`
	Scopes           []string `json:"scopes,omitempty"`
}

type Serve struct {
	config               *Config
	encryptionSecretFile *secretFile
	idps                 []*idp
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

type ecdsaKey struct {
	key *ecdsa.PublicKey
	kid string
}

type encryptionSecret struct {
	Secret string `json:"secret"`
}

type idTokenResponse struct {
	IdToken   string `json:"id_token"`
	State     string `json:"state"`
	TokenType string `json:"token_type"`
}

type idp struct {
	clientSecret     *secret
	clientSecretFile *secretFile
	contextPath      string
	discovered       *discovered
	ecdsaKeys        []*ecdsaKey
	name             string
	postLogoutUrl    string
	rsaKeys          []*rsaKey
	scopeParameter   string
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

type secret struct {
	ClientID     string `json:"clientID"`
	ClientSecret string `json:"clientSecret"`
}

type secretFile struct {
	filename  string
	timestamp int64
}

func CreateConfig() *Config {
	return &Config{}
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	var idps []*idp = nil

	if !config.LazyDiscovery {
		var err error = nil
		idps, err = discoverIdps(config)

		if err != nil {
			log.Println(err.Error())
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
		next:                 next,
		parser:               jwt.NewParser(),
	}, nil
}

func (serve *Serve) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	err := serve.lazyDiscoverIdps()

	if err != nil {
		log.Println(err.Error() + forRequest + requestToString(req))
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	if serve.isCallback(req) {
		fmt.Println("Callback from " + req.URL.String())
		serve.handleCallback(rw, req)
	} else if serve.isLogoutSelf(req) {
		fmt.Println("Log out of IDP")
		serve.logoutIdp(rw, req)
	} else {
		_, i, err := serve.validToken(req)

		if err != nil {
			serve.handleInvalidToken(rw, req)
		} else {
			serve.handleValidToken(rw, req, i)
		}
	}
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

func (serve *Serve) authenticate(rw http.ResponseWriter, req *http.Request) {
	i, err := serve.getIdpForRequest(req)

	if err != nil {
		log.Println(err.Error() + forRequest + requestToString(req))
		http.Error(rw, "Unauthorized", http.StatusUnauthorized)
	} else {
		u, err := serve.authenticationUrl(req, i)

		if err == nil {
			fmt.Println(redirectTo + u)
			http.Redirect(rw, req, u, http.StatusFound)
		} else {
			log.Println(err.Error() + forRequest + requestToString(req))
			http.Error(rw, "Bad request", http.StatusBadRequest)
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

	enc, err := encrypt(req.URL.String(), sec)

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

func bearerToken(req *http.Request) string {
	if req.Header == nil {
		return ""
	}

	header := req.Header.Get(authorization)

	if header == "" {
		return ""
	}

	parts := strings.Split(header, " ")

	if len(parts) != 2 && !isBearer(parts[0]) {
		return ""
	}

	return parts[1]
}

func callbackUrl(req *http.Request, contextPath string) string {
	return url.QueryEscape("https://" + req.Host + contextPath + callback)
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

	for i := 0; i < len(a); i++ {
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

	fmt.Println("Discovering " + u)
	resp, err := http.Get(u)

	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, errors.New(resp.Status)
	}

	defer streamCloser(resp.Body, "OIDC discovery response stream could not be closed")

	res := discovered{}
	err = json.NewDecoder(resp.Body).Decode(&res)

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
		ecdsaKeys:        ecdsaKeys,
		name:             idpConfig.Name,
		postLogoutUrl:    idpConfig.PostLogoutUrl,
		rsaKeys:          rsaKeys,
		scopeParameter:   scopeParameter(scopes(idpConfig.Scopes, disc.ScopesSupported))}, nil
}

func discoverIdps(config *Config) ([]*idp, error) {
	idps := make([]*idp, len(config.Idps))

	for i := 0; i < len(config.Idps); i++ {
		idp, err := discoverIdp(config.Idps[i], config)

		if err != nil {
			return nil, err
		}

		idps[i] = idp
	}

	return idps, nil
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

func (idp *idp) endSessionUrl(req *http.Request) string {
	return idp.discovered.EndSessionEndpoint +
		"?client_id=" +
		callbackUrl(req, idp.contextPath) +
		"&post_logout_redirect_uri=" +
		idp.logoutUrl()
}

func extractEcdsaKey(key *key) (*ecdsaKey, error) {
	decodedX, err := decodeBigInt(key.X)

	if err != nil {
		return nil, err
	}

	decodedY, err := decodeBigInt(key.Y)

	if err != nil {
		return nil, err
	}

	return &ecdsaKey{key: &ecdsa.PublicKey{Curve: curve(key.Crv), X: decodedX, Y: decodedY},
		kid: key.Kid}, nil
}

func extractKeys(keys *keys) ([]*rsaKey, []*ecdsaKey, error) {
	ecdsaKeys := []*ecdsaKey{}
	var err error = nil
	rsaKeys := []*rsaKey{}

	for i := 0; i < len(keys.Keys) && err == nil; i++ {
		k := keys.Keys[i]

		if k.Use == sig {
			if k.Kty == rsaType {
				rsaKeys, err = appendRsa(rsaKeys, &k)
			} else if k.Kty == ecType {
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
	decodedN, err := decodeBigInt(key.N)

	if err != nil {
		return nil, err
	}

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

func (idp *idp) findEcdsaKey(kid string) *ecdsaKey {
	for i := 0; i < len(idp.ecdsaKeys); i++ {
		if kid == idp.ecdsaKeys[i].kid {
			return idp.ecdsaKeys[i]
		}
	}

	return nil
}

func (idp *idp) findRsaKey(kid string) *rsaKey {
	for i := 0; i < len(idp.rsaKeys); i++ {
		if kid == idp.rsaKeys[i].kid {
			return idp.rsaKeys[i]
		}
	}

	return nil
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

	fmt.Println("Decrypted callback state: " + decrypted)
	idpName := getIdp(decrypted)

	return &authenticationResponse{
		code:        q.Get(codeField),
		idp:         idpName,
		originalUrl: removeParameter(decrypted, idpField)}, nil
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

func (idp *idp) getEcdsaKey(kid string) (*ecdsa.PublicKey, error) {
	k := idp.findEcdsaKey(kid)

	if k != nil {
		return k.key, nil
	}

	err := idp.reloadKeys()

	if err != nil {
		return nil, err
	}

	k = idp.findEcdsaKey(kid)

	if k == nil {
		for i := range idp.ecdsaKeys {
			fmt.Print(" " + idp.ecdsaKeys[i].kid)
		}

		return nil, errors.New("unknown kid " + kid)
	}

	return k.key, nil
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

func getGcm(secret []byte) (cipher.AEAD, error) {
	ciph, err := aes.NewCipher(secret)

	if err != nil {
		return nil, err
	}

	return cipher.NewGCM(ciph)
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

func getIdp(u string) string {
	parsed, err := url.Parse(u)

	if err != nil {
		return ""
	}

	return parsed.Query().Get(idpField)
}

func (serve *Serve) getIdp(name string) (*idp, error) {
	for i := 0; i < len(serve.idps); i++ {
		if name == serve.idps[i].name || (name == "" && serve.idps[i].name == defaultIdp) {
			fmt.Println("Using IDP " + serve.idps[i].name)
			return serve.idps[i], nil
		}
	}

	return nil, errors.New("idp " + name + " is not configured")
}

func (serve *Serve) getIdpForIssuer(issuer string) (*idp, error) {
	for i := 0; i < len(serve.idps); i++ {
		if issuer == serve.idps[i].discovered.Issuer {
			return serve.idps[i], nil
		}
	}

	return nil, errors.New("idp is not configured for issuer " + issuer)
}

func (serve *Serve) getIdpForRequest(req *http.Request) (*idp, error) {
	field := req.URL.Query().Get(idpField)

	if field != "" {
		return serve.getIdp(field)
	}

	token, _ := getToken(req)

	if token != "" {
		parsed, err := serve.parseToken(token)

		if err != nil {
			log.Println(err.Error() + forToken + token)
			return nil, err
		}

		i, err := serve.getIdpForToken(parsed)

		return i, nil
	}

	return serve.getIdp(defaultIdp)
}

func (serve *Serve) getIdpForToken(token *jwt.Token) (*idp, error) {
	issuer, err := token.Claims.GetIssuer()

	if err != nil {
		log.Println(err.Error())
		return nil, err
	}

	idp, err := serve.getIdpForIssuer(issuer)

	if err != nil {
		log.Println(err.Error())
		return nil, err
	}

	return idp, nil
}

func (idp *idp) getRsaKey(kid string) (*rsa.PublicKey, error) {
	k := idp.findRsaKey(kid)

	if k != nil {
		return k.key, nil
	}

	err := idp.reloadKeys()

	if err != nil {
		return nil, err
	}

	k = idp.findRsaKey(kid)

	if k == nil {
		for i := range idp.ecdsaKeys {
			fmt.Print(" " + idp.ecdsaKeys[i].kid)
		}

		return nil, errors.New("unknown kid " + kid)
	}

	return k.key, nil
}

func getToken(req *http.Request) (string, error) {
	if token := bearerToken(req); token != "" {
		return token, nil
	}

	return cookieToken(req)
}

func (serve *Serve) handleCallback(rw http.ResponseWriter, req *http.Request) {
	authRes, err := serve.getAuthenticationResponse(req)

	if err != nil {
		log.Println("getAuthenticationResponse: " + err.Error() + forRequest + requestToString(req))
		http.Error(rw, err.Error(), http.StatusBadRequest)

		return
	}

	i, err := serve.getIdp(authRes.idp)

	if err != nil {
		log.Println("getIdp: " + err.Error() + forRequest + requestToString(req))
		http.Error(rw, err.Error(), http.StatusBadRequest)

		return
	}

	tokenRes, err := i.getIdToken(authRes, req)

	if err != nil {
		log.Println("getIdToken: " + err.Error() + forRequest + requestToString(req))
		http.Error(rw, err.Error(), http.StatusBadRequest)

		return
	}

	_, err = serve.validateIdToken(tokenRes.IdToken, i)

	if err != nil {
		log.Println("validateIdToken: " + err.Error() + forToken + tokenRes.IdToken + " and" +
			forRequest + requestToString(req))
		http.Error(rw, err.Error(), http.StatusBadRequest)
	} else {
		serve.setAccessTokenCookie(rw, req, tokenRes.IdToken)
		fmt.Println(redirectTo + authRes.originalUrl)
		http.Redirect(rw, req, authRes.originalUrl, http.StatusFound)
	}
}

func (serve *Serve) handleInvalidToken(rw http.ResponseWriter, req *http.Request) {
	if isXhr(req) {
		http.Error(rw, "Unauthorized", http.StatusUnauthorized)
	} else {
		fmt.Println("Authenticating")
		serve.authenticate(rw, req)
	}
}

func (serve *Serve) handleValidToken(rw http.ResponseWriter, req *http.Request, idp *idp) {
	fmt.Println("Valid token")

	if serve.isLogout(req) {
		fmt.Println("Logging out")
		serve.logoutSelf(rw, req, idp)
	} else {
		serve.setTokenOnHeader(req)
		serve.next.ServeHTTP(rw, req)
	}
}

func hasValues(s []string) bool {
	return s != nil && len(s) > 0
}

func headerToString(header http.Header) string {
	s := ""

	for k, v := range header {
		s += k + ": " + strings.Join(v, ",") + " "
	}

	return s
}

func indexOf(a []string, e string) int {
	for i := 0; i < len(a); i++ {
		if e == a[i] {
			return i
		}
	}

	return -1
}

func isBearer(s string) bool {
	return strings.ToLower(s) == bearer
}

func (serve *Serve) isCallback(req *http.Request) bool {
	if serve.config.ContextPath != "" {
		return req.URL.Path == serve.config.ContextPath+callback
	}

	return req.URL.Path == callback
}

func (serve *Serve) isLogout(req *http.Request) bool {
	return serve.isPath(req, logout)
}

func (serve *Serve) isLogoutSelf(req *http.Request) bool {
	return serve.isPath(req, logoutself)
}

func (serve *Serve) isPath(req *http.Request, path string) bool {
	return req.URL.Path == serve.config.ContextPath+path
}

func isXhr(req *http.Request) bool {
	return req.Header.Get(requestedWithHeader) == xmlHttpRequest
}

func (serve *Serve) lazyDiscoverIdps() error {
	if serve.idps == nil {
		var err error = nil

		serve.idps, err = discoverIdps(serve.config)

		if err != nil {
			log.Println(err.Error())
		}

		return err
	}

	return nil
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

	fmt.Printf("Loaded %d Keys from %s\n", len(loaded.Keys), jwksUri)
	return extractKeys(&loaded)
}

func (serve *Serve) logoutIdp(rw http.ResponseWriter, req *http.Request) {
	i, err := serve.getIdpForRequest(req)

	if err != nil {
		log.Println(err.Error() + forRequest + requestToString(req))
		http.Error(rw, "No IDP found", http.StatusNotFound)
	} else if i.postLogoutUrl == "" {
		http.Error(rw, "not implemented", http.StatusNotImplemented)
	} else if i.discovered.EndSessionEndpoint != "" {
		fmt.Println(redirectTo + i.endSessionUrl(req))
		http.Redirect(rw, req, i.endSessionUrl(req), http.StatusFound)
	} else {
		fmt.Println(redirectTo + i.postLogoutUrl)
		http.Redirect(rw, req, i.postLogoutUrl, http.StatusFound)
	}
}

func (serve *Serve) logoutSelf(rw http.ResponseWriter, req *http.Request, idp *idp) {
	serve.setAccessTokenCookie(rw, req, deleted)
	fmt.Println(redirectTo + serve.logoutSelfUrl(req, idp))
	http.Redirect(rw, req, serve.logoutSelfUrl(req, idp), http.StatusFound)
}

func (serve *Serve) logoutSelfUrl(req *http.Request, idp *idp) string {
	return "https://" + req.URL.Host + serve.config.ContextPath + logoutself + "?" + idpField +
		"=" + idp.name
}

func (idp *idp) logoutUrl() string {
	return url.QueryEscape(idp.postLogoutUrl)
}

func (serve *Serve) parseToken(token string) (*jwt.Token, error) {
	t, _, err := serve.parser.ParseUnverified(token, jwt.MapClaims{})

	return t, err
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

func readEncryptionSecret(file string) (*encryptionSecret, error) {
	content, err := os.ReadFile(file)

	if err != nil {
		return nil, err
	}

	sec := encryptionSecret{}
	err = json.Unmarshal(content, &sec)

	return &sec, err
}

func (idp *idp) reloadKeys() error {
	rsaKeys, ecdsaKeys, err := loadKeys(idp.discovered.JwksUri)

	if err != nil {
		return err
	}

	idp.rsaKeys = rsaKeys
	idp.ecdsaKeys = ecdsaKeys

	return nil
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

func streamCloser(closer io.Closer, errorMessage string) {
	if err := closer.Close(); err != nil {
		log.Println(errorMessage + "\n" + err.Error())
	}
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

	fmt.Println("tokenRequestBody: " + body)
	return strings.NewReader(body), nil
}

func validate[T any](token string, key *T, serve *Serve) (*jwt.Token, error) {
	validated, err := serve.parser.Parse(token, func(t *jwt.Token) (any, error) {
		return key, nil
	})

	if err == nil {
		return validated, nil
	}

	return nil, err
}

func (serve *Serve) validateIdToken(token string, idp *idp) (*jwt.Token, error) {
	tok, err := serve.parseToken(token)

	if err != nil {
		return nil, err
	}

	validated, err := serve.validateJwt(tok, token, idp)

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

func (serve *Serve) validateJwt(token *jwt.Token, unparsedToken string, idp *idp) (*jwt.Token, error) {
	if strings.HasPrefix(token.Method.Alg(), "RS") {
		k, err := idp.getRsaKey(token.Header[kid].(string))

		if err != nil {
			return nil, err
		}

		return validate(unparsedToken, k, serve)
	}

	if strings.HasPrefix(token.Method.Alg(), "EC") ||
		strings.HasPrefix(token.Method.Alg(), "ES") {
		k, err := idp.getEcdsaKey(token.Header[kid].(string))

		if err != nil {
			return nil, err
		}

		return validate(unparsedToken, k, serve)
	}

	return nil, errors.New("unsupported algorithm " + token.Method.Alg())
}

func (serve *Serve) validToken(req *http.Request) (*jwt.Token, *idp, error) {
	token, err := getToken(req)

	if err != nil {
		return nil, nil, err
	}

	tok, err := serve.parseToken(token)

	if err != nil {
		log.Println(err.Error() + forToken + token)
		return nil, nil, err
	}

	i, err := serve.getIdpForToken(tok)

	if err != nil {
		log.Println(err.Error() + forToken + token)
		return nil, nil, err
	}

	t, err := serve.validateJwt(tok, token, i)

	if err == nil && t.Valid {
		return t, i, nil
	}

	if err != nil {
		log.Println(err.Error() + forToken + token)
	}

	return nil, nil, err
}

func withoutOfflineAccess(scopes []string) []string {
	index := indexOf(scopes, offlineAccess)

	if index == -1 {
		return scopes
	}

	return deleteElement(scopes, index)
}
