package goidc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"github.com/carlmjohnson/requests"
	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/json"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	paramClientID              = "client_id"
	paramCode                  = "code"
	paramRedirectURI           = "redirect_uri"
	paramScope                 = "scope"
	paramResponseType          = "response_type"
	paramState                 = "state"
	paramCodeChallenge         = "code_challenge"
	paramCodeChallengeMethod   = "code_challenge_method"
	paramGrantType             = "grant_type"
	paramCodeVerifier          = "code_verifier"
	codeChallengeMethodS256    = "S256"
	grantTypeAuthorizationCode = "authorization_code"
	responseTypeCode           = "code"
)

const (
	SCOPEOPENID  = "openid"
	SCOPEPROFILE = "profile"
	SCOPEEMAIL   = "email"
)

// DefaultScopes provides an easy-to-use set of scopes for basic apps.
var DefaultScopes = []string{SCOPEOPENID, SCOPEPROFILE, SCOPEEMAIL}

// Client as this is a simple implementation of OIDC at this point, this client is intended to only help facilitate PKCE for
// its OIDC implementation.
type Client[C any] struct {
	issuer    string
	clientID  string
	endpoints Endpoints

	cachedKeys         map[string]jose.JSONWebKey
	keyRefreshDuration time.Duration
	keyLocker          sync.RWMutex
}

func NewClient[C any](issuer, clientID string, endpoints Endpoints, keyRefreshDuration time.Duration) *Client[C] {
	c := &Client[C]{issuer: issuer,
		clientID:           clientID,
		endpoints:          endpoints,
		cachedKeys:         make(map[string]jose.JSONWebKey),
		keyRefreshDuration: keyRefreshDuration,
	}
	c.init()

	return c
}

// BuildAuthenticateRedirect this builds the URL to redirect to, it also returns the PKCE raw value (to be stored in session/cookie/etc.)
// or an error if encountered.
func (c *Client[C]) BuildAuthenticateRedirect(state, redirectURI string, scopes []string) (*url.URL, string, error) {
	codeVerifier, err := generateRandomString(24)
	if err != nil {
		return nil, "", err
	}

	hash := sha256.New()
	hash.Write([]byte(codeVerifier))
	code := base64.RawURLEncoding.EncodeToString(hash.Sum(nil))

	scope := strings.Join(scopes, " ")

	u, err := requests.URL(c.issuer).Path(c.endpoints.Authorize()).
		Param(paramClientID, c.clientID).
		Param(paramRedirectURI, redirectURI).
		Param(paramScope, scope).
		Param(paramResponseType, responseTypeCode).
		Param(paramState, state).
		Param(paramCodeChallenge, code).
		Param(paramCodeChallengeMethod, codeChallengeMethodS256).
		URL()

	return u, codeVerifier, err
}

// RequestAuthResponse takes the code returned on the callback endpoint and turns it into the auth response, again this is working with PKCE.
func (c *Client[C]) RequestAuthResponse(code, redirectURI, codeVerifier string) (*AuthResponse, error) {
	data := url.Values{}
	data.Set(paramCode, code)
	data.Set(paramGrantType, grantTypeAuthorizationCode)
	data.Set(paramRedirectURI, redirectURI)
	data.Set(paramClientID, c.clientID)
	data.Set(paramCodeVerifier, codeVerifier)

	var ar AuthResponse
	err := requests.URL(c.issuer).Path(c.endpoints.Token()).
		Post().
		BodyForm(data).
		ToJSON(&ar).
		Fetch(context.Background())

	return &ar, err
}

// ParseClaims takes the id_token returned from the authentication request, parses it based upon type C associated with this struct instance.
func (c *Client[C]) ParseClaims(idToken string) (*C, error) {
	tok, tokErr := jose.ParseSigned(idToken)
	if tokErr != nil {
		return nil, tokErr
	}

	var key jose.JSONWebKey
	var ok bool

	c.keyLocker.RLock()
	// TODO: Handle this a bit more robustly.
	key, ok = c.cachedKeys[tok.Signatures[0].Header.KeyID]
	c.keyLocker.RUnlock()

	if !ok {
		c.refreshKeys()
	}

	c.keyLocker.RLock()
	// TODO: Handle this a bit more robustly.
	key, ok = c.cachedKeys[tok.Signatures[0].Header.KeyID]
	c.keyLocker.RUnlock()

	if !ok {
		return nil, errors.New("key not found")
	}

	bs, err := tok.Verify(key)
	if err != nil {
		return nil, err
	}

	claims := new(C)
	err = json.Unmarshal(bs, claims)

	return claims, err
}

func (c *Client[C]) init() {
	err := c.refreshKeys()
	if err != nil {
		slog.Info("error loading keys", "error", err)
	}

	keysTicker := time.NewTicker(c.keyRefreshDuration)
	go func() {
		for range keysTicker.C {
			err = c.refreshKeys()
			if err != nil {
				slog.Info("error refreshing keys", "error", err)
			}
		}
	}()
}

func (c *Client[C]) refreshKeys() error {
	slog.Info("Refreshing jwks")
	var keys jose.JSONWebKeySet
	err := requests.URL(c.issuer).Path(c.endpoints.Keys()).ToJSON(&keys).Fetch(context.TODO())
	if err != nil {
		return err
	}

	c.keyLocker.Lock()
	defer c.keyLocker.Unlock()

	clear(c.cachedKeys)
	for _, key := range keys.Keys {
		c.cachedKeys[key.KeyID] = key
	}

	return nil
}
