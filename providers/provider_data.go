package providers

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"reflect"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"golang.org/x/oauth2"
)

const (
	OIDCEmailClaim  = "email"
	OIDCGroupsClaim = "groups"
)

// ProviderData contains information required to configure all implementations
// of OAuth2 providers
type ProviderData struct {
	ProviderName      string
	LoginURL          *url.URL
	RedeemURL         *url.URL
	ProfileURL        *url.URL
	ProtectedResource *url.URL
	ValidateURL       *url.URL
	// Auth request params & related, see
	//https://openid.net/specs/openid-connect-basic-1_0.html#rfc.section.2.1.1.1
	AcrValues        string
	ApprovalPrompt   string // NOTE: Renamed to "prompt" in OAuth2
	ClientID         string
	ClientSecret     string
	ClientSecretFile string
	Scope            string
	Prompt           string

	// Common OIDC options for any OIDC-based providers to consume
	AllowUnverifiedEmail bool
	UserClaim            string
	EmailClaim           string
	GroupsClaim          string
	Verifier             *oidc.IDTokenVerifier
	LogoutTokenVerifier  *oidc.IDTokenVerifier

	// Universal Group authorization data structure
	// any provider can set to consume
	AllowedGroups map[string]struct{}
}

// Data returns the ProviderData
func (p *ProviderData) Data() *ProviderData { return p }

func (p *ProviderData) GetClientSecret() (clientSecret string, err error) {
	if p.ClientSecret != "" || p.ClientSecretFile == "" {
		return p.ClientSecret, nil
	}

	// Getting ClientSecret can fail in runtime so we need to report it without returning the file name to the user
	fileClientSecret, err := ioutil.ReadFile(p.ClientSecretFile)
	if err != nil {
		logger.Errorf("error reading client secret file %s: %s", p.ClientSecretFile, err)
		return "", errors.New("could not read client secret file")
	}
	return string(fileClientSecret), nil
}

// SetAllowedGroups organizes a group list into the AllowedGroups map
// to be consumed by Authorize implementations
func (p *ProviderData) SetAllowedGroups(groups []string) {
	p.AllowedGroups = make(map[string]struct{}, len(groups))
	for _, group := range groups {
		p.AllowedGroups[group] = struct{}{}
	}
}

type providerDefaults struct {
	name        string
	loginURL    *url.URL
	redeemURL   *url.URL
	profileURL  *url.URL
	validateURL *url.URL
	scope       string
}

func (p *ProviderData) setProviderDefaults(defaults providerDefaults) {
	p.ProviderName = defaults.name
	p.LoginURL = defaultURL(p.LoginURL, defaults.loginURL)
	p.RedeemURL = defaultURL(p.RedeemURL, defaults.redeemURL)
	p.ProfileURL = defaultURL(p.ProfileURL, defaults.profileURL)
	p.ValidateURL = defaultURL(p.ValidateURL, defaults.validateURL)

	if p.Scope == "" {
		p.Scope = defaults.scope
	}
}

// defaultURL will set return a default value if the given value is not set.
func defaultURL(u *url.URL, d *url.URL) *url.URL {
	if u != nil && u.String() != "" {
		// The value is already set
		return u
	}

	// If the default is given, return that
	if d != nil {
		return d
	}
	return &url.URL{}
}

// ****************************************************************************
// These private OIDC helper methods are available to any providers that are
// OIDC compliant
// ****************************************************************************

// OIDCClaims is a struct to unmarshal the OIDC claims from an ID Token payload
type OIDCClaims struct {
	Subject      string   `json:"sub"`
	Email        string   `json:"-"`
	Groups       []string `json:"-"`
	Verified     *bool    `json:"email_verified"`
	Nonce        string   `json:"nonce"`
	SessionState string   `json:"session_state"`
	Sid          string   `json:"sid"`

	raw map[string]interface{}
}

func (p *ProviderData) verifyIDToken(ctx context.Context, token *oauth2.Token) (*oidc.IDToken, error) {
	rawIDToken := getIDToken(token)
	if strings.TrimSpace(rawIDToken) == "" {
		return nil, ErrMissingIDToken
	}
	if p.Verifier == nil {
		return nil, ErrMissingOIDCVerifier
	}
	return p.Verifier.Verify(ctx, rawIDToken)
}

// buildSessionFromClaims uses IDToken claims to populate a fresh SessionState
// with non-Token related fields.
func (p *ProviderData) buildSessionFromClaims(idToken *oidc.IDToken) (*sessions.SessionState, error) {
	ss := &sessions.SessionState{}

	if idToken == nil {
		return ss, nil
	}

	claims, err := p.getClaims(idToken)
	if err != nil {
		return nil, fmt.Errorf("couldn't extract claims from id_token (%v)", err)
	}

	ss.User = claims.Subject
	ss.Email = claims.Email
	ss.Groups = claims.Groups

	// Allow specialized providers that embed OIDCProvider to control the User
	// claim. Not exposed as a configuration flag to generic OIDC provider
	// users (yet).
	if p.UserClaim != "" {
		user, ok := claims.raw[p.UserClaim].(string)
		if !ok {
			return nil, fmt.Errorf("unable to extract custom UserClaim (%s)", p.UserClaim)
		}
		ss.User = user
	}

	// TODO (@NickMeves) Deprecate for dynamic claim to session mapping
	if pref, ok := claims.raw["preferred_username"].(string); ok {
		ss.PreferredUsername = pref
	}

	// `email_verified` must be present and explicitly set to `false` to be
	// considered unverified.
	verifyEmail := (p.EmailClaim == OIDCEmailClaim) && !p.AllowUnverifiedEmail
	if verifyEmail && claims.Verified != nil && !*claims.Verified {
		return nil, fmt.Errorf("email in id_token (%s) isn't verified", claims.Email)
	}

	// Save sid into the session to create internal session id using OIDC's sid
	ss.SessionID = claims.Sid

	return ss, nil
}

// getClaims extracts IDToken claims into an OIDCClaims
func (p *ProviderData) getClaims(idToken *oidc.IDToken) (*OIDCClaims, error) {
	claims := &OIDCClaims{}

	// Extract default claims.
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse default id_token claims: %v", err)
	}
	// Extract custom claims.
	if err := idToken.Claims(&claims.raw); err != nil {
		return nil, fmt.Errorf("failed to parse all id_token claims: %v", err)
	}

	email := claims.raw[p.EmailClaim]
	if email != nil {
		claims.Email = fmt.Sprint(email)
	}
	claims.Groups = p.extractGroups(claims.raw)

	return claims, nil
}

// checkNonce compares the session's nonce with the IDToken's nonce claim
func (p *ProviderData) checkNonce(s *sessions.SessionState, idToken *oidc.IDToken) error {
	claims, err := p.getClaims(idToken)
	if err != nil {
		return fmt.Errorf("id_token claims extraction failed: %v", err)
	}
	if !s.CheckNonce(claims.Nonce) {
		return errors.New("id_token nonce claim does not match the session nonce")
	}
	return nil
}

// extractGroups extracts groups from a claim to a list in a type safe manner.
// If the claim isn't present, `nil` is returned. If the groups claim is
// present but empty, `[]string{}` is returned.
func (p *ProviderData) extractGroups(claims map[string]interface{}) []string {
	rawClaim, ok := claims[p.GroupsClaim]
	if !ok {
		return nil
	}

	// Handle traditional list-based groups as well as non-standard singleton
	// based groups. Both variants support complex objects if needed.
	var claimGroups []interface{}
	switch raw := rawClaim.(type) {
	case []interface{}:
		claimGroups = raw
	case interface{}:
		claimGroups = []interface{}{raw}
	}

	groups := []string{}
	for _, rawGroup := range claimGroups {
		formattedGroup, err := formatGroup(rawGroup)
		if err != nil {
			logger.Errorf("Warning: unable to format group of type %s with error %s",
				reflect.TypeOf(rawGroup), err)
			continue
		}
		groups = append(groups, formattedGroup)
	}
	return groups
}

func (p *ProviderData) getOIDCBackchannelSignOutKey(req *http.Request) (string, error) {
	err := req.ParseForm()
	if err != nil {
		return "", fmt.Errorf("couldn't parse backchannel sign out request form: %v", err)
	}

	logoutTokenRaw := req.Form.Get("logout_token")
	if logoutTokenRaw == "" {
		return "", errors.New("logout_token form field not in backchannel sign out request")
	}

	if p.LogoutTokenVerifier == nil {
		return "", ErrMissingOIDCVerifier
	}

	logoutToken, err := p.LogoutTokenVerifier.Verify(req.Context(), logoutTokenRaw)
	if err != nil {
		return "", fmt.Errorf("logout_token verification failed: %v", err)
	}

	// TODO verify logout token more
	// https://openid.net/specs/openid-connect-backchannel-1_0.html#Validation

	var claims struct {
		Sid string `json:"sid"`
	}
	if err := logoutToken.Claims(&claims); err != nil {
		return "", fmt.Errorf("logout_token unmarshaling failed: %v", err)
	}

	// If a session ID was provided, use that as the basis of the sign out key
	// for this request
	if claims.Sid != "" {
		return claims.Sid, nil
	}

	// TODO How do we support sign out by "sub"?

	return "", errors.New("logout token did not contain `sid` or `sub` claims")
}
