package persistence

import (
	"crypto/aes"
	"fmt"
	"net/http"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/encryption"
)

// Manager wraps a Store and handles the implementation details of the
// sessions.SessionStore with its use of session tickets
type Manager struct {
	Store   Store
	Options *options.Cookie
}

// NewManager creates a Manager that can wrap a Store and manage the
// sessions.SessionStore implementation details
func NewManager(store Store, cookieOpts *options.Cookie) *Manager {
	return &Manager{
		Store:   store,
		Options: cookieOpts,
	}
}

// Save saves a session in a persistent Store. Save will generate (or reuse an
// existing) ticket which manages unique per session encryption & retrieval
// from the persistent data store.
func (m *Manager) Save(rw http.ResponseWriter, req *http.Request, s *sessions.SessionState) error {
	if s.CreatedAt == nil || s.CreatedAt.IsZero() {
		s.CreatedAtNow()
	}

	tckt, err := decodeTicketFromRequest(req, m.Options)
	if err != nil {
		tckt, err = newTicket(m.Options, s)
		if err != nil {
			return fmt.Errorf("error creating a session ticket: %v", err)
		}
	}

	err = tckt.saveSession(s, func(key string, val []byte, exp time.Duration) error {
		return m.Store.Save(req.Context(), key, val, exp)
	})
	if err != nil {
		return err
	}

	return tckt.setCookie(rw, req, s)
}

// Load reads sessions.SessionState information from a session store. It will
// use the session ticket from the http.Request's cookie.
func (m *Manager) Load(req *http.Request) (*sessions.SessionState, error) {
	tckt, err := decodeTicketFromRequest(req, m.Options)
	if err != nil {
		return nil, err
	}

	return tckt.loadSession(
		func(key string) ([]byte, error) {
			return m.Store.Load(req.Context(), key)
		},
		m.Store.Lock,
	)
}

// Clear clears any saved session information for a given ticket cookie.
// Then it clears all session data for that ticket in the Store.
func (m *Manager) Clear(rw http.ResponseWriter, req *http.Request) error {
	tckt, err := decodeTicketFromRequest(req, m.Options)
	if err != nil {
		// Always clear the cookie, even when we can't load a cookie from
		// the request
		tckt = &ticket{
			options: m.Options,
		}
		tckt.clearCookie(rw, req)
		// Don't raise an error if we didn't have a Cookie
		if err == http.ErrNoCookie {
			return nil
		}
		return fmt.Errorf("error decoding ticket to clear session: %v", err)
	}

	tckt.clearCookie(rw, req)
	return tckt.clearSession(func(key string) error {
		return m.Store.Clear(req.Context(), key)
	})
}

// ClearSignOutKey clears saved session information for a given sign out key
// from redis
func (m *Manager) ClearSignOutKey(req *http.Request, signOutKey string) error {
	return m.Store.Clear(req.Context(), signOutKey)
}

// AddSignedOutUser adds singed out user session into redis, which is used as
// block list when authenticating the user later
func (m *Manager) AddSignedOutUser(req *http.Request, s *sessions.SignedOutState) error {
	key := fmt.Sprintf("%s-nbf-%s", m.Options.Name, s.Sub)

	secret := make([]byte, aes.BlockSize)
	copy(secret, m.Options.Name)

	c, err := encryption.NewGCMCipher(secret)
	if err != nil {
		return fmt.Errorf("failed to make an AES-GCM cipher from the secret: %v", err)
	}

	ciphertext, err := s.EncodeSignedOutState(c, false)
	if err != nil {
		return fmt.Errorf("failed to encode signed out state: %v", err)
	}

	return m.Store.Save(req.Context(), key, ciphertext, m.Options.Expire)
}

// LoadSignedOutUser loads the signed out user session from redis
func (m *Manager) LoadSignedOutUser(req *http.Request, sub string) (*sessions.SignedOutState, error) {
	key := fmt.Sprintf("%s-nbf-%s", m.Options.Name, sub)

	val, err := m.Store.Load(req.Context(), key)
	if err != nil {
		return nil, fmt.Errorf("failed to load signed out state: %v", err)
	}

	secret := make([]byte, aes.BlockSize)
	copy(secret, m.Options.Name)

	c, err := encryption.NewGCMCipher(secret)
	if err != nil {
		return nil, fmt.Errorf("failed to make an AES-GCM cipher from the secret: %v", err)
	}

	s, err := sessions.DecodeSignedOutState(val, c, false)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signed out state: %v", err)
	}

	return s, nil
}
