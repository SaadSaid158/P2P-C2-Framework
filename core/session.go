package core

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// PeerSession represents an active session with a peer
type PeerSession struct {
	PeerID         string           `json:"peer_id"`
	PublicKey      *rsa.PublicKey   `json:"-"` // Not serialized
	SessionKey     []byte           `json:"-"` // AES session key
	DHKeyPair      *DHKeyPair       `json:"-"` // Our DH key pair for this session
	PeerDHPublicKey *big.Int        `json:"-"` // Peer's DH public key
	EstablishedAt  time.Time        `json:"established_at"`
	LastActivity   time.Time        `json:"last_activity"`
	IsActive       bool             `json:"is_active"`
	Capabilities   []string         `json:"capabilities"`
	IPAddress      string           `json:"ip_address"`
	Port           int              `json:"port"`
}

// SessionTable manages all active peer sessions
type SessionTable struct {
	sessions map[string]*PeerSession
	mutex    sync.RWMutex
}

// NewSessionTable creates a new session table
func NewSessionTable() *SessionTable {
	return &SessionTable{
		sessions: make(map[string]*PeerSession),
	}
}

// AddSession adds a new peer session
func (st *SessionTable) AddSession(peerID string, pubKey *rsa.PublicKey, ipAddress string, port int) *PeerSession {
	st.mutex.Lock()
	defer st.mutex.Unlock()

	session := &PeerSession{
		PeerID:        peerID,
		PublicKey:     pubKey,
		EstablishedAt: time.Now(),
		LastActivity:  time.Now(),
		IsActive:      true,
		IPAddress:     ipAddress,
		Port:          port,
		Capabilities:  []string{},
	}

	st.sessions[peerID] = session
	return session
}

// GetSession retrieves a session by peer ID
func (st *SessionTable) GetSession(peerID string) (*PeerSession, bool) {
	st.mutex.RLock()
	defer st.mutex.RUnlock()

	session, exists := st.sessions[peerID]
	return session, exists
}

// UpdateLastActivity updates the last activity timestamp for a session
func (st *SessionTable) UpdateLastActivity(peerID string) {
	st.mutex.Lock()
	defer st.mutex.Unlock()

	if session, exists := st.sessions[peerID]; exists {
		session.LastActivity = time.Now()
	}
}

// SetSessionKey sets the AES session key for a peer
func (st *SessionTable) SetSessionKey(peerID string, sessionKey []byte) error {
	st.mutex.Lock()
	defer st.mutex.Unlock()

	session, exists := st.sessions[peerID]
	if !exists {
		return fmt.Errorf("session not found for peer %s", peerID)
	}

	session.SessionKey = sessionKey
	return nil
}

// SetDHKeyPair sets the DH key pair for a session
func (st *SessionTable) SetDHKeyPair(peerID string, dhKeyPair *DHKeyPair) error {
	st.mutex.Lock()
	defer st.mutex.Unlock()

	session, exists := st.sessions[peerID]
	if !exists {
		return fmt.Errorf("session not found for peer %s", peerID)
	}

	session.DHKeyPair = dhKeyPair
	return nil
}

// SetPeerDHPublicKey sets the peer's DH public key
func (st *SessionTable) SetPeerDHPublicKey(peerID string, peerDHPubKey *big.Int) error {
	st.mutex.Lock()
	defer st.mutex.Unlock()

	session, exists := st.sessions[peerID]
	if !exists {
		return fmt.Errorf("session not found for peer %s", peerID)
	}

	session.PeerDHPublicKey = peerDHPubKey
	return nil
}

// CompleteHandshake completes the DH handshake and derives session key
func (st *SessionTable) CompleteHandshake(peerID string, additionalEntropy []byte) error {
	st.mutex.Lock()
	defer st.mutex.Unlock()

	session, exists := st.sessions[peerID]
	if !exists {
		return fmt.Errorf("session not found for peer %s", peerID)
	}

	if session.DHKeyPair == nil || session.PeerDHPublicKey == nil {
		return fmt.Errorf("DH keys not set for peer %s", peerID)
	}

	// Compute shared secret
	dhShared := session.DHKeyPair.ComputeSharedSecret(session.PeerDHPublicKey)

	// Derive session key
	session.SessionKey = DeriveSessionKey(dhShared, additionalEntropy)

	return nil
}

// RemoveSession removes a session
func (st *SessionTable) RemoveSession(peerID string) {
	st.mutex.Lock()
	defer st.mutex.Unlock()

	delete(st.sessions, peerID)
}

// DeactivateSession marks a session as inactive
func (st *SessionTable) DeactivateSession(peerID string) {
	st.mutex.Lock()
	defer st.mutex.Unlock()

	if session, exists := st.sessions[peerID]; exists {
		session.IsActive = false
	}
}

// GetActiveSessions returns all active sessions
func (st *SessionTable) GetActiveSessions() []*PeerSession {
	st.mutex.RLock()
	defer st.mutex.RUnlock()

	var activeSessions []*PeerSession
	for _, session := range st.sessions {
		if session.IsActive {
			activeSessions = append(activeSessions, session)
		}
	}

	return activeSessions
}

// GetAllSessions returns all sessions
func (st *SessionTable) GetAllSessions() []*PeerSession {
	st.mutex.RLock()
	defer st.mutex.RUnlock()

	var allSessions []*PeerSession
	for _, session := range st.sessions {
		allSessions = append(allSessions, session)
	}

	return allSessions
}

// CleanupInactiveSessions removes sessions that have been inactive for too long
func (st *SessionTable) CleanupInactiveSessions(timeout time.Duration) {
	st.mutex.Lock()
	defer st.mutex.Unlock()

	now := time.Now()
	for peerID, session := range st.sessions {
		if now.Sub(session.LastActivity) > timeout {
			delete(st.sessions, peerID)
		}
	}
}

// SetCapabilities sets the capabilities for a peer session
func (st *SessionTable) SetCapabilities(peerID string, capabilities []string) error {
	st.mutex.Lock()
	defer st.mutex.Unlock()

	session, exists := st.sessions[peerID]
	if !exists {
		return fmt.Errorf("session not found for peer %s", peerID)
	}

	session.Capabilities = capabilities
	return nil
}

// HasCapability checks if a peer has a specific capability
func (st *SessionTable) HasCapability(peerID string, capability string) bool {
	st.mutex.RLock()
	defer st.mutex.RUnlock()

	session, exists := st.sessions[peerID]
	if !exists {
		return false
	}

	for _, cap := range session.Capabilities {
		if cap == capability {
			return true
		}
	}

	return false
}

// GetSessionCount returns the total number of sessions
func (st *SessionTable) GetSessionCount() int {
	st.mutex.RLock()
	defer st.mutex.RUnlock()

	return len(st.sessions)
}

// GetActiveSessionCount returns the number of active sessions
func (st *SessionTable) GetActiveSessionCount() int {
	st.mutex.RLock()
	defer st.mutex.RUnlock()

	count := 0
	for _, session := range st.sessions {
		if session.IsActive {
			count++
		}
	}

	return count
}

// ExportSessions exports session information (without sensitive data) as JSON
func (st *SessionTable) ExportSessions() ([]byte, error) {
	st.mutex.RLock()
	defer st.mutex.RUnlock()

	// Create a sanitized version without sensitive data
	type SafeSession struct {
		PeerID        string    `json:"peer_id"`
		EstablishedAt time.Time `json:"established_at"`
		LastActivity  time.Time `json:"last_activity"`
		IsActive      bool      `json:"is_active"`
		Capabilities  []string  `json:"capabilities"`
		IPAddress     string    `json:"ip_address"`
		Port          int       `json:"port"`
	}

	var safeSessions []SafeSession
	for _, session := range st.sessions {
		safeSessions = append(safeSessions, SafeSession{
			PeerID:        session.PeerID,
			EstablishedAt: session.EstablishedAt,
			LastActivity:  session.LastActivity,
			IsActive:      session.IsActive,
			Capabilities:  session.Capabilities,
			IPAddress:     session.IPAddress,
			Port:          session.Port,
		})
	}

	return json.MarshalIndent(safeSessions, "", "  ")
}

