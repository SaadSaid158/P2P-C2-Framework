package core

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"p2p-c2-framework/util"
)

// HandshakeManager manages the handshake process between peers
type HandshakeManager struct {
	localPeerID    string
	keyPair        *RSAKeyPair
	sessionTable   *SessionTable
	logger         *util.Logger
}

// NewHandshakeManager creates a new handshake manager
func NewHandshakeManager(peerID string, keyPair *RSAKeyPair, sessionTable *SessionTable) *HandshakeManager {
	return &HandshakeManager{
		localPeerID:  peerID,
		keyPair:      keyPair,
		sessionTable: sessionTable,
		logger:       util.GetLogger("handshake"),
	}
}

// InitiateHandshake initiates a handshake with a peer
func (hm *HandshakeManager) InitiateHandshake(targetPeerID string, capabilities []string) (*Packet, error) {
	hm.logger.Info("Initiating handshake with peer %s", targetPeerID)

	// Generate DH key pair for this session
	dhKeyPair, err := GenerateDHKeyPair(StandardDHParams)
	if err != nil {
		return nil, fmt.Errorf("failed to generate DH key pair: %w", err)
	}

	// Store DH key pair in session (create session if it doesn't exist)
	_, exists := hm.sessionTable.GetSession(targetPeerID)
	if !exists {
		// We don't have the peer's public key yet, so we'll add it later
		hm.sessionTable.AddSession(targetPeerID, nil, "", 0)
	}

	err = hm.sessionTable.SetDHKeyPair(targetPeerID, dhKeyPair)
	if err != nil {
		return nil, fmt.Errorf("failed to store DH key pair: %w", err)
	}

	// Create handshake init payload
	payload := &HandshakeInitPayload{
		DHPublicKey:  base64.StdEncoding.EncodeToString(dhKeyPair.PublicKey.Bytes()),
		Capabilities: capabilities,
		Version:      "1.0",
	}

	// Create packet
	packet := NewPacket(PacketTypeHandshakeInit, hm.localPeerID, targetPeerID)
	
	// Set payload (no encryption for handshake init)
	err = packet.SetPayload(payload, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to set packet payload: %w", err)
	}

	// Sign the packet
	err = packet.Sign(hm.keyPair)
	if err != nil {
		return nil, fmt.Errorf("failed to sign packet: %w", err)
	}

	hm.logger.Debug("Handshake init packet created for peer %s", targetPeerID)
	return packet, nil
}

// HandleHandshakeInit handles an incoming handshake init packet
func (hm *HandshakeManager) HandleHandshakeInit(packet *Packet, peerPublicKey *rsa.PublicKey) (*Packet, error) {
	hm.logger.Info("Handling handshake init from peer %s", packet.PeerID)

	// Verify packet signature
	err := packet.VerifySignature(peerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("handshake init signature verification failed: %w", err)
	}

	// Parse payload
	var payload HandshakeInitPayload
	err = packet.GetPayload(nil, &payload) // No encryption for handshake init
	if err != nil {
		return nil, fmt.Errorf("failed to parse handshake init payload: %w", err)
	}

	// Decode peer's DH public key
	peerDHPubKeyBytes, err := base64.StdEncoding.DecodeString(payload.DHPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode peer DH public key: %w", err)
	}

	peerDHPubKey := new(big.Int).SetBytes(peerDHPubKeyBytes)

	// Create or update session
	_, exists := hm.sessionTable.GetSession(packet.PeerID)
	if !exists {
		hm.sessionTable.AddSession(packet.PeerID, peerPublicKey, "", 0)
	}

	// Set capabilities
	err = hm.sessionTable.SetCapabilities(packet.PeerID, payload.Capabilities)
	if err != nil {
		return nil, fmt.Errorf("failed to set peer capabilities: %w", err)
	}

	// Generate our DH key pair
	dhKeyPair, err := GenerateDHKeyPair(StandardDHParams)
	if err != nil {
		return nil, fmt.Errorf("failed to generate DH key pair: %w", err)
	}

	// Store DH keys
	err = hm.sessionTable.SetDHKeyPair(packet.PeerID, dhKeyPair)
	if err != nil {
		return nil, fmt.Errorf("failed to store DH key pair: %w", err)
	}

	err = hm.sessionTable.SetPeerDHPublicKey(packet.PeerID, peerDHPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to store peer DH public key: %w", err)
	}

	// Generate additional entropy for session key derivation
	additionalEntropy, err := GenerateRandomBytes(16)
	if err != nil {
		return nil, fmt.Errorf("failed to generate additional entropy: %w", err)
	}

	// Complete handshake (derive session key)
	err = hm.sessionTable.CompleteHandshake(packet.PeerID, additionalEntropy)
	if err != nil {
		return nil, fmt.Errorf("failed to complete handshake: %w", err)
	}

	// Create handshake response payload
	responsePayload := &HandshakeResponsePayload{
		DHPublicKey:       base64.StdEncoding.EncodeToString(dhKeyPair.PublicKey.Bytes()),
		Capabilities:      []string{"command", "file_transfer", "plugin"}, // Our capabilities
		Version:           "1.0",
		AdditionalEntropy: base64.StdEncoding.EncodeToString(additionalEntropy),
	}

	// Create response packet
	responsePacket := NewPacket(PacketTypeHandshakeResponse, hm.localPeerID, packet.PeerID)
	
	// Set payload (no encryption for handshake response)
	err = responsePacket.SetPayload(responsePayload, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to set response packet payload: %w", err)
	}

	// Sign the response packet
	err = responsePacket.Sign(hm.keyPair)
	if err != nil {
		return nil, fmt.Errorf("failed to sign response packet: %w", err)
	}

	hm.logger.Info("Handshake with peer %s completed successfully", packet.PeerID)
	return responsePacket, nil
}

// HandleHandshakeResponse handles an incoming handshake response packet
func (hm *HandshakeManager) HandleHandshakeResponse(packet *Packet, peerPublicKey *rsa.PublicKey) error {
	hm.logger.Info("Handling handshake response from peer %s", packet.PeerID)

	// Verify packet signature
	err := packet.VerifySignature(peerPublicKey)
	if err != nil {
		return fmt.Errorf("handshake response signature verification failed: %w", err)
	}

	// Parse payload
	var payload HandshakeResponsePayload
	err = packet.GetPayload(nil, &payload) // No encryption for handshake response
	if err != nil {
		return fmt.Errorf("failed to parse handshake response payload: %w", err)
	}

	// Decode peer's DH public key
	peerDHPubKeyBytes, err := base64.StdEncoding.DecodeString(payload.DHPublicKey)
	if err != nil {
		return fmt.Errorf("failed to decode peer DH public key: %w", err)
	}

	peerDHPubKey := new(big.Int).SetBytes(peerDHPubKeyBytes)

	// Decode additional entropy
	additionalEntropy, err := base64.StdEncoding.DecodeString(payload.AdditionalEntropy)
	if err != nil {
		return fmt.Errorf("failed to decode additional entropy: %w", err)
	}

	// Store peer's DH public key
	err = hm.sessionTable.SetPeerDHPublicKey(packet.PeerID, peerDHPubKey)
	if err != nil {
		return fmt.Errorf("failed to store peer DH public key: %w", err)
	}

	// Set peer capabilities
	err = hm.sessionTable.SetCapabilities(packet.PeerID, payload.Capabilities)
	if err != nil {
		return fmt.Errorf("failed to set peer capabilities: %w", err)
	}

	// Complete handshake (derive session key)
	err = hm.sessionTable.CompleteHandshake(packet.PeerID, additionalEntropy)
	if err != nil {
		return fmt.Errorf("failed to complete handshake: %w", err)
	}

	hm.logger.Info("Handshake with peer %s completed successfully", packet.PeerID)
	return nil
}

// GetSessionKey returns the session key for a peer (after successful handshake)
func (hm *HandshakeManager) GetSessionKey(peerID string) ([]byte, error) {
	session, exists := hm.sessionTable.GetSession(peerID)
	if !exists {
		return nil, fmt.Errorf("no session found for peer %s", peerID)
	}

	if session.SessionKey == nil {
		return nil, fmt.Errorf("handshake not completed for peer %s", peerID)
	}

	return session.SessionKey, nil
}

// IsHandshakeComplete checks if handshake is complete for a peer
func (hm *HandshakeManager) IsHandshakeComplete(peerID string) bool {
	session, exists := hm.sessionTable.GetSession(peerID)
	if !exists {
		return false
	}

	return session.SessionKey != nil
}

