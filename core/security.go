package core

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
	"p2p-c2-framework/util"
	"time"
)

// ValidateDHParameters validates Diffie-Hellman parameters
func ValidateDHParameters(params *DHParams) error {
	if params == nil {
		return fmt.Errorf("DH parameters cannot be nil")
	}

	// Check if P is prime (basic check)
	if params.P == nil || params.P.BitLen() < 2048 {
		return fmt.Errorf("DH prime P must be at least 2048 bits")
	}

	// Check if G is valid
	if params.G == nil || params.G.Cmp(big.NewInt(1)) <= 0 || params.G.Cmp(params.P) >= 0 {
		return fmt.Errorf("DH generator G must be > 1 and < P")
	}

	return nil
}

// ValidateDHPublicKey validates a Diffie-Hellman public key
func ValidateDHPublicKey(publicKey *big.Int, params *DHParams) error {
	if publicKey == nil {
		return fmt.Errorf("DH public key cannot be nil")
	}

	// Check if public key is in valid range
	if publicKey.Cmp(big.NewInt(1)) <= 0 || publicKey.Cmp(params.P) >= 0 {
		return fmt.Errorf("DH public key must be > 1 and < P")
	}

	// Check if public key is not 1 or P-1 (weak keys)
	pMinus1 := new(big.Int).Sub(params.P, big.NewInt(1))
	if publicKey.Cmp(big.NewInt(1)) == 0 || publicKey.Cmp(pMinus1) == 0 {
		return fmt.Errorf("DH public key is weak (1 or P-1)")
	}

	return nil
}

// SecureHandshakeManager provides enhanced handshake security
type SecureHandshakeManager struct {
	*HandshakeManager
	logger         *util.Logger
	nonceStore     map[string]time.Time
	maxNonceAge    time.Duration
	rateLimiter    map[string]time.Time
	maxAttempts    int
}

// NewSecureHandshakeManager creates a secure handshake manager
func NewSecureHandshakeManager(peerID string, keyPair *RSAKeyPair, sessionTable *SessionTable) *SecureHandshakeManager {
	base := NewHandshakeManager(peerID, keyPair, sessionTable)
	
	return &SecureHandshakeManager{
		HandshakeManager: base,
		logger:           util.GetLogger("secure-handshake"),
		nonceStore:       make(map[string]time.Time),
		maxNonceAge:      5 * time.Minute,
		rateLimiter:      make(map[string]time.Time),
		maxAttempts:      3,
	}
}

// ValidateHandshakeInit validates handshake init packet with security checks
func (shm *SecureHandshakeManager) ValidateHandshakeInit(packet *Packet) error {
	// Check rate limiting
	if lastAttempt, exists := shm.rateLimiter[packet.PeerID]; exists {
		if time.Since(lastAttempt) < time.Minute {
			return fmt.Errorf("rate limit exceeded for peer %s", packet.PeerID)
		}
	}
	shm.rateLimiter[packet.PeerID] = time.Now()

	// Validate packet timestamp
	if packet.Timestamp == 0 {
		return fmt.Errorf("missing timestamp in handshake init")
	}

	packetTime := time.Unix(packet.Timestamp, 0)
	if time.Since(packetTime) > 5*time.Minute {
		return fmt.Errorf("handshake init packet too old")
	}

	if packetTime.After(time.Now().Add(time.Minute)) {
		return fmt.Errorf("handshake init packet from future")
	}

	return nil
}

// GenerateNonce generates a cryptographically secure nonce
func GenerateNonce() (string, error) {
	nonce := make([]byte, 32)
	_, err := rand.Read(nonce)
	if err != nil {
		return "", err
	}

	// Add timestamp for uniqueness
	timestamp := time.Now().Unix()
	hash := sha256.New()
	hash.Write(nonce)
	hash.Write([]byte(fmt.Sprintf("%d", timestamp)))

	return base64.StdEncoding.EncodeToString(hash.Sum(nil)), nil
}

// ValidateNonce validates a nonce for replay protection
func (shm *SecureHandshakeManager) ValidateNonce(nonce string) error {
	// Check if nonce was already used
	if _, exists := shm.nonceStore[nonce]; exists {
		return fmt.Errorf("nonce replay detected")
	}

	// Store nonce with timestamp
	shm.nonceStore[nonce] = time.Now()

	// Clean up old nonces
	shm.cleanupOldNonces()

	return nil
}

// cleanupOldNonces removes expired nonces
func (shm *SecureHandshakeManager) cleanupOldNonces() {
	now := time.Now()
	for nonce, timestamp := range shm.nonceStore {
		if now.Sub(timestamp) > shm.maxNonceAge {
			delete(shm.nonceStore, nonce)
		}
	}
}

// SecureInitiateHandshake initiates a secure handshake
func (shm *SecureHandshakeManager) SecureInitiateHandshake(targetPeerID string, capabilities []string) (*Packet, error) {
	// Generate nonce for replay protection
	nonce, err := GenerateNonce()
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Store nonce
	err = shm.ValidateNonce(nonce)
	if err != nil {
		return nil, fmt.Errorf("nonce validation failed: %w", err)
	}

	// Generate DH key pair with validation
	dhKeyPair, err := GenerateDHKeyPair(StandardDHParams)
	if err != nil {
		return nil, fmt.Errorf("failed to generate DH key pair: %w", err)
	}

	// Validate our own DH public key
	err = ValidateDHPublicKey(dhKeyPair.PublicKey, StandardDHParams)
	if err != nil {
		return nil, fmt.Errorf("generated DH public key is invalid: %w", err)
	}

	// Store DH key pair in session
	_, exists := shm.sessionTable.GetSession(targetPeerID)
	if !exists {
		shm.sessionTable.AddSession(targetPeerID, nil, "", 0)
	}

	err = shm.sessionTable.SetDHKeyPair(targetPeerID, dhKeyPair)
	if err != nil {
		return nil, fmt.Errorf("failed to store DH key pair: %w", err)
	}

	// Create enhanced handshake init payload
	payload := &HandshakeInitPayload{
		DHPublicKey:  base64.StdEncoding.EncodeToString(dhKeyPair.PublicKey.Bytes()),
		Capabilities: capabilities,
		Version:      "1.0",
		Nonce:        nonce,
	}

	// Create packet with current timestamp
	packet := NewPacket(PacketTypeHandshakeInit, shm.localPeerID, targetPeerID)
	packet.Timestamp = time.Now().Unix()
	
	// Set payload
	err = packet.SetPayload(payload, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to set packet payload: %w", err)
	}

	// Sign the packet
	err = packet.Sign(shm.keyPair)
	if err != nil {
		return nil, fmt.Errorf("failed to sign packet: %w", err)
	}

	shm.logger.Debug("Secure handshake init packet created for peer %s", targetPeerID)
	return packet, nil
}

// InputSanitizer provides input validation and sanitization
type InputSanitizer struct {
	logger *util.Logger
}

// NewInputSanitizer creates a new input sanitizer
func NewInputSanitizer() *InputSanitizer {
	return &InputSanitizer{
		logger: util.GetLogger("sanitizer"),
	}
}

// ValidatePeerID validates a peer ID format and content
func (is *InputSanitizer) ValidatePeerID(peerID string) error {
	if len(peerID) == 0 {
		return fmt.Errorf("peer ID cannot be empty")
	}

	if len(peerID) > 256 {
		return fmt.Errorf("peer ID too long: %d characters (max 256)", len(peerID))
	}

	// Check for valid base64 encoding
	_, err := base64.StdEncoding.DecodeString(peerID)
	if err != nil {
		return fmt.Errorf("peer ID must be valid base64: %w", err)
	}

	return nil
}

// ValidateTaskID validates a task ID
func (is *InputSanitizer) ValidateTaskID(taskID string) error {
	if len(taskID) == 0 {
		return fmt.Errorf("task ID cannot be empty")
	}

	if len(taskID) > 128 {
		return fmt.Errorf("task ID too long: %d characters (max 128)", len(taskID))
	}

	// Check for dangerous characters
	for _, char := range taskID {
		if char < 32 || char > 126 {
			return fmt.Errorf("task ID contains invalid character: %c", char)
		}
	}

	return nil
}

// ValidateCommand validates a command string
func (is *InputSanitizer) ValidateCommand(command string) error {
	if len(command) == 0 {
		return fmt.Errorf("command cannot be empty")
	}

	if len(command) > 1024 {
		return fmt.Errorf("command too long: %d characters (max 1024)", len(command))
	}

	// Check for dangerous patterns
	dangerousPatterns := []string{
		"rm -rf /",
		":(){ :|:& };:",
		"dd if=/dev/zero",
		"mkfs.",
		"format c:",
	}

	for _, pattern := range dangerousPatterns {
		if contains(command, pattern) {
			return fmt.Errorf("command contains dangerous pattern: %s", pattern)
		}
	}

	return nil
}

// ValidateFilePath validates a file path
func (is *InputSanitizer) ValidateFilePath(path string) error {
	if len(path) == 0 {
		return fmt.Errorf("file path cannot be empty")
	}

	if len(path) > 4096 {
		return fmt.Errorf("file path too long: %d characters (max 4096)", len(path))
	}

	// Check for path traversal attempts
	dangerousPatterns := []string{
		"../",
		"..\\",
		"/etc/passwd",
		"/etc/shadow",
		"C:\\Windows\\System32",
	}

	for _, pattern := range dangerousPatterns {
		if contains(path, pattern) {
			return fmt.Errorf("file path contains dangerous pattern: %s", pattern)
		}
	}

	return nil
}

// contains checks if a string contains a substring (case-insensitive)
func contains(s, substr string) bool {
	return len(s) >= len(substr) && 
		   (s == substr || 
		    (len(s) > len(substr) && 
		     (s[:len(substr)] == substr || 
		      s[len(s)-len(substr):] == substr || 
		      containsMiddle(s, substr))))
}

// containsMiddle checks if substring is in the middle of string
func containsMiddle(s, substr string) bool {
	for i := 1; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

