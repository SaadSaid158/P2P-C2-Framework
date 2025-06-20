package core

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

// KeyStore manages RSA key pairs and peer public keys
type KeyStore struct {
	keyDir       string
	localKeyPair *RSAKeyPair
	peerKeys     map[string]*rsa.PublicKey
}

// NewKeyStore creates a new key store
func NewKeyStore(keyDir string) (*KeyStore, error) {
	// Create key directory if it doesn't exist
	err := os.MkdirAll(keyDir, 0700)
	if err != nil {
		return nil, fmt.Errorf("failed to create key directory: %w", err)
	}

	ks := &KeyStore{
		keyDir:   keyDir,
		peerKeys: make(map[string]*rsa.PublicKey),
	}

	// Load or generate local key pair
	err = ks.loadOrGenerateLocalKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to load/generate local key pair: %w", err)
	}

	// Load peer public keys
	err = ks.loadPeerKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to load peer keys: %w", err)
	}

	return ks, nil
}

// loadOrGenerateLocalKeyPair loads existing key pair or generates a new one
func (ks *KeyStore) loadOrGenerateLocalKeyPair() error {
	privateKeyPath := filepath.Join(ks.keyDir, "local_private.pem")
	publicKeyPath := filepath.Join(ks.keyDir, "local_public.pem")

	// Check if keys exist
	if _, err := os.Stat(privateKeyPath); os.IsNotExist(err) {
		// Generate new key pair
		keyPair, err := GenerateRSAKeyPair(2048)
		if err != nil {
			return fmt.Errorf("failed to generate RSA key pair: %w", err)
		}

		// Save private key
		err = ks.savePrivateKey(privateKeyPath, keyPair.PrivateKey)
		if err != nil {
			return fmt.Errorf("failed to save private key: %w", err)
		}

		// Save public key
		err = ks.savePublicKey(publicKeyPath, keyPair.PublicKey)
		if err != nil {
			return fmt.Errorf("failed to save public key: %w", err)
		}

		ks.localKeyPair = keyPair
		return nil
	}

	// Load existing keys
	privateKey, err := ks.loadPrivateKey(privateKeyPath)
	if err != nil {
		return fmt.Errorf("failed to load private key: %w", err)
	}

	publicKey, err := ks.loadPublicKey(publicKeyPath)
	if err != nil {
		return fmt.Errorf("failed to load public key: %w", err)
	}

	ks.localKeyPair = &RSAKeyPair{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}

	return nil
}

// savePrivateKey saves a private key to file
func (ks *KeyStore) savePrivateKey(path string, key *rsa.PrivateKey) error {
	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	keyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer file.Close()

	return pem.Encode(file, keyPEM)
}

// savePublicKey saves a public key to file
func (ks *KeyStore) savePublicKey(path string, key *rsa.PublicKey) error {
	keyBytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return err
	}

	keyPEM := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: keyBytes,
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	return pem.Encode(file, keyPEM)
}

// loadPrivateKey loads a private key from file
func (ks *KeyStore) loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	keyData, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// loadPublicKey loads a public key from file
func (ks *KeyStore) loadPublicKey(path string) (*rsa.PublicKey, error) {
	keyData, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}

	return rsaPub, nil
}

// loadPeerKeys loads all peer public keys from the peers directory
func (ks *KeyStore) loadPeerKeys() error {
	peersDir := filepath.Join(ks.keyDir, "peers")
	
	// Create peers directory if it doesn't exist
	err := os.MkdirAll(peersDir, 0755)
	if err != nil {
		return err
	}

	// Read all .pem files in peers directory
	files, err := filepath.Glob(filepath.Join(peersDir, "*.pem"))
	if err != nil {
		return err
	}

	for _, file := range files {
		// Extract peer ID from filename
		filename := filepath.Base(file)
		peerID := filename[:len(filename)-4] // Remove .pem extension

		// Load public key
		publicKey, err := ks.loadPublicKey(file)
		if err != nil {
			continue // Skip invalid keys
		}

		ks.peerKeys[peerID] = publicKey
	}

	return nil
}

// GetLocalKeyPair returns the local key pair
func (ks *KeyStore) GetLocalKeyPair() *RSAKeyPair {
	return ks.localKeyPair
}

// GetPeerPublicKey returns a peer's public key
func (ks *KeyStore) GetPeerPublicKey(peerID string) (*rsa.PublicKey, bool) {
	key, exists := ks.peerKeys[peerID]
	return key, exists
}

// AddPeerPublicKey adds a peer's public key to the store
func (ks *KeyStore) AddPeerPublicKey(peerID string, publicKey *rsa.PublicKey) error {
	// Validate the public key
	if publicKey.N == nil || publicKey.E == 0 {
		return fmt.Errorf("invalid public key")
	}

	// Check key size (minimum 2048 bits)
	if publicKey.N.BitLen() < 2048 {
		return fmt.Errorf("public key too small: %d bits (minimum 2048)", publicKey.N.BitLen())
	}

	// Save to file
	peerKeyPath := filepath.Join(ks.keyDir, "peers", peerID+".pem")
	err := ks.savePublicKey(peerKeyPath, publicKey)
	if err != nil {
		return fmt.Errorf("failed to save peer public key: %w", err)
	}

	// Add to memory
	ks.peerKeys[peerID] = publicKey
	return nil
}

// RemovePeerPublicKey removes a peer's public key
func (ks *KeyStore) RemovePeerPublicKey(peerID string) error {
	// Remove from memory
	delete(ks.peerKeys, peerID)

	// Remove file
	peerKeyPath := filepath.Join(ks.keyDir, "peers", peerID+".pem")
	err := os.Remove(peerKeyPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	return nil
}

// ListPeerIDs returns all known peer IDs
func (ks *KeyStore) ListPeerIDs() []string {
	peerIDs := make([]string, 0, len(ks.peerKeys))
	for peerID := range ks.peerKeys {
		peerIDs = append(peerIDs, peerID)
	}
	return peerIDs
}

// ExportPublicKey exports the local public key as PEM string
func (ks *KeyStore) ExportPublicKey() (string, error) {
	keyBytes, err := x509.MarshalPKIXPublicKey(ks.localKeyPair.PublicKey)
	if err != nil {
		return "", err
	}

	keyPEM := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: keyBytes,
	}

	return string(pem.EncodeToMemory(keyPEM)), nil
}

// ImportPublicKey imports a public key from PEM string
func (ks *KeyStore) ImportPublicKey(peerID, pemData string) error {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return fmt.Errorf("failed to decode PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("not an RSA public key")
	}

	return ks.AddPeerPublicKey(peerID, rsaPub)
}

// GenerateSharedSecret generates a shared secret for initial authentication
func (ks *KeyStore) GenerateSharedSecret() (string, error) {
	// Generate 32 random bytes
	secretBytes := make([]byte, 32)
	_, err := rand.Read(secretBytes)
	if err != nil {
		return "", err
	}

	// Hash with local public key for uniqueness
	hash := sha256.New()
	hash.Write(secretBytes)
	
	localPubBytes, err := x509.MarshalPKIXPublicKey(ks.localKeyPair.PublicKey)
	if err != nil {
		return "", err
	}
	hash.Write(localPubBytes)

	return base64.StdEncoding.EncodeToString(hash.Sum(nil)), nil
}

