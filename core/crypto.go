package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
)

// RSAKeyPair represents an RSA key pair
type RSAKeyPair struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

// DHParams represents Diffie-Hellman parameters
type DHParams struct {
	P *big.Int // Prime modulus
	G *big.Int // Generator
}

// DHKeyPair represents a Diffie-Hellman key pair
type DHKeyPair struct {
	PrivateKey *big.Int
	PublicKey  *big.Int
	Params     *DHParams
}

// EncryptedMessage represents an encrypted message with authentication
type EncryptedMessage struct {
	Ciphertext []byte
	Nonce      []byte
	Tag        []byte
}

// Standard 2048-bit DH parameters (RFC 3526 Group 14)
var StandardDHParams = &DHParams{
	P: mustParseBigInt("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16),
	G: big.NewInt(2),
}

// GenerateRSAKeyPair generates a new RSA key pair
func GenerateRSAKeyPair(bits int) (*RSAKeyPair, error) {
	if bits < 2048 {
		return nil, errors.New("RSA key size must be at least 2048 bits")
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	return &RSAKeyPair{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	}, nil
}

// GeneratePeerID generates a peer ID from an RSA public key
func GeneratePeerID(pubKey *rsa.PublicKey) (string, error) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}

	hash := sha256.Sum256(pubKeyBytes)
	return base64.StdEncoding.EncodeToString(hash[:]), nil
}

// ExportPrivateKeyPEM exports RSA private key to PEM format
func (kp *RSAKeyPair) ExportPrivateKeyPEM() ([]byte, error) {
	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(kp.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privKeyBytes,
	}

	return pem.EncodeToMemory(block), nil
}

// ExportPublicKeyPEM exports RSA public key to PEM format
func (kp *RSAKeyPair) ExportPublicKeyPEM() ([]byte, error) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(kp.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}

	return pem.EncodeToMemory(block), nil
}

// ImportPrivateKeyPEM imports RSA private key from PEM format
func ImportPrivateKeyPEM(pemData []byte) (*RSAKeyPair, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA private key")
	}

	return &RSAKeyPair{
		PrivateKey: rsaPrivateKey,
		PublicKey:  &rsaPrivateKey.PublicKey,
	}, nil
}

// ImportPublicKeyPEM imports RSA public key from PEM format
func ImportPublicKeyPEM(pemData []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}

	return rsaPublicKey, nil
}

// GenerateDHKeyPair generates a Diffie-Hellman key pair
func GenerateDHKeyPair(params *DHParams) (*DHKeyPair, error) {
	// Generate random private key
	privateKey, err := rand.Int(rand.Reader, params.P)
	if err != nil {
		return nil, fmt.Errorf("failed to generate DH private key: %w", err)
	}

	// Calculate public key: g^private mod p
	publicKey := new(big.Int).Exp(params.G, privateKey, params.P)

	return &DHKeyPair{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		Params:     params,
	}, nil
}

// ComputeSharedSecret computes the DH shared secret
func (kp *DHKeyPair) ComputeSharedSecret(otherPublicKey *big.Int) []byte {
	// shared = other_public^private mod p
	shared := new(big.Int).Exp(otherPublicKey, kp.PrivateKey, kp.Params.P)
	return shared.Bytes()
}

// DeriveSessionKey derives an AES session key from DH shared secret and additional entropy
func DeriveSessionKey(dhShared []byte, additionalEntropy []byte) []byte {
	// Combine DH shared secret with additional entropy
	combined := append(dhShared, additionalEntropy...)
	hash := sha256.Sum256(combined)
	return hash[:]
}

// EncryptAESGCM encrypts data using AES-GCM
func EncryptAESGCM(key []byte, plaintext []byte) (*EncryptedMessage, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	return &EncryptedMessage{
		Ciphertext: ciphertext,
		Nonce:      nonce,
		Tag:        ciphertext[len(ciphertext)-gcm.Overhead():],
	}, nil
}

// DecryptAESGCM decrypts data using AES-GCM
func DecryptAESGCM(key []byte, encMsg *EncryptedMessage) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, encMsg.Nonce, encMsg.Ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// SignMessage signs a message using RSA private key
func (kp *RSAKeyPair) SignMessage(message []byte) ([]byte, error) {
	hash := sha256.Sum256(message)
	signature, err := rsa.SignPKCS1v15(rand.Reader, kp.PrivateKey, crypto.SHA256, hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign message: %w", err)
	}
	return signature, nil
}

// VerifySignature verifies a message signature using RSA public key
func VerifySignature(pubKey *rsa.PublicKey, message []byte, signature []byte) error {
	hash := sha256.Sum256(message)
	err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hash[:], signature)
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}
	return nil
}

// GenerateRandomBytes generates cryptographically secure random bytes
func GenerateRandomBytes(length int) ([]byte, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return bytes, nil
}

// Helper function to parse big integers from hex strings
func mustParseBigInt(s string, base int) *big.Int {
	n, ok := new(big.Int).SetString(s, base)
	if !ok {
		panic("failed to parse big integer")
	}
	return n
}

