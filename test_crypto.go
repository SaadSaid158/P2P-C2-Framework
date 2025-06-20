package main

import (
	"fmt"
	"log"
	"p2p-c2-framework/core"
)

func main() {
	fmt.Println("=== P2P C2 Framework Cryptography Tests ===")
	
	// Test RSA key generation
	fmt.Println("\n1. Testing RSA key generation...")
	keyPair, err := core.GenerateRSAKeyPair(2048)
	if err != nil {
		log.Fatalf("Failed to generate RSA key pair: %v", err)
	}
	fmt.Println("✓ RSA key pair generated successfully")
	
	// Test peer ID generation
	fmt.Println("\n2. Testing peer ID generation...")
	peerID, err := core.GeneratePeerID(keyPair.PublicKey)
	if err != nil {
		log.Fatalf("Failed to generate peer ID: %v", err)
	}
	fmt.Printf("✓ Peer ID generated: %s\n", peerID[:16]+"...")
	
	// Test key export/import
	fmt.Println("\n3. Testing key export/import...")
	privPEM, err := keyPair.ExportPrivateKeyPEM()
	if err != nil {
		log.Fatalf("Failed to export private key: %v", err)
	}
	
	pubPEM, err := keyPair.ExportPublicKeyPEM()
	if err != nil {
		log.Fatalf("Failed to export public key: %v", err)
	}
	
	importedKeyPair, err := core.ImportPrivateKeyPEM(privPEM)
	if err != nil {
		log.Fatalf("Failed to import private key: %v", err)
	}
	
	importedPubKey, err := core.ImportPublicKeyPEM(pubPEM)
	if err != nil {
		log.Fatalf("Failed to import public key: %v", err)
	}
	
	// Verify imported keys match
	if importedKeyPair.PublicKey.N.Cmp(keyPair.PublicKey.N) != 0 {
		log.Fatalf("Imported private key doesn't match original")
	}
	
	if importedPubKey.N.Cmp(keyPair.PublicKey.N) != 0 {
		log.Fatalf("Imported public key doesn't match original")
	}
	
	fmt.Println("✓ Key export/import successful")
	
	// Test Diffie-Hellman key exchange
	fmt.Println("\n4. Testing Diffie-Hellman key exchange...")
	
	// Generate DH key pairs for two peers
	dhKeyPair1, err := core.GenerateDHKeyPair(core.StandardDHParams)
	if err != nil {
		log.Fatalf("Failed to generate DH key pair 1: %v", err)
	}
	
	dhKeyPair2, err := core.GenerateDHKeyPair(core.StandardDHParams)
	if err != nil {
		log.Fatalf("Failed to generate DH key pair 2: %v", err)
	}
	
	// Compute shared secrets
	sharedSecret1 := dhKeyPair1.ComputeSharedSecret(dhKeyPair2.PublicKey)
	sharedSecret2 := dhKeyPair2.ComputeSharedSecret(dhKeyPair1.PublicKey)
	
	// Verify shared secrets match
	if string(sharedSecret1) != string(sharedSecret2) {
		log.Fatalf("DH shared secrets don't match")
	}
	
	fmt.Printf("✓ DH key exchange successful, shared secret length: %d bytes\n", len(sharedSecret1))
	
	// Test session key derivation
	fmt.Println("\n5. Testing session key derivation...")
	additionalEntropy, err := core.GenerateRandomBytes(16)
	if err != nil {
		log.Fatalf("Failed to generate additional entropy: %v", err)
	}
	
	sessionKey1 := core.DeriveSessionKey(sharedSecret1, additionalEntropy)
	sessionKey2 := core.DeriveSessionKey(sharedSecret2, additionalEntropy)
	
	if string(sessionKey1) != string(sessionKey2) {
		log.Fatalf("Derived session keys don't match")
	}
	
	fmt.Printf("✓ Session key derivation successful, key length: %d bytes\n", len(sessionKey1))
	
	// Test AES-GCM encryption/decryption
	fmt.Println("\n6. Testing AES-GCM encryption/decryption...")
	plaintext := []byte("This is a test message for AES-GCM encryption")
	
	encryptedMsg, err := core.EncryptAESGCM(sessionKey1, plaintext)
	if err != nil {
		log.Fatalf("Failed to encrypt message: %v", err)
	}
	
	decryptedText, err := core.DecryptAESGCM(sessionKey1, encryptedMsg)
	if err != nil {
		log.Fatalf("Failed to decrypt message: %v", err)
	}
	
	if string(decryptedText) != string(plaintext) {
		log.Fatalf("Decrypted text doesn't match original")
	}
	
	fmt.Printf("✓ AES-GCM encryption/decryption successful\n")
	fmt.Printf("  Original: %s\n", string(plaintext))
	fmt.Printf("  Decrypted: %s\n", string(decryptedText))
	
	// Test message signing and verification
	fmt.Println("\n7. Testing message signing and verification...")
	message := []byte("This is a test message for RSA signing")
	
	signature, err := keyPair.SignMessage(message)
	if err != nil {
		log.Fatalf("Failed to sign message: %v", err)
	}
	
	err = core.VerifySignature(keyPair.PublicKey, message, signature)
	if err != nil {
		log.Fatalf("Failed to verify signature: %v", err)
	}
	
	fmt.Printf("✓ Message signing and verification successful\n")
	fmt.Printf("  Message: %s\n", string(message))
	fmt.Printf("  Signature length: %d bytes\n", len(signature))
	
	// Test signature verification with wrong message (should fail)
	wrongMessage := []byte("This is a different message")
	err = core.VerifySignature(keyPair.PublicKey, wrongMessage, signature)
	if err == nil {
		log.Fatalf("Signature verification should have failed for wrong message")
	}
	fmt.Println("✓ Signature verification correctly failed for wrong message")
	
	// Test session table
	fmt.Println("\n8. Testing session table...")
	sessionTable := core.NewSessionTable()
	
	// Add a session
	session := sessionTable.AddSession(peerID, keyPair.PublicKey, "127.0.0.1", 8443)
	if session == nil {
		log.Fatalf("Failed to add session")
	}
	
	// Retrieve the session
	retrievedSession, exists := sessionTable.GetSession(peerID)
	if !exists || retrievedSession.PeerID != peerID {
		log.Fatalf("Failed to retrieve session")
	}
	
	// Set DH key pair and peer public key
	err = sessionTable.SetDHKeyPair(peerID, dhKeyPair1)
	if err != nil {
		log.Fatalf("Failed to set DH key pair: %v", err)
	}
	
	err = sessionTable.SetPeerDHPublicKey(peerID, dhKeyPair2.PublicKey)
	if err != nil {
		log.Fatalf("Failed to set peer DH public key: %v", err)
	}
	
	// Complete handshake
	err = sessionTable.CompleteHandshake(peerID, additionalEntropy)
	if err != nil {
		log.Fatalf("Failed to complete handshake: %v", err)
	}
	
	// Verify session key was set
	if retrievedSession.SessionKey == nil {
		log.Fatalf("Session key was not set after handshake")
	}
	
	fmt.Printf("✓ Session table operations successful\n")
	fmt.Printf("  Active sessions: %d\n", sessionTable.GetActiveSessionCount())
	
	fmt.Println("\n=== All cryptography tests passed! ===")
}

