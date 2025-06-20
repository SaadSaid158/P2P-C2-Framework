package network

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"p2p-c2-framework/core"
	"p2p-c2-framework/util"
	"sync"
	"time"
)

// Connection represents a network connection to a peer
type Connection struct {
	conn       net.Conn
	peerID     string
	address    string
	isIncoming bool
	lastSeen   time.Time
	mutex      sync.RWMutex
}

// NetworkManager manages network connections and communication
type NetworkManager struct {
	localPeerID    string
	sessionTable   *core.SessionTable
	keyPair        *core.RSAKeyPair
	connections    map[string]*Connection
	listeners      []net.Listener
	messageHandler func(*core.Packet, *Connection)
	logger         *util.Logger
	mutex          sync.RWMutex
	shutdown       chan bool
	wg             sync.WaitGroup
}

// NewNetworkManager creates a new network manager
func NewNetworkManager(peerID string, sessionTable *core.SessionTable, keyPair *core.RSAKeyPair) *NetworkManager {
	return &NetworkManager{
		localPeerID:  peerID,
		sessionTable: sessionTable,
		keyPair:      keyPair,
		connections:  make(map[string]*Connection),
		listeners:    make([]net.Listener, 0),
		logger:       util.GetLogger("network"),
		shutdown:     make(chan bool),
	}
}

// SetMessageHandler sets the message handler function
func (nm *NetworkManager) SetMessageHandler(handler func(*core.Packet, *Connection)) {
	nm.messageHandler = handler
}

// StartTCPListener starts a TCP listener on the specified address and port
func (nm *NetworkManager) StartTCPListener(address string, port int) error {
	listenAddr := fmt.Sprintf("%s:%d", address, port)
	
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("failed to start TCP listener on %s: %w", listenAddr, err)
	}

	nm.mutex.Lock()
	nm.listeners = append(nm.listeners, listener)
	nm.mutex.Unlock()

	nm.logger.Info("TCP listener started on %s", listenAddr)

	nm.wg.Add(1)
	go nm.acceptConnections(listener)

	return nil
}

// StartTLSListener starts a TLS listener on the specified address and port
func (nm *NetworkManager) StartTLSListener(address string, port int, certFile, keyFile string) error {
	listenAddr := fmt.Sprintf("%s:%d", address, port)

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("failed to load TLS certificate: %w", err)
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	listener, err := tls.Listen("tcp", listenAddr, config)
	if err != nil {
		return fmt.Errorf("failed to start TLS listener on %s: %w", listenAddr, err)
	}

	nm.mutex.Lock()
	nm.listeners = append(nm.listeners, listener)
	nm.mutex.Unlock()

	nm.logger.Info("TLS listener started on %s", listenAddr)

	nm.wg.Add(1)
	go nm.acceptConnections(listener)

	return nil
}

// ConnectTCP connects to a peer via TCP
func (nm *NetworkManager) ConnectTCP(address string, port int) (*Connection, error) {
	target := fmt.Sprintf("%s:%d", address, port)
	
	conn, err := net.DialTimeout("tcp", target, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", target, err)
	}

	connection := &Connection{
		conn:       conn,
		address:    target,
		isIncoming: false,
		lastSeen:   time.Now(),
	}

	nm.logger.Info("Connected to %s", target)

	nm.wg.Add(1)
	go nm.handleConnection(connection)

	return connection, nil
}

// ConnectTLS connects to a peer via TLS
func (nm *NetworkManager) ConnectTLS(address string, port int, skipVerify bool) (*Connection, error) {
	target := fmt.Sprintf("%s:%d", address, port)

	config := &tls.Config{
		InsecureSkipVerify: skipVerify,
	}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 30 * time.Second}, "tcp", target, config)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s via TLS: %w", target, err)
	}

	connection := &Connection{
		conn:       conn,
		address:    target,
		isIncoming: false,
		lastSeen:   time.Now(),
	}

	nm.logger.Info("Connected to %s via TLS", target)

	nm.wg.Add(1)
	go nm.handleConnection(connection)

	return connection, nil
}

// SendPacket sends a packet to a specific peer
func (nm *NetworkManager) SendPacket(packet *core.Packet, peerID string) error {
	nm.mutex.RLock()
	connection, exists := nm.connections[peerID]
	nm.mutex.RUnlock()

	if !exists {
		return fmt.Errorf("no connection to peer %s", peerID)
	}

	return nm.sendPacketToConnection(packet, connection)
}

// BroadcastPacket sends a packet to all connected peers
func (nm *NetworkManager) BroadcastPacket(packet *core.Packet) error {
	nm.mutex.RLock()
	connections := make([]*Connection, 0, len(nm.connections))
	for _, conn := range nm.connections {
		connections = append(connections, conn)
	}
	nm.mutex.RUnlock()

	var lastErr error
	for _, conn := range connections {
		if err := nm.sendPacketToConnection(packet, conn); err != nil {
			nm.logger.Error("Failed to send packet to %s: %v", conn.peerID, err)
			lastErr = err
		}
	}

	return lastErr
}

// sendPacketToConnection sends a packet to a specific connection
func (nm *NetworkManager) sendPacketToConnection(packet *core.Packet, connection *Connection) error {
	// Get session for encryption
	session, exists := nm.sessionTable.GetSession(connection.peerID)
	_ = session // Mark as used to avoid compiler warning
	_ = exists  // Mark as used to avoid compiler warning

	// Sign the packet
	if err := packet.Sign(nm.keyPair); err != nil {
		return fmt.Errorf("failed to sign packet: %w", err)
	}

	// Convert packet to JSON
	packetBytes, err := packet.ToJSON()
	if err != nil {
		return fmt.Errorf("failed to serialize packet: %w", err)
	}

	// Send packet
	connection.mutex.Lock()
	defer connection.mutex.Unlock()

	// Write packet length followed by packet data
	packetLen := len(packetBytes)
	lenBytes := make([]byte, 4)
	lenBytes[0] = byte(packetLen >> 24)
	lenBytes[1] = byte(packetLen >> 16)
	lenBytes[2] = byte(packetLen >> 8)
	lenBytes[3] = byte(packetLen)

	if _, err := connection.conn.Write(lenBytes); err != nil {
		return fmt.Errorf("failed to write packet length: %w", err)
	}

	if _, err := connection.conn.Write(packetBytes); err != nil {
		return fmt.Errorf("failed to write packet data: %w", err)
	}

	connection.lastSeen = time.Now()
	nm.logger.Debug("Sent packet type %s to %s", packet.Type, connection.peerID)

	return nil
}

// acceptConnections accepts incoming connections
func (nm *NetworkManager) acceptConnections(listener net.Listener) {
	defer nm.wg.Done()

	for {
		select {
		case <-nm.shutdown:
			return
		default:
			conn, err := listener.Accept()
			if err != nil {
				nm.logger.Error("Failed to accept connection: %v", err)
				continue
			}

			connection := &Connection{
				conn:       conn,
				address:    conn.RemoteAddr().String(),
				isIncoming: true,
				lastSeen:   time.Now(),
			}

			nm.logger.Info("Accepted connection from %s", connection.address)

			nm.wg.Add(1)
			go nm.handleConnection(connection)
		}
	}
}

// handleConnection handles a connection
func (nm *NetworkManager) handleConnection(connection *Connection) {
	defer nm.wg.Done()
	defer connection.conn.Close()

	reader := bufio.NewReader(connection.conn)

	for {
		select {
		case <-nm.shutdown:
			return
		default:
			// Set read timeout
			connection.conn.SetReadDeadline(time.Now().Add(60 * time.Second))

			// Read packet length (4 bytes)
			lenBytes := make([]byte, 4)
			if _, err := reader.Read(lenBytes); err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				nm.logger.Debug("Connection closed: %v", err)
				return
			}

			// Calculate packet length
			packetLen := int(lenBytes[0])<<24 | int(lenBytes[1])<<16 | int(lenBytes[2])<<8 | int(lenBytes[3])

			// Validate packet length
			if packetLen <= 0 || packetLen > 1024*1024 { // Max 1MB packet
				nm.logger.Error("Invalid packet length: %d", packetLen)
				return
			}

			// Read packet data
			packetBytes := make([]byte, packetLen)
			if _, err := reader.Read(packetBytes); err != nil {
				nm.logger.Error("Failed to read packet data: %v", err)
				return
			}

			// Parse packet
			packet, err := core.FromJSON(packetBytes)
			if err != nil {
				nm.logger.Error("Failed to parse packet: %v", err)
				continue
			}

			// Update connection peer ID if not set
			if connection.peerID == "" {
				connection.peerID = packet.PeerID
				nm.mutex.Lock()
				nm.connections[packet.PeerID] = connection
				nm.mutex.Unlock()
			}

			connection.lastSeen = time.Now()
			nm.logger.Debug("Received packet type %s from %s", packet.Type, packet.PeerID)

			// Handle the packet
			if nm.messageHandler != nil {
				go nm.messageHandler(packet, connection)
			}
		}
	}
}

// GetConnections returns all active connections
func (nm *NetworkManager) GetConnections() map[string]*Connection {
	nm.mutex.RLock()
	defer nm.mutex.RUnlock()

	connections := make(map[string]*Connection)
	for peerID, conn := range nm.connections {
		connections[peerID] = conn
	}

	return connections
}

// GetConnection returns a specific connection
func (nm *NetworkManager) GetConnection(peerID string) (*Connection, bool) {
	nm.mutex.RLock()
	defer nm.mutex.RUnlock()

	conn, exists := nm.connections[peerID]
	return conn, exists
}

// CloseConnection closes a connection to a specific peer
func (nm *NetworkManager) CloseConnection(peerID string) error {
	nm.mutex.Lock()
	defer nm.mutex.Unlock()

	connection, exists := nm.connections[peerID]
	if !exists {
		return fmt.Errorf("no connection to peer %s", peerID)
	}

	connection.conn.Close()
	delete(nm.connections, peerID)

	nm.logger.Info("Closed connection to %s", peerID)
	return nil
}

// Shutdown shuts down the network manager
func (nm *NetworkManager) Shutdown() {
	nm.logger.Info("Shutting down network manager")

	// Signal shutdown
	close(nm.shutdown)

	// Close all listeners
	nm.mutex.Lock()
	for _, listener := range nm.listeners {
		listener.Close()
	}

	// Close all connections
	for _, connection := range nm.connections {
		connection.conn.Close()
	}
	nm.mutex.Unlock()

	// Wait for all goroutines to finish
	nm.wg.Wait()

	nm.logger.Info("Network manager shutdown complete")
}

// GetConnectionCount returns the number of active connections
func (nm *NetworkManager) GetConnectionCount() int {
	nm.mutex.RLock()
	defer nm.mutex.RUnlock()
	return len(nm.connections)
}

// CleanupStaleConnections removes connections that haven't been active
func (nm *NetworkManager) CleanupStaleConnections(timeout time.Duration) {
	nm.mutex.Lock()
	defer nm.mutex.Unlock()

	now := time.Now()
	for peerID, connection := range nm.connections {
		if now.Sub(connection.lastSeen) > timeout {
			nm.logger.Info("Closing stale connection to %s", peerID)
			connection.conn.Close()
			delete(nm.connections, peerID)
		}
	}
}

// Connection methods

// GetPeerID returns the peer ID for this connection
func (c *Connection) GetPeerID() string {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.peerID
}

// GetAddress returns the address for this connection
func (c *Connection) GetAddress() string {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.address
}

// IsIncoming returns true if this is an incoming connection
func (c *Connection) IsIncoming() bool {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.isIncoming
}

// GetLastSeen returns the last activity time for this connection
func (c *Connection) GetLastSeen() time.Time {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.lastSeen
}

