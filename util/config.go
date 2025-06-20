package util

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Config represents the configuration for the C2 framework
type Config struct {
	// Common settings
	LogLevel    string `json:"log_level"`
	LogModules  []string `json:"log_modules"`
	
	// Tracker settings
	Tracker TrackerConfig `json:"tracker"`
	
	// Agent settings
	Agent AgentConfig `json:"agent"`
	
	// Network settings
	Network NetworkConfig `json:"network"`
	
	// Security settings
	Security SecurityConfig `json:"security"`
}

// TrackerConfig represents tracker-specific configuration
type TrackerConfig struct {
	ListenAddress    string `json:"listen_address"`
	ListenPort       int    `json:"listen_port"`
	MaxConnections   int    `json:"max_connections"`
	AuthRequired     bool   `json:"auth_required"`
	AuthPassword     string `json:"auth_password"`
	TLSEnabled       bool   `json:"tls_enabled"`
	TLSCertFile      string `json:"tls_cert_file"`
	TLSKeyFile       string `json:"tls_key_file"`
	SessionTimeout   int    `json:"session_timeout_minutes"`
}

// AgentConfig represents agent-specific configuration
type AgentConfig struct {
	TrackerAddress     string   `json:"tracker_address"`
	TrackerPort        int      `json:"tracker_port"`
	BeaconInterval     int      `json:"beacon_interval_seconds"`
	BeaconJitter       int      `json:"beacon_jitter_percent"`
	MaxRetries         int      `json:"max_retries"`
	RetryDelay         int      `json:"retry_delay_seconds"`
	Capabilities       []string `json:"capabilities"`
	WorkingDirectory   string   `json:"working_directory"`
	TempDirectory      string   `json:"temp_directory"`
	MaxTasksPerBeacon  int      `json:"max_tasks_per_beacon"`
	ThrottleDelay      int      `json:"throttle_delay_ms"`
}

// NetworkConfig represents network-specific configuration
type NetworkConfig struct {
	DHTPeers           []string `json:"dht_peers"`
	DHTPort            int      `json:"dht_port"`
	MaxPeers           int      `json:"max_peers"`
	ConnectionTimeout  int      `json:"connection_timeout_seconds"`
	KeepAliveInterval  int      `json:"keepalive_interval_seconds"`
	OnionRouting       bool     `json:"onion_routing_enabled"`
	MaxHops            int      `json:"max_hops"`
}

// SecurityConfig represents security-specific configuration
type SecurityConfig struct {
	RSAKeySize         int    `json:"rsa_key_size"`
	SessionKeySize     int    `json:"session_key_size"`
	RequireSignatures  bool   `json:"require_signatures"`
	AllowSelfSigned    bool   `json:"allow_self_signed"`
	KeyExchangeTimeout int    `json:"key_exchange_timeout_seconds"`
	SandboxDetection   bool   `json:"sandbox_detection_enabled"`
	SandboxAction      string `json:"sandbox_action"` // "exit", "idle", "continue"
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		LogLevel:   "info",
		LogModules: []string{"tracker", "agent", "crypto", "network", "dht"},
		
		Tracker: TrackerConfig{
			ListenAddress:  "0.0.0.0",
			ListenPort:     8443,
			MaxConnections: 1000,
			AuthRequired:   true,
			AuthPassword:   "changeme",
			TLSEnabled:     false,
			SessionTimeout: 30,
		},
		
		Agent: AgentConfig{
			TrackerAddress:    "127.0.0.1",
			TrackerPort:       8443,
			BeaconInterval:    60,
			BeaconJitter:      20,
			MaxRetries:        3,
			RetryDelay:        5,
			Capabilities:      []string{"command", "file_transfer", "plugin"},
			WorkingDirectory:  "/tmp",
			TempDirectory:     "/tmp",
			MaxTasksPerBeacon: 5,
			ThrottleDelay:     100,
		},
		
		Network: NetworkConfig{
			DHTPeers:          []string{},
			DHTPort:           8444,
			MaxPeers:          50,
			ConnectionTimeout: 30,
			KeepAliveInterval: 60,
			OnionRouting:      true,
			MaxHops:           3,
		},
		
		Security: SecurityConfig{
			RSAKeySize:         2048,
			SessionKeySize:     32,
			RequireSignatures:  true,
			AllowSelfSigned:    false,
			KeyExchangeTimeout: 30,
			SandboxDetection:   true,
			SandboxAction:      "continue",
		},
	}
}

// LoadConfig loads configuration from a JSON file
func LoadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &config, nil
}

// SaveConfig saves configuration to a JSON file
func (c *Config) SaveConfig(filename string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(filename, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// LoadConfigFromEnv loads configuration from environment variables
func LoadConfigFromEnv() *Config {
	config := DefaultConfig()

	// Override with environment variables if present
	if val := os.Getenv("C2_LOG_LEVEL"); val != "" {
		config.LogLevel = val
	}

	if val := os.Getenv("C2_LOG_MODULES"); val != "" {
		config.LogModules = strings.Split(val, ",")
	}

	// Tracker settings
	if val := os.Getenv("C2_TRACKER_ADDRESS"); val != "" {
		config.Tracker.ListenAddress = val
	}

	if val := os.Getenv("C2_TRACKER_PORT"); val != "" {
		if port, err := strconv.Atoi(val); err == nil {
			config.Tracker.ListenPort = port
		}
	}

	if val := os.Getenv("C2_TRACKER_AUTH_PASSWORD"); val != "" {
		config.Tracker.AuthPassword = val
	}

	if val := os.Getenv("C2_TRACKER_TLS_ENABLED"); val != "" {
		config.Tracker.TLSEnabled = val == "true"
	}

	if val := os.Getenv("C2_TRACKER_TLS_CERT"); val != "" {
		config.Tracker.TLSCertFile = val
	}

	if val := os.Getenv("C2_TRACKER_TLS_KEY"); val != "" {
		config.Tracker.TLSKeyFile = val
	}

	// Agent settings
	if val := os.Getenv("C2_AGENT_TRACKER_ADDRESS"); val != "" {
		config.Agent.TrackerAddress = val
	}

	if val := os.Getenv("C2_AGENT_TRACKER_PORT"); val != "" {
		if port, err := strconv.Atoi(val); err == nil {
			config.Agent.TrackerPort = port
		}
	}

	if val := os.Getenv("C2_AGENT_BEACON_INTERVAL"); val != "" {
		if interval, err := strconv.Atoi(val); err == nil {
			config.Agent.BeaconInterval = interval
		}
	}

	if val := os.Getenv("C2_AGENT_BEACON_JITTER"); val != "" {
		if jitter, err := strconv.Atoi(val); err == nil {
			config.Agent.BeaconJitter = jitter
		}
	}

	if val := os.Getenv("C2_AGENT_CAPABILITIES"); val != "" {
		config.Agent.Capabilities = strings.Split(val, ",")
	}

	// Network settings
	if val := os.Getenv("C2_DHT_PEERS"); val != "" {
		config.Network.DHTPeers = strings.Split(val, ",")
	}

	if val := os.Getenv("C2_DHT_PORT"); val != "" {
		if port, err := strconv.Atoi(val); err == nil {
			config.Network.DHTPort = port
		}
	}

	if val := os.Getenv("C2_ONION_ROUTING"); val != "" {
		config.Network.OnionRouting = val == "true"
	}

	// Security settings
	if val := os.Getenv("C2_RSA_KEY_SIZE"); val != "" {
		if size, err := strconv.Atoi(val); err == nil {
			config.Security.RSAKeySize = size
		}
	}

	if val := os.Getenv("C2_REQUIRE_SIGNATURES"); val != "" {
		config.Security.RequireSignatures = val == "true"
	}

	if val := os.Getenv("C2_SANDBOX_DETECTION"); val != "" {
		config.Security.SandboxDetection = val == "true"
	}

	if val := os.Getenv("C2_SANDBOX_ACTION"); val != "" {
		config.Security.SandboxAction = val
	}

	return config
}

// Validate validates the configuration
func (c *Config) Validate() error {
	// Validate log level
	validLogLevels := []string{"debug", "info", "warn", "error", "fatal"}
	if !contains(validLogLevels, c.LogLevel) {
		return fmt.Errorf("invalid log level: %s", c.LogLevel)
	}

	// Validate tracker settings
	if c.Tracker.ListenPort < 1 || c.Tracker.ListenPort > 65535 {
		return fmt.Errorf("invalid tracker port: %d", c.Tracker.ListenPort)
	}

	if c.Tracker.MaxConnections < 1 {
		return fmt.Errorf("max connections must be at least 1")
	}

	if c.Tracker.TLSEnabled {
		if c.Tracker.TLSCertFile == "" || c.Tracker.TLSKeyFile == "" {
			return fmt.Errorf("TLS cert and key files must be specified when TLS is enabled")
		}
	}

	// Validate agent settings
	if c.Agent.TrackerPort < 1 || c.Agent.TrackerPort > 65535 {
		return fmt.Errorf("invalid agent tracker port: %d", c.Agent.TrackerPort)
	}

	if c.Agent.BeaconInterval < 1 {
		return fmt.Errorf("beacon interval must be at least 1 second")
	}

	if c.Agent.BeaconJitter < 0 || c.Agent.BeaconJitter > 100 {
		return fmt.Errorf("beacon jitter must be between 0 and 100 percent")
	}

	// Validate network settings
	if c.Network.DHTPort < 1 || c.Network.DHTPort > 65535 {
		return fmt.Errorf("invalid DHT port: %d", c.Network.DHTPort)
	}

	if c.Network.MaxPeers < 1 {
		return fmt.Errorf("max peers must be at least 1")
	}

	if c.Network.MaxHops < 1 || c.Network.MaxHops > 10 {
		return fmt.Errorf("max hops must be between 1 and 10")
	}

	// Validate security settings
	if c.Security.RSAKeySize < 2048 {
		return fmt.Errorf("RSA key size must be at least 2048 bits")
	}

	if c.Security.SessionKeySize < 16 {
		return fmt.Errorf("session key size must be at least 16 bytes")
	}

	validSandboxActions := []string{"exit", "idle", "continue"}
	if !contains(validSandboxActions, c.Security.SandboxAction) {
		return fmt.Errorf("invalid sandbox action: %s", c.Security.SandboxAction)
	}

	return nil
}

// contains checks if a slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

