package core

import (
	"encoding/json"
	"fmt"
	"time"
)

// TaskType represents the type of task
type TaskType string

const (
	TaskTypeCommand     TaskType = "command"
	TaskTypeFileUpload  TaskType = "file_upload"
	TaskTypeFileDownload TaskType = "file_download"
	TaskTypePlugin      TaskType = "plugin"
	TaskTypeProxy       TaskType = "proxy"
	TaskTypeBeacon      TaskType = "beacon"
)

// TaskStatus represents the status of a task
type TaskStatus string

const (
	TaskStatusPending   TaskStatus = "pending"
	TaskStatusRunning   TaskStatus = "running"
	TaskStatusCompleted TaskStatus = "completed"
	TaskStatusFailed    TaskStatus = "failed"
	TaskStatusCancelled TaskStatus = "cancelled"
)

// Task represents a task to be executed
type Task struct {
	ID          string                 `json:"id"`
	Type        TaskType               `json:"type"`
	Status      TaskStatus             `json:"status"`
	TargetPeer  string                 `json:"target_peer"`
	Command     string                 `json:"command,omitempty"`
	Arguments   []string               `json:"arguments,omitempty"`
	Payload     []byte                 `json:"payload,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
	StartedAt   *time.Time             `json:"started_at,omitempty"`
	CompletedAt *time.Time             `json:"completed_at,omitempty"`
	Result      []byte                 `json:"result,omitempty"`
	Error       string                 `json:"error,omitempty"`
	Route       []string               `json:"route,omitempty"` // For onion routing
}

// TaskResult represents the result of a task execution
type TaskResult struct {
	TaskID      string    `json:"task_id"`
	Status      TaskStatus `json:"status"`
	Output      []byte    `json:"output,omitempty"`
	Error       string    `json:"error,omitempty"`
	CompletedAt time.Time `json:"completed_at"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// NewTask creates a new task
func NewTask(taskType TaskType, targetPeer string) *Task {
	return &Task{
		ID:         generateTaskID(),
		Type:       taskType,
		Status:     TaskStatusPending,
		TargetPeer: targetPeer,
		CreatedAt:  time.Now(),
		Metadata:   make(map[string]interface{}),
	}
}

// NewCommandTask creates a new command task
func NewCommandTask(targetPeer, command string, args []string) *Task {
	task := NewTask(TaskTypeCommand, targetPeer)
	task.Command = command
	task.Arguments = args
	return task
}

// NewFileUploadTask creates a new file upload task
func NewFileUploadTask(targetPeer string, fileData []byte, filename string) *Task {
	task := NewTask(TaskTypeFileUpload, targetPeer)
	task.Payload = fileData
	task.Metadata["filename"] = filename
	return task
}

// NewFileDownloadTask creates a new file download task
func NewFileDownloadTask(targetPeer, remotePath string) *Task {
	task := NewTask(TaskTypeFileDownload, targetPeer)
	task.Metadata["remote_path"] = remotePath
	return task
}

// NewPluginTask creates a new plugin execution task
func NewPluginTask(targetPeer, pluginName string, pluginArgs []string) *Task {
	task := NewTask(TaskTypePlugin, targetPeer)
	task.Command = pluginName
	task.Arguments = pluginArgs
	return task
}

// NewProxyTask creates a new proxy task for onion routing
func NewProxyTask(targetPeer string, innerTask *Task, route []string) *Task {
	task := NewTask(TaskTypeProxy, targetPeer)
	task.Route = route
	
	// Serialize inner task as payload
	innerTaskBytes, _ := json.Marshal(innerTask)
	task.Payload = innerTaskBytes
	
	return task
}

// Start marks the task as started
func (t *Task) Start() {
	t.Status = TaskStatusRunning
	now := time.Now()
	t.StartedAt = &now
}

// Complete marks the task as completed with result
func (t *Task) Complete(result []byte) {
	t.Status = TaskStatusCompleted
	t.Result = result
	now := time.Now()
	t.CompletedAt = &now
}

// Fail marks the task as failed with error
func (t *Task) Fail(err string) {
	t.Status = TaskStatusFailed
	t.Error = err
	now := time.Now()
	t.CompletedAt = &now
}

// Cancel marks the task as cancelled
func (t *Task) Cancel() {
	t.Status = TaskStatusCancelled
	now := time.Now()
	t.CompletedAt = &now
}

// IsFinished returns true if the task is in a terminal state
func (t *Task) IsFinished() bool {
	return t.Status == TaskStatusCompleted || 
		   t.Status == TaskStatusFailed || 
		   t.Status == TaskStatusCancelled
}

// Duration returns the duration of task execution
func (t *Task) Duration() time.Duration {
	if t.StartedAt == nil {
		return 0
	}
	
	endTime := time.Now()
	if t.CompletedAt != nil {
		endTime = *t.CompletedAt
	}
	
	return endTime.Sub(*t.StartedAt)
}

// ToResult converts the task to a TaskResult
func (t *Task) ToResult() *TaskResult {
	result := &TaskResult{
		TaskID:   t.ID,
		Status:   t.Status,
		Output:   t.Result,
		Error:    t.Error,
		Metadata: t.Metadata,
	}
	
	if t.CompletedAt != nil {
		result.CompletedAt = *t.CompletedAt
	}
	
	return result
}

// SetMetadata sets a metadata value
func (t *Task) SetMetadata(key string, value interface{}) {
	if t.Metadata == nil {
		t.Metadata = make(map[string]interface{})
	}
	t.Metadata[key] = value
}

// GetMetadata gets a metadata value
func (t *Task) GetMetadata(key string) (interface{}, bool) {
	if t.Metadata == nil {
		return nil, false
	}
	value, exists := t.Metadata[key]
	return value, exists
}

// GetMetadataString gets a metadata value as string
func (t *Task) GetMetadataString(key string) (string, bool) {
	value, exists := t.GetMetadata(key)
	if !exists {
		return "", false
	}
	
	str, ok := value.(string)
	return str, ok
}

// GetMetadataInt gets a metadata value as int
func (t *Task) GetMetadataInt(key string) (int, bool) {
	value, exists := t.GetMetadata(key)
	if !exists {
		return 0, false
	}
	
	// Handle both int and float64 (from JSON unmarshaling)
	switch v := value.(type) {
	case int:
		return v, true
	case float64:
		return int(v), true
	default:
		return 0, false
	}
}

// Clone creates a deep copy of the task
func (t *Task) Clone() *Task {
	clone := &Task{
		ID:         t.ID,
		Type:       t.Type,
		Status:     t.Status,
		TargetPeer: t.TargetPeer,
		Command:    t.Command,
		Arguments:  make([]string, len(t.Arguments)),
		CreatedAt:  t.CreatedAt,
		Error:      t.Error,
		Route:      make([]string, len(t.Route)),
	}
	
	copy(clone.Arguments, t.Arguments)
	copy(clone.Route, t.Route)
	
	if t.Payload != nil {
		clone.Payload = make([]byte, len(t.Payload))
		copy(clone.Payload, t.Payload)
	}
	
	if t.Result != nil {
		clone.Result = make([]byte, len(t.Result))
		copy(clone.Result, t.Result)
	}
	
	if t.StartedAt != nil {
		startedAt := *t.StartedAt
		clone.StartedAt = &startedAt
	}
	
	if t.CompletedAt != nil {
		completedAt := *t.CompletedAt
		clone.CompletedAt = &completedAt
	}
	
	if t.Metadata != nil {
		clone.Metadata = make(map[string]interface{})
		for k, v := range t.Metadata {
			clone.Metadata[k] = v
		}
	}
	
	return clone
}

// generateTaskID generates a unique task ID
func generateTaskID() string {
	// Generate a random ID using current timestamp and random bytes
	randomBytes, _ := GenerateRandomBytes(8)
	return fmt.Sprintf("task_%d_%x", time.Now().UnixNano(), randomBytes)
}

