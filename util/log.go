package util

import (
	"fmt"
	"log"
	"os"
	"sync"
)

// LogLevel represents the logging level
type LogLevel int

const (
	LogLevelDebug LogLevel = iota
	LogLevelInfo
	LogLevelWarn
	LogLevelError
	LogLevelFatal
)

// String returns the string representation of the log level
func (l LogLevel) String() string {
	switch l {
	case LogLevelDebug:
		return "DEBUG"
	case LogLevelInfo:
		return "INFO"
	case LogLevelWarn:
		return "WARN"
	case LogLevelError:
		return "ERROR"
	case LogLevelFatal:
		return "FATAL"
	default:
		return "UNKNOWN"
	}
}

// Logger represents a modular logger
type Logger struct {
	module   string
	level    LogLevel
	enabled  bool
	logger   *log.Logger
	mutex    sync.RWMutex
}

// LoggerManager manages multiple loggers
type LoggerManager struct {
	loggers     map[string]*Logger
	globalLevel LogLevel
	mutex       sync.RWMutex
}

var (
	globalLoggerManager *LoggerManager
	once                sync.Once
)

// GetLoggerManager returns the global logger manager instance
func GetLoggerManager() *LoggerManager {
	once.Do(func() {
		globalLoggerManager = &LoggerManager{
			loggers:     make(map[string]*Logger),
			globalLevel: LogLevelInfo,
		}
	})
	return globalLoggerManager
}

// GetLogger returns a logger for the specified module
func GetLogger(module string) *Logger {
	manager := GetLoggerManager()
	manager.mutex.Lock()
	defer manager.mutex.Unlock()

	if logger, exists := manager.loggers[module]; exists {
		return logger
	}

	logger := &Logger{
		module:  module,
		level:   manager.globalLevel,
		enabled: true,
		logger:  log.New(os.Stdout, "", log.LstdFlags),
	}

	manager.loggers[module] = logger
	return logger
}

// SetGlobalLogLevel sets the global log level for all loggers
func SetGlobalLogLevel(level LogLevel) {
	manager := GetLoggerManager()
	manager.mutex.Lock()
	defer manager.mutex.Unlock()

	manager.globalLevel = level
	for _, logger := range manager.loggers {
		logger.SetLevel(level)
	}
}

// EnableModule enables logging for a specific module
func EnableModule(module string) {
	manager := GetLoggerManager()
	manager.mutex.Lock()
	defer manager.mutex.Unlock()

	if logger, exists := manager.loggers[module]; exists {
		logger.Enable()
	}
}

// DisableModule disables logging for a specific module
func DisableModule(module string) {
	manager := GetLoggerManager()
	manager.mutex.Lock()
	defer manager.mutex.Unlock()

	if logger, exists := manager.loggers[module]; exists {
		logger.Disable()
	}
}

// SetLevel sets the log level for this logger
func (l *Logger) SetLevel(level LogLevel) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.level = level
}

// Enable enables this logger
func (l *Logger) Enable() {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.enabled = true
}

// Disable disables this logger
func (l *Logger) Disable() {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.enabled = false
}

// IsEnabled returns true if the logger is enabled
func (l *Logger) IsEnabled() bool {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	return l.enabled
}

// shouldLog returns true if the message should be logged
func (l *Logger) shouldLog(level LogLevel) bool {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	return l.enabled && level >= l.level
}

// log logs a message with the specified level
func (l *Logger) log(level LogLevel, format string, args ...interface{}) {
	if !l.shouldLog(level) {
		return
	}

	message := fmt.Sprintf(format, args...)
	logLine := fmt.Sprintf("[%s] [%s] %s", level.String(), l.module, message)
	
	l.logger.Println(logLine)
	
	// Exit on fatal errors
	if level == LogLevelFatal {
		os.Exit(1)
	}
}

// Debug logs a debug message
func (l *Logger) Debug(format string, args ...interface{}) {
	l.log(LogLevelDebug, format, args...)
}

// Info logs an info message
func (l *Logger) Info(format string, args ...interface{}) {
	l.log(LogLevelInfo, format, args...)
}

// Warn logs a warning message
func (l *Logger) Warn(format string, args ...interface{}) {
	l.log(LogLevelWarn, format, args...)
}

// Error logs an error message
func (l *Logger) Error(format string, args ...interface{}) {
	l.log(LogLevelError, format, args...)
}

// Fatal logs a fatal message and exits
func (l *Logger) Fatal(format string, args ...interface{}) {
	l.log(LogLevelFatal, format, args...)
}

// Debugf is an alias for Debug
func (l *Logger) Debugf(format string, args ...interface{}) {
	l.Debug(format, args...)
}

// Infof is an alias for Info
func (l *Logger) Infof(format string, args ...interface{}) {
	l.Info(format, args...)
}

// Warnf is an alias for Warn
func (l *Logger) Warnf(format string, args ...interface{}) {
	l.Warn(format, args...)
}

// Errorf is an alias for Error
func (l *Logger) Errorf(format string, args ...interface{}) {
	l.Error(format, args...)
}

// Fatalf is an alias for Fatal
func (l *Logger) Fatalf(format string, args ...interface{}) {
	l.Fatal(format, args...)
}

// SetOutput sets the output destination for the logger
func (l *Logger) SetOutput(output *os.File) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.logger.SetOutput(output)
}

// SetFlags sets the flags for the logger
func (l *Logger) SetFlags(flags int) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.logger.SetFlags(flags)
}

// GetModules returns a list of all registered modules
func GetModules() []string {
	manager := GetLoggerManager()
	manager.mutex.RLock()
	defer manager.mutex.RUnlock()

	modules := make([]string, 0, len(manager.loggers))
	for module := range manager.loggers {
		modules = append(modules, module)
	}

	return modules
}

// GetModuleStatus returns the status of all modules
func GetModuleStatus() map[string]bool {
	manager := GetLoggerManager()
	manager.mutex.RLock()
	defer manager.mutex.RUnlock()

	status := make(map[string]bool)
	for module, logger := range manager.loggers {
		status[module] = logger.IsEnabled()
	}

	return status
}

