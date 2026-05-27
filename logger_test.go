package logger

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// MockExporter captures logs to verify dispatching
type MockExporter struct {
	mu   sync.Mutex
	Logs []LogItem
}

func (m *MockExporter) Export(item LogItem) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Logs = append(m.Logs, item)
	return nil
}

func TestLogDispatcher_PubSub(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "log_test")
	defer os.RemoveAll(tmpDir)
	walPath := filepath.Join(tmpDir, "test.wal")

	// 1. Initialize Dispatcher
	ld, err := NewLogDispatcher("test_service", 10, walPath)
	if err != nil {
		t.Fatalf("Failed to create dispatcher: %v", err)
	}
	defer ld.Close()

	// 2. Register Mock Exporter
	mock := &MockExporter{}
	ld.RegisterExporter(mock)

	// 3. Send Logs
	ld.Info("Test message 1")
	ld.Audit("user1", "LOGIN", "success")

	// 4. Wait for async processing
	time.Sleep(100 * time.Millisecond)

	// 5. Verify Dispatch
	mock.mu.Lock()
	if len(mock.Logs) != 2 {
		t.Fatalf("Expected 2 logs, got %d", len(mock.Logs))
	}
	
	if mock.Logs[0].Level != "INFO" || mock.Logs[0].Message != "Test message 1" {
		t.Errorf("Log 1 mismatch: got %v", mock.Logs[0])
	}

	if mock.Logs[1].Level != "AUDIT" || mock.Logs[1].Actor != "user1" {
		t.Errorf("Log 2 mismatch: got %v", mock.Logs[1])
	}
	mock.mu.Unlock()
}

func TestLogDispatcher_Fallback(t *testing.T) {
	// Test that a failing exporter doesn't crash the system and logs to WAL
	tmpDir, _ := os.MkdirTemp("", "log_test_fail")
	defer os.RemoveAll(tmpDir)
	walPath := filepath.Join(tmpDir, "fail.wal")

	ld, _ := NewLogDispatcher("test_fail", 10, walPath)
	
	// Register a broken exporter
	ld.RegisterExporter(&BrokenExporter{})
	
	ld.Info("Should end up in WAL")
	time.Sleep(100 * time.Millisecond)
	
	ld.Close()
	
	// Assert WAL file exists and has content (simplified check)
	if _, err := os.Stat(walPath); os.IsNotExist(err) {
		t.Error("WAL file was not created for fallback")
	}
}

type BrokenExporter struct{}
func (b *BrokenExporter) Export(item LogItem) error {
	return os.ErrPermission // Simulate failure
}
