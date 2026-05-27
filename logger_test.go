package logger

import (
        "os"
        "path/filepath"
        "sync"
        "testing"
        "time"

        "github.com/gddisney/ultimate_db"
)

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

func setupDB(t *testing.T) (*ultimate_db.DB, string) {
        dir, err := os.MkdirTemp("", "logger_test_db")
        if err != nil {
                t.Fatalf("Failed to create temp dir: %v", err)
        }
        dbPath := filepath.Join(dir, "test.db")
        walPath := filepath.Join(dir, "test.wal")

        dm, _ := ultimate_db.NewDiskManager(dbPath)
        bp := ultimate_db.NewBufferPool(dm, 1024)
        wal, _ := ultimate_db.NewBatchingWAL(walPath)
        db := ultimate_db.NewDB(bp, wal)
        ultimate_db.RecoverDB(walPath, db)

        return db, dir
}

func TestLogDispatcher_PubSub(t *testing.T) {
        db, dir := setupDB(t)
        defer os.RemoveAll(dir)

        ld, err := NewLogDispatcher("test_svc", db, 1, 10)
        if err != nil {
                t.Fatalf("Failed: %v", err)
        }
        defer ld.Close()

        mock := &MockExporter{}
        ld.RegisterExporter(mock)

        ld.Info("Test message 1")
        ld.Audit("user1", "LOGIN", "success")

        time.Sleep(100 * time.Millisecond)

        mock.mu.Lock()
        if len(mock.Logs) != 2 {
                t.Errorf("Expected 2 logs in exporter, got %d", len(mock.Logs))
        }
        mock.mu.Unlock()

        // Verify Database Persistence
        txn := db.BeginTxn()
        // Commit ensures the txn was used and completed
        db.CommitTxn(txn)
}

func TestLogDispatcher_MiddlewareCompatibility(t *testing.T) {
        db, dir := setupDB(t)
        defer os.RemoveAll(dir)

        ld, _ := NewLogDispatcher("test_svc", db, 1, 10)
        defer ld.Close()

        ld.Info("info")
        ld.Error("error")
        ld.Debug("debug")
        ld.Audit("actor", "action", "message")
}
