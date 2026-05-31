package logger

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/0TrustCloud/secure_data_format"
	"github.com/0TrustCloud/ultimate_db"
)

// =============================================================================
// Interface Mock Layer for Test Isolation
// =============================================================================

type mockTxnHandle struct {
	id        uint64
	committed bool
	aborted   bool
}

func (m *mockTxnHandle) ID() uint64    { return m.id }
func (m *mockTxnHandle) Commit() error { m.committed = true; return nil }
func (m *mockTxnHandle) Abort() error  { m.aborted = true; return nil }

type mockKVStore struct {
	records map[string][]byte
	nextID  uint64
}

func (m *mockKVStore) Begin() ultimate_db.TxnHandle {
	m.nextID++
	return &mockTxnHandle{id: m.nextID}
}

func (m *mockKVStore) Get(txn ultimate_db.TxnHandle, key []byte) ([]byte, error) {
	if val, ok := m.records[string(key)]; ok {
		return val, nil
	}
	return nil, fmt.Errorf("key not found")
}

func (m *mockKVStore) Put(txn ultimate_db.TxnHandle, key []byte, value []byte, ttl time.Duration) error {
	m.records[string(key)] = value
	return nil
}

func (m *mockKVStore) Delete(txn ultimate_db.TxnHandle, key []byte) error {
	delete(m.records, string(key))
	return nil
}

func (m *mockKVStore) NewIterator(txn ultimate_db.TxnHandle, prefix []byte) ultimate_db.KVIterator {
	return nil
}

type mockLockManager struct {
	acquiredLocks map[string]uint64
}

func (m *mockLockManager) Acquire(txnID uint64, key string, mode ultimate_db.LockMode) error {
	m.acquiredLocks[key] = txnID
	return nil
}

func (m *mockLockManager) Release(txnID uint64, key string) error {
	delete(m.acquiredLocks, key)
	return nil
}

func (m *mockLockManager) ReleaseAll(txnID uint64) error {
	return nil
}

// mockExporter collects compiled logs received from the dispatcher pipe
type mockExporter struct {
	mu   sync.Mutex
	logs []LogItem
}

func (e *mockExporter) Export(item LogItem) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.logs = append(e.logs, item)
	return nil
}

func (e *mockExporter) getLogs() []LogItem {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]LogItem, len(e.logs))
	copy(out, e.logs)
	return out
}

// Helper to bootstrap a test SDF engine instance
func setupTestSDFEngine(t *testing.T) *secure_data_format.SecureDataEngine {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed generating test key pair: %v", err)
	}

	storeMock := &mockKVStore{records: make(map[string][]byte)}
	lockMock := &mockLockManager{acquiredLocks: make(map[string]uint64)}

	engine, err := secure_data_format.New(storeMock, lockMock, "test-log-authority", privKey)
	if err != nil {
		t.Fatalf("failed initializing underlying SDF engine: %v", err)
	}

	return engine
}

// =============================================================================
// Log Dispatcher Test Suites
// =============================================================================

func TestLogDispatcher_Initialization(t *testing.T) {
	sdf := setupTestSDFEngine(t)

	ld, err := NewLogDispatcher("edge-router-service", 100, sdf)
	if err != nil {
		t.Fatalf("failed initializing LogDispatcher: %v", err)
	}
	defer ld.Close()

	if ld.serviceName != "edge-router-service" {
		t.Errorf("expected service name 'edge-router-service', got '%s'", ld.serviceName)
	}
}

func TestLogDispatcher_StandardLoggingPipeline(t *testing.T) {
	sdf := setupTestSDFEngine(t)
	ld, _ := NewLogDispatcher("auth-node", 100, sdf)
	defer ld.Close()

	exp := &mockExporter{logs: []LogItem{}}
	ld.RegisterExporter(exp)

	// Emit distinct types across the standard logging matrix
	ld.Info("System layer initialized successfully")
	ld.Error("Database socket descriptor dropped unexpectedly")
	ld.Debug("Cache validation lookup path complete")
	ld.Audit("admin-greg", "REVOKE_DEVICE", "Blacklisted hardware certificate identity")

	// Allow the async queue processing loop to drain cleanly
	time.Sleep(50 * time.Millisecond)

	logs := exp.getLogs()
	if len(logs) != 4 {
		t.Fatalf("expected 4 logs to pass through exporter, got: %d", len(logs))
	}

	expectedLevels := map[string]bool{"INFO": true, "ERROR": true, "DEBUG": true, "AUDIT": true}
	for _, item := range logs {
		if !expectedLevels[item.Level] {
			t.Errorf("unexpected log level encountered: %s", item.Level)
		}

		if item.Service != "auth-node" {
			t.Errorf("expected service context field to match 'auth-node', got: %s", item.Service)
		}

		// Critical verification: Ensure every item received a valid SDF cryptographic signature token
		if item.Token == "" {
			t.Errorf("cryptographic failure: log item with level %s missing secure token envelope", item.Level)
		}
	}

	// Verify target metrics inside the compiled audit statement
	auditItem := logs[3]
	if auditItem.Actor != "admin-greg" || auditItem.Action != "REVOKE_DEVICE" {
		t.Errorf("audit context structural extraction mismatch: got actor=%s action=%s", auditItem.Actor, auditItem.Action)
	}
}

func TestLogDispatcher_QueueOverflowFallback(t *testing.T) {
	sdf := setupTestSDFEngine(t)
	
	// Initialize with a zero-buffered queue to trigger immediate overflow fallback states
	ld, _ := NewLogDispatcher("rate-limited-gateway", 0, sdf)
	defer ld.Close()

	exp := &mockExporter{logs: []LogItem{}}
	ld.RegisterExporter(exp)

	// Sending while channel is unbuffered forces immediate execution through the synchronous fallback block
	ld.Error("Emergency backpressure threshold breached")

	// Verify fallback successfully self-signed and processed straight to storage interfaces
	targetAddress := fmt.Sprintf("log:rate-limited-gateway")
	txn := sdf.Store.Begin()
	
	// Since nanosecond timestamps are variable, check the memory index loop for any keys with our matching profile range
	it := storeHasKeyPrefix(sdf.Store, "transaction_ledger:log:rate-limited-gateway")
	txn.Commit()

	if !it {
		t.Error("fallback failure: emergency out-of-band log skipped structural transactional ledger persistence steps")
	}
}

// Helper utility to inspect mock storage keys for dynamic timestamps
func storeHasKeyPrefix(store ultimate_db.KVStore, prefix string) bool {
	mStore, ok := store.(*mockKVStore)
	if !ok {
		return false
	}
	for k := range mStore.records {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}
