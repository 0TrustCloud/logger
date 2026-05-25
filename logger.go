package logger

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/gddisney/secure_network"
	"github.com/gddisney/ultimate_db"
)

// LogItem represents a structured log entry sent across the mesh.
type LogItem struct {
	Timestamp int64  `json:"timestamp"`
	Level     string `json:"level"`
	Message   string `json:"message"`
	Service   string `json:"service"`
	// Audit metadata fields
	Actor  string `json:"actor,omitempty"`
	Action string `json:"action,omitempty"`
}

// RPCLogger provides an asynchronous logging client that falls back to a local WAL.
type RPCLogger struct {
	rpcManager  *secure_network.RPCManager
	localWAL    *ultimate_db.BatchingWAL
	serviceName string
	queue       chan LogItem
	wg          sync.WaitGroup
	ctx         context.Context
	cancel      context.CancelFunc
}

// NewRPCLogger initializes a new async mesh logger with local WAL persistence.
func NewRPCLogger(rpc *secure_network.RPCManager, serviceName string, bufferSize int, walPath string) (*RPCLogger, error) {
	ctx, cancel := context.WithCancel(context.Background())

	wal, err := ultimate_db.NewBatchingWAL(walPath)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize local logger WAL: %w", err)
	}

	l := &RPCLogger{
		rpcManager:  rpc,
		localWAL:    wal,
		serviceName: serviceName,
		queue:       make(chan LogItem, bufferSize),
		ctx:         ctx,
		cancel:      cancel,
	}

	l.wg.Add(1)
	go l.processQueue()

	return l, nil
}

// Info logs an informational message asynchronously.
func (l *RPCLogger) Info(message string) {
	l.send(LogItem{Level: "INFO", Message: message})
}

// Error logs an error message asynchronously.
func (l *RPCLogger) Error(message string) {
	l.send(LogItem{Level: "ERROR", Message: message})
}

// Debug logs a debug message asynchronously.
func (l *RPCLogger) Debug(message string) {
	l.send(LogItem{Level: "DEBUG", Message: message})
}

// Audit logs a security-sensitive action.
func (l *RPCLogger) Audit(actor, action, message string) {
	l.send(LogItem{
		Level:   "AUDIT",
		Actor:   actor,
		Action:  action,
		Message: message,
	})
}

// send internalizes common log item creation.
func (l *RPCLogger) send(item LogItem) {
	item.Timestamp = time.Now().UnixNano()
	item.Service = l.serviceName

	select {
	case l.queue <- item:
		// Queued in memory successfully
	default:
		l.persistLocally(item, "queue_full")
	}
}

// processQueue handles transmitting logs via RPC.
func (l *RPCLogger) processQueue() {
	defer l.wg.Done()
	for {
		select {
		case <-l.ctx.Done():
			l.flush()
			return
		case item, ok := <-l.queue:
			if !ok {
				return
			}
			l.dispatchRPC(item)
		}
	}
}

// dispatchRPC attempts to send the log over the mesh.
func (l *RPCLogger) dispatchRPC(item LogItem) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := l.rpcManager.Call(ctx, "system.log", item)
	if err != nil {
		l.persistLocally(item, fmt.Sprintf("rpc_failed: %v", err))
	}
}

// persistLocally writes a failed log to the ultimate_db WAL.
func (l *RPCLogger) persistLocally(item LogItem, reason string) {
	data, err := json.Marshal(item)
	if err != nil {
		fmt.Printf("CRITICAL: Failed to marshal log: %v\n", err)
		return
	}

	txnID := uint64(0)
	expiresAt := time.Now().Add(24 * 7 * time.Hour).UnixNano() // Audit logs kept longer
	pageID := ultimate_db.PageID(999)
	key := []byte(fmt.Sprintf("log:%d", item.Timestamp))

	err = l.localWAL.Append(txnID, expiresAt, pageID, key, data)
	if err != nil {
		fmt.Printf("CRITICAL: Failed to append to local WAL: %v\n", err)
		return
	}
}

// flush empties the queue safely during shutdown.
func (l *RPCLogger) flush() {
	close(l.queue)
	for item := range l.queue {
		l.persistLocally(item, "node_shutdown")
	}
}

// Close safely flushes the logger and closes the local WAL.
func (l *RPCLogger) Close() {
	l.cancel()
	l.wg.Wait()
	l.localWAL.Close()
}
