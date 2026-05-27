package logger

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/gddisney/ultimate_db"
)

// LogItem represents a structured log entry.
type LogItem struct {
	Timestamp int64  `json:"timestamp"`
	Level     string `json:"level"`
	Message   string `json:"message"`
	Service   string `json:"service"`
	Actor     string `json:"actor,omitempty"`
	Action    string `json:"action,omitempty"`
}

// Exporter defines the interface for custom log targets (SIEM, RPC, etc.)
type Exporter interface {
	Export(item LogItem) error
}

// LogDispatcher manages the async pipeline and exporter registry.
type LogDispatcher struct {
	exporters   []Exporter
	exportersMu sync.RWMutex
	localWAL    *ultimate_db.BatchingWAL
	serviceName string
	queue       chan LogItem
	wg          sync.WaitGroup
	ctx         context.Context
	cancel      context.CancelFunc
}

// NewLogDispatcher initializes the pub/sub logging system.
func NewLogDispatcher(serviceName string, bufferSize int, walPath string) (*LogDispatcher, error) {
	ctx, cancel := context.WithCancel(context.Background())

	wal, err := ultimate_db.NewBatchingWAL(walPath)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to init WAL: %w", err)
	}

	ld := &LogDispatcher{
		exporters:   []Exporter{},
		localWAL:    wal,
		serviceName: serviceName,
		queue:       make(chan LogItem, bufferSize),
		ctx:         ctx,
		cancel:      cancel,
	}

	ld.wg.Add(1)
	go ld.processQueue()

	return ld, nil
}

// RegisterExporter adds a new destination (e.g., SIEM, RPC) to the dispatcher.
func (ld *LogDispatcher) RegisterExporter(e Exporter) {
	ld.exportersMu.Lock()
	defer ld.exportersMu.Unlock()
	ld.exporters = append(ld.exporters, e)
}

// --- Standard Logging Interface ---

func (ld *LogDispatcher) Info(message string)   { ld.send(LogItem{Level: "INFO", Message: message}) }
func (ld *LogDispatcher) Error(message string)  { ld.send(LogItem{Level: "ERROR", Message: message}) }
func (ld *LogDispatcher) Debug(message string)  { ld.send(LogItem{Level: "DEBUG", Message: message}) }
func (ld *LogDispatcher) Audit(actor, action, message string) {
	ld.send(LogItem{Level: "AUDIT", Actor: actor, Action: action, Message: message})
}

// send adds an item to the queue.
func (ld *LogDispatcher) send(item LogItem) {
	item.Timestamp = time.Now().UnixNano()
	item.Service = ld.serviceName

	select {
	case ld.queue <- item:
	default:
		ld.persistLocally(item, "queue_full")
	}
}

// processQueue handles the pub/sub distribution.
func (ld *LogDispatcher) processQueue() {
	defer ld.wg.Done()
	for {
		select {
		case <-ld.ctx.Done():
			ld.flush()
			return
		case item, ok := <-ld.queue:
			if !ok {
				return
			}
			ld.dispatch(item)
		}
	}
}

// dispatch sends the item to all registered exporters.
func (ld *LogDispatcher) dispatch(item LogItem) {
	ld.exportersMu.RLock()
	defer ld.exportersMu.RUnlock()

	for _, exp := range ld.exporters {
		if err := exp.Export(item); err != nil {
			ld.persistLocally(item, fmt.Sprintf("exporter_error: %v", err))
		}
	}
}

// persistLocally provides a fallback for failed exports or full queues.
func (ld *LogDispatcher) persistLocally(item LogItem, reason string) {
	data, _ := json.Marshal(item)
	key := []byte(fmt.Sprintf("log:%d:%s", item.Timestamp, reason))
	_ = ld.localWAL.Append(0, time.Now().Add(24*7*time.Hour).UnixNano(), 999, key, data)
}

func (ld *LogDispatcher) flush() {
	close(ld.queue)
	for item := range ld.queue {
		ld.persistLocally(item, "shutdown_flush")
	}
}

func (ld *LogDispatcher) Close() {
	ld.cancel()
	ld.wg.Wait()
	ld.localWAL.Close()
}
