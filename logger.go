package logger

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/0TrustCloud/ultimate_db"
)

type RPCLogger = LogDispatcher

// LogItem represents a standardized zero-trust telemetry frame.
type LogItem struct {
	Timestamp int64  `json:"timestamp"`
	Level     string `json:"level"`
	Message   string `json:"message"`
	Service   string `json:"service"`
	Actor     string `json:"actor,omitempty"`
	Action    string `json:"action,omitempty"`
}

type Exporter interface {
	Export(item LogItem) error
}

type LogDispatcher struct {
	exporters   []Exporter
	exportersMu sync.RWMutex
	db          *ultimate_db.DB
	logPage     ultimate_db.PageID
	serviceName string
	queue       chan LogItem
	wg          sync.WaitGroup
	ctx         context.Context
	cancel      context.CancelFunc
}

// NewLogDispatcher configures an asynchronous, zero-copy structural logging subsystem.
func NewLogDispatcher(serviceName string, db *ultimate_db.DB, logPage ultimate_db.PageID, bufferSize int) (*LogDispatcher, error) {
	ctx, cancel := context.WithCancel(context.Background())

	ld := &LogDispatcher{
		exporters:   []Exporter{},
		db:          db,
		logPage:     logPage,
		serviceName: serviceName,
		queue:       make(chan LogItem, bufferSize),
		ctx:         ctx,
		cancel:      cancel,
	}

	ld.wg.Add(1)
	go ld.processQueue()

	return ld, nil
}

func (ld *LogDispatcher) RegisterExporter(e Exporter) {
	ld.exportersMu.Lock()
	defer ld.exportersMu.Unlock()
	ld.exporters = append(ld.exporters, e)
}

// send processes formatting rules instantly and pushes the element to the lock-free queue channel
func (ld *LogDispatcher) send(item LogItem) {
	item.Timestamp = time.Now().UnixNano()
	item.Service = ld.serviceName

	// TERMINAL STDOUT: Print logs instantly using fast conditional strings
	if item.Level == "AUDIT" {
		log.Printf("[%s] %s | Actor: %s | Action: %s | %s", item.Level, item.Service, item.Actor, item.Action, item.Message)
	} else if item.Action != "" {
		log.Printf("[%s] %s | Action: %s | %s", item.Level, item.Service, item.Action, item.Message)
	} else {
		log.Printf("[%s] %s | %s", item.Level, item.Service, item.Message)
	}

	// Dynamic Channel Guard: Prevents caller blocking during high-velocity threat ingestion bursts.
	// In production, we log a warning on stdout if the internal database pipeline is experiencing backpressure.
	select {
	case ld.queue <- item:
	default:
		log.Printf("[WARNING] Telemetry queue saturation. Log frame dropped to safeguard core plane uptime.")
	}
}

// processQueue acts as a single-threaded batching manager, pulling elements 
// asynchronously and committing them to the durable slot storage blocks.
func (ld *LogDispatcher) processQueue() {
	defer ld.wg.Done()

	const maxBatchSize = 128
	const batchTimeout = 10 * time.Millisecond

	batch := make([]LogItem, 0, maxBatchSize)
	ticker := time.NewTicker(batchTimeout)
	defer ticker.Stop()

	flushBatch := func() {
		if len(batch) == 0 {
			return
		}

		// Group-Commit Optimization: Enclose the entire batch inside a single transaction context
		txn := ld.db.BeginTxn()
		for _, item := range batch {
			data, err := json.Marshal(item)
			if err != nil {
				continue
			}
			key := []byte(fmt.Sprintf("log:%d", item.Timestamp))
			_ = ld.db.Write(ld.logPage, txn, key, data, 0)
		}
		ld.db.CommitTxn(txn)

		// Dispatch to secondary monitoring exports asynchronously
		for _, item := range batch {
			ld.dispatch(item)
		}
		batch = batch[:0]
	}

	for {
		select {
		case <-ld.ctx.Done():
			// Drain remaining buffer contents before executing termination sequences
			for {
				select {
				case item := <-ld.queue:
					batch = append(batch, item)
					if len(batch) >= maxBatchSize {
						flushBatch()
					}
				default:
					flushBatch()
					return
				}
			}

		case item, ok := <-ld.queue:
			if !ok {
				flushBatch()
				return
			}
			batch = append(batch, item)
			if len(batch) >= maxBatchSize {
				flushBatch()
			}

		case <-ticker.C:
			flushBatch()
		}
	}
}

func (ld *LogDispatcher) dispatch(item LogItem) {
	ld.exportersMu.RLock()
	defer ld.exportersMu.RUnlock()
	for _, exp := range ld.exporters {
		_ = exp.Export(item)
	}
}

func (ld *LogDispatcher) Log(level, component, msg string) {
	ld.send(LogItem{
		Level:   strings.ToUpper(strings.TrimSpace(level)),
		Action:  component,
		Message: msg,
	})
}

func (ld *LogDispatcher) Info(msg string)  { ld.send(LogItem{Level: "INFO", Message: msg}) }
func (ld *LogDispatcher) Error(msg string) { ld.send(LogItem{Level: "ERROR", Message: msg}) }
func (ld *LogDispatcher) Debug(msg string) { ld.send(LogItem{Level: "DEBUG", Message: msg}) }
func (ld *LogDispatcher) Audit(actor, action, msg string) {
	ld.send(LogItem{Level: "AUDIT", Actor: actor, Action: action, Message: msg})
}

// Close gracefully stops the worker thread and forces all trailing records to disk
func (ld *LogDispatcher) Close() {
	ld.cancel()
	ld.wg.Wait()
}
