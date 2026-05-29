package logger

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/gddisney/ultimate_db"
)

type RPCLogger = LogDispatcher

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

func (ld *LogDispatcher) send(item LogItem) {
	item.Timestamp = time.Now().UnixNano()
	item.Service = ld.serviceName

	ld.persistToDB(item)

	select {
	case ld.queue <- item:
	default:
	}
}

func (ld *LogDispatcher) persistToDB(item LogItem) {
	data, _ := json.Marshal(item)
	key := []byte(fmt.Sprintf("log:%d", item.Timestamp))

	txn := ld.db.BeginTxn()
	_ = ld.db.Write(ld.logPage, txn, key, data, 0)
	ld.db.CommitTxn(txn)
}

func (ld *LogDispatcher) processQueue() {
	defer ld.wg.Done()
	for {
		select {
		case <-ld.ctx.Done():
			return
		case item, ok := <-ld.queue:
			if !ok {
				return
			}
			ld.dispatch(item)
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

// FIX: Standardized level strings using strings.ToUpper to make the invocation casing-agnostic
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

func (ld *LogDispatcher) Close() {
	ld.cancel()
	ld.wg.Wait()
}
