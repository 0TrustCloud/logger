
# Cryptographic Logging Dispatcher (`logger`)

The `logger` package provides a high-throughput, tamper-evident structured logging framework designed for zero-trust systems to have verifiable cryptographic state contracts managed by the **Secure Data Format (SDF)** protocol engine.

Every emitted log statement, debugging event, or system audit record compiles directly into an immutable transaction receipt. Once a log entry is signed and sealed, its existence and contents are cryptographically provable and structurally impossible to retroactively alter or erase.

---

## 1. Architectural Blueprint

The logger is split into a non-blocking asynchronous dispatch pipeline and an emergency synchronous fallback pathway:

* **Asynchronous Queue Fast-Path:** In normal operations, log requests enter an active memory channel queue. A background processor handles the execution stream, pulling records, compiling them via the `SdfEngine`, and transmitting the fully signed token payloads to registered external destinations (such as SIEM platforms or upstream RPC logging sinks).
* **Emergency Backpressure Fallback:** If the asynchronous channel buffer fills completely or blocks due to external downstream exporter delays, the dispatcher triggers an automated synchronous fallback block. This bypasses the memory queue, forcing the compiling thread to write the ledger and index state updates directly into storage without losing tracking continuity.

---

## 2. Core Interfaces & Structures

### The Log Item Descriptor

Stores the uncompiled log schema domain fields alongside the resulting token footprint.

```go
type LogItem struct {
	Timestamp int64  `json:"timestamp"`
	Level     string `json:"level"`
	Message   string `json:"message"`
	Service   string `json:"service"`
	Actor     string `json:"actor,omitempty"`
	Action    string `json:"action,omitempty"`
	Token     string `json:"token,omitempty"` // Cryptographic SDF signature envelope
}

```

### The Exporter Interface

Allows you to attach custom output targets to pipe the finalized, token-enriched records straight into external SIEM tools or localized files.

```go
type Exporter interface {
	Export(item LogItem) error
}

```

---

## 3. Configuration & Usage

### Initializing the Logging Fabric

```go
import (
	"github.com/0TrustCloud/logger"
	"github.com/0TrustCloud/secure_data_format"
)

// Initialize the dispatcher with your service context and active SDF compiler engine
logDispatcher, err := logger.NewLogDispatcher("vault-service-pod", 1024, sdfEngineInstance)
if err != nil {
	panic(err)
}

// Register any external monitoring exporters
logDispatcher.RegisterExporter(myCustomSIEMExporter)

```

### Standard Telemetry Mappings

```go
// Standard application operational telemetry
logDispatcher.Info("Cryptographic key rotation interval began cleanly")
logDispatcher.Debug("Cache ring buffer validation passed")
logDispatcher.Error("Connection pool dropped connection socket 0x04")

// Strict structural compliance auditing
logDispatcher.Audit(
	"operator-greg", 
	"REVOKE_DEVICE", 
	"Blacklisted hardware posture certificate mapping",
)

```

---

## 4. Under the Hood: SDF Invocations

When an event triggers compilation, the dispatcher coordinates an internal state creation routine targeting `ProfileStructuredLog`. It passes unique nanosecond timestamps as order nonces to maintain strict ledger sequences:

```go
script := `log:event(status("emitted"))`
targetAddress := "log:vault-service-pod:1774831200000000000"

tx := secure_data_format.DataInvocation{
	TargetAddress: targetAddress,
	Caller:        "vault-service-pod",
	Nonce:         1774831200000000000,
	Method:        "EMIT",
	Profile:       secure_data_format.ProfileStructuredLog,
	Args: map[string]interface{}{
		"level":   "AUDIT",
		"message": "Blacklisted hardware posture certificate mapping",
		"actor":   "operator-greg",
		"action":  "REVOKE_DEVICE",
	},
}

```

This compilation generates a standard tamper-evident token payload, which is assigned back onto the `Token` property of your `LogItem` statement before being handed off to external exporters.

---

## 5. Security & Protection Matrix

| Threat Vector | Mitigation Strategy |
| --- | --- |
| **Log Cleansing / Deletion Attacks** | Logs are appended directly onto the immutable SDF `transaction_ledger`. Malicious actors or compromised root administrators cannot go back and rewrite historic hash chains. |
| **Out-of-Order Log Injection** | Incremental nanosecond timestamp assignments double as cryptographic transaction nonces, preventing retroactive back-dating or log-injection spoofing. |
| **Backpressure Log Loss** | If the async processing pipeline overflows, the dispatcher shifts to immediate synchronous compilation to guarantee transactional persistence before return. |

---

## 6. Local Testing Workflow

The package contains an in-memory mock framework to cleanly verify that logs are processing, self-signing, and routing correctly across different logging levels.

Run the local logging test suite using the standard Go toolchain:

```bash
go test -v ./...

```
