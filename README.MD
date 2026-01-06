# 🦉 Shard

*A sharp-eyed load tester that lives in your terminal.*

> When servers misbehave, the owl hoooots… and counts everything.

---

## 🚀 What is Shard?

**Shard** is a minimalist, high-performance **HTTP load testing tool** built for engineers who want **signal, not noise**.

It runs from your terminal, fires controlled bursts of requests at a server, and tells you:

* how fast responses are
* where requests fail
* which HTTP status families dominate
* when does your system slows down *before* it crashes

No dashboards. No web UI.
At best -> numbers and insights.

---

## 🧠 Philosophy

Shard follows three simple rules:

1. **The load tool should never crash before the server**
2. **Pressure should be visible, not hidden**
3. **Latency and failure reasons matter more than vanity RPS**

That’s it.

---

## ✨ Key Features

* ⚙️ **Bounded worker pool** (no goroutine explosions)

* 📊 **HTTP status family breakdown**

  * 2xx / 3xx / 4xx / 5xx / other
* ❌ **Top error reasons**

  * DNS, connect, timeout, TLS, etc.
* ⏱️ **Accurate latency tracking**
* 🧾 **JSONL output** (machine-friendly, grep-friendly)
* 🦉 **Terminal-first** — because browsers are noisy

---

## 📦 Installation

### 🔧 Option 1 — Build from source (recommended)

```bash
git clone https://github.com/yourname/shard.git
cd shard
go build -o shard ./cmd
```

You’ll get a single binary: `shard`

---

## ▶️ Usage

```bash
./shard attack --cfg example.json
./shard report --in logs.jsonl
```

Shard reads everything from a config file — no 20-flag CLI nonsense.

---

## ⚙️ Example `example.json`

```json
{
  "target": {
    "method": "GET",
    "url": "https://example.com/api"
  },
  "load": {
    "rate": 50,
    "duration": "10s",
    "concurrency": 128,
    "queue_size": 256,
    "timeout": "10s",
    "disable_keepalive": false,
    "insecure_tls": false,
    "http2": true
  },
  "output": {
    "jsonl": "logs.jsonl",
    "progress": "progress.log"
  }
}
```

---

## 🧱 Backpressure Modes (Important)

Shard **never** lets pending work grow unbounded.

## 📊 Live Output (Example)

```
sent=500 success=472 fail=28
2xx=450 3xx=22 4xx=18 5xx=10 other=0
avg=123ms
topErr: timeout=12 connect=9 dns=7
```

Shard tells you:

* what succeeded
* what failed
* *why* it failed
* and whether **your tool or your server** was the bottleneck

---

## 📁 Outputs

* **progress.log** — human-readable live stats
* **logs.jsonl** — one JSON object per request (perfect for analysis)

---

## 🧠 What Shard Is *Not*

* ❌ A browser-based load tester
* ❌ A distributed system (by design)
* ❌ A UI-heavy dashboard tool

Shard is for engineers who like:

* terminals
* numbers
* understanding failure modes

---

## 🦉 Why “Shard”?

Because:

* load breaks systems into shards
* latency fractures before failure
* and the owl sees what others miss

---

## 🦉 Author

Built by **Onaga08** —
a night owl who prefers terminals, numbers, and quiet confidence.
