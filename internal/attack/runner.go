package attack

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"shard/internal/config"
)

// Runner executes the attack.
type Runner struct {
	cfg    *config.Config
	client *http.Client
}

// StatsCollector maintains real-time metrics.
type StatsCollector struct {
	sent     int64
	success  int64
	fail     int64
	failMap  sync.Map
	totalLat int64
	twoXX    int64
	threeXX  int64
	fourXX   int64
	fiveXX   int64
}

// NewRunner creates a new attack runner from config.
func NewRunner(cfg *config.Config) (*Runner, error) {
	timeout, _ := time.ParseDuration(cfg.Load.Timeout)

	transport := &http.Transport{
		DisableKeepAlives: cfg.Load.DisableKeepAlive,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: cfg.Load.InsecureTLS},
	}

	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}

	return &Runner{cfg: cfg, client: client}, nil
}

// Run executes the full test and writes JSONL results.
func (r *Runner) Run(ctx context.Context, outPath string) error {
	rate := r.cfg.Load.Rate
	duration, _ := time.ParseDuration(r.cfg.Load.Duration)
	concurrency := r.cfg.Load.Concurrency

	req, err := r.makeRequest()
	if err != nil {
		return fmt.Errorf("make request: %w", err)
	}

	workCh := make(chan int, r.cfg.Load.QueueSize)
	results := make(chan Result, concurrency*2)
	stats := &StatsCollector{}
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for range workCh {
				res := r.doRequest(req)
				select {
				case results <- res:
				case <-ctx.Done():
					return
				}
			}
		}(i)
	}

	// Open results output file
	outFile, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("open output: %w", err)
	}
	defer outFile.Close()

	// Open persistent progress log
	progressFile, err := os.Create("progress.log")
	if err != nil {
		return fmt.Errorf("open progress log: %w", err)
	}
	defer progressFile.Close()

	// Writer + live progress goroutine
	go func() {
		enc := json.NewEncoder(outFile)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()

		start := time.Now()
		for {
			select {
			case res, ok := <-results:
				if !ok {
					printStats(stats, start, progressFile)
					fmt.Fprintln(progressFile, "---- Test completed ----")
					return
				}
				stats.Add(res)
				_ = enc.Encode(res)
			case <-ticker.C:
				printStats(stats, start, progressFile)
			}
		}
	}()

	// Fixed-rate scheduler
	interval := time.Second / time.Duration(rate)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	stop := time.After(duration)
	count := 0
loop:
	for {
		select {
		case <-stop:
			break loop
		case <-ticker.C:
			select {
			case workCh <- count:
				count++
			case <-ctx.Done():
				break loop
			}
		}
	}
	close(workCh)
	wg.Wait()
	close(results)
	return nil
}

// makeRequest builds the base HTTP request from config.
func (r *Runner) makeRequest() (*http.Request, error) {
	body := strings.NewReader("")
	if r.cfg.Target.BodyFile != "" {
		data, err := os.ReadFile(r.cfg.Target.BodyFile)
		if err != nil {
			return nil, fmt.Errorf("read body file: %w", err)
		}
		body = strings.NewReader(string(data))
	}

	req, err := http.NewRequest(r.cfg.Target.Method, r.cfg.Target.URL, body)
	if err != nil {
		return nil, err
	}
	for k, v := range r.cfg.Target.Headers {
		req.Header.Set(k, v)
	}
	return req, nil
}

// doRequest executes one traced HTTP request.
func (r *Runner) doRequest(base *http.Request) Result {
	var res Result
	var phases PhaseTimings
	var reused bool

	start := time.Now()
	req := base.Clone(context.Background())

	trace := &httptrace.ClientTrace{
		GotConn:      func(info httptrace.GotConnInfo) { reused = info.Reused },
		DNSStart:     func(_ httptrace.DNSStartInfo) { phases.DNS = time.Since(start) },
		DNSDone:      func(_ httptrace.DNSDoneInfo) { phases.DNS = time.Since(start) - phases.DNS },
		ConnectStart: func(_, _ string) { phases.Connect = time.Since(start) },
		ConnectDone: func(net, addr string, err error) {
			if err == nil {
				phases.Connect = time.Since(start) - phases.Connect
			}
		},
		TLSHandshakeStart:    func() { phases.TLS = time.Since(start) },
		TLSHandshakeDone:     func(_ tls.ConnectionState, _ error) { phases.TLS = time.Since(start) - phases.TLS },
		GotFirstResponseByte: func() { phases.TTFB = time.Since(start) },
	}

	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	resp, err := r.client.Do(req)
	total := time.Since(start)
	res.Timestamp = start
	res.Phases = phases
	res.Reused = reused
	res.Phases.Total = total

	if err != nil {
		res.Error = classifyError(err)
		res.FailPhase = res.Error
		return res
	}
	res.Code = resp.StatusCode
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return res
}

// classifyError creates a taxonomy label for an error and phase tag.
func classifyError(err error) string {
	msg := err.Error()
	switch {
	case os.IsTimeout(err):
		return "timeout"
	case strings.Contains(msg, "no such host"):
		return "dns"
	case strings.Contains(msg, "connection refused"), strings.Contains(msg, "connect"):
		return "connect"
	case strings.Contains(msg, "tls"):
		return "tls"
	case strings.Contains(msg, "EOF"), strings.Contains(msg, "read"):
		return "ttfb"
	default:
		return "other"
	}
}

// Add updates stats with a result.
func (s *StatsCollector) Add(r Result) {
	atomic.AddInt64(&s.sent, 1)
	if r.Error != "" {
		atomic.AddInt64(&s.fail, 1)
		s.failMap.LoadOrStore(r.FailPhase, new(int64))
		val, _ := s.failMap.Load(r.FailPhase)
		ptr := val.(*int64)
		atomic.AddInt64(ptr, 1)
		return
	}
	atomic.AddInt64(&s.success, 1)
	atomic.AddInt64(&s.totalLat, r.Phases.Total.Milliseconds())
	// per-status-family counts
	if r.Code > 0 {
		switch r.Code / 100 {
		case 2:
			atomic.AddInt64(&s.twoXX, 1)
		case 3:
			atomic.AddInt64(&s.threeXX, 1)
		case 4:
			atomic.AddInt64(&s.fourXX, 1)
		case 5:
			atomic.AddInt64(&s.fiveXX, 1)
		}
	}
}

// Snapshot returns a snapshot of current stats safely.
func (s *StatsCollector) Snapshot() (sent, success, fail int64, avgLat float64, fails map[string]int64, families map[string]int64) {
	sent = atomic.LoadInt64(&s.sent)
	success = atomic.LoadInt64(&s.success)
	fail = atomic.LoadInt64(&s.fail)
	totalLat := atomic.LoadInt64(&s.totalLat)
	if success > 0 {
		avgLat = float64(totalLat) / float64(success)
	}
	fails = make(map[string]int64)
	s.failMap.Range(func(k, v any) bool {
		fails[k.(string)] = atomic.LoadInt64(v.(*int64))
		return true
	})
	families = map[string]int64{
		"2xx": atomic.LoadInt64(&s.twoXX),
		"3xx": atomic.LoadInt64(&s.threeXX),
		"4xx": atomic.LoadInt64(&s.fourXX),
		"5xx": atomic.LoadInt64(&s.fiveXX),
	}
	return
}

// printStats prints real-time progress to terminal and writes it to progress.log.
func printStats(stats *StatsCollector, start time.Time, progressFile *os.File) {
	sent, success, fail, avg, fails, fam := stats.Snapshot()
	elapsed := time.Since(start).Round(time.Second)

	// live terminal line (overwrites)
	fmt.Printf("\r[%v] sent=%d ok=%d fail=%d avg=%.1fms",
		elapsed, sent, success, fail, avg)

	// append families
	var famParts []string
	if v := fam["2xx"]; v > 0 {
		famParts = append(famParts, fmt.Sprintf("2xx=%d", v))
	}
	if v := fam["3xx"]; v > 0 {
		famParts = append(famParts, fmt.Sprintf("3xx=%d", v))
	}
	if v := fam["4xx"]; v > 0 {
		famParts = append(famParts, fmt.Sprintf("4xx=%d", v))
	}
	if v := fam["5xx"]; v > 0 {
		famParts = append(famParts, fmt.Sprintf("5xx=%d", v))
	}
	if len(famParts) > 0 {
		fmt.Printf(" (%s)", strings.Join(famParts, " "))
	}

	// build fail breakdown
	var failParts []string
	for k, v := range fails {
		failParts = append(failParts, fmt.Sprintf("%s=%d", k, v))
	}

	// persistent log line
	line := fmt.Sprintf("[%v] sent=%d ok=%d fail=%d avg=%.1fms",
		elapsed, sent, success, fail, avg)
	if len(failParts) > 0 {
		line += " (" + strings.Join(failParts, ", ") + ")"
	}
	if len(famParts) > 0 {
		line += " " + strings.Join(famParts, " ")
	}
	line += "\n"

	if progressFile != nil {
		progressFile.WriteString(line)
	}
}
